/**
 * Phase 1 adversarial test set — scope containment as a single transport-layer
 * chokepoint. Covers the original 8-case set plus the 5 cases added for the
 * three-way programId policy (real / lab / invalid) and the redirect-hop
 * guard in scopedHttp. DB and DNS are mocked so every scenario is deterministic;
 * axios is mocked for the scopedHttp redirect-loop tests (4, 5, 13).
 *
 * Each `it` name states the expected verdict — read failures as "the guard's
 * decision was wrong", not "the mock was wrong".
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockLimit, mockWhere, mockFrom, mockSelect, mockResolve, mockResolve4 } = vi.hoisted(() => ({
  mockLimit: vi.fn(),
  mockWhere: vi.fn(),
  mockFrom: vi.fn(),
  mockSelect: vi.fn(),
  mockResolve: vi.fn(),
  mockResolve4: vi.fn(),
}));

vi.mock('../db', () => ({ db: { select: mockSelect } }));
vi.mock('../db/schema', () => ({ programs: { id: 'id' }, targets: {} }));
vi.mock('drizzle-orm', () => ({ eq: vi.fn((a, b) => ({ a, b })) }));
vi.mock('dns', () => ({ default: { promises: { resolve: mockResolve, resolve4: mockResolve4 } } }));
vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));
vi.mock('axios', () => ({ default: { get: vi.fn(), post: vi.fn(), request: vi.fn() } }));

import { ScopeGuard } from '../middleware/scopeGuard';
import { scopedHttp, OutOfScopeError } from '../lib/net/scoped-http';
import axios from 'axios';

// ── Per-test fixtures ────────────────────────────────────────────────────────
let programRows: Array<{ id: number; scope: string[]; outOfScope: string[] }> = [];
let aRecords: Record<string, string[]> = {};

function setProgram(id: number, scope: string[], outOfScope: string[] = []) {
  programRows = [{ id, scope, outOfScope }];
}
function setA(host: string, ips: string[]) {
  aRecords[host] = ips;
}

beforeEach(() => {
  programRows = [];
  aRecords = {};
  vi.clearAllMocks();

  mockSelect.mockImplementation(() => ({ from: mockFrom }));
  mockFrom.mockImplementation(() => ({ where: mockWhere }));
  mockWhere.mockImplementation(() => ({ limit: mockLimit }));
  mockLimit.mockImplementation(() => Promise.resolve(programRows));

  mockResolve.mockImplementation(() => Promise.reject(new Error('no CNAME')));
  mockResolve4.mockImplementation((host: string) =>
    aRecords[host] ? Promise.resolve(aRecords[host]) : Promise.reject(new Error('no A record')));

  // Fresh singleton per test — ScopeGuard caches scope for 30s per programId,
  // which would leak state across (and within, for a changed-scope test) tests.
  (ScopeGuard as unknown as { instance: undefined }).instance = undefined;
});

describe('Phase 1 adversarial set — ScopeGuard.isInScope', () => {
  it('1. in-scope host → allowed', async () => {
    setProgram(101, ['example.com'], []);
    setA('example.com', ['93.184.216.34']); // public IP, no CNAME
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('https://example.com/path', 101);
    expect(r.allowed).toBe(true);
  });

  it('2. out-of-scope host → blocked', async () => {
    setProgram(101, ['example.com'], []);
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('https://evil.com/', 101);
    expect(r.allowed).toBe(false);
  });

  it('3. explicitly-excluded subdomain of an in-scope wildcard → blocked', async () => {
    setProgram(101, ['*.example.com'], ['admin.example.com']);
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('https://admin.example.com/panel', 101);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/out-of-scope pattern/i);
  });

  it('4. (via scopedHttp) request that redirects to an out-of-scope host → blocked at the redirect hop', async () => {
    setProgram(301, ['good.com'], []);
    setA('good.com', ['1.2.3.4']);
    vi.mocked(axios.get).mockResolvedValueOnce({
      status: 302, headers: { location: 'https://evil.com/steal' }, data: '',
    } as never);
    await expect(scopedHttp.get('https://good.com/redirector', {}, 301))
      .rejects.toThrow(OutOfScopeError);
    // The redirect target must never actually be requested.
    expect(axios.request).not.toHaveBeenCalled();
    expect(axios.get).toHaveBeenCalledTimes(1); // only the first (in-scope) hop fired
  });

  it('5. (via scopedHttp) request that redirects to an excluded IP → blocked', async () => {
    setProgram(302, ['good.com', 'sneaky.net'], ['10.0.0.99']);
    setA('good.com', ['1.2.3.4']);
    setA('sneaky.net', ['10.0.0.99']); // in-scope hostname, but resolves to an excluded IP
    vi.mocked(axios.get).mockResolvedValueOnce({
      status: 302, headers: { location: 'https://sneaky.net/pivot' }, data: '',
    } as never);
    await expect(scopedHttp.get('https://good.com/redirector', {}, 302))
      .rejects.toThrow(OutOfScopeError);
    expect(axios.request).not.toHaveBeenCalled();
  });

  it('6. in-scope hostname that A-records to an excluded IP → blocked on resolved-IP check', async () => {
    setProgram(101, ['sneaky.net'], ['10.0.0.99']);
    setA('sneaky.net', ['10.0.0.99']);
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('https://sneaky.net/', 101);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/resolved ip.*matches/i);
  });

  it('7. malformed / unparseable URL → fail closed (blocked)', async () => {
    setProgram(101, ['example.com'], []);
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('not a url at all ??', 101);
    expect(r.allowed).toBe(false);
  });

  it('8. scope-evaluation throws (DB error) → fail closed', async () => {
    mockLimit.mockImplementationOnce(() => Promise.reject(new Error('DB connection lost')));
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('https://example.com/', 101);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/failing closed/i);
  });

  it('9. missing / 0 programId → blocked (fail closed), not skipped', async () => {
    const guard = ScopeGuard.getInstance();
    const rMissing = await guard.isInScope('https://example.com/', undefined as unknown as number);
    expect(rMissing.allowed).toBe(false);
    expect(rMissing.reason).toMatch(/invalid programId/i);
    const rZero = await guard.isInScope('https://example.com/', 0);
    expect(rZero.allowed).toBe(false);
    expect(rZero.reason).toMatch(/invalid programId/i);
    // Neither call should have touched the DB — invalid is rejected before any lookup.
    expect(mockSelect).not.toHaveBeenCalled();
  });

  it('10. programId===-1 (lab sentinel): private-IP target allowed, but the loaded scope\'s own exclusions still bind', async () => {
    setProgram(-1, ['localhost', '10.0.0.0/8'], []);
    setA('localhost', ['127.0.0.1']);
    const guard = ScopeGuard.getInstance();
    const allowed = await guard.isInScope('http://localhost:3000/', -1);
    expect(allowed.allowed).toBe(true); // private/loopback IP not blocked under lab policy

    // Same lab program, now with an explicit exclusion — cache must not mask the change.
    guard.invalidateCache(-1);
    setProgram(-1, ['localhost', '*.internal.lab'], ['admin.internal.lab']);
    const blocked = await guard.isInScope('http://admin.internal.lab/', -1);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toMatch(/out-of-scope pattern/i);
  });

  it('11. programId > 0 (real program) against a host resolving to a private IP → blocked (rebinding)', async () => {
    setProgram(202, ['public-looking.com'], []);
    setA('public-looking.com', ['10.1.2.3']); // public hostname, rebinds to RFC-1918
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('https://public-looking.com/', 202);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/rebinding/i);
  });

  it('12. DNS resolution failure on the resolved-IP/CIDR check under programId > 0 → fail closed', async () => {
    // IP/CIDR exclusions are declared, but the terminal host's A record can't be resolved.
    setProgram(202, ['flaky.com'], ['10.0.0.0/8']);
    // no setA('flaky.com', ...) → dns.promises.resolve4 rejects
    const guard = ScopeGuard.getInstance();
    const r = await guard.isInScope('https://flaky.com/', 202);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/could not resolve/i);
  });

  it('13. redirect hop whose scope check fails (DNS resolution error on a real program with declared IP/CIDR exclusions) → request ABORTED', async () => {
    // "real" policy + declared IP/CIDR exclusion → resolve4 failure fails closed (see test 12).
    // First hop resolves fine; the redirect hop's re-validation hits a resolution
    // failure and must abort before any second axios call is made.
    setProgram(303, ['good.com'], ['10.0.0.0/8']);
    mockResolve4.mockImplementationOnce(() => Promise.resolve(['1.2.3.4'])) // hop 1: resolves fine
                .mockImplementationOnce(() => Promise.reject(new Error('resolver timeout'))); // hop 2 (redirect target)
    vi.mocked(axios.get).mockResolvedValueOnce({
      status: 302, headers: { location: 'https://good.com/next' }, data: '',
    } as never);
    await expect(scopedHttp.get('https://good.com/start', {}, 303))
      .rejects.toThrow(OutOfScopeError);
    expect(axios.request).not.toHaveBeenCalled();
    expect(axios.get).toHaveBeenCalledTimes(1); // hop 2 never fires — aborted before dispatch
  });
});

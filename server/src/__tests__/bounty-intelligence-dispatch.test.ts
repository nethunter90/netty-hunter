/**
 * BountyIntelligenceService recon migration verification (Phase 2,
 * external-tool chokepoint). reconSubdomains/reconTechnologies/
 * reconEndpoints previously shelled out to subfinder/whatweb/httpx with the
 * raw, unvalidated, unscoped request-body target (2026-07-21 RCE stopgap).
 * Confirms they now dispatch through dispatchTool() — scope-checked,
 * execFile array-args — including reconEndpoints' per-host loop (previously
 * a single un-scope-checked multi-target httpx call).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { dispatchToolMock } = vi.hoisted(() => ({ dispatchToolMock: vi.fn() }));

vi.mock('../lib/net/dispatch-tool', () => ({
  dispatchTool: dispatchToolMock,
}));

import { BountyIntelligenceService } from '../lib/bounty-intelligence';

// Skip the real constructor (ProgramFetcher.startAutoFetch(), file-system
// storage dirs, etc.) — these three methods only touch their own params.
function makeBareService(): any {
  return Object.create(BountyIntelligenceService.prototype);
}

const DOMAIN = 'example.test';
const TARGET_URL = 'https://example.test';
const PROGRAM_ID = 7;

beforeEach(() => {
  dispatchToolMock.mockReset();
  dispatchToolMock.mockResolvedValue({ stdout: '', stderr: '', durationMs: 1, bin: 'x', args: [] });
});

describe('reconSubdomains/reconTechnologies/reconEndpoints — dispatchTool wiring', () => {
  it('reconSubdomains calls dispatchTool with a {domain} placeholder and the resolved programId', async () => {
    const svc = makeBareService();
    await svc.reconSubdomains(DOMAIN, TARGET_URL, 'medium', true, PROGRAM_ID);
    expect(dispatchToolMock).toHaveBeenCalledWith(expect.objectContaining({
      tool: 'subfinder', target: TARGET_URL, programId: PROGRAM_ID,
      args: expect.arrayContaining(['{domain}']),
    }));
  });

  it('reconTechnologies calls dispatchTool for whatweb with the resolved programId', async () => {
    const svc = makeBareService();
    await svc.reconTechnologies(DOMAIN, TARGET_URL, true, PROGRAM_ID);
    expect(dispatchToolMock).toHaveBeenCalledWith(expect.objectContaining({
      tool: 'whatweb', target: TARGET_URL, programId: PROGRAM_ID,
    }));
  });

  it('reconEndpoints dispatches ONE call per host (domain + each subdomain), each independently scope-checked', async () => {
    const svc = makeBareService();
    const subdomains = [{ hostname: 'api.example.test' }, { hostname: 'admin.example.test' }];
    await svc.reconEndpoints(DOMAIN, subdomains, 'medium', true, PROGRAM_ID);
    expect(dispatchToolMock).toHaveBeenCalledTimes(3); // domain + 2 subdomains
    const targets = dispatchToolMock.mock.calls.map((c: any) => c[0].target);
    expect(targets).toContain('https://example.test');
    expect(targets).toContain('https://api.example.test');
    expect(targets).toContain('https://admin.example.test');
    for (const call of dispatchToolMock.mock.calls) {
      expect(call[0].programId).toBe(PROGRAM_ID);
      expect(call[0].tool).toBe('httpx');
    }
  });

  it('reconEndpoints: one out-of-scope host does not abort the rest of the batch', async () => {
    dispatchToolMock
      .mockRejectedValueOnce(new Error('out of scope'))
      .mockResolvedValueOnce({ stdout: '{"url":"https://api.example.test/","status_code":200}', stderr: '', durationMs: 1, bin: 'httpx', args: [] });
    const svc = makeBareService();
    const result = await svc.reconEndpoints(DOMAIN, [{ hostname: 'api.example.test' }], 'medium', true, PROGRAM_ID);
    expect(result.length).toBe(1);
    expect(result[0].url).toBe('https://api.example.test/');
  });

  it('isReal=false never calls dispatchTool (simulation path unaffected)', async () => {
    const svc = makeBareService();
    const result = await svc.reconSubdomains(DOMAIN, TARGET_URL, 'shallow', false, PROGRAM_ID);
    expect(dispatchToolMock).not.toHaveBeenCalled();
    expect(result.length).toBeGreaterThan(0);
  });
});

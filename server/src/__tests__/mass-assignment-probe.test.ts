/**
 * MassAssignmentProber — found live alongside the identical bug in
 * race-condition-detector.ts: on a target where guessed endpoints
 * (/api/user, /api/me, /api/profile, ...) don't actually exist and the
 * server falls through to a global SPA catch-all (any unmatched path,
 * including under /api/, returns the same index.html shell), the probe's
 * existing "baseline" only GETs the same guessed path — which hits the
 * identical catch-all and returns the identical shell, so `accepted =
 * [200,201,204].includes(status)` was true for every single guessed
 * endpoint regardless of whether it was real. All 17 findings from a live
 * hunt against such a target were false positives.
 *
 * Fixed with the same technique as race-condition-detector.ts: a real
 * bogus-path baseline (same HTTP method, a path guaranteed not to exist)
 * to distinguish "the server has a real route here" from "everything 200s."
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

vi.mock('../lib/tools/csrf-aware-request', () => ({
  csrfAwareRequest: vi.fn(),
}));

vi.mock('axios', () => ({
  default: { get: vi.fn(), request: vi.fn() },
}));

import axios from 'axios';
import { csrfAwareRequest } from '../lib/tools/csrf-aware-request';
import { massAssignmentProber } from '../lib/tools/mass-assignment-probe';

const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;
const mockedRequest = axios.request as unknown as ReturnType<typeof vi.fn>;
const mockedCsrf = csrfAwareRequest as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedGet.mockReset();
  mockedRequest.mockReset();
  mockedCsrf.mockReset();
});

describe('MassAssignmentProber', () => {
  it('does not flag a SPA catch-all where every guessed endpoint 200s identically (the real false positive found live)', async () => {
    const shellBody = '<!DOCTYPE html><html>...</html>';
    mockedGet.mockResolvedValue({ status: 200, data: shellBody }); // same-path GET baseline
    mockedRequest.mockResolvedValue({ status: 200, data: shellBody }); // bogus-path PUT/PATCH/POST baseline
    mockedCsrf.mockResolvedValue({ status: 200, data: shellBody, csrfBypassUsed: false }); // every guessed endpoint

    // Distinct host per test — the prober caches its bogus-path baseline
    // per targetUrl, so reusing a host across tests would leak state.
    const result = await massAssignmentProber.probe('http://catchall-example.com/');

    expect(result.vulns).toEqual([]);
    expect(result.hypotheses).toEqual([]);
  });

  it('still flags a real endpoint that accepts privileged fields and differs from the catch-all baseline', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: 'Not Found' });
    mockedRequest.mockResolvedValue({ status: 404, data: 'Not Found' }); // bogus-path baselines: real 404s

    mockedCsrf.mockImplementation(async (url: string) => {
      if (url.includes('/api/user')) {
        // Real, distinct route that actually accepts the privileged field.
        return { status: 200, data: { role: 'admin', isAdmin: true }, csrfBypassUsed: false };
      }
      return { status: 404, data: 'Not Found', csrfBypassUsed: false };
    });

    const result = await massAssignmentProber.probe('http://real-endpoint-example.com/');

    const vuln = result.vulns.find(v => v.endpoint === 'http://real-endpoint-example.com/api/user');
    expect(vuln).toBeDefined();
    expect(vuln!.accepted).toBe(true);

    const hyp = result.hypotheses.find(h => h.raw === vuln);
    expect(hyp!.vulnClass).toBe('mass_assignment');
  });

  it('normalizes a trailing slash on targetUrl instead of producing a double slash', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: '' });
    mockedRequest.mockResolvedValue({ status: 404, data: '' });
    mockedCsrf.mockResolvedValue({ status: 404, data: '', csrfBypassUsed: false });

    await massAssignmentProber.probe('http://slash-example.com/');

    const csrfUrls = mockedCsrf.mock.calls.map((c: unknown[]) => c[0] as string);
    expect(csrfUrls.every(u => !u.includes('//api'))).toBe(true);
  });
});

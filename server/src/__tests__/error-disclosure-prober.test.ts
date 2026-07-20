/**
 * error-disclosure-prober — malformed input provoking a leaky error response.
 *
 * Ground truth from a real target (2026-07-10): hardcoded default creds leaked
 * in an error message, and raw error.message returned to the client across
 * ~6 routes, leaking internal filesystem paths. secret-scanner.ts's
 * fetchAndScan() explicitly excludes non-200 responses, so nothing scans error
 * bodies at all — this prober closes that gap.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({
      isInScope: vi.fn().mockResolvedValue({ allowed: true }),
    }),
  },
}));

vi.mock('axios', () => ({
  default: { request: vi.fn() },
}));

import axios from 'axios';
import { errorDisclosureProber } from '../lib/tools/error-disclosure-prober';

const mockedRequest = axios.request as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedRequest.mockReset();
});

describe('errorDisclosureProber', () => {
  it('flags a secret leaked via a provoked error response', async () => {
    mockedRequest.mockResolvedValue({
      status: 500,
      data: { error: 'DB connection failed: postgres://admin:S3cretPass!@db.internal:5432/prod' },
      headers: {},
    });

    const result = await errorDisclosureProber.probe('http://localhost:5000/api/users?id=1');

    expect(result.findings.length).toBeGreaterThan(0);
    const withSecret = result.findings.find(f => f.secretsFound.length > 0);
    expect(withSecret).toBeDefined();
    expect(withSecret!.secretsFound).toContain('db_connection');
  });

  it('flags a raw stack trace / internal path leak even with no credential present', async () => {
    mockedRequest.mockResolvedValue({
      status: 400,
      data: { error: "Cannot read properties of undefined (reading 'id')\n    at Object.<anonymous> (/home/kali/Desktop/Kali-Web-IDE/server/routes.ts:143:22)" },
      headers: {},
    });

    const result = await errorDisclosureProber.probe('http://localhost:5000/api/files/read?path=x');

    expect(result.findings.length).toBeGreaterThan(0);
    const withPath = result.findings.find(f => f.pathsLeaked.length > 0);
    expect(withPath).toBeDefined();
    expect(withPath!.pathsLeaked).toEqual(expect.arrayContaining(['unix_absolute_path']));
  });

  it('does not flag a clean, generic error response', async () => {
    mockedRequest.mockResolvedValue({
      status: 400,
      data: { success: false, error: 'Invalid request' },
      headers: {},
    });

    const result = await errorDisclosureProber.probe('http://localhost:5000/api/users?id=1');

    expect(result.findings).toEqual([]);
    expect(result.hypotheses).toEqual([]);
  });

  it('scans responses regardless of status code, not just 4xx/5xx', async () => {
    // Some apps embed the error in a 200 response body instead of a real
    // error status — this must not gate on status code.
    mockedRequest.mockResolvedValue({
      status: 200,
      data: { success: false, error: 'ENOENT: no such file or directory, open \'/etc/shadow\'' },
      headers: {},
    });

    const result = await errorDisclosureProber.probe('http://localhost:5000/api/files/read?path=x');

    expect(result.findings.length).toBeGreaterThan(0);
  });
});

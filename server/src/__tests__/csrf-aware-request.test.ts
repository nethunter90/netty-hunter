/**
 * csrf-aware-request — double-submit-cookie CSRF bypass.
 *
 * Proven live against a real target (Kali-Web-IDE, 2026-07-10): GET /api/csrf-token
 * mints a cookie + returns the same value in the JSON body with zero auth; POST
 * endpoints protected by a double-submit check (cookie === header, no server-side
 * session tie) accept the request once that self-minted token is replayed as both
 * the cookie and the expected header. A prober that stops at the first CSRF-shaped
 * 403 never discovers this whole class of finding.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('axios', () => ({
  default: { get: vi.fn(), request: vi.fn() },
}));

import axios from 'axios';
import { csrfAwareRequest, getCsrfHeaders, resetCsrfCache } from '../lib/tools/csrf-aware-request';

const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;
const mockedRequest = axios.request as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  resetCsrfCache();
  mockedGet.mockReset();
  mockedRequest.mockReset();
});

describe('csrfAwareRequest', () => {
  it('returns immediately when the request succeeds without CSRF protection', async () => {
    mockedRequest.mockResolvedValueOnce({ status: 200, data: { success: true }, headers: {} });

    const result = await csrfAwareRequest('http://localhost:5000/api/files/write', 'POST', { path: 'x' });

    expect(result.status).toBe(200);
    expect(result.csrfBypassUsed).toBe(false);
    expect(mockedRequest).toHaveBeenCalledTimes(1);
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it('discovers a token endpoint and retries with cookie+header on a CSRF-shaped 403', async () => {
    mockedRequest
      .mockResolvedValueOnce({ status: 403, data: { success: false, error: 'Invalid CSRF token' }, headers: {} })
      .mockResolvedValueOnce({ status: 200, data: { success: true }, headers: {} });

    mockedGet.mockResolvedValueOnce({
      status: 200,
      data: { csrfToken: 'minted-token-abc' },
      headers: { 'set-cookie': ['_csrf_token=minted-token-abc; Path=/; SameSite=Strict'] },
    });

    const result = await csrfAwareRequest('http://localhost:5000/api/files/write', 'POST', { path: 'x' });

    expect(result.status).toBe(200);
    expect(result.csrfBypassUsed).toBe(true);
    expect(mockedGet).toHaveBeenCalledTimes(1);
    expect(mockedGet.mock.calls[0][0]).toBe('http://localhost:5000/api/csrf-token');

    const retryHeaders = mockedRequest.mock.calls[1][0].headers;
    expect(retryHeaders['Cookie']).toContain('_csrf_token=minted-token-abc');
    expect(retryHeaders['x-csrf-token']).toBe('minted-token-abc');
  });

  it('falls back to the original rejection when no token endpoint exists', async () => {
    mockedRequest.mockResolvedValueOnce({
      status: 403, data: { success: false, error: 'Invalid CSRF token' }, headers: {},
    });
    mockedGet.mockResolvedValue({ status: 404, data: {}, headers: {} });

    const result = await csrfAwareRequest('http://localhost:5000/api/files/write', 'POST', { path: 'x' });

    expect(result.status).toBe(403);
    expect(result.csrfBypassUsed).toBe(false);
    expect(mockedRequest).toHaveBeenCalledTimes(1);
  });

  it('does not treat a non-CSRF 403 as a discovery trigger', async () => {
    mockedRequest.mockResolvedValueOnce({
      status: 403, data: { error: 'Forbidden: insufficient permissions' }, headers: {},
    });

    const result = await csrfAwareRequest('http://localhost:5000/api/admin/users', 'DELETE', {});

    expect(result.csrfBypassUsed).toBe(false);
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it('caches discovery per-origin so a second CSRF-rejected call does not re-probe candidate paths', async () => {
    mockedRequest
      .mockResolvedValueOnce({ status: 403, data: { error: 'csrf' }, headers: {} })
      .mockResolvedValueOnce({ status: 200, data: { success: true }, headers: {} })
      .mockResolvedValueOnce({ status: 403, data: { error: 'csrf' }, headers: {} })
      .mockResolvedValueOnce({ status: 200, data: { success: true }, headers: {} });

    mockedGet.mockResolvedValueOnce({
      status: 200,
      data: { csrfToken: 'tok-1' },
      headers: { 'set-cookie': ['_csrf_token=tok-1'] },
    });

    await csrfAwareRequest('http://localhost:5000/api/a', 'POST', {});
    await csrfAwareRequest('http://localhost:5000/api/b', 'POST', {});

    expect(mockedGet).toHaveBeenCalledTimes(1);
  });
});

describe('getCsrfHeaders', () => {
  it('returns matching cookie and header entries for a warm-up call', async () => {
    mockedGet.mockResolvedValueOnce({
      status: 200,
      data: { csrfToken: 'warm-token' },
      headers: { 'set-cookie': ['_csrf_token=warm-token; Path=/'] },
    });

    const headers = await getCsrfHeaders('http://localhost:5000');

    expect(headers['Cookie']).toBe('_csrf_token=warm-token');
    expect(headers['x-csrf-token']).toBe('warm-token');
  });

  it('returns an empty object when no token endpoint is reachable', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: {}, headers: {} });

    const headers = await getCsrfHeaders('http://localhost:5000');

    expect(headers).toEqual({});
  });
});

/**
 * ScopeGuard path-aware matching — pure helpers, no DB.
 *
 * Pins the safety-critical invariants of the host+path scope gate:
 *  - host-only patterns behave exactly as before (admit any path),
 *  - path-bearing patterns restrict to their subtree (boundary-safe),
 *  - out-of-scope takes precedence,
 *  - port is not part of host identity (localhost:5000 scoping works),
 *  - loopback/private literals are recognized as local (rebinding bypass).
 */
import { describe, it, expect } from 'vitest';
import {
  evaluateScopeDecision, hostMatches, pathMatches, parsePattern, isLocalHostname,
} from '../middleware/scopeGuard';

describe('parsePattern', () => {
  it('splits host and path; strips scheme + trailing slash', () => {
    expect(parsePattern('http://localhost:5000/api/Addresss/')).toEqual({ hostPart: 'localhost:5000', pathPrefix: '/api/Addresss' });
    expect(parsePattern('example.com')).toEqual({ hostPart: 'example.com', pathPrefix: null });
    expect(parsePattern('*')).toEqual({ hostPart: '*', pathPrefix: null });
  });
});

describe('hostMatches', () => {
  it('matches ignoring port and wildcard prefix; * matches all', () => {
    expect(hostMatches('localhost', 'localhost:5000')).toBe(true);   // port stripped
    expect(hostMatches('localhost', 'localhost')).toBe(true);
    expect(hostMatches('api.example.com', '*.example.com')).toBe(true);
    expect(hostMatches('example.com', '*.example.com')).toBe(true);
    expect(hostMatches('anything.test', '*')).toBe(true);
    expect(hostMatches('evil.com', 'example.com')).toBe(false);
  });
});

describe('pathMatches', () => {
  it('null/root admits any path', () => {
    expect(pathMatches('/anything', null)).toBe(true);
    expect(pathMatches('/anything', '/')).toBe(true);
  });
  it('is boundary-safe (no false prefix match)', () => {
    expect(pathMatches('/api/Addresss', '/api/Addresss')).toBe(true);
    expect(pathMatches('/api/Addresss/1', '/api/Addresss')).toBe(true);
    expect(pathMatches('/api/AddresssBook', '/api/Addresss')).toBe(false);
    expect(pathMatches('/api/admin', '/api/Addresss')).toBe(false);
  });
});

describe('isLocalHostname', () => {
  it('recognizes loopback / private literals', () => {
    expect(isLocalHostname('localhost')).toBe(true);
    expect(isLocalHostname('localhost:5000')).toBe(true);
    expect(isLocalHostname('127.0.0.1')).toBe(true);
    expect(isLocalHostname('10.0.0.5')).toBe(true);
    expect(isLocalHostname('::1')).toBe(true);
    expect(isLocalHostname('example.com')).toBe(false);
    expect(isLocalHostname('8.8.8.8')).toBe(false);
  });
});

describe('evaluateScopeDecision', () => {
  it('host-only scope admits any path (backward compatible)', () => {
    expect(evaluateScopeDecision('example.com', '/anything', ['example.com'], []).allowed).toBe(true);
    expect(evaluateScopeDecision('x.test', '/y', ['*'], []).allowed).toBe(true);
  });

  it('path scope restricts to the subtree', () => {
    const inScope = ['localhost:5000/api/Addresss'];
    expect(evaluateScopeDecision('localhost', '/api/Addresss', inScope, []).allowed).toBe(true);
    expect(evaluateScopeDecision('localhost', '/api/Addresss/1', inScope, []).allowed).toBe(true);
    const blocked = evaluateScopeDecision('localhost', '/api/admin', inScope, []);
    expect(blocked.allowed).toBe(false);
    expect(blocked.reason).toMatch(/path .* outside/i);
  });

  it('out-of-scope takes precedence (host-only and path)', () => {
    // host-only OOS blocks the whole host even if in-scope
    expect(evaluateScopeDecision('admin.example.com', '/x', ['*.example.com'], ['admin.example.com']).allowed).toBe(false);
    // path OOS blocks only its subtree; siblings stay allowed
    const inScope = ['localhost:5000'];
    const outScope = ['localhost:5000/api/admin'];
    expect(evaluateScopeDecision('localhost', '/api/admin/x', inScope, outScope).allowed).toBe(false);
    expect(evaluateScopeDecision('localhost', '/api/Addresss', inScope, outScope).allowed).toBe(true);
  });

  it('blocks a host not present in any in-scope pattern', () => {
    const r = evaluateScopeDecision('evil.com', '/', ['example.com'], []);
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/not found in any in-scope/i);
  });
});

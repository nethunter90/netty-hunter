/**
 * OOB-RCE injection vectors — buildRceOobAttempts().
 *
 * The blind-RCE OOB probe must cover shell-BREAKOUT contexts (a param embedded in
 * a command), not just the raw value-as-command case, across multiple param names
 * and both GET/POST — otherwise it misses real command-injection sinks.
 */
import { describe, it, expect } from 'vitest';
import { buildRceOobAttempts } from '../agents/HunterEngine';

const CB = 'http://localhost:3001/api/callback/abc-123';

describe('buildRceOobAttempts', () => {
  const attempts = buildRceOobAttempts('http://localhost:5000/run?host=x', CB);
  const urls = attempts.map(a => a.url);
  const all = attempts.map(a => a.url + JSON.stringify(a.body ?? {}));

  it('is bounded to the hard cap', () => {
    expect(attempts.length).toBeGreaterThan(0);
    expect(attempts.length).toBeLessThanOrEqual(24);
  });

  it('includes shell-breakout variants, not just raw', () => {
    const joined = decodeURIComponent(all.join(' ')).replace(/\+/g, ' ');
    expect(joined).toMatch(/;\s*curl/);      // semicolon
    expect(joined).toMatch(/\|\s*curl/);     // pipe
    expect(joined).toMatch(/\$\(curl/);      // command substitution
    expect(joined).toMatch(/`curl/);         // backtick
  });

  it('covers multiple param names including one already on the URL', () => {
    // host is present on the target URL → findInjectableParams surfaces it
    const hasHost = urls.some(u => new URL(u).searchParams.has('host'));
    const hasCmd = urls.some(u => new URL(u).searchParams.has('cmd'));
    expect(hasHost).toBe(true);
    expect(hasCmd).toBe(true);
  });

  it('every attempt references the callback and exfils whoami', () => {
    for (const a of all) {
      const dec = decodeURIComponent(a);
      expect(dec).toContain('/api/callback/abc-123');
      expect(dec).toContain('u=$(whoami)');
    }
  });

  it('includes at least one POST attempt', () => {
    expect(attempts.some(a => a.method === 'POST' && a.body)).toBe(true);
  });
});

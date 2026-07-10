/**
 * applyVulnClassAllowlist — hard scope-narrowing gate.
 *
 * focusVulnClasses is additive-only (seeds extra priority hypotheses; every
 * other prober/class still runs and reports normally). This is the real
 * exclusionary filter for narrowing a hunt down to one or a few vuln classes
 * deliberately — e.g. "RCE only" to cut noise and inconsistency down to a
 * single, well-understood surface.
 */
import { describe, it, expect } from 'vitest';
import { applyVulnClassAllowlist } from '../agents/HunterEngine';

function hyp(vulnClass: string, status = 'pending') {
  return { vulnClass, status, id: `${vulnClass}-${Math.random()}` };
}

describe('applyVulnClassAllowlist', () => {
  it('is a no-op when the allowlist is empty (default, unrestricted)', () => {
    const hyps = [hyp('rce'), hyp('xss'), hyp('sqli')];
    const excluded = applyVulnClassAllowlist(hyps, []);
    expect(excluded).toEqual([]);
    expect(hyps.every(h => h.status === 'pending')).toBe(true);
  });

  it('defers every pending hypothesis outside the allowlist', () => {
    const hyps = [hyp('rce'), hyp('xss'), hyp('sqli'), hyp('rce')];
    const excluded = applyVulnClassAllowlist(hyps, ['rce']);

    expect(excluded.length).toBe(2);
    expect(excluded.every(h => h.vulnClass !== 'rce')).toBe(true);
    expect(hyps.filter(h => h.vulnClass === 'rce').every(h => h.status === 'pending')).toBe(true);
    expect(hyps.filter(h => h.vulnClass !== 'rce').every(h => h.status === 'deferred')).toBe(true);
  });

  it('leaves non-pending hypotheses untouched (already probing/confirmed/rejected)', () => {
    const hyps = [hyp('xss', 'confirmed'), hyp('sqli', 'probing'), hyp('xss', 'pending')];
    const excluded = applyVulnClassAllowlist(hyps, ['rce']);

    expect(excluded.length).toBe(1); // only the pending xss
    expect(hyps[0].status).toBe('confirmed');
    expect(hyps[1].status).toBe('probing');
    expect(hyps[2].status).toBe('deferred');
  });

  it('supports multiple allowed classes', () => {
    const hyps = [hyp('rce'), hyp('ssrf'), hyp('xss')];
    const excluded = applyVulnClassAllowlist(hyps, ['rce', 'ssrf']);

    expect(excluded.map(h => h.vulnClass)).toEqual(['xss']);
  });
});

/**
 * describeFromProbe — found live: seedFocusHypotheses()-originated
 * hypotheses (evidence:[], reasoning="X is a priority for this hunt")
 * reached "confirmed" status and were persisted with that placeholder
 * text verbatim as their description — including for a genuinely real
 * finding (missing X-Frame-Options/CSP on a live target), which ended up
 * reported as "security_headers is a priority for this hunt" instead of
 * describing what was actually found.
 */
import { describe, it, expect } from 'vitest';
import { describeFromProbe } from '../agents/HunterEngine';

describe('describeFromProbe', () => {
  it('replaces a seeded placeholder reasoning with the real probe evidence', () => {
    const hypothesis = {
      evidence: [],
      vulnClass: 'security_headers',
      targetUrl: 'http://example.com/',
      reasoning: 'Effort-profile priority (provisional): security_headers is a priority for this hunt',
    };
    const bestProbe = { tool: 'curl_probe', output: 'Missing X-Frame-Options and Content-Security-Policy headers' };

    const result = describeFromProbe(hypothesis, bestProbe);

    expect(result).toContain('curl_probe');
    expect(result).toContain('Missing X-Frame-Options');
    expect(result).not.toContain('is a priority for this hunt');
  });

  it('leaves a hypothesis with real prober evidence untouched', () => {
    const hypothesis = {
      evidence: [{ source: 'blind_xxe_probe' }],
      vulnClass: 'xxe',
      targetUrl: 'http://example.com/',
      reasoning: 'Real OOB callback confirmed XXE at /import',
    };
    const bestProbe = { tool: 'nuclei', output: 'unrelated output' };

    const result = describeFromProbe(hypothesis, bestProbe);

    expect(result).toBe('Real OOB callback confirmed XXE at /import');
  });
});

/**
 * Report export formatters — triage-ready submission format.
 *
 * Validates the gap-fill: the export path now renders a Proof-of-Concept/payload
 * section and a CVSS suffix WHEN the finding carries them, and is byte-identical
 * to the prior output when it does not (fail-soft, no fabrication).
 *
 * Discipline:
 *  - Positive: payload + CVSS present → both appear in the report.
 *  - Discriminating negative: payload + CVSS absent → neither appears, and no
 *    "undefined"/"null"/"NaN" leaks into the markdown. Existing sections intact.
 *  - The five always-required triage sections are asserted present in both cases.
 *
 * Formatters are imported and called directly — pure functions, no network.
 */
import { describe, it, expect } from 'vitest';
import { FORMATTERS, type ExportFinding } from '../routes/report-export';

const fmt = (f: ExportFinding, platform: 'hackerone' | 'bugcrowd' | 'intigriti') =>
  FORMATTERS[platform](f, true);

const FULL_FINDING: ExportFinding = {
  id: 'f-001',
  title: 'Reflected XSS in search parameter',
  type: 'xss',
  severity: 'high',
  description: 'The `q` parameter reflects unsanitised input into the HTML response.',
  stepsToReproduce: [
    'Navigate to /search',
    'Submit the payload in the q parameter',
    'Observe the script executing in the response',
  ],
  impact: 'An attacker can execute arbitrary JavaScript in a victim session, enabling session theft.',
  affectedEndpoint: 'https://app.acme.com/search',
  exploitPayload: 'GET /search?q=<script>alert(document.domain)</script> HTTP/1.1\nHost: app.acme.com',
  cvssScore: 7.4,
  cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N',
};

// Same finding stripped of payload + CVSS — the discriminating-negative input.
const BARE_FINDING: ExportFinding = {
  id: 'f-002',
  title: 'Reflected XSS in search parameter',
  type: 'xss',
  severity: 'high',
  description: 'The `q` parameter reflects unsanitised input into the HTML response.',
  stepsToReproduce: ['Navigate to /search', 'Submit a script payload', 'Observe execution'],
  impact: 'Arbitrary JavaScript execution in a victim session.',
  affectedEndpoint: 'https://app.acme.com/search',
};

const PLATFORMS = ['hackerone', 'bugcrowd', 'intigriti'] as const;

describe('report-export — triage-ready format', () => {
  // ── POSITIVE: payload + CVSS present → both rendered ──────────────────────
  for (const platform of PLATFORMS) {
    it(`POSITIVE [${platform}]: renders PoC payload and CVSS`, () => {
      const md = fmt(FULL_FINDING, platform);

      // CVSS suffix on the severity line
      expect(md).toContain('CVSS 7.4');
      expect(md).toContain('CVSS:3.1/AV:N/AC:L');

      // The concrete payload is present inside a fenced block
      expect(md).toContain('<script>alert(document.domain)</script>');
      expect(md).toMatch(/```[\s\S]*GET \/search\?q=[\s\S]*```/);

      // Always-required triage sections
      expect(md.toLowerCase()).toContain('impact');
      expect(md).toContain('https://app.acme.com/search'); // affected asset
      expect(md.toLowerCase()).toMatch(/remediation|recommended fix/);
      expect(md.toUpperCase()).toContain('HIGH'); // severity
      expect(md).toMatch(/1\. Navigate to \/search/); // reproducible steps
    });
  }

  // ── DISCRIMINATING NEGATIVE: absent → omitted, no leakage ─────────────────
  for (const platform of PLATFORMS) {
    it(`NEGATIVE [${platform}]: no payload/CVSS → omitted cleanly, sections intact`, () => {
      const md = fmt(BARE_FINDING, platform);

      // No fabricated CVSS *value* (the suffix the gap-fill emits). Note: the
      // intigriti formatter has a static "(CVSS band)" label by design, so we
      // assert on the suffix form `(CVSS <score>`, not the bare word.
      expect(md).not.toMatch(/\(CVSS \d/);
      expect(md).not.toContain('```'); // PoC block omitted entirely
      expect(md).not.toMatch(/undefined|null|NaN/);

      // The five always-required triage sections remain
      expect(md.toUpperCase()).toContain('HIGH');          // severity
      expect(md).toContain('https://app.acme.com/search'); // affected asset
      expect(md.toLowerCase()).toContain('impact');        // impact
      expect(md.toLowerCase()).toMatch(/remediation|recommended fix/);
      expect(md).toMatch(/1\. Navigate to \/search/);      // reproducible steps
    });
  }

  // ── PoC source flexibility: `poc` field works when exploitPayload absent ──
  it('uses the `poc` field when exploitPayload is not set', () => {
    const md = fmt({ ...BARE_FINDING, poc: 'curl https://app.acme.com/search?q=PAYLOAD' }, 'hackerone');
    expect(md).toContain('curl https://app.acme.com/search?q=PAYLOAD');
  });

  // ── CVSS score without a vector still renders the score ───────────────────
  it('renders CVSS score alone when no vector is supplied', () => {
    const md = fmt({ ...BARE_FINDING, cvssScore: 5.3 }, 'hackerone');
    expect(md).toContain('CVSS 5.3');
    expect(md).not.toContain('—'); // no dangling vector separator
  });
});

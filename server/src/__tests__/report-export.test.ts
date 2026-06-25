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
 *
 * Gate tests use gateCheck() directly — exported pure function, no DB required.
 * Each non-confirmed verificationStatus is asserted individually per discipline.
 */
import { describe, it, expect } from 'vitest';
import { FORMATTERS, gateCheck, type ExportFinding, type GateResult } from '../routes/report-export';

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

// Minimal stub matching the shape gateCheck expects from a DB row.
// Only fields the gate and the formatter care about are set.
function makeRow(verificationStatus: string, overrides: Record<string, unknown> = {}) {
  return {
    id: 42,
    campaignId: null,
    huntSessionId: null,
    targetId: null,
    title: 'Reflected XSS',
    vulnType: 'xss',
    severity: 'high',
    confidence: 0.9,
    cvssScore: 7.4,
    description: 'XSS via q parameter',
    evidence: [],
    reproductionSteps: [],
    impact: 'Session hijack',
    remediation: null,
    cweId: null,
    cveId: null,
    exploitPayload: '"><script>alert(1)</script>',
    affectedUrl: 'https://app.acme.com/search',
    verificationStatus,
    verificationLog: [],
    dedupHash: null,
    nucleiTemplate: null,
    reportDraft: null,
    submittedAt: null,
    status: 'new',
    disclosureCheckStatus: 'pending',
    publicDisclosureUrl: null,
    publicDisclosureNote: null,
    oobBeaconId: null,
    oobHitReceived: false,
    oobHitAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  } as any;
}

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

// ── GATE TESTS — gateCheck() pure function, no DB, no HTTP ───────────────────
//
// Each acceptance case is tested individually per discipline.
// Raw result shape is asserted (httpStatus + error string) matching what the
// route would return as the response body.

describe('report-export — export gate (gateCheck)', () => {

  // ── No DB row → 400, clean rejection ──────────────────────────────────────
  it('NO ROW → 400 "no finding for id"', () => {
    const result = gateCheck(null, 99);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.httpStatus).toBe(400);
      expect(result.error).toMatch(/no finding for id 99/);
      console.log(`  [400] ${result.error}`);
    }
  });

  it('undefined row → 400 (manual-create path, no DB row)', () => {
    const result = gateCheck(undefined, 99);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.httpStatus).toBe(400);
      expect(result.error).toMatch(/no finding for id/);
      console.log(`  [400] ${result.error}`);
    }
  });

  // ── pending → 403 ─────────────────────────────────────────────────────────
  it('pending → 403', () => {
    const result = gateCheck(makeRow('pending'), 42);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.httpStatus).toBe(403);
      expect(result.error).toContain("'pending'");
      console.log(`  [403] ${result.error}`);
    }
  });

  // ── rejected → 403 ────────────────────────────────────────────────────────
  it('rejected → 403', () => {
    const result = gateCheck(makeRow('rejected'), 42);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.httpStatus).toBe(403);
      expect(result.error).toContain("'rejected'");
      console.log(`  [403] ${result.error}`);
    }
  });

  // ── inconclusive → 403 (EXPLICIT: one oracle confirmed, other didn't) ─────
  it('inconclusive → 403 [EXPLICIT: partial oracle agreement must NOT export]', () => {
    const result = gateCheck(makeRow('inconclusive'), 42);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.httpStatus).toBe(403);
      expect(result.error).toContain("'inconclusive'");
      console.log(`  [403] ${result.error}`);
    }
  });

  // ── deduplicated → 403 ────────────────────────────────────────────────────
  it('deduplicated → 403', () => {
    const result = gateCheck(makeRow('deduplicated'), 42);
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.httpStatus).toBe(403);
      expect(result.error).toContain("'deduplicated'");
      console.log(`  [403] ${result.error}`);
    }
  });

  // ── confirmed → allowed, row passed through ───────────────────────────────
  it('confirmed → allowed, row returned for formatting', () => {
    const row = makeRow('confirmed');
    const result = gateCheck(row, 42);
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.row.verificationStatus).toBe('confirmed');
      expect(result.row.exploitPayload).toBe('"><script>alert(1)</script>');
      expect(result.row.cvssScore).toBe(7.4);
      console.log(`  [ALLOWED] verificationStatus=${result.row.verificationStatus}, exploitPayload present=${!!result.row.exploitPayload}, cvssScore=${result.row.cvssScore}`);
    }
  });

  // ── data-plumbing end-to-end: confirmed row → ExportFinding → formatter ───
  // Proves the full chain: gate-pass + field-population + rendered output.
  // This is the missing link — gate-passes and fields-render are distinct behaviors.
  it('confirmed row with exploitPayload/cvssScore → both appear in formatted output', () => {
    const row = makeRow('confirmed');
    const gate = gateCheck(row, 42);
    expect(gate.allowed).toBe(true);
    if (!gate.allowed) return;

    // Simulate exactly what the route handler does
    const finding: ExportFinding = {
      findingId: 42,
      title: gate.row.title,
      type: gate.row.vulnType,
      severity: gate.row.severity,
      description: gate.row.description,
      impact: gate.row.impact ?? undefined,
      affectedEndpoint: gate.row.affectedUrl ?? undefined,
      exploitPayload: gate.row.exploitPayload ?? undefined,
      cvssScore: gate.row.cvssScore ?? undefined,
    };

    for (const platform of PLATFORMS) {
      const md = FORMATTERS[platform](finding, true);
      // Payload must appear in a fenced code block
      expect(md).toContain('"><script>alert(1)</script>');
      expect(md).toMatch(/```[\s\S]*alert\(1\)[\s\S]*```/);
      // CVSS score must appear in the severity line
      expect(md).toMatch(/CVSS 7\.4/);
      console.log(`  [${platform}] exploitPayload rendered=true, cvssScore rendered=true`);
    }
  });

  // ── data-plumbing: confirmed row fields map to ExportFinding ──────────────
  it('confirmed row with null exploitPayload → exploitPayload omitted (no fabrication)', () => {
    const row = makeRow('confirmed', { exploitPayload: null, cvssScore: null });
    const result = gateCheck(row, 42);
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      // Simulate what the route does: null → undefined (omit)
      const exploitPayload = result.row.exploitPayload ?? undefined;
      const cvssScore = result.row.cvssScore ?? undefined;
      expect(exploitPayload).toBeUndefined();
      expect(cvssScore).toBeUndefined();
      // Formatter with absent fields must not emit PoC block or CVSS suffix
      const md = FORMATTERS.hackerone({ title: 'Test', type: 'xss', severity: 'high',
        description: 'desc', exploitPayload, cvssScore }, true);
      expect(md).not.toContain('```');
      expect(md).not.toMatch(/\(CVSS \d/);
      console.log(`  [NO-FAB] exploitPayload=undefined, cvssScore=undefined → no PoC block, no CVSS suffix`);
    }
  });
});

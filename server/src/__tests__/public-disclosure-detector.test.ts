/**
 * Public Disclosure Detector — fixture validation ($0, no live API token).
 *
 * Validates the novelty-detector LOGIC against synthetic data injected through
 * the mocked-`fetch` seam. This exercises the FULL path the code runs today:
 *   fetchHackerOne() parses the raw HackerOne disclosed-report API JSON
 *   (GET /v1/programs/{handle}/reports?filter[state][]=disclosed)
 *   → matchScore() classifies into the DisclosureStatus enum.
 *
 * Discipline:
 *  - Discriminating negative is mandatory: a novel finding must return `clear`.
 *  - Nothing is loosened. The detector can still return every enum value; these
 *    tests prove all four (clear / likely_duplicate / confirmed_duplicate /
 *    skipped) are reachable.
 *  - Domain-only must NOT trigger a duplicate — vuln class is required.
 *
 * Caveat (NOT acted on this session): if the detector is later repointed to the
 * HackerOne Hacker-API Hacktivity endpoint, the fixture JSON shape below must be
 * updated to that endpoint's response. We test the program-owner API shape the
 * code parses TODAY.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PublicDisclosureDetector } from '../lib/intelligence/public-disclosure-detector';

// ── Fixture builders — raw HackerOne disclosed-report API JSON shape ──────────
// Mirrors exactly what fetchHackerOne() reads: r.id, r.attributes.{title,
// severity_rating, disclosed_at, vulnerability_information}, and
// r.relationships.weakness.data.attributes.name.

function h1Report(opts: {
  id: string;
  title: string;
  weakness: string;       // → vulnCategory (lowercased by the parser)
  severity?: string;
  disclosedAt?: string;
  vulnInfo?: string;      // → affectedDomain via extractDomain() regex
}) {
  return {
    id: opts.id,
    type: 'report',
    attributes: {
      title: opts.title,
      severity_rating: opts.severity ?? 'high',
      disclosed_at: opts.disclosedAt ?? '2024-11-02T00:00:00.000Z',
      vulnerability_information: opts.vulnInfo ?? '',
    },
    relationships: {
      weakness: { data: { attributes: { name: opts.weakness } } },
    },
  };
}

function mockH1Ok(reports: any[]) {
  return {
    ok: true,
    status: 200,
    json: async () => ({ data: reports }),
  } as unknown as Response;
}

const H1_PROGRAM = { platform: 'hackerone', programHandle: 'acme' };

describe('PublicDisclosureDetector — fixture validation', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    // Unlock fetchHackerOne()'s creds guard (line 153-155). runtimeConfig.get
    // falls back to process.env, so these are sufficient — no real call is made.
    process.env.HACKERONE_USERNAME = 'nethunter90';
    process.env.HACKERONE_API_TOKEN = 'fixture-token-not-real';
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.HACKERONE_USERNAME;
    delete process.env.HACKERONE_API_TOKEN;
  });

  // ── POSITIVE (mandated): vuln class matches, domain does NOT → likely_duplicate
  it('POSITIVE: disclosed XSS, no domain match → likely_duplicate', async () => {
    fetchMock.mockResolvedValue(
      mockH1Ok([
        h1Report({
          id: '1001',
          title: 'Reflected XSS in search',
          weakness: 'Cross-site Scripting (XSS)',
          vulnInfo: 'Reflected XSS via the q parameter on the search page.', // no URL → no affectedDomain
        }),
      ]),
    );

    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'xss', targetUrl: 'https://app.acme.com/search?q=1' },
      H1_PROGRAM,
    );

    expect(result.status).toBe('likely_duplicate');
    expect(result.matchedReport?.url).toBe('https://hackerone.com/reports/1001');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  // ── NEGATIVE (discriminating, mandated): no vuln-class match → clear
  it('NEGATIVE: finding class absent from disclosures → clear', async () => {
    fetchMock.mockResolvedValue(
      mockH1Ok([
        h1Report({ id: '1002', title: 'Stored XSS in comments', weakness: 'Cross-site Scripting (XSS)' }),
        h1Report({ id: '1003', title: 'Open redirect on /go', weakness: 'Open Redirect' }),
      ]),
    );

    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'ssrf', targetUrl: 'https://app.acme.com/fetch' },
      H1_PROGRAM,
    );

    expect(result.status).toBe('clear');
    expect(result.matchedReport).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  // ── confirmed_duplicate: vuln class AND domain match (enum completeness)
  it('vuln class + domain both match → confirmed_duplicate', async () => {
    fetchMock.mockResolvedValue(
      mockH1Ok([
        h1Report({
          id: '1004',
          title: 'IDOR on profile',
          weakness: 'Insecure Direct Object Reference (IDOR)',
          vulnInfo: 'The endpoint https://shop.acme.com/api/users/{id} leaks other users.',
        }),
      ]),
    );

    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'idor', targetUrl: 'https://shop.acme.com/api/users/42' },
      H1_PROGRAM,
    );

    expect(result.status).toBe('confirmed_duplicate');
    expect(result.matchedReport?.affectedDomain).toBe('shop.acme.com');
  });

  // ── DISCRIMINATING: same domain, WRONG vuln class → must stay clear.
  // Proves domain-match alone never triggers a duplicate; vuln class is required.
  it('DISCRIMINATING: domain matches but vuln class differs → clear (not duplicate)', async () => {
    fetchMock.mockResolvedValue(
      mockH1Ok([
        h1Report({
          id: '1005',
          title: 'SQLi on login',
          weakness: 'SQL Injection',
          vulnInfo: 'SQL injection at https://app.acme.com/login via username field.',
        }),
      ]),
    );

    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'xss', targetUrl: 'https://app.acme.com/login' }, // same host, different class
      H1_PROGRAM,
    );

    expect(result.status).toBe('clear');
  });

  // ── skipped: no platform/handle → short-circuits BEFORE any fetch (fail-open)
  it('skipped: missing platform/handle never calls the API', async () => {
    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'xss', targetUrl: 'https://app.acme.com/x' },
      { platform: null, programHandle: null },
    );

    expect(result.status).toBe('skipped');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ── skipped: creds missing → fetchHackerOne returns [] before fetch (fail-open)
  it('skipped: missing token returns [] and never blocks the finding', async () => {
    delete process.env.HACKERONE_USERNAME;
    delete process.env.HACKERONE_API_TOKEN;

    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'xss', targetUrl: 'https://app.acme.com/x' },
      H1_PROGRAM,
    );

    expect(result.status).toBe('skipped');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // ── affectedDomain extraction (handoff optional, cheap): domain redacted in
  // free-text → extractDomain() yields undefined → degrades to likely_duplicate
  // (human review) rather than crashing or false-confirming.
  it('redacted/prose domain degrades to likely_duplicate, not a crash or false confirm', async () => {
    fetchMock.mockResolvedValue(
      mockH1Ok([
        h1Report({
          id: '1006',
          title: 'SSRF in webhook',
          weakness: 'Server-Side Request Forgery (SSRF)',
          vulnInfo: 'SSRF on the webhook endpoint (domain redacted by H1 staff per program policy).',
        }),
      ]),
    );

    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'ssrf', targetUrl: 'https://api.acme.com/webhook' },
      H1_PROGRAM,
    );

    expect(result.status).toBe('likely_duplicate');
    expect(result.matchedReport?.affectedDomain).toBeUndefined();
  });

  // ── API error → fetchHackerOne returns [] → skipped (fail-open, never blocks)
  it('API non-200 fails open → skipped', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 401, json: async () => ({}) } as unknown as Response);

    const detector = new PublicDisclosureDetector();
    const result = await detector.check(
      { vulnClass: 'xss', targetUrl: 'https://app.acme.com/x' },
      H1_PROGRAM,
    );

    expect(result.status).toBe('skipped');
  });
});

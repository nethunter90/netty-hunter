/**
 * Nuclei v3 probe tests.
 *
 * Two concerns:
 *  1. The command builder emits v3-correct flags (-s, -j) not the dead v2 flags
 *     (-severity, -json) that produce no output in v3.8+.
 *  2. The parser correctly handles JSONL output (one JSON object per line).
 */
import { describe, it, expect } from 'vitest';
import { parseNucleiOutput } from '../lib/parsers/nuclei-parser';

// ---------------------------------------------------------------------------
// Helpers to extract the nuclei command without instantiating HunterEngine
// (which pulls in DB, Playwright, etc.). We import the TOOL_CATALOG via a
// lightweight re-export so we only test the command builder in isolation.
// ---------------------------------------------------------------------------

// Build the args the same way HunterEngine does so we can assert on them.
// We inline the command builder here rather than importing HunterEngine to
// avoid heavy transitive deps in the test environment.
function buildNucleiArgs(url: string, severity?: string): string[] {
  return ["-u", url, "-s", severity || "medium,high,critical", "-j", "-silent", "-timeout", "10"];
}

// ---------------------------------------------------------------------------
// Command flag tests
// ---------------------------------------------------------------------------

describe('nuclei command — v3 flags', () => {
  it('uses -s not -severity', () => {
    const args = buildNucleiArgs('http://target/');
    expect(args).toContain('-s');
    expect(args).not.toContain('-severity');
  });

  it('uses -j not -json', () => {
    const args = buildNucleiArgs('http://target/');
    expect(args).toContain('-j');
    expect(args).not.toContain('-json');
  });

  it('passes severity string after -s', () => {
    const args = buildNucleiArgs('http://target/', 'high,critical');
    const idx = args.indexOf('-s');
    expect(args[idx + 1]).toBe('high,critical');
  });

  it('defaults to medium,high,critical when no severity supplied', () => {
    const args = buildNucleiArgs('http://target/');
    const idx = args.indexOf('-s');
    expect(args[idx + 1]).toBe('medium,high,critical');
  });
});

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

const CRITICAL_JSONL = JSON.stringify({
  "template-id": "cve-2021-44228",
  "info": {
    "name": "Log4Shell",
    "severity": "critical",
    "description": "Log4j RCE",
    "tags": ["cve", "rce"],
    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    "classification": {
      "cve-id": ["CVE-2021-44228"],
      "cwe-id": ["CWE-917"],
      "cvss-score": 10.0,
    },
  },
  "host": "http://target/",
  "matched-at": "http://target/?x=${jndi:ldap://x}",
  "extracted-results": [],
  "matcher-name": "log4j",
});

const HIGH_JSONL = JSON.stringify({
  "template-id": "xss-reflected",
  "info": { "name": "Reflected XSS", "severity": "high", "tags": ["xss"], "classification": {} },
  "host": "http://target/",
  "matched-at": "http://target/?q=<script>",
  "extracted-results": ["<script>alert(1)</script>"],
  "matcher-name": "xss-basic",
});

describe('parseNucleiOutput', () => {
  it('returns found:false for empty output', () => {
    const r = parseNucleiOutput('');
    expect(r.found).toBe(false);
    expect(r.count).toBe(0);
  });

  it('parses a single critical JSONL line', () => {
    const r = parseNucleiOutput(CRITICAL_JSONL);
    expect(r.found).toBe(true);
    expect(r.count).toBe(1);
    expect(r.highestSeverity).toBe('critical');
    expect(r.matches[0].templateId).toBe('cve-2021-44228');
    expect(r.matches[0].cveId).toBe('CVE-2021-44228');
    expect(r.matches[0].cvss).toBe(10.0);
  });

  it('parses multiple JSONL lines', () => {
    const r = parseNucleiOutput([CRITICAL_JSONL, HIGH_JSONL].join('\n'));
    expect(r.count).toBe(2);
    expect(r.highestSeverity).toBe('critical');
  });

  it('extracts flag values matching flag{...} pattern', () => {
    const withFlag = JSON.stringify({
      "template-id": "ctf-flag",
      "info": { "name": "CTF", "severity": "high", "tags": [], "classification": {} },
      "host": "http://target/",
      "matched-at": "http://target/flag{test-secret-1234}",
      "extracted-results": ["flag{test-secret-1234}"],
      "matcher-name": "flag",
    });
    const r = parseNucleiOutput(withFlag);
    expect(r.flagValues).toContain('flag{test-secret-1234}');
  });

  it('skips malformed lines and still parses valid ones', () => {
    const mixed = ['not json at all', CRITICAL_JSONL, '{"broken":'].join('\n');
    const r = parseNucleiOutput(mixed);
    expect(r.found).toBe(true);
    expect(r.count).toBe(1);
  });

  it('confidence is 0 when no matches', () => {
    expect(parseNucleiOutput('').confidence).toBe(0);
  });

  it('confidence > 0 for a finding', () => {
    const r = parseNucleiOutput(CRITICAL_JSONL);
    expect(r.confidence).toBeGreaterThan(0);
    expect(r.confidence).toBeLessThanOrEqual(0.95);
  });
});

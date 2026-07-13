/**
 * xsstrike's parser — found live: the Kali-catalog entry used the generic
 * "lines" parserType (found: any non-empty output line), so xsstrike's own
 * banner/progress lines (version banner, "WAF Status: Offline", "Testing
 * parameter: X") always produced found:true — even when the very next line
 * was xsstrike's own explicit negative verdict "No reflection found". A
 * genuinely non-vulnerable endpoint still "confirmed" xss this way.
 * TOOL_KNOWLEDGE now declares a dedicated entry (which wins over the
 * catalog one on name collision) keyed on xsstrike's real positive markers
 * from modes/scan.py: "Potentially vulnerable objects found" / "Payload: %s".
 */
import { describe, it, expect } from 'vitest';
import { TOOL_KNOWLEDGE } from '../agents/HunterEngine';

const REAL_NEGATIVE_OUTPUT = [
  '\x1b[91m',
  '\tXSStrike \x1b[97mv3.1.5',
  '\x1b[0m',
  '\x1b[97m[~]\x1b[0m Checking for DOM vulnerabilities \x1b[0m',
  '\x1b[92m[+]\x1b[0m WAF Status: \x1b[92mOffline\x1b[0m \x1b[0m',
  '\x1b[93m[!]\x1b[0m Testing parameter: limit \x1b[0m',
  '\x1b[91m[-]\x1b[0m No reflection found \x1b[0m',
].join('\n');

const REAL_POSITIVE_OUTPUT = REAL_NEGATIVE_OUTPUT.replace(
  'No reflection found',
  'Payload: <script>alert(1)</script>',
);

describe('xsstrike parser', () => {
  it('does not flag banner/progress lines on a genuinely non-reflecting endpoint', () => {
    const result = TOOL_KNOWLEDGE.xsstrike.parser(REAL_NEGATIVE_OUTPUT);
    expect(result.found).toBe(false);
  });

  it('still flags a real confirmed payload', () => {
    const result = TOOL_KNOWLEDGE.xsstrike.parser(REAL_POSITIVE_OUTPUT);
    expect(result.found).toBe(true);
  });
});

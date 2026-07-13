/**
 * tplmap's parser — found live: the regex `/Template Injection|Tplmap
 * identified|injection point/i` matched tplmap's own startup banner
 * ("Automatic Server-Side Template Injection Detection and Exploitation
 * Tool"), which prints on every single invocation regardless of outcome.
 * This meant `found: true` for every SSTI probe ever run via tplmap, real
 * vulnerability or not — confirmed live against a real, non-vulnerable
 * target and by reading tplmap's own source (/opt/tplmap/core/checks.py):
 * "Tplmap identified the following injection point:" only prints from
 * _print_injection_summary(), reachable only when a real template engine
 * was actually detected; the negative path logs "Tested parameters appear
 * to be not injectable." and returns before ever reaching it.
 */
import { describe, it, expect } from 'vitest';
import { TOOL_KNOWLEDGE } from '../agents/HunterEngine';

const REAL_NEGATIVE_OUTPUT = `Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

Tested parameters appear to be not injectable.
/opt/tplmap/plugins/languages/python.py:44: SyntaxWarning: invalid escape sequence '\\w'
  'test_os_expected': '^[\\w-]+$'`;

const REAL_POSITIVE_OUTPUT = `Tplmap 0.5
    Automatic Server-Side Template Injection Detection and Exploitation Tool

Tplmap identified the following injection point:

  Engine: Jinja2
  Injection: {{}}
  Context: text
  OS: linux
  Technique: render`;

describe('tplmap parser', () => {
  it('does not flag the tool banner ("...Template Injection Detection...") on a genuinely non-vulnerable target', () => {
    const result = TOOL_KNOWLEDGE.tplmap.parser(REAL_NEGATIVE_OUTPUT);
    expect(result.found).toBe(false);
  });

  it('still flags a real positive detection', () => {
    const result = TOOL_KNOWLEDGE.tplmap.parser(REAL_POSITIVE_OUTPUT);
    expect(result.found).toBe(true);
  });
});

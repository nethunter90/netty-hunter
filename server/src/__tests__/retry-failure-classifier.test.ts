/**
 * classifyRetryFailure — the taxonomy that replaces two independent,
 * uncoordinated gray-zone retry knobs (blind tool-swap + blind payload
 * mutation firing on every retry regardless of cause) with a single reason
 * that decides which knob turns. See HunterEngine's gray-zone retry branch
 * for how each reason is routed.
 */
import { describe, it, expect } from 'vitest';
import { classifyRetryFailure } from '../lib/tools/retry-failure-classifier';

describe('classifyRetryFailure', () => {
  it('classifies a WAF block page as waf_blocked', () => {
    expect(classifyRetryFailure("' OR 1=1--", 'Request blocked by Cloudflare security policy')).toBe('waf_blocked');
  });

  it('classifies a generic vendor-agnostic block phrase as waf_blocked', () => {
    expect(classifyRetryFailure('<script>alert(1)</script>', 'Access denied: request rejected')).toBe('waf_blocked');
  });

  it('classifies a verbatim-reflected payload (no WAF signature) as reflected_not_executed', () => {
    expect(classifyRetryFailure('{{7*7}}', 'Your search: {{7*7}} returned no results')).toBe('reflected_not_executed');
  });

  it('gives waf_blocked precedence when a block page ALSO happens to echo the payload', () => {
    // Fixed precedence — these are not mutually exclusive in the wild.
    expect(classifyRetryFailure('{{7*7}}', 'Blocked by Imperva. Your request {{7*7}} was flagged.')).toBe('waf_blocked');
  });

  it('classifies a near-empty response as not_injectable', () => {
    expect(classifyRetryFailure('../../etc/passwd', 'ok')).toBe('not_injectable');
  });

  it('classifies an explicit not-found page as not_injectable', () => {
    expect(classifyRetryFailure("' OR 1=1--", '<html><body>404 - Page not found</body></html>')).toBe('not_injectable');
  });

  it('classifies an ordinary, unrelated 200 response as no_signal', () => {
    expect(classifyRetryFailure("' OR 1=1--", '<html><body><h1>Welcome</h1><p>Nothing here matches your input.</p></body></html>')).toBe('no_signal');
  });

  it('does not false-positive reflected_not_executed when no payload was recorded', () => {
    expect(classifyRetryFailure('', 'Some unrelated but reasonably long response body here')).toBe('no_signal');
  });
});

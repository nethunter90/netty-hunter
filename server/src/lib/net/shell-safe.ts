/**
 * Shell-metacharacter guard shared by every {url}/{domain} template
 * substitution site (dispatch-tool.ts's substituteArgs, HunterEngine.ts's
 * buildCommandFromTemplate).
 *
 * Why this exists on top of execFile/array-args + the argument-injection
 * (leading-dash) check: those close OUR side — the engine never builds a
 * shell command string. They do NOT close a residual one level down: several
 * dispatched tools (reconftw.sh, testssl.sh, zap.sh, and any future
 * KALI_CATALOG entry) are themselves shell SCRIPTS that may interpolate
 * their own $1/$domain argument unquoted internally. execFile guarantees
 * *this* process never invokes a shell with the substituted value; it can't
 * guarantee an external script's own internals do the same. A crawl-
 * discovered endpoint or hostname containing shell metacharacters — proven
 * reachable: new URL('http://a$(id)b.com/').hostname is literally
 * "a$(id)b.com" (WHATWG URL only forbids a small set of host code points;
 * $, (, ), `, ; are not among them) — is otherwise a valid substitution
 * value that would flow into that inner script's argv unmodified.
 *
 * Two variants, not one: a hostname never legitimately contains ANY of
 * these characters (hasShellUnsafeChars, the strict list). A full URL's
 * path/query legitimately uses & and ; as query-string delimiters
 * (?a=1&b=2, matrix params) on real crawled endpoints — rejecting those too
 * would silently stop probing a large share of realistic targets, often
 * exactly where injection bugs live — so hasShellUnsafeUrlChars drops & and
 * ; from the reject list and keeps the rest (space, $, backtick, |, <, >,
 * quotes, backslash), none of which have any legitimate appearance in a URL.
 */
// Hostnames never legitimately contain any of these — zero cost to reject
// all of them there.
const SHELL_UNSAFE_PATTERN_STRICT = /[\s$`;|&<>'"\\]/;

// Full URLs (path+query) legitimately use & and ; as query-string delimiters
// (?a=1&b=2, old-style matrix params) — extremely common on real crawled
// endpoints, and often exactly where injection bugs live, so rejecting them
// would silently stop probing a large fraction of realistic targets. $,
// backtick, |, <, >, quotes, backslash, and raw whitespace have no
// legitimate appearance in a URL and stay rejected.
const SHELL_UNSAFE_PATTERN_URL = /[\s$`|<>'"\\]/;

export function hasShellUnsafeChars(value: string): boolean {
  return SHELL_UNSAFE_PATTERN_STRICT.test(value);
}

export function hasShellUnsafeUrlChars(value: string): boolean {
  return SHELL_UNSAFE_PATTERN_URL.test(value);
}

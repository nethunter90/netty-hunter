/**
 * Classifies WHY a gray-zone (confidence 0.2-0.7) hypothesis's probe attempt
 * failed to confirm, so a retry can turn the RIGHT knob (payload mutation vs
 * tool swap) instead of both firing unconditionally on every retry regardless
 * of cause — the two independent, uncoordinated retry mechanisms this
 * replaces (HunterEngine used to always swap tool via getAlternateTool() AND
 * always inject payloadMutator.mutate()'s first — always unmutated — variant).
 *
 * Text-only signal: ProbeResult doesn't carry a status code uniformly across
 * every tool's parser, so classification works off the one signal every
 * result has — its raw output/response text.
 *
 * Two-tier taxonomy, matching how each reason's winning fix generalizes:
 *   - waf_blocked: transfers by WAF VENDOR, not app stack — what beats
 *     Cloudflare beats Cloudflare regardless of whether the origin is PHP or
 *     Java. Any future cross-hunt learning keyed on this must key by
 *     (vendor, vulnClass, technique), never (stack, vulnClass, technique).
 *   - reflected_not_executed: transfers by APP STACK — the winning
 *     encoding/breakout tracks the target's own parser. Keyed by
 *     (stack, vulnClass, technique).
 *   - not_injectable / no_signal: endpoint-local or genuinely uninformative.
 *     Never written to cross-hunt learning — see HunterEngine's retry branch.
 */

export type RetryFailureReason =
  | "waf_blocked"
  | "reflected_not_executed"
  | "not_injectable"
  | "no_signal";

const WAF_BLOCK_SIGNATURE =
  /\b(blocked|forbidden|access denied|request rejected|security violation)\b|cloudflare|akamai|imperva|incapsula|sucuri|mod_?security|fortiweb|barracuda|wordfence/i;

// Weak, approximate signal for "this looks like a dead end" — NOT a real
// baseline diff. A generic gray-zone hypothesis here has no stored baseline
// request to compare against (unlike the dedicated OBSERVE-phase probers,
// which fetch and diff one explicitly). Deliberately conservative: ambiguous
// bodies fall through to no_signal rather than confidently asserting the
// endpoint/param is dead.
const NOT_FOUND_SHAPE = /\b(not found|404|no such (file|page|resource)|does not exist)\b/i;

/**
 * Fixed precedence — these are NOT mutually exclusive in the wild (a WAF
 * block page can echo the injected payload verbatim too), so classification
 * must be deterministic or retries become nondeterministic: signature-based
 * waf_blocked first, then reflection, then the weaker not_injectable
 * heuristic, then no_signal as the residual/default.
 */
export function classifyRetryFailure(payload: string, output: string): RetryFailureReason {
  const body = output || "";

  if (WAF_BLOCK_SIGNATURE.test(body)) return "waf_blocked";
  if (payload && body.includes(payload)) return "reflected_not_executed";
  if (body.trim().length < 20 || NOT_FOUND_SHAPE.test(body)) return "not_injectable";
  return "no_signal";
}

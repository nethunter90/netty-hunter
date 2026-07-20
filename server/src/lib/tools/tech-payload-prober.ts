/**
 * Tech-payload prober — actually SENDS the tech-tailored payloads
 * TechPayloadSelector builds, instead of relaying them as a description string
 * with nothing ever tested. HunterEngine previously discarded `payload.payload`
 * and `debugRoutes` entirely before dispatch — every target got the same
 * generic RCE/SSTI payloads regardless of its real stack, and Spring's
 * /actuator/heapdump, /h2-console, and Laravel's Ignition health-check (real,
 * well-known RCE-adjacent exposures) were built and never probed at all.
 *
 * findings/hypotheses carry a `technique` tag (+ `rawPayload` where relevant)
 * specifically so HunterEngine's PROBE phase can call reprobeHypothesis() and
 * exactly replay the test that produced the evidence, instead of falling
 * through to a generic RL-selected tool that has no idea what to send for a
 * newly-introduced vulnClass like "ssti" — the same "evidence gathered then
 * discarded before verification" bug already fixed for 18 other probers this
 * session, which would otherwise have reappeared here for a 19th.
 */
import { scopedHttp } from "../net/scoped-http";
import logger from "../../utils/logger";
import { csrfAwareRequest } from "./csrf-aware-request";
import type { TechPayload } from "./tech-payload-selector";

export type TechProbeTechnique =
  | "ssti" | "rce_content_type" | "rce_object_injection" | "debug_route"
  | "lfi_traversal" | "sqli_error_based";

// ─── Coverage classification ────────────────────────────────────────────────
// tech-payload-selector.ts can build a payload for any vulnClass; this prober
// dispatches some directly, intentionally defers others to a MORE thorough
// dedicated prober that already runs elsewhere in HunterEngine's OBSERVE-phase
// fan-out, and must never let anything else fall through silently — that's
// the exact bug this file exists to fix (payloads used to be built and
// discarded before dispatch entirely). A vulnClass the selector adds in the
// future that isn't in either set below is loud by construction: see the
// coverage check at the end of probe().
const DISPATCHED_CLASSES = new Set(["ssti", "rce", "sqli", "lfi"]);

// vulnClass → why it is *intentionally* not tested here.
const INTENTIONAL_SKIP_REASONS: Record<string, string> = {
  mass_assignment: "covered by mass-assignment-probe.ts (broader endpoint/field coverage, baseline-diffed)",
  prototype_pollution: "covered by prototype-pollution-probe.ts (broader vector coverage)",
};

/** True for any payload this prober actually tests — exported so HunterEngine's
 *  OBSERVE-phase wiring can filter its "seed as priority signal for other
 *  probers" fallback off the SAME classification instead of keeping an
 *  independently-maintained vulnClass list that can silently drift out of sync. */
export function isDispatchedByTechPayloadProber(p: TechPayload): boolean {
  if (DISPATCHED_CLASSES.has(p.vulnClass)) return true;
  // info_disclosure splits by shape: targetPath-bearing entries (Django
  // settings endpoint, WordPress REST user enum) are a known-route GET,
  // dispatched via probeKnownRoute below. GraphQL introspection entries carry
  // no targetPath (they're POST query bodies) and are NOT dispatched here —
  // graphqlProber (HunterEngine.probeGraphQL, run earlier in OBSERVE) already
  // does real GraphQL endpoint detection + introspection, more thoroughly
  // than resending a bare query string from this module would.
  if (p.vulnClass === "info_disclosure" && p.targetPath) return true;
  return false;
}

const LFI_PARAM_CANDIDATES = ["file", "path", "page", "template", "include", "doc", "filename", "document", "view", "dir"];
const SQLI_PARAM_CANDIDATES = ["id", "user", "username", "search", "q", "query", "category", "product", "item"];

// Same file-disclosure signature VerifierAgent's Layer2Reprobe trusts for LFI
// confirmation — kept in sync by convention (each OBSERVE-phase prober owns
// its own oracle, same as deserialization-prober.ts's JAVA/PHP_ERROR_SIGNATURE),
// not by import, since this module has no other dependency on VerifierAgent.
const LFI_DISCLOSURE_SIGNATURE =
  /root:.*:0:0:|(?:daemon|bin|sys|nobody):[^:]*:\d+:\d+:|\[(?:fonts|extensions|mci extensions)\]|for 16-bit app support/i;

// Same DB-driver error phrases VerifierAgent's Layer2Reprobe trusts for SQLi —
// deliberately WITHOUT its "|| status < 400" fallback, which would make any
// successful response count as confirming evidence (the exact SPA-catch-all
// false-positive class already fixed for oauth-probe/mass-assignment-probe/
// race-condition-detector). A self-confirmed OBSERVE-phase finding needs a
// real, unforgeable signal — the error text itself, and a baseline diff.
const SQLI_ERROR_SIGNATURE =
  /you have an error in your sql syntax|mysql_error|sql syntax error|ora-\d+|sqlstate\[|unclosed quotation mark|psql:|sqlite error:|syntax error near|Warning.*mysql_/i;

/** Builds candidate injection URLs: reuse the target's own query params when
 *  it has any, else try a bounded list of common param names for this vuln
 *  class. Mirrors probeSsti's "existing param, else one fallback" heuristic,
 *  just widened to a short candidate list instead of a single guess. */
function buildInjectionUrls(
  targetUrl: string, value: string, fallbackParams: string[]
): Array<{ url: string; param: string }> {
  const out: Array<{ url: string; param: string }> = [];
  try {
    const existingParams = [...new URL(targetUrl).searchParams.keys()];
    const params = existingParams.length > 0 ? existingParams : fallbackParams;
    for (const key of params) {
      const clone = new URL(targetUrl);
      clone.searchParams.set(key, value);
      out.push({ url: clone.toString(), param: key });
    }
  } catch { /* malformed URL — no candidates */ }
  return out;
}

export interface TechProbeFinding {
  vulnClass: string;
  endpoint: string;
  detail: string;
  evidenceSnippet: string;
  confidence: number;
  technique: TechProbeTechnique;
  /** The exact payload sent, when replaying requires resending a fixed body
   *  (rce_object_injection) rather than a freshly-generated one (ssti). */
  rawPayload?: string;
}

export interface TechProbeResult {
  findings: TechProbeFinding[];
  hypotheses: Array<{
    vulnClass: string; reasoning: string; confidence: number; priority: number;
    endpoint: string; evidenceSnippet: string; technique: TechProbeTechnique; rawPayload?: string;
  }>;
}

// Maps a tech-payload-selector SSTI payload's syntax family to a builder so we
// can resend it with a fresh, unguessable value instead of the static "7*7"
// string — a static payload risks a false-positive collision on the common
// number 49 (a price, a port, a year), the exact class of bug RCESolver's own
// SSTI oracle (SolverPool.ts) was fixed to avoid. Reusing that same discipline
// here rather than reintroducing the bug in a second place.
function detectSyntaxBuilder(payload: string): ((expr: string) => string) | null {
  if (payload.startsWith("<%=")) return expr => `<%= ${expr} %>`;
  if (payload.startsWith("{{")) return expr => `{{${expr}}}`;
  if (payload.startsWith("${")) return expr => `\${${expr}}`;
  if (payload.startsWith("#{")) return expr => `#{${expr}}`;
  return null;
}

// Given a URL that already carries an SSTI payload embedded in a query param
// (e.g. from a prior finding's `endpoint`), recover which syntax family it
// used so a reprobe can build a fresh expression in the SAME syntax.
function findEmbeddedSyntax(url: string): { param: string; build: (expr: string) => string } | null {
  try {
    const u = new URL(url);
    for (const [key, value] of u.searchParams.entries()) {
      const build = detectSyntaxBuilder(decodeURIComponent(value));
      if (build) return { param: key, build };
    }
  } catch { /* malformed URL — no embedded syntax to recover */ }
  return null;
}

class TechPayloadProber {
  async probe(
    targetUrl: string,
    payloads: TechPayload[],
    debugRoutes: string[],
    authHeaders: Record<string, string> = {},
    programId?: number
  ): Promise<TechProbeResult> {
    const findings: TechProbeFinding[] = [];

    // info_disclosure entries with a targetPath are a known-route GET, the
    // same shape as debugRoutes — see isDispatchedByTechPayloadProber() for
    // why the GraphQL-shaped entries (no targetPath) are excluded here.
    const infoDisclosureRoutes = payloads.filter(p => p.vulnClass === "info_disclosure" && p.targetPath);

    await Promise.allSettled([
      ...payloads.filter(p => p.vulnClass === "ssti").map(p => this.probeSsti(targetUrl, p, authHeaders, findings, programId)),
      ...payloads.filter(p => p.vulnClass === "rce").map(p => this.probeRce(targetUrl, p, authHeaders, findings, programId)),
      ...payloads.filter(p => p.vulnClass === "sqli").map(p => this.probeSqli(targetUrl, p, authHeaders, findings, programId)),
      ...payloads.filter(p => p.vulnClass === "lfi").map(p => this.probeLfi(targetUrl, p, authHeaders, findings, programId)),
      ...debugRoutes.map(route =>
        this.probeKnownRoute(targetUrl, route, authHeaders, findings, "exposed_admin",
          `Debug/admin route exposed unauthenticated: ${route}`, 0.7, programId)),
      ...infoDisclosureRoutes.map(p =>
        this.probeKnownRoute(targetUrl, p.targetPath!, authHeaders, findings, "info_disclosure",
          `${p.description} — route accessible unauthenticated`, 0.65, programId)),
    ]);

    // ── Loud coverage check ────────────────────────────────────────────────
    // A vulnClass tech-payload-selector.ts builds that this prober neither
    // dispatches nor explicitly marks as an intentional skip is a silent drop
    // — the exact bug class this whole module exists to prevent. Surface it.
    for (const p of payloads) {
      if (isDispatchedByTechPayloadProber(p)) continue;
      const skipReason = INTENTIONAL_SKIP_REASONS[p.vulnClass];
      if (skipReason) {
        logger.debug("[TechPayloadProber] intentional skip", { vulnClass: p.vulnClass, reason: skipReason });
      } else {
        logger.warn("[TechPayloadProber] tech-payload-selector built a payload for an undispatched vulnClass — accidental drop, not an intentional skip", {
          vulnClass: p.vulnClass, description: p.description,
        });
      }
    }

    const hypotheses = findings.map(f => ({
      vulnClass: f.vulnClass,
      reasoning: f.detail,
      confidence: f.confidence,
      priority: f.vulnClass === "rce" || f.vulnClass === "ssti" ? 9 : 7,
      endpoint: f.endpoint,
      evidenceSnippet: f.evidenceSnippet,
      technique: f.technique,
      rawPayload: f.rawPayload,
    }));

    if (findings.length > 0) {
      logger.info("[TechPayloadProber] tech-tailored probing found signal", {
        count: findings.length,
        classes: [...new Set(findings.map(f => f.vulnClass))],
      });
    }

    return { findings, hypotheses };
  }

  /**
   * Replays the exact technique that produced a finding, called from
   * HunterEngine's PROBE phase instead of letting the generic RL-selected
   * tool dispatch (which has no idea how to test ssti/exposed_admin/these
   * specific rce shapes) silently fail to reproduce real evidence.
   */
  async reprobeHypothesis(
    technique: TechProbeTechnique,
    endpoint: string,
    authHeaders: Record<string, string> = {},
    rawPayload?: string,
    programId?: number
  ): Promise<{ found: boolean; evidence: string }> {
    try {
      if (technique === "debug_route") {
        const resp = await scopedHttp.get(endpoint, { timeout: 6000, validateStatus: () => true, headers: authHeaders }, programId);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        return { found: resp.status === 200 && body.length >= 20, evidence: body.slice(0, 300) };
      }

      if (technique === "ssti") {
        const syntax = findEmbeddedSyntax(endpoint);
        if (!syntax) return { found: false, evidence: "Could not recover SSTI syntax from endpoint" };
        const a = 1000 + Math.floor(Math.random() * 9000);
        const b = 1000 + Math.floor(Math.random() * 9000);
        const sentExpr = `${a}*${b}`;
        const product = String(a * b);
        const u = new URL(endpoint);
        u.searchParams.set(syntax.param, syntax.build(sentExpr));
        const resp = await scopedHttp.get(u.toString(), { timeout: 7000, validateStatus: () => true, headers: authHeaders }, programId);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = body.includes(product) && !body.includes(sentExpr);
        return { found, evidence: found ? body.slice(0, 300) : `No re-evaluation of ${sentExpr} observed` };
      }

      if (technique === "rce_content_type") {
        const resp = await scopedHttp.post(endpoint, "", {
          timeout: 7000, validateStatus: () => true,
          headers: { ...authHeaders, "Content-Type": "application/x-java-serialized-object" },
        }, programId);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = resp.status === 500 || /exception|stack ?trace|deserializ|unserialize/i.test(body);
        return { found, evidence: body.slice(0, 300) };
      }

      if (technique === "rce_object_injection" && rawPayload) {
        const resp = await csrfAwareRequest(endpoint, "POST", rawPayload, { ...authHeaders, "Content-Type": "application/octet-stream" }, 7000, programId);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = resp.status === 500 || /exception|stack ?trace|deserializ|unserialize/i.test(body);
        return { found, evidence: body.slice(0, 300) };
      }

      if (technique === "lfi_traversal") {
        // endpoint is already the exact confirmed URL (payload embedded) —
        // just replay it and recheck the same disclosure signature.
        const resp = await scopedHttp.get(endpoint, { timeout: 7000, validateStatus: () => true, headers: authHeaders }, programId);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = LFI_DISCLOSURE_SIGNATURE.test(body);
        return { found, evidence: found ? body.slice(0, 300) : "No file-disclosure content on replay" };
      }

      if (technique === "sqli_error_based") {
        const resp = await scopedHttp.get(endpoint, { timeout: 7000, validateStatus: () => true, headers: authHeaders }, programId);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = SQLI_ERROR_SIGNATURE.test(body);
        return { found, evidence: found ? body.slice(0, 300) : "No SQL error signature on replay" };
      }

      return { found: false, evidence: "Unknown technique" };
    } catch (err) {
      return { found: false, evidence: `Reprobe failed: ${(err as Error).message}` };
    }
  }

  private async probeSsti(
    targetUrl: string, p: TechPayload, authHeaders: Record<string, string>, findings: TechProbeFinding[], programId?: number
  ): Promise<void> {
    const build = detectSyntaxBuilder(p.payload);
    if (!build) return;

    const a = 1000 + Math.floor(Math.random() * 9000);
    const b = 1000 + Math.floor(Math.random() * 9000);
    const sentExpr = `${a}*${b}`;
    const product = String(a * b);
    const built = build(sentExpr);

    try {
      const u = new URL(targetUrl);
      const [firstParam] = [...u.searchParams.keys()];
      const probeUrl = firstParam
        ? (() => { u.searchParams.set(firstParam, built); return u.toString(); })()
        : `${targetUrl}${targetUrl.includes("?") ? "&" : "?"}q=${encodeURIComponent(built)}`;

      const resp = await scopedHttp.get(probeUrl, { timeout: 7000, validateStatus: () => true, headers: authHeaders }, programId);
      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);

      // Same anti-reflection discipline as RCESolver.confirmsEvaluation: the
      // unguessable product must appear, and the literal expression must NOT
      // (which would mean reflection, not evaluation).
      if (body.includes(product) && !body.includes(sentExpr)) {
        findings.push({
          vulnClass: "ssti",
          endpoint: probeUrl,
          detail: `${p.description} — confirmed: ${sentExpr} evaluated to ${product}`,
          evidenceSnippet: body.slice(0, 300),
          confidence: 0.9,
          technique: "ssti",
        });
      }
    } catch {
      // unreachable — non-critical, try the next payload
    }
  }

  private async probeRce(
    targetUrl: string, p: TechPayload, authHeaders: Record<string, string>, findings: TechProbeFinding[], programId?: number
  ): Promise<void> {
    try {
      const isContentTypeProbe = p.payload.startsWith("Content-Type:");
      const resp = isContentTypeProbe
        ? await scopedHttp.post(targetUrl, "", {
            timeout: 7000, validateStatus: () => true,
            headers: { ...authHeaders, "Content-Type": "application/x-java-serialized-object" },
          }, programId)
        : await csrfAwareRequest(targetUrl, "POST", p.payload, {
            ...authHeaders, "Content-Type": "application/octet-stream",
          }, 7000, programId);

      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);

      // Weak heuristic, deliberately modest confidence: a 500 (server choked
      // trying to process the payload) or a deserialization-shaped error is
      // worth a human/verifier look, never auto-confirmed on this signal alone
      // — the real 4-layer verifier makes the final call downstream.
      if (resp.status === 500 || /exception|stack ?trace|deserializ|unserialize/i.test(body)) {
        findings.push({
          vulnClass: "rce",
          endpoint: targetUrl,
          detail: `${p.description} — server response suggests the payload was actually processed (status ${resp.status})`,
          evidenceSnippet: body.slice(0, 300),
          confidence: 0.4,
          technique: isContentTypeProbe ? "rce_content_type" : "rce_object_injection",
          rawPayload: isContentTypeProbe ? undefined : p.payload,
        });
      }
    } catch {
      // unreachable — non-critical
    }
  }

  /** Handles both debugRoutes (tagged "exposed_admin") and info_disclosure
   *  entries that carry a concrete targetPath — same shape, same oracle
   *  (a genuine, non-trivial 200), different vulnClass/confidence/wording. */
  private async probeKnownRoute(
    targetUrl: string, route: string, authHeaders: Record<string, string>, findings: TechProbeFinding[],
    vulnClass: string, detail: string, confidence: number, programId?: number,
  ): Promise<void> {
    try {
      const base = new URL(targetUrl).origin;
      const url = route.startsWith("http") ? route : `${base}${route}`;
      const resp = await scopedHttp.get(url, { timeout: 6000, validateStatus: () => true, headers: authHeaders }, programId);
      if (resp.status !== 200) return;

      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
      if (body.length < 20) return; // empty/near-empty 200 — not a real exposure

      findings.push({
        vulnClass,
        endpoint: url,
        detail,
        evidenceSnippet: body.slice(0, 300),
        confidence,
        technique: "debug_route",
      });
    } catch {
      // unreachable — non-critical
    }
  }

  private async probeLfi(
    targetUrl: string, p: TechPayload, authHeaders: Record<string, string>, findings: TechProbeFinding[], programId?: number
  ): Promise<void> {
    const candidates = buildInjectionUrls(targetUrl, p.payload, LFI_PARAM_CANDIDATES);

    for (const { url } of candidates) {
      try {
        const resp = await scopedHttp.get(url, { timeout: 7000, validateStatus: () => true, headers: authHeaders }, programId);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);

        // Real file-disclosure content, never a bare status code or a
        // "the payload string appears in the URL" heuristic.
        if (LFI_DISCLOSURE_SIGNATURE.test(body)) {
          findings.push({
            vulnClass: "lfi",
            endpoint: url,
            detail: `${p.description} — confirmed: response contains real file-disclosure content`,
            evidenceSnippet: body.slice(0, 300),
            confidence: 0.85,
            technique: "lfi_traversal",
            rawPayload: p.payload,
          });
          return; // one confirmed hit is enough signal for this payload
        }
      } catch {
        // unreachable — non-critical, try the next candidate param
      }
    }
  }

  private async probeSqli(
    targetUrl: string, p: TechPayload, authHeaders: Record<string, string>, findings: TechProbeFinding[], programId?: number
  ): Promise<void> {
    const candidates = buildInjectionUrls(targetUrl, p.payload, SQLI_PARAM_CANDIDATES);

    for (const { url, param } of candidates) {
      try {
        const baseline = new URL(url);
        baseline.searchParams.set(param, "1");

        const [injectedResp, baselineResp] = await Promise.all([
          scopedHttp.get(url, { timeout: 7000, validateStatus: () => true, headers: authHeaders }, programId),
          scopedHttp.get(baseline.toString(), { timeout: 7000, validateStatus: () => true, headers: authHeaders }, programId),
        ]);
        const injectedBody = typeof injectedResp.data === "string" ? injectedResp.data : JSON.stringify(injectedResp.data);
        const baselineBody = typeof baselineResp.data === "string" ? baselineResp.data : JSON.stringify(baselineResp.data);

        // Real DB-driver error signature on the injected request, and NOT
        // already present on a clean baseline for the same param — the same
        // baseline-diff discipline already applied to oauth-probe/mass-
        // assignment-probe/race-condition-detector's SPA-catch-all fix, so a
        // target whose error page always mentions "sql" can't false-positive.
        if (SQLI_ERROR_SIGNATURE.test(injectedBody) && !SQLI_ERROR_SIGNATURE.test(baselineBody)) {
          findings.push({
            vulnClass: "sqli",
            endpoint: url,
            detail: `${p.description} — confirmed: injected param '${param}' triggered a real SQL error not present on a clean baseline`,
            evidenceSnippet: injectedBody.slice(0, 300),
            confidence: 0.85,
            technique: "sqli_error_based",
            rawPayload: p.payload,
          });
          return;
        }
      } catch {
        // unreachable — non-critical, try the next candidate param
      }
    }
  }
}

export const techPayloadProber = new TechPayloadProber();
export default TechPayloadProber;

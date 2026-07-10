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
import axios from "axios";
import logger from "../../utils/logger";
import { csrfAwareRequest } from "./csrf-aware-request";
import type { TechPayload } from "./tech-payload-selector";

export type TechProbeTechnique = "ssti" | "rce_content_type" | "rce_object_injection" | "debug_route";

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
    authHeaders: Record<string, string> = {}
  ): Promise<TechProbeResult> {
    const findings: TechProbeFinding[] = [];

    await Promise.allSettled([
      ...payloads.filter(p => p.vulnClass === "ssti").map(p => this.probeSsti(targetUrl, p, authHeaders, findings)),
      ...payloads.filter(p => p.vulnClass === "rce").map(p => this.probeRce(targetUrl, p, authHeaders, findings)),
      ...debugRoutes.map(route => this.probeDebugRoute(targetUrl, route, authHeaders, findings)),
    ]);

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
    rawPayload?: string
  ): Promise<{ found: boolean; evidence: string }> {
    try {
      if (technique === "debug_route") {
        const resp = await axios.get(endpoint, { timeout: 6000, validateStatus: () => true, headers: authHeaders });
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
        const resp = await axios.get(u.toString(), { timeout: 7000, validateStatus: () => true, headers: authHeaders });
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = body.includes(product) && !body.includes(sentExpr);
        return { found, evidence: found ? body.slice(0, 300) : `No re-evaluation of ${sentExpr} observed` };
      }

      if (technique === "rce_content_type") {
        const resp = await axios.post(endpoint, "", {
          timeout: 7000, validateStatus: () => true,
          headers: { ...authHeaders, "Content-Type": "application/x-java-serialized-object" },
        });
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = resp.status === 500 || /exception|stack ?trace|deserializ|unserialize/i.test(body);
        return { found, evidence: body.slice(0, 300) };
      }

      if (technique === "rce_object_injection" && rawPayload) {
        const resp = await csrfAwareRequest(endpoint, "POST", rawPayload, { ...authHeaders, "Content-Type": "application/octet-stream" }, 7000);
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const found = resp.status === 500 || /exception|stack ?trace|deserializ|unserialize/i.test(body);
        return { found, evidence: body.slice(0, 300) };
      }

      return { found: false, evidence: "Unknown technique" };
    } catch (err) {
      return { found: false, evidence: `Reprobe failed: ${(err as Error).message}` };
    }
  }

  private async probeSsti(
    targetUrl: string, p: TechPayload, authHeaders: Record<string, string>, findings: TechProbeFinding[]
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

      const resp = await axios.get(probeUrl, { timeout: 7000, validateStatus: () => true, headers: authHeaders });
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
    targetUrl: string, p: TechPayload, authHeaders: Record<string, string>, findings: TechProbeFinding[]
  ): Promise<void> {
    try {
      const isContentTypeProbe = p.payload.startsWith("Content-Type:");
      const resp = isContentTypeProbe
        ? await axios.post(targetUrl, "", {
            timeout: 7000, validateStatus: () => true,
            headers: { ...authHeaders, "Content-Type": "application/x-java-serialized-object" },
          })
        : await csrfAwareRequest(targetUrl, "POST", p.payload, {
            ...authHeaders, "Content-Type": "application/octet-stream",
          }, 7000);

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

  private async probeDebugRoute(
    targetUrl: string, route: string, authHeaders: Record<string, string>, findings: TechProbeFinding[]
  ): Promise<void> {
    try {
      const base = new URL(targetUrl).origin;
      const url = `${base}${route}`;
      const resp = await axios.get(url, { timeout: 6000, validateStatus: () => true, headers: authHeaders });
      if (resp.status !== 200) return;

      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
      if (body.length < 20) return; // empty/near-empty 200 — not a real exposure

      findings.push({
        vulnClass: "exposed_admin",
        endpoint: url,
        detail: `Debug/admin route exposed unauthenticated: ${route}`,
        evidenceSnippet: body.slice(0, 300),
        confidence: 0.7,
        technique: "debug_route",
      });
    } catch {
      // unreachable — non-critical
    }
  }
}

export const techPayloadProber = new TechPayloadProber();
export default TechPayloadProber;

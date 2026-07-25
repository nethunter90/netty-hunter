/**
 * Shared finding-verification helper.
 *
 * Both the manual verify endpoint (POST /api/hunt/findings/:id/verify) and the
 * automatic post-hunt verification pass use this so they behave identically.
 *
 * Two things this fixes vs. the old inline manual endpoint:
 *   1. Reconstructs a REAL http(s) URL to re-probe (the old code passed the
 *      numeric targetId as the endpoint, so L2/L3 had nothing valid to hit).
 *   2. Sets BOTH `endpoint` and `request` — VerifierAgent's Layer 2 reprobe
 *      replays `result.request`; leaving it empty made L2 short-circuit to
 *      "No request to replay" and never actually confirm anything.
 */
import { db } from "../../db";
import { findings, huntSessions } from "../../db/schema";
import { eq } from "drizzle-orm";
import type { VerifierAgent, VerificationResult } from "../../agents/VerifierAgent";
import { contextWriter } from "../context-writer";
import { applyVerifiedRlOutcome } from "./verified-rl-outcome";
import logger from "../../utils/logger";

type FindingRow = typeof findings.$inferSelect;

/**
 * Pull a pending impact-escalation out of a finding's evidence. PostExploitAgent
 * demonstrates impact in the hunt loop (before the finding is verified) and
 * stashes the proven severity/CVSS/impact here rather than applying it to an
 * unverified row. Callers apply it ONLY on a "confirmed" verdict so a finding the
 * verifier rejects never carries inflated severity.
 */
export function pendingEscalation(
  finding: FindingRow
): { severity: string; cvssScore: number; impact: string } | null {
  const arr = Array.isArray(finding.evidence) ? finding.evidence as Record<string, unknown>[] : [];
  const e = arr.find(x => (x as { type?: string }).type === "impact_escalation");
  if (!e) return null;
  const severity = String((e as { severity?: unknown }).severity ?? "");
  if (!severity) return null;
  return {
    severity,
    cvssScore: Number((e as { cvssScore?: unknown }).cvssScore ?? 0),
    impact: String((e as { impact?: unknown }).impact ?? ""),
  };
}

/** Reconstruct a real http(s) URL to re-probe from a stored finding. */
export function deriveVerificationUrl(finding: FindingRow, fallbackUrl = ""): string {
  const affected = (finding as { affectedUrl?: string | null }).affectedUrl;
  if (affected && /^https?:\/\//i.test(affected)) return affected;

  const host = (() => { try { return new URL(fallbackUrl).host; } catch { return ""; } })();
  try {
    const blob = JSON.stringify(finding.evidence ?? "");
    const urls = blob.match(/https?:\/\/[^\s"'\\]+/g) || [];
    const onHost = host ? urls.find(u => u.includes(host)) : urls[0];
    if (onHost) return onHost;
  } catch { /* evidence not serialisable — fall through */ }

  const fromTitle = finding.title?.match(/https?:\/\/\S+/)?.[0];
  if (fromTitle) return fromTitle;

  return fallbackUrl;
}

/**
 * Run the 4-layer verifier on a stored finding and persist the verdict.
 * Returns the full VerificationResult (or null if the finding couldn't be
 * pointed at a usable URL).
 */
export async function verifyAndPersistFinding(
  verifier: VerifierAgent,
  finding: FindingRow,
  fallbackUrl = ""
): Promise<VerificationResult | null> {
  const endpoint = deriveVerificationUrl(finding, fallbackUrl);
  if (!/^https?:\/\//i.test(endpoint)) {
    logger.warn("[verify-finding] No usable URL to verify against", { findingId: finding.id });
    return null;
  }

  const evidenceArr = Array.isArray(finding.evidence)
    ? finding.evidence as Record<string, unknown>[]
    : [];

  // Recover the discovery oracle and any captured stateful proof. Findings from
  // the Claude-directed Playwright agent store the agent ProbeResult (carrying
  // .tool) plus a { type:"raw_http", data } entry holding the real request/
  // response pairs. Surfacing those lets the verifier (a) bar the stateless L2
  // reprobe from voting on a stateful finding and (b) give L4 the actual proof
  // to reason over instead of an empty response.
  const discoveryTool = evidenceArr
    .map(e => (e as { tool?: string }).tool)
    .find(t => typeof t === "string" && t.length > 0);
  const rawHttp = evidenceArr.find(e => (e as { type?: string }).type === "raw_http");
  const capturedProof = rawHttp ? String((rawHttp as { data?: unknown }).data ?? "") : "";

  const mockResult = {
    taskId: String(finding.id),
    solverId: "verify",
    endpoint,
    vulnClass: finding.vulnType as Parameters<VerifierAgent["verify"]>[0]["vulnClass"],
    found: true,
    confidence: finding.confidence,
    evidence: evidenceArr[0] || {},
    payload: finding.exploitPayload || "",
    request: endpoint, // L2 reprobe replays this — must be the real URL, not ""
    response: capturedProof.slice(0, 4000),
    duration: 0,
    toolsUsed: [],
    discoveryTool,
    // An OOB beacon that fired during the hunt is authoritative, non-destructive
    // proof — the verifier uses this to confirm rce/ssrf/xxe/blind classes without
    // a stateless L2 reprobe (which can't replay an already-fired callback) vetoing.
    oobConfirmed: finding.oobHitReceived === true,
    programId: finding.programId ?? undefined,
  };

  // Pass the finding's own stored dedupHash so Layer 1 doesn't reject it as a
  // "duplicate of itself" on a second manual verify click.
  const verification = await verifier.verify(mockResult, {
    skipDedupHash: finding.dedupHash ?? undefined,
  });

  // Apply PostExploitAgent's proven severity/CVSS escalation only now that we have
  // a verdict — and only if it's "confirmed". This is the gate that keeps the
  // hunt-loop escalation from inflating severity on a finding that fails verify.
  const escalation = verification.finalVerdict === "confirmed" ? pendingEscalation(finding) : null;

  // When L1 deduplicates this finding against an existing row, writing the same
  // dedupHash onto THIS row would violate the unique constraint (the hash already
  // belongs to the canonical finding). Mark it "duplicate" and persist the log
  // without touching dedupHash so the canonical row keeps sole ownership.
  const isDuplicate = verification.finalVerdict === "deduplicated";
  // dedupHash is only persisted on a CONFIRMED verdict (see CampaignOrchestrator.ts's
  // matching guard) — Layer1Dedup now only blocks future attempts on a prior
  // CONFIRMED match, so the same hash can legitimately recur across several
  // rejected findings for the same target; writing it on every non-duplicate
  // verdict would violate the unique constraint the second such hash appears.

  // When a payload-adaptation retry is what actually confirmed the finding, the
  // original exploitPayload/affectedUrl are the ones that FAILED — persist the
  // adapted payload that legitimately passed the same verification gate so the
  // report documents real, reproducible proof instead of the failing original.
  const adaptation = verification.adaptation;

  await db.update(findings).set({
    verificationStatus: isDuplicate ? "duplicate" : verification.finalVerdict,
    verificationLog: [verification] as unknown as Record<string, unknown>[],
    confidence: verification.finalConfidence,
    ...(verification.finalVerdict === "confirmed" ? { dedupHash: verification.dedupHash } : {}),
    ...(escalation ? {
      severity: escalation.severity,
      cvssScore: escalation.cvssScore,
      impact: escalation.impact,
    } : {}),
    ...(adaptation ? {
      exploitPayload: adaptation.adaptedPayload,
      affectedUrl: adaptation.adaptedUrl,
      // Stash the real adapted request/response as raw_http evidence — the
      // report builder reads this instead of citing the failing original.
      evidence: [
        ...evidenceArr,
        { type: "raw_http", data: `GET ${adaptation.adaptedUrl} HTTP/1.1\n\nHTTP/1.1 ${adaptation.statusCode}\n${adaptation.responseSnippet}` },
      ] as unknown as Record<string, unknown>[],
    } : {}),
    updatedAt: new Date(),
  }).where(eq(findings.id, finding.id)).catch(e =>
    logger.warn("[verify-finding] DB update failed", { findingId: finding.id, err: String(e) })
  );

  // Reconcile hunt-findings.json — HunterEngine's own fast-path confidence
  // threshold populated this entry before this more rigorous pipeline ran,
  // so the file is the write-once heuristic snapshot until corrected here.
  // Mirrors CampaignOrchestrator.layer5_verificationGate's identical fixup
  // (updateFindingConfidence on confirm / retractFinding otherwise) so both
  // verification consumers leave the operator-facing artifact honest, not
  // just the DB row.
  if (verification.finalVerdict === "confirmed") {
    contextWriter.updateFindingConfidence(finding.id, verification.finalConfidence);
  } else {
    contextWriter.retractFinding(finding.id);
  }

  // RL/ROI reinforcement, gated on the real verdict instead of the fast-path
  // heuristic that originally populated this row (see verified-rl-outcome.ts).
  await applyVerifiedRlOutcome(
    { vulnType: finding.vulnType, confidence: verification.finalConfidence, programId: finding.programId },
    isDuplicate ? "deduplicated" : verification.finalVerdict,
  );

  return verification;
}

/**
 * Verify every still-pending finding for a hunt session (keyed by sessionUuid).
 * Runs sequentially to avoid spawning N concurrent Playwright replays. Used by
 * the automatic post-hunt verification pass so console-launched hunts self-verify.
 */
export async function verifyPendingForSession(
  verifier: VerifierAgent,
  sessionUuid: string,
  fallbackUrl = ""
): Promise<{ verified: number; confirmed: number }> {
  const [session] = await db.select({ id: huntSessions.id })
    .from(huntSessions).where(eq(huntSessions.sessionUuid, sessionUuid)).limit(1);
  if (!session) {
    logger.warn("[verify-finding] session not found for auto-verify", { sessionUuid });
    return { verified: 0, confirmed: 0 };
  }

  const pending = await db.select().from(findings)
    .where(eq(findings.huntSessionId, session.id));

  let confirmed = 0;
  let verified = 0;
  for (const finding of pending) {
    if (finding.verificationStatus === "confirmed") continue; // idempotent on resume
    if (finding.verificationStatus === "duplicate") continue;  // already resolved
    try {
      const result = await verifyAndPersistFinding(verifier, finding, fallbackUrl);
      if (result && result.finalVerdict !== "deduplicated") {
        verified++;
        if (result.finalVerdict === "confirmed") confirmed++;
      }
    } catch (err) {
      logger.warn("[verify-finding] session verify failed for finding", { findingId: finding.id, err: String(err) });
    }
  }
  return { verified, confirmed };
}

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
import logger from "../../utils/logger";

type FindingRow = typeof findings.$inferSelect;

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
    response: "",
    duration: 0,
    toolsUsed: [],
  };

  // Pass the finding's own stored dedupHash so Layer 1 doesn't reject it as a
  // "duplicate of itself" on a second manual verify click.
  const verification = await verifier.verify(mockResult, {
    skipDedupHash: finding.dedupHash ?? undefined,
  });

  await db.update(findings).set({
    verificationStatus: verification.finalVerdict,
    verificationLog: [verification] as unknown as Record<string, unknown>[],
    confidence: verification.finalConfidence,
    dedupHash: verification.dedupHash,
    updatedAt: new Date(),
  }).where(eq(findings.id, finding.id)).catch(e =>
    logger.warn("[verify-finding] DB update failed", { findingId: finding.id, err: String(e) })
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
    try {
      const result = await verifyAndPersistFinding(verifier, finding, fallbackUrl);
      if (result) {
        verified++;
        if (result.finalVerdict === "confirmed") confirmed++;
      }
    } catch (err) {
      logger.warn("[verify-finding] session verify failed for finding", { findingId: finding.id, err: String(err) });
    }
  }
  return { verified, confirmed };
}

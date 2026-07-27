/**
 * Program behavioral-rules enforcement — readiness blocker #3.
 *
 * The single chokepoint for "is this restricted action authorized against
 * this program's rules of engagement." Before this file, WAF-bypass and
 * exploitation-tool authorization each had their own hand-rolled
 * lab/real + policy-string check (WAFBypass.ts's checkWafBypassAuthorization,
 * ExploitationToolGate.ts's checkExploitationToolAuthorization — both
 * already correctly fail-closed, 2026-07-21 item D). Automated scanning
 * (ZAP + nuclei) and fuzzing (ffuf/gobuster/feroxbuster/wfuzz/arjun) had NO
 * program-level authorization at all — only ZAP had a per-hunt opt-in
 * toggle with zero connection to what the program's rules actually permit.
 *
 * isActionAllowed() is the one place this logic lives now. The two existing
 * checkXAuthorization() functions are subsumed — they call this gate
 * internally instead of re-deriving the lab/real + policy-string logic —
 * their own scope-check and (for exploitation tools) the deploy-time flag
 * stay where they are, since those are independent questions this gate
 * doesn't answer.
 */
import { isCrossCampaignEligible } from "../lib/hunter/custom-target-program";
import { ScopeGuard } from "../middleware/scopeGuard";
import { db } from "../db";
import { programs } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";

export type RestrictedAction = "waf_bypass" | "exploitation_tools" | "automated_scanning" | "fuzzing";

export interface PolicyCheckResult {
  allowed: boolean;
  reason?: string;
}

/**
 * program: only `isLab` is required — callers that already have the full
 * row can pass it directly; callers with just a programId should look up
 * `{ isLab }` once (see the two subsumed wrappers below for the pattern).
 * policy: the program's raw policy string for THIS action
 * ("unspecified"/"allowed"/"disallowed"/anything else) — pass whichever
 * column corresponds to `action` (wafBypassPolicy, exploitationToolsPolicy,
 * automatedScanningPolicy, fuzzingPolicy).
 *
 * Lab (`!isCrossCampaignEligible`) always permits — it's the operator's own
 * target, no ban risk, no rules of engagement to violate. Real requires an
 * EXPLICIT "allowed"; "unspecified" and "disallowed" both deny. This is the
 * same posture the two pre-existing gates already proved correct — this
 * function generalizes it, not changes it.
 *
 * 2026-07-26 (scope-binding handoff, Fix 1): `program` used to be
 * `{ platform: string }`; every custom-target hunt (the platform's own
 * documented default launch path) resolves to `platform: "local"`
 * regardless of whether the target is the practice lab or a real ad-hoc
 * engagement, which made this gate auto-permit for real hunts too. Now
 * keyed off the dedicated `isLab` column (see schema.ts / resolveCustomTargetProgram).
 */
export function isActionAllowed(
  program: { isLab: boolean },
  policy: string | null | undefined,
  action: RestrictedAction,
): PolicyCheckResult {
  if (!isCrossCampaignEligible(program)) {
    return { allowed: true }; // lab/custom/other — the operator's own target
  }

  if (policy !== "allowed") {
    const reason = `${action} not authorized — program policy is "${policy ?? "unspecified"}", not "allowed"`;
    logger.warn(`[ActionPolicyGate] ${action} blocked — program policy is not explicitly "allowed"`, {
      action, policy: policy ?? "unspecified",
    });
    return { allowed: false, reason };
  }

  return { allowed: true };
}

/**
 * checkAutomatedScanningAuthorization / checkFuzzingAuthorization — the
 * URL+programId-shaped entry points used at the actual tool-dispatch sites
 * (ZAP/nuclei, ffuf/gobuster/feroxbuster/wfuzz/arjun), mirroring
 * checkWafBypassAuthorization/checkExploitationToolAuthorization's own
 * shape (scope-check + program lookup + the shared gate) without needing a
 * standalone wrapper file each — there's no deploy-time flag or
 * per-hunt-toggle question for these two, so a thin function here is enough.
 */
async function checkPolicyAuthorization(
  url: string, programId: number | undefined, policyColumn: "automatedScanningPolicy" | "fuzzingPolicy", action: RestrictedAction,
): Promise<PolicyCheckResult> {
  if (programId === undefined) {
    logger.warn(`[ActionPolicyGate] ${action} blocked — no programId supplied (fail-closed default)`, { url });
    return { allowed: false, reason: "No programId supplied — cannot authorize without a known program" };
  }

  const { allowed, reason } = await ScopeGuard.getInstance().isInScope(url, programId);
  if (!allowed) {
    logger.warn(`[ActionPolicyGate] ${action} blocked by scope guard`, { url, programId, reason });
    return { allowed: false, reason: `Out of scope: ${reason}` };
  }

  const [program] = await db.select({
    isLab: programs.isLab,
    automatedScanningPolicy: programs.automatedScanningPolicy,
    fuzzingPolicy: programs.fuzzingPolicy,
  }).from(programs).where(eq(programs.id, programId)).limit(1);
  if (!program) {
    return { allowed: false, reason: `Program ${programId} not found` };
  }
  return isActionAllowed(program, program[policyColumn], action);
}

export function checkAutomatedScanningAuthorization(url: string, programId: number | undefined): Promise<PolicyCheckResult> {
  return checkPolicyAuthorization(url, programId, "automatedScanningPolicy", "automated_scanning");
}

export function checkFuzzingAuthorization(url: string, programId: number | undefined): Promise<PolicyCheckResult> {
  return checkPolicyAuthorization(url, programId, "fuzzingPolicy", "fuzzing");
}

export interface PreflightWarning {
  code: string;
  message: string;
}

/**
 * Real-launch pre-flight (2026-07-23, blocker #3) — the structural reminder
 * the readiness audit found missing. NEVER refuses a launch by itself: every
 * restricted action it checks is already fail-closed at the gate (a missing
 * policy blocks the TOOL, not the hunt), so an unspecified policy makes the
 * hunt safe-but-degraded, not unsafe — Amendment 1. Scope validity is a
 * separate, pre-existing hard refusal (CampaignOrchestrator's Layer 1 /
 * HunterEngine.startHunt()'s root scope check) this function does not
 * duplicate.
 *
 * Amendment 2: only flags UNSPECIFIED policies (undecided) — an explicit
 * "allowed" or "disallowed" is a decision already made, stays silent. Lab
 * programs get zero warnings (isCrossCampaignEligible false) — it's the
 * operator's own target, nothing to remind them of.
 */
export function runProgramPreflight(program: {
  isLab: boolean;
  wafBypassPolicy: string;
  exploitationToolsPolicy: string;
  automatedScanningPolicy: string;
  fuzzingPolicy: string;
  authConfig?: { loginUrl?: string; livenessUrl?: string } | null;
}): PreflightWarning[] {
  if (!isCrossCampaignEligible(program)) return [];

  const warnings: PreflightWarning[] = [];
  const policies: Array<[string, string, RestrictedAction]> = [
    ["wafBypassPolicy", program.wafBypassPolicy, "waf_bypass"],
    ["exploitationToolsPolicy", program.exploitationToolsPolicy, "exploitation_tools"],
    ["automatedScanningPolicy", program.automatedScanningPolicy, "automated_scanning"],
    ["fuzzingPolicy", program.fuzzingPolicy, "fuzzing"],
  ];
  for (const [field, value, action] of policies) {
    if (!value || value === "unspecified") {
      warnings.push({
        code: `${action}_unspecified`,
        message: `${field} is unspecified — ${action.replace(/_/g, " ")} will be BLOCKED for this hunt (fail-closed default). Set ${field}="allowed" on this program if its rules of engagement permit it.`,
      });
    }
  }

  if (program.authConfig?.loginUrl && !program.authConfig?.livenessUrl) {
    warnings.push({
      code: "liveness_url_unset",
      message: "authConfig.livenessUrl is not set — a mid-hunt auth-session drop may go undetected if the target's public root doesn't distinguish authenticated from unauthenticated responses. Set authConfig.livenessUrl to a real authenticated-only endpoint (e.g. an /api/me-style route) to guarantee detection.",
    });
  }

  return warnings;
}

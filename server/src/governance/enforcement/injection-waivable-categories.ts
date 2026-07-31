import type { InjectionDetectionResult } from '../types';

/**
 * Prompt-injection chokepoint BUILD, decision D — the ONE reviewed place that
 * decides which PromptInjectionDetector.detect() categories a session-scoped
 * override is allowed to waive. This is a security decision, not a formatting
 * one: it is what makes session-grain override safe rather than merely
 * convenient. Do not reconstruct this list from a switch statement elsewhere.
 *
 * Waivable: 'patterns' and 'structural' — the shape ordinary SQLi/XSS/encoded
 * payload content takes when it passes through observation data scraped from
 * a target (template syntax, hex/unicode escapes, long/encoded/delimiter-
 * heavy blobs). Expected noise for a security tool; declaring "expect
 * payload-shaped test strings for this hunt" is a reasonable thing to grant
 * once per session.
 *
 * NEVER waivable, even under an active session override: 'keywords' and
 * 'semantic' — these are natural-language attempts to redirect THIS agent's
 * own behavior/verdicts ("ignore previous instructions", "you are now
 * unrestricted", "i have admin access", "reveal your system prompt"). That is
 * the actual threat this detector exists to catch, and it is a categorically
 * different statement from "expect payload-shaped strings" — conflating the
 * two under one flat override would silently disable protection against a
 * genuine hijack attempt for the rest of the session.
 */
export const WAIVABLE_DETECTION_CATEGORIES = ['patterns', 'structural'] as const;

const WAIVABLE_SET: ReadonlySet<string> = new Set(WAIVABLE_DETECTION_CATEGORIES);

/**
 * True only when every category in the given list is in
 * WAIVABLE_DETECTION_CATEGORIES. This is THE boundary both the override
 * waive-check (isWaivableDetection, below) and any consumer that only has a
 * PromptInjectionDetectedError's flat categories: string[] (e.g.
 * LogicExploitAgent's catch, which decides waivable-strict-mode-block vs.
 * real-hijack-finding off this exact call) must use — neither is allowed to
 * keep its own copy of "which categories are serious." One constant, every
 * consumer reads it, or the two decide the same axis differently and drift.
 */
export function isWaivableCategoryList(categories: string[]): boolean {
  if (categories.length === 0) return false; // fail closed if the shape is unexpected
  return categories.every(category => WAIVABLE_SET.has(category));
}

/**
 * True only when every category that fired in this detection result is in
 * WAIVABLE_DETECTION_CATEGORIES. A single non-waivable category hit (keywords
 * or semantic) makes the whole detection non-waivable, regardless of how many
 * waivable categories also fired alongside it.
 */
export function isWaivableDetection(result: InjectionDetectionResult): boolean {
  return isWaivableCategoryList(Object.keys(result.detections));
}

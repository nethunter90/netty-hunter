import logger from '../../utils/logger';
import { promptInjectionDetector } from '../index';
import { isWaivableDetection } from './injection-waivable-categories';
import { hasActiveInjectionOverride } from './governed-grants';

export type InjectionScreenSource = 'sdk' | 'cli';

/**
 * Prompt-injection chokepoint BUILD, decision C — thrown from the shared LLM
 * chokepoint (ClaudeClient.createMessage()) and the CLI-bridge fallback
 * (ClaudeBridge.reason()) BEFORE the API/subprocess call is made. Mirrors the
 * existing LLMBudgetExceededError/LLMDollarBudgetExceededError precedent:
 * callers that need graceful handling (a loop, a route) catch this specific
 * class; callers with a catch-all already get it for free. Never caught and
 * silently swallowed at the throw site itself — logging without gating would
 * rebuild the exact recordDecision()-audit-sink defect this design closes.
 */
export class PromptInjectionDetectedError extends Error {
  constructor(
    public readonly score: number,
    public readonly reasons: string[],
    public readonly categories: string[],
    public readonly sessionId: string | undefined,
    public readonly source: InjectionScreenSource,
  ) {
    super(
      `Prompt injection detected (score ${score}/100, source=${source}` +
      `${sessionId ? `, session=${sessionId}` : ''}, categories=[${categories.join(', ')}]): ${reasons.join('; ')}`,
    );
    this.name = 'PromptInjectionDetectedError';
  }
}

// ── Failure-visibility counters (BUILD R3) ──────────────────────────────────
// In-memory, keyed by sessionId — same shape as ClaudeClient's spend/callCount
// Maps. persistLlmSpend() reads these alongside the spend ledger so
// promptInjectionChecksRun/Positives land on the exact same DB write as
// llmSpendUsd/llmCallCount, never a separate, driftable write path.
const checksRun = new Map<string, number>();
const positives = new Map<string, number>();

export function getInjectionStats(sessionId: string): { checksRun: number; positives: number } {
  return { checksRun: checksRun.get(sessionId) ?? 0, positives: positives.get(sessionId) ?? 0 };
}

export function clearInjectionStats(sessionId: string): void {
  checksRun.delete(sessionId);
  positives.delete(sessionId);
}

/**
 * Screen a chunk of (potentially target-controlled) text before it is sent to
 * the model. Runs the detector, ALWAYS scores and logs a positive (visibility
 * is never traded for permissiveness — see decision D), and throws
 * PromptInjectionDetectedError unless BOTH: (a) every category that fired is
 * in the waivable set (injection-waivable-categories.ts), AND (b) the calling
 * hunt session currently holds an active override (governed-grants.ts, live
 * per-call check — never trust a value cached before this call).
 *
 * No-ops on empty/whitespace-only text without touching the detector or the
 * override cache — nothing to screen.
 */
export async function screenForInjection(
  text: string,
  sessionId: string | undefined,
  source: InjectionScreenSource,
): Promise<void> {
  if (!text || !text.trim()) return;

  if (sessionId) checksRun.set(sessionId, (checksRun.get(sessionId) ?? 0) + 1);

  // agentId non-empty routes a positive through coreGovernance.recordDecision()
  // inside the detector itself — this is how a positive stays logged/auditable
  // even when the call below ends up waived, not blocked.
  const result = promptInjectionDetector.detect(text, sessionId ?? 'llm-chokepoint', `createMessage[${source}]`);
  if (result.safe) return;

  if (sessionId) positives.set(sessionId, (positives.get(sessionId) ?? 0) + 1);

  const categories = Object.keys(result.detections);
  const waivable = isWaivableDetection(result);

  if (waivable && sessionId) {
    const overridden = await hasActiveInjectionOverride(sessionId);
    if (overridden) {
      logger.warn('[injection-guard] Positive detection WAIVED by active session override', {
        sessionId, source, score: result.score, categories, reasons: result.reasons,
      });
      return;
    }
  }

  logger.error('[injection-guard] BLOCKING call — prompt injection detected', {
    sessionId, source, score: result.score, categories, reasons: result.reasons, waivable,
  });
  throw new PromptInjectionDetectedError(result.score, result.reasons, categories, sessionId, source);
}

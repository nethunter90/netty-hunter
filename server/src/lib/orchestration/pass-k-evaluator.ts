// 2026-07-22 (Phase 2, external-tool chokepoint): PassKEvaluator.evaluate()
// (the multi-attempt-via-completeAgents runner) was removed here — dynamic-
// reference-checked dead code (confirmed via grep for every call form: direct
// `.evaluate(`, string-keyed dynamic dispatch, DI/config lookup — zero live
// callers found anywhere except this class's own definition). It was the
// ONLY caller of layer5-complete-agents.ts's `completeAgents` (the Record of
// CompleteMetaAgent instances whose runTool() methods shelled out via raw
// exec() with weak/no escaping — the same RCE class as layer5-meta-agents.ts,
// see that file's migration comment). Deleting the dead caller alongside the
// vulnerable dependency it was the only path to, rather than migrating code
// nothing reaches. PassKEvaluatorService/resolveK() below (the only live
// member of this file) never touched completeAgents and is unaffected.

// DEFAULT_K_VALUES represent the maximum (turbo/intensive) attempts per agent type.
// Scaled down for standard resource class to conserve LLM inference budget.
export const DEFAULT_K_VALUES: Record<string, number> = {
  recon: 2,
  exploit: 3,
  credential: 2,
  intel: 2,
  blueteam: 1,
  pivot: 3,
  report: 1,
  wordlist: 1,
  simgen: 1,
  smart: 2,
  scanner: 1,
  support: 1,
};

// Payout tier → k multiplier. High-payout programs justify more LLM attempts.
const PAYOUT_K_TIERS: Array<{ minPayout: number; k: number }> = [
  { minPayout: 5000, k: 3 },
  { minPayout: 1000, k: 2 },
  { minPayout: 0,    k: 1 },
];

export class PassKEvaluatorService {
  /**
   * Resolve how many attempts to run for an agent type given the resource class
   * and optional expected program payout. Uses the DEFAULT_K_VALUES as the
   * maximum ceiling and scales down for lower resource classes.
   */
  resolveK(
    agentType: string,
    resourceClass: 'lightweight' | 'standard' | 'enterprise' = 'standard',
    expectedPayout?: number
  ): number {
    const base = DEFAULT_K_VALUES[agentType] ?? 2;

    // Payout-based override takes priority when a payout estimate is available
    if (expectedPayout !== undefined) {
      const tier = PAYOUT_K_TIERS.find(t => expectedPayout >= t.minPayout);
      const payoutK = tier?.k ?? 1;
      // Cap at the DEFAULT for this agent type so expensive agents don't over-run
      return Math.min(payoutK, base);
    }

    // Resource class scaling: enterprise → full k, standard → default, lightweight → halved
    switch (resourceClass) {
      case 'enterprise':  return Math.min(base + 1, 4);
      case 'standard':    return base;
      case 'lightweight': return Math.max(Math.floor(base / 2), 1);
    }
  }
}

export const passKEvaluator = new PassKEvaluatorService();

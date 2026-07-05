/**
 * FailurePrediction — pre-probe signal that estimates whether a hypothesis
 * is worth probing before spending tool budget on it.
 *
 * Tracks real outcomes via recordOutcome() and adjusts predictions as data
 * accumulates. Starts from conservative base rates per vuln class.
 */

export type Complexity = "trivial" | "simple" | "moderate" | "complex" | "expert";

interface OutcomeRecord {
  successes: number;
  total: number;
}

// Historical base failure rates per vuln class (cold-start priors)
const BASE_FAILURE_RATE: Record<string, number> = {
  sqli: 0.45,
  xss: 0.50,
  ssrf: 0.60,
  idor: 0.35,
  rce: 0.70,
  lfi: 0.65,
  xxe: 0.72,
  csrf: 0.55,
  cors: 0.40,
  auth_bypass: 0.58,
  info_disclosure: 0.25,
  misconfig: 0.30,
  security_headers: 0.20,
  open_redirect: 0.45,
  ssti: 0.75,
  deserialization: 0.68,
  prototype_pollution: 0.72,
};

const COMPLEXITY_MULTIPLIER: Record<Complexity, number> = {
  trivial: 0.5,
  simple: 0.75,
  moderate: 1.0,
  complex: 1.4,
  expert: 1.8,
};

// Skip threshold: if predicted failure probability exceeds this, skip
const SKIP_THRESHOLD = 0.82;

// A prior-only estimate (zero real outcomes recorded yet) must never trigger
// a skip on its own. Without this floor, rce (0.70 base) × "complex" (1.4x,
// matched by the word "rce"/"chain" in its own auto-generated reasoning)
// clamps to 0.95 and gets vetoed before the very first probe — on every
// hunt, forever, with no way to ever gather disconfirming evidence. A skip
// has to be earned by real observed failures, not guessed from the prior.
const MIN_SAMPLES_BEFORE_SKIP = 3;

// Even once a (vulnClass, complexity) bucket has earned a skip verdict from
// real failures, letting it skip *every* subsequent hypothesis forever means
// it can never recover — skipped hypotheses never call recordOutcome, so an
// unlucky early streak permanently freezes the empirical rate that caused
// it. Periodically probe anyway so fresh evidence keeps flowing.
const EXPLORATION_RATE = 0.15;

class FailurePredictionEngine {
  private outcomes = new Map<string, OutcomeRecord>();

  recordOutcome(vulnClass: string, complexity: Complexity, succeeded: boolean): void {
    const key = `${vulnClass}:${complexity}`;
    const rec = this.outcomes.get(key) ?? { successes: 0, total: 0 };
    rec.total++;
    if (succeeded) rec.successes++;
    this.outcomes.set(key, rec);
  }

  predict(vulnClass: string, complexity: Complexity): {
    failureProbability: number;
    shouldSkip: boolean;
    reason: string;
  } {
    const key = `${vulnClass}:${complexity}`;
    const rec = this.outcomes.get(key);

    const baseRate = BASE_FAILURE_RATE[vulnClass] ?? 0.55;
    const multiplier = COMPLEXITY_MULTIPLIER[complexity];

    let failureProbability: number;
    let dataSource: string;

    if (rec && rec.total >= 5) {
      // Enough empirical data — blend with prior (Bayesian update)
      const empirical = 1 - (rec.successes / rec.total);
      failureProbability = (empirical * 0.7) + (baseRate * multiplier * 0.3);
      dataSource = `empirical (n=${rec.total})`;
    } else if (rec && rec.total > 0) {
      // Some data but not enough — weight prior more heavily
      const empirical = 1 - (rec.successes / rec.total);
      const w = rec.total / 5;
      failureProbability = (empirical * w * 0.7) + (baseRate * multiplier * (1 - w * 0.3));
      dataSource = `partial (n=${rec.total})`;
    } else {
      failureProbability = Math.min(0.95, baseRate * multiplier);
      dataSource = "prior";
    }

    failureProbability = Math.min(0.95, Math.max(0.05, failureProbability));

    const hasEnoughSamples = (rec?.total ?? 0) >= MIN_SAMPLES_BEFORE_SKIP;
    let shouldSkip = hasEnoughSamples && failureProbability >= SKIP_THRESHOLD;

    if (shouldSkip && Math.random() < EXPLORATION_RATE) {
      shouldSkip = false;
      dataSource = `${dataSource}, exploration override`;
    }

    const reason = shouldSkip
      ? `${vulnClass} on ${complexity} target: ${Math.round(failureProbability * 100)}% predicted failure rate [${dataSource}] — skipping`
      : `${vulnClass}: ${Math.round(failureProbability * 100)}% predicted failure [${dataSource}]`;

    return { failureProbability, shouldSkip, reason };
  }

  complexityFrom(tags: string[], description: string): Complexity {
    const combined = (tags.join(" ") + " " + description).toLowerCase();
    if (/chain|multi.step|pivot|rce|deseri|prototype|race/i.test(combined)) return "complex";
    if (/bypass|blind|second.order|stored|oauth|jwt/i.test(combined)) return "moderate";
    if (/reflect|basic|classic|simple|direct/i.test(combined)) return "simple";
    if (tags.length === 0) return "moderate";
    return "simple";
  }
}

export const failurePrediction = new FailurePredictionEngine();

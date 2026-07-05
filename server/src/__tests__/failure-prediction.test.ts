import { describe, it, expect, beforeEach } from "vitest";
import { failurePrediction } from "../lib/intelligence/failure-prediction";

describe("FailurePredictionEngine", () => {
  beforeEach(() => {
    // Fresh engine state per test — private map, so reach in via a new instance
    // isn't exported; instead we use vulnClass/complexity keys unique per test
    // to avoid cross-test contamination of the shared singleton.
  });

  it("never skips on prior alone, even when baseRate x complexity clamps to the max", () => {
    // rce (0.70 base) classified as "complex" (1.4x) clamps to 0.95 — this is
    // exactly the case that used to veto every RCE hypothesis on the very
    // first attempt, on every hunt, forever, because "rce"/"chain" appear in
    // its own auto-generated reasoning text and match the complexity regex.
    const prediction = failurePrediction.predict("rce", "complex");
    expect(prediction.failureProbability).toBeGreaterThanOrEqual(0.82);
    expect(prediction.shouldSkip).toBe(false);
  });

  it("still allows a skip once enough real failures are recorded", () => {
    const vulnClass = "test_vuln_empirical_skip";
    for (let i = 0; i < 5; i++) {
      failurePrediction.recordOutcome(vulnClass, "complex", false);
    }
    // Run predict() repeatedly — exploration is probabilistic (15%), so
    // assert the *possibility* of skip exists across many draws rather than
    // requiring every single call to skip.
    const results = Array.from({ length: 200 }, () => failurePrediction.predict(vulnClass, "complex"));
    const anySkipped = results.some(r => r.shouldSkip);
    const anyExplored = results.some(r => !r.shouldSkip);
    expect(anySkipped).toBe(true);
    expect(anyExplored).toBe(true); // exploration prevents a permanent, unrecoverable lock-out
  });

  it("does not skip with fewer than the minimum sample size, regardless of how bad they were", () => {
    const vulnClass = "test_vuln_insufficient_samples";
    failurePrediction.recordOutcome(vulnClass, "moderate", false);
    failurePrediction.recordOutcome(vulnClass, "moderate", false);
    // Only 2 real failures recorded — below MIN_SAMPLES_BEFORE_SKIP (3) —
    // must not skip yet, even though 2/2 failures looks damning.
    const prediction = failurePrediction.predict(vulnClass, "moderate");
    expect(prediction.shouldSkip).toBe(false);
  });

  it("unlisted vuln classes (e.g. hidden_endpoints) are not skipped from a cold start", () => {
    const prediction = failurePrediction.predict("hidden_endpoints_test_unique", "moderate");
    expect(prediction.shouldSkip).toBe(false);
  });
});

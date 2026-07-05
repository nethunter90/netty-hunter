/**
 * RCESolver SSTI-oracle honesty test (2026-07-03).
 *
 * The old oracle matched bare /49/ for the {{7*7}} probe — a 0.95 RCE confirm
 * that fires on ANY response merely containing "49" (a price, a port, a
 * count, a year). Same false-positive class the nonce-echo oracle
 * (VerifierAgent.reprobeRceNonceEcho) exists to prevent; fixed the same way —
 * random unguessable product + reflection guard.
 */
import { describe, it, expect } from "vitest";
import { RCESolver } from "../agents/SolverPool";

describe("RCESolver.confirmsEvaluation (SSTI honesty fix)", () => {
  it("does NOT confirm when the response merely contains an incidental number matching the old bare-/49/ bug class", () => {
    // Same shape as the original bug: a page listing a $49 product, a count
    // of 49 items, a port 49xxx, or a year — none of these prove evaluation.
    const incidentalBodies = [
      "Price: $49.00 — Add to cart",
      "49 results found for your search",
      "Server listening on port 4900",
      "Copyright 1949-2026",
    ];
    for (const body of incidentalBodies) {
      // Using the REAL random factors a live probe would generate — the
      // point is that a page written before the probe ran can't possibly
      // contain today's random product, so this must always be false.
      expect(RCESolver.confirmsEvaluation(body, "4821*3157", "15224097")).toBe(false);
    }
  });

  it("does NOT confirm when the literal sent expression is merely reflected back (input echo, not evaluation)", () => {
    const sentExpr = "4821*3157";
    const product = "15224097";
    // Reflects the payload verbatim — e.g. an unauthenticated search page
    // echoing the query string back into the page.
    const reflectedBody = `You searched for: {{${sentExpr}}}`;
    expect(RCESolver.confirmsEvaluation(reflectedBody, sentExpr, product)).toBe(false);
  });

  it("confirms only when the product appears AND the literal expression does not (genuine evaluation)", () => {
    const sentExpr = "4821*3157";
    const product = "15224097";
    const evaluatedBody = `Result: ${product}`;
    expect(RCESolver.confirmsEvaluation(evaluatedBody, sentExpr, product)).toBe(true);
  });

  it("rejects a product below the unguessable-token floor even if present and unreflected", () => {
    // Guards against a degenerate case where small factors produce a short,
    // more easily-coincidental product (e.g. a low-digit number).
    expect(RCESolver.confirmsEvaluation("The answer is 49", "7*7", "49")).toBe(false);
  });
});

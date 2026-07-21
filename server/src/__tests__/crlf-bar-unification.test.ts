import { describe, test, expect } from "vitest";
import { isCrlfImpactProven, MARKER_HEADER, MARKER_VALUE } from "../lib/tools/crlf-probe";

/**
 * CRLF bar unification — Phase 1 validation (2026-07-21).
 *
 * Test 1 uses a MOCKED headers object rather than a live positive-case
 * endpoint: modern Node's http module rejects raw CR/LF in setHeader() calls
 * (ERR_INVALID_CHAR), which is exactly why logic-lab's own author could not
 * build a genuinely exploitable header-splitting endpoint even if they'd
 * wanted to (server.js:10-17) — a live positive case isn't constructible on
 * this stack. The predicate's LOGIC is still fully exercised directly; tests
 * 2-4 use the real, live, known-negative lab for end-to-end integration proof.
 */
describe("CRLF bar unification — isCrlfImpactProven()", () => {
  test("1. header-sink case (mocked): a new response header line -> predicate TRUE", () => {
    // Simulates what a genuinely vulnerable backend's parsed response headers
    // would look like if response splitting were possible — the marker
    // header actually present as its own header key.
    const headers = {
      "content-type": "text/html",
      [MARKER_HEADER.toLowerCase()]: MARKER_VALUE,
    };
    expect(isCrlfImpactProven(headers)).toBe(true);
  });

  test("2. body-reflection-only case (mocked): no header key -> predicate FALSE", () => {
    const headers = {
      "content-type": "text/html",
      // no X-Injected key present — the marker only ever showed up in the body,
      // which isCrlfImpactProven() never inspects (headers-only by design).
    };
    expect(isCrlfImpactProven(headers)).toBe(false);
  });

  test("3. no headers at all -> predicate FALSE (never throws)", () => {
    expect(isCrlfImpactProven(undefined)).toBe(false);
    expect(isCrlfImpactProven(null)).toBe(false);
    expect(isCrlfImpactProven({})).toBe(false);
  });
});

describe("CRLF bar unification — live integration against logic-lab (known negative)", () => {
  const TARGET = "http://localhost:8081/?x=%0d%0aX-Injected:+crlf-netty";

  test("4. logic-lab's real endpoint: body reflects the marker, but predicate is FALSE (no header sink, matches Phase-0 source-code verdict)", async () => {
    const res = await fetch(TARGET);
    const body = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k] = v; });

    // The body DOES reflect (confirms the endpoint is live/reachable and the
    // reflection itself is real) ...
    expect(body).toContain(MARKER_VALUE);
    // ... but no real header sink exists, so the unified predicate correctly
    // says false — this is the Leak-C-false-candidate check: crlf_probe will
    // now classify this exact endpoint as reflected_input, not crlf_injection,
    // so it can no longer seat a false CRLF hypothesis via Leak C's selector.
    expect(isCrlfImpactProven(headers)).toBe(false);
  });
});

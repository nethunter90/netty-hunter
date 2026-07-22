// Readiness pass item B: dynamicRateLimiter is now wired live into
// scopedHttp's scopedRequest() (see lib/net/scoped-http.ts). It is a
// process-wide singleton with real setTimeout-based pacing and cross-test
// bucket state (burst/backoff/quarantine counters keyed by hostname persist
// across test files that reuse the same mock hostnames), so unit tests must
// not exercise it — that's exactly what its own DYNAMIC_RATE_LIMIT_ENABLED
// escape hatch is for. Real pacing is proven live (raw hunt logs), never by
// a unit test, per the readiness-pass rule that a passing unit test doesn't
// count for rate limiting.
process.env.DYNAMIC_RATE_LIMIT_ENABLED = "false";

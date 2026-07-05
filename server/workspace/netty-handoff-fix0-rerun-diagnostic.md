# Netty Hunter — Diagnostic Handoff: The Fix #0 Re-Run

_Compiled 2026-07-04. Fix #0 (failure-prediction skip gate) is built, tested (239/239), and the status-honesty follow-on is closed. This is NOT a "did it work" check — it's a re-diagnosis. Fix #1 and Fix #2 as scoped may be wrong-sized or wrong entirely once this run's data is in. Do not rebuild #1/#2 from the old handoff — re-derive them from what actually happens this run._

---

## WHAT'S LANDED THIS SESSION (banked, do not redo)

**Fix #0 — `server/src/lib/intelligence/failure-prediction.ts`:**
- `MIN_SAMPLES_BEFORE_SKIP = 3` — a skip must be earned by real observed failures, never granted on the prior alone. Kills failure mode 1 (rce/deserialization/prototype_pollution clamped to 0.95 and vetoed on hypothesis #1, forever, because "rce"/"chain" in their own reasoning text matches the "complex" 1.4x regex).
- `EXPLORATION_RATE = 0.15` — even an earned skip lets ~15% through anyway. Kills failure mode 2 (a bucket that crosses threshold from 3 early real failures can never recover, since skipped hypotheses never call `recordOutcome`).
- Skip log promoted `debug` → `info`, plus a new `hunt:hypothesis_skipped` event. This was the actual reason the bug survived five sessions undetected — the veto never appeared anywhere the default log level would show it.
- Test file `failure-prediction.test.ts` (4 tests) locks in all four corners: no skip on prior alone even at max clamp, skip still possible after real failures (the gate's legitimate function is preserved, not just disabled), no skip below the sample floor, unlisted classes not vetoed cold.

**Status-honesty follow-on — `HunterEngine.ts`:**
- Added `"deferred"` as a new `Hypothesis.status` value, distinct from `"rejected"`.
- `"rejected"` is now reserved for hypotheses that were **actually probed** and the evidence came back negative (the two call sites at confidence-update time, both already gated on `relatedProbes.length > 0` / a real confidence computation — these were already honest, untouched).
- `"deferred"` now covers the two never-probed paths: failure-prediction skip, and scope-guard rejection (out-of-scope was silently sharing the same lie).
- `hunt:update` now emits `deferredHypotheses` alongside `pendingHypotheses`/`rejectedHypotheses` so this is visible in the live feed and DB progress record, not just inferred from absence.
- **Why this mattered on its own:** without it, Fix #0 reduces *how much* gets silently deferred, but anything still deferred (past-budget, or the 15% that don't get the exploration roll) would still have read as `"rejected"` — the same lie in smaller volume. The scorecard needs this distinction to be trustworthy, independent of how good the gate math is.
- `jsonb` column in the DB schema, no enum constraint — safe to add without a migration. `tsc --noEmit` clean, 239/239 tests still pass.

**The real 8-item Kali-Web-IDE key, recovered from an earlier session transcript (never lived in a file — do not go looking for `SECURITY-NOTES-DO-NOT-FIX.md` again, that was sentprime's and has been deleted):**
1. Auth bypass (critical) — `server/auth.ts`: `isAuthenticated()` unconditionally calls `next()`
2. Unauthenticated WiFi endpoints — `/api/wifi/interfaces`, `/monitor`, `/scan`, `/captures` — no auth middleware
3. OS command injection — `/api/wifi/monitor` & `/scan`: `interface` field interpolated into shell `exec()`
4. Path traversal via BSSID — `server/desktop-agent/index.ts` `wifi:start_capture` socket handler
5. Unauthenticated/unvalidated WebSocket WiFi controls — deauth/scan via socket, no authz check
6. Insecure capture storage — `/tmp/wifi-captures`, world-writable, listed via unauthenticated endpoint
7. Unsanitized `projectDir` in build orchestrator — `server/desktop-agent/build/build-orchestrator.ts` `autonomousBuild()` — path traversal/arbitrary file write
8. Prompt/command injection in `claudeBuild` — user goal embedded in a shell prompt to `claude -p --dangerously-skip-permissions`

**Save this list somewhere durable this time** — it's been re-derived from a stale transcript twice now because it was never written down.

---

## THE RE-RUN: SPECIFIC PREDICTIONS TO CHECK (not a vibe check — a diagnosis)

Launch the hunt against Kali-Web-IDE (via the supervisor, port 5000) exactly as before. While it runs and after it completes, check these in order:

### Prediction 1 — RCE hypotheses survive to real probes for the first time in the arc
Pull the session's hypotheses (`GET /api/hunt/session/<uuid>`) and filter `vulnClass === "rce"`. Before Fix #0: 4/4 rejected, 0 probes, every single time. **This run: check whether any RCE hypothesis has an associated probe entry in `session.probes` (match by `hypothesisId`).**
- If yes — this is the Gate-2 nonce-echo oracle's first in-situ firing in the entire arc. Note the verdict (confirmed/rejected/inconclusive) regardless of outcome; the point is it *ran*.
- If still zero probes — check whether they're now `"deferred"` (correctly labeled, still not enough exploration luck / still legitimately deprioritized) vs still silently mislabeled. If still 0 probes after this fix, that's a new, different bug — don't assume Fix #0 alone guarantees every RCE hypothesis fires; `EXPLORATION_RATE` is probabilistic, not a guarantee for any single hunt.

### Prediction 2 — desktop-agent / build-orchestrator / auth.ts may now get probed without any crawl change
Last run these three were **never generated as hypotheses at all** (not deferred — absent). If the shared-cause theory holds only partially, it's possible some path already generates hypotheses for these (e.g., via a class that was being vetoed at the *hypothesize* stage in some other way) — check freshly, don't assume.
- If they now appear **and get probed**: Fix #2 (the discovery-routing gap) may not be needed at all, or shrinks to "whatever's still unreached." Re-scope it down.
- If they still never appear as hypotheses **at all** (not even `deferred`): this confirms it's a genuine discovery gap (crawl never sees these routes), not a prediction-gate issue. Fix #2 stands as originally scoped — diagnose why the crawl doesn't reach them (second-level panel interaction / mount-silent panels / DOM-diff need) before building anything.

### Prediction 3 — wifi's real status this time
Check `/api/wifi/interfaces` and `/api/wifi/monitor`/`/scan`/`/captures` (note: only `/api/wifi/interfaces` was ever discovered last run — the other three under item #2/#3/#5/#6 of the key were **never even discovered**, a separate gap from the prediction-gate issue). For whichever wifi hypotheses exist:
- Confirm the status is now legible: `"deferred"` (never probed) vs `"rejected"` (probed, negative) vs `"confirmed"`.
- If `/api/wifi/interfaces` gets a real probe this time and still comes back negative, that's an honest miss on item #2 — the vuln is "no auth middleware," and a generic `hidden_endpoints`-class probe (a `curl_probe` checking for injection-like signals) doesn't actually test for missing-auth. That's a **fourth potential gap**, separate from all of #0/#1/#2: no vuln class/probe in this engine specifically tests "does this endpoint require auth that it should." Flag it if you see it, don't build for it yet.

### Prediction 4 — Fix #1's symptom (evidence-free placeholder confirms) should persist
Fix #0 doesn't touch L1 dedup or the "Effort-profile priority" placeholder hypotheses' confirm path — those are separate mechanisms. Expect the same shape: 20 `open_redirect`s on the bare base URL, generic 200-OK "proof," collapsing to the same handful of stale cross-session hashes.
- If this noise is **gone or much smaller**, that's surprising and means Fix #1 was misdiagnosed — go find out why before assuming it's fixed.
- If it **persists at similar volume**, Fix #1 stands as scoped: fix the loose provisional-confirm heuristic (generic 200-OK isn't evidence) and stop cross-session hash dedup from letting evidence-free hypotheses skip L2 forever.

---

## SCORING THE RE-RUN — do this before deciding what #1/#2 are

1. Pull the full session hypotheses + probes, same method as last time (`GET /api/hunt/session/<uuid>`, cross-reference `probes` array by `hypothesisId` — don't trust `status` alone without checking for an actual probe record, and don't trust engine-side `status:"confirmed"` without running it through the real `VerifierAgent` 4-layer pipeline, same as last time. 47→8→0 was the real number; the raw provisional count is not the number to report).
2. For every hypothesis, classify: `confirmed` (survived full verification) / `rejected` (probed, verifier said no) / `deferred` (never probed) / `inconclusive`.
3. Map to all 8 key items **by endpoint identity**, not vuln class name. Score N of 8, with each item's status being one of: confirmed / probed-and-rejected / deferred-never-reached / hypothesis-never-generated (four distinct outcomes now, not two — this granularity is new and is the point of this session's fixes).
4. Report which of the four re-run predictions above held, and which didn't — that's the actual deliverable, more than the recall number itself.

---

## SEQUENCING
1. **Re-run now**, against the corrected 8-item key, with Fix #0 + status-honesty in place.
2. **Score with the four-way classification** (confirmed/rejected/deferred/never-generated) — this alone will re-scope Fix #1 and Fix #2.
3. **Only then** decide what Fix #1 and Fix #2 actually need to be — do not rebuild them from the pre-Fix-#0 handoff's description. If either dissolved or shrank, say so plainly; if either stands as scoped, build it next with the same diagnose-first discipline as this session.

---

## ONE-LINE FOR OPUS
Fix #0 (failure-prediction never skips on prior alone; earned skips get 15% exploration so they can't permanently lock out a class) plus a status-honesty fix (`"deferred"` now distinct from `"rejected"` — never-probed vs. tested-negative) are both built, tested, and merged. This is a re-diagnosis re-run, not a validation re-run: check whether RCE hypotheses finally reach a real probe (Gate-2 oracle's first in-situ shot all arc), whether desktop-agent/build-orchestrator/auth.ts hypotheses appear now that the gate isn't silently vetoing (if they still never even *generate*, that confirms Fix #2 as a genuine discovery gap; if they generate-and-probe now, Fix #2 shrinks or dissolves), and whether Fix #1's placeholder-noise symptom persists unchanged (expected, since Fix #0 doesn't touch dedup) or surprisingly clears (investigate why before trusting it). Score with four buckets — confirmed / rejected / deferred / never-generated — against the real, now-recovered 8-item key (saved in this handoff, don't re-derive it a third time). Don't rebuild #1/#2 from the old plan; let this run's data re-scope them.

# Builder's Journal — Sentinel Primordial / Netty Hunter

> A retroactive "why" companion to the git history. Not a spec (see `ARCHITECTURE.md`)
> and not a system map for a cold start (see `HANDOFF.md`) — this is the reasoning
> trail: what broke, what was found live, and why a given fix was the right one,
> in the order it actually happened.

## How this document came to exist

This project didn't keep a builder's journal from day one, and by the time that felt
like a real loss, 517 commits of history already existed with no single narrative
tying them together. This document is a best-effort retroactive reconstruction: six
AI agents each read a contiguous chronological slice of the full git log (`git log
--no-merges --pretty=fuller`, in order, no gaps) and distilled every commit that
carried real reasoning in its body into plain-language entries, citing the short
hash and date so anything below can be traced back to the actual diff.

**What this can't recover:** reasoning that only ever existed in a chat conversation
(with a local terminal session or a cloud session) and never made it into a commit
message is gone. Where the git record itself is thin — a bare one-line commit title
with no body, a purely mechanical bulk-data commit, a multi-week gap with nothing
committed in between — each era's section says so explicitly in its own **Thin
record** callout, rather than inventing a plausible-sounding justification that
isn't actually there. Treat this as honest about its own blind spots, not complete.

**Keeping this going forward:** the fix for "I wish I'd started this earlier" is to
stop losing it from here on. When a commit fixes something non-obvious — a root
cause, a live-verified false-positive count, a design tradeoff — add a short entry
to the relevant era below (or a new one, if enough time has passed) instead of
letting the reasoning live only in the commit message. Both the local terminal
session and this cloud session can append here.

## Table of contents

1. [Feb–Jun 2026: From a One-Shot Scaffold to a Self-Correcting Hunt Engine](#feb-jun-2026)
2. [Jun 6–7 2026: Taming the Overnight Datagen Pipeline, Then a Visual-Tagging Detour](#jun-6-7-2026)
3. [Jun 7–8 2026: Dataset Grind, Real-CVE Scraping, and the Phase 0 Recon Pipeline](#jun-7-8-2026)
4. [Jun 8–21 2026: Claude Becomes the Real Tier-0 Brain, Then the Verification Pipeline Gets Torn Apart and Rebuilt](#jun-8-21-2026)
5. [Jun 23–Jul 8 2026: Honesty Audits — Impact Verification, Scope Enforcement, and Tool Invocation All Get the Same Treatment](#jun-23-jul-8-2026)
6. [Jul 8–12 2026: The Evidence-Discarding Bug Sweep, the Workflow Split, and the RCE-Only Pivot](#jul-8-12-2026)

---

<a id="feb-jun-2026"></a>

## 1. Feb–Jun 2026: From a One-Shot Scaffold to a Self-Correcting Hunt Engine

This era runs from the platform's original big-bang commit through the eve of a large documentation/dataset day. It splits into a handful of distinct pushes separated by weeks-long gaps (Feb 19 → Apr 11, Apr 11 → May 22), followed by a dense, almost daily run of hardening and feature work from May 22 through June 6.

### The initial build (Feb 18–19)

The entire platform was scaffolded in one commit, `6f75fe9` (2026-02-18): Hunter Engine, SolverPool, a 7-module WAF bypass system, the 4-layer VerifierAgent, ScopeGuard, ModelRouter, the intelligence modules (ROI model, reinforcement store, autonomy tracker, exploit-chain intelligence, backward hunt engine), the Drizzle/Postgres schema, and the full React frontend — effectively the whole system description that later became this project's architecture.

The next day, `2eb1f9a` (2026-02-18) introduced the CampaignOrchestrator's 6-layer pipeline (Governance Gate → Target Intelligence → Strategy Planning → Execution → Verification → Intelligence Harvest) as the structured spine that would coordinate everything built the day before.

Almost immediately, `7243f68` (2026-02-19) went back and fixed the gaps the first pass had left: `/api/hunt/*`, `/api/bounty/*`, and `/api/orchestration/*` were completely unauthenticated; `PATCH /bounty/programs/:id` allowed mass assignment; the session store was in-memory (wiped on restart); and HunterEngine had `targetId`/`huntSessionId` hardcoded to `1` rather than threading real DB-inserted IDs — meaning campaign-scoped queries were silently broken. This commit also filled in 9 solver classes (LFI, RFI, XXE, CORS, CSRF, auth bypass, misconfig, RCE, info disclosure) that had been empty stubs in the registry, and wired the RL/ROI feedback loops that the initial build had left as stubs.

### The April correction: closing gaps from external review

After a roughly seven-week gap, `6b7356c` (2026-04-11) addressed "three architectural gaps from external review" — the record doesn't say who reviewed it, but the fixes are concrete: inconclusive hypotheses (confidence 0.2–0.7) are now retried up to twice with a rotated tool instead of being dropped; ROI calculations blend global base payouts with a program's own historical payout/success-rate data; and a per-domain queue caps concurrent solvers at 2 req/s so parallel solvers hitting the same host don't hammer it.

The same day, `2891066` (2026-04-11) tackled three separate reliability problems: Ollama calls previously had no circuit breaker, so a dead model would make every call wait a full 120s to time out — a breaker (CLOSED/OPEN/HALF_OPEN, trips after 3 failures, 30s recovery) now fails fast instead. Budget enforcement was previously coarse; a pre-flight check was added before every tool invocation so runs stop as soon as budget is exhausted rather than after the fact. And verification evidence (Playwright screenshots) was being stored as base64 blobs directly in the findings table — moved to files on disk to stop DB bloat.

### May 22: performance and fairness fixes

After another six-week gap, a short cluster landed: `f29a168` (2026-05-22) added a Playwright UI sweep script with no further explanation. `1e62700` (2026-05-22) fixed three "strategic bottlenecks": the hunt loop never yielded to the event loop between phases, so concurrent hunts and socket callbacks could starve during model inference (fixed with `setImmediate()`); prompts grew unbounded over long hunts, so an `ObservationCompressor` now condenses old observations into a compact state vector; and every scope check re-ran an 8-pillar validation, so a 5-minute TTL cache was added for repeated hostnames. `b28ea96` (2026-05-22) is a docs-only update describing those three changes.

`ae7de99` (2026-05-22) is worth calling out for its explicit reasoning: the autonomy gating logic previously capped the *entire* platform's deployment mode at "supervised" if any single domain scored low — even if that domain (e.g., `exploit_chain_depth`) was structurally hard to score well on regardless of actual skill. The fix introduces a per-domain "natural ceiling" so a domain sitting near its realistic maximum reads as high-autonomy instead of being penalized for a ceiling it can't exceed. Safety-critical domains (scope adherence, false-positive rate) keep a ceiling of 1.0 — no forgiveness — while composite scoring and regression alerts still use raw, unadjusted scores so problems aren't hidden by the normalization.

### May 23: a day devoted to state consistency

`6aa5868` (2026-05-23) is a single commit fixing seven distinct state-consistency risks identified across the codebase: missing graph-event wiring for verified/rejected findings, a get-then-update race in the reinforcement store (replaced with an atomic `INSERT … ON CONFLICT`), a cold dedup cache on restart (now preloads the last 500 confirmed hashes), non-idempotent report generation, mission memory that only lived in `/tmp`, unbounded temporal-decay history, and a findings counter that could drift from the DB. `db1238313` (2026-05-23) followed up with four more "structural reliability" fixes: mission memory moved from filesystem snapshots to a real DB table with upsert semantics; graph reconciliation made idempotent via a `verificationId` first-write-wins guard; Playwright moved off the main event loop into a `worker_threads` worker; and orchestration gained a resume path so a crashed campaign could pick back up without double-billing already-confirmed findings through the verification pipeline again. `7fa8bfa` (2026-05-23) documents both.

Two more targeted fixes followed the same day. `fb2dbc0` (2026-05-23) addressed "exploration suffocation" — the RL-driven tool selector was increasingly ignoring novel tools once historical data accumulated against them, so a 15% epsilon-greedy override was added to force occasional exploration of under-tried techniques — alongside a fix for targets that hard-banned the platform's IP: after 5 consecutive 403s, a 1-hour ban is recorded and further probes against that target are skipped rather than hung. `e7f0a3f` (2026-05-23) refined both of these: the ban-detection canary previously only recognized HTTP 403, but a network-level block (ECONNRESET, ETIMEDOUT, etc.) silently drops the connection instead — now treated as a ban signal too. Separately, the sparse-data ROI prior was changed from a hard cliff (flat 0.25 below 5 attempts) to a smooth Beta(1,3) posterior, removing a discontinuity at the 5-attempt boundary. `73b8666` (2026-05-23) documents these. `cbf8c2e` (2026-05-23) added the backend for the XBOW CTF benchmark the frontend already called — Docker-container-per-challenge with flag pattern matching.

### May 29: usability, local models, and a tool ecosystem

`3d627c9` (2026-05-29) exempted localhost from all three rate limiters so local dev didn't get hit by the 15-minute window cap. `6b03a69` (2026-05-29) fixed a genuinely nasty bug: the auth interceptor redirected to `/login` on every 401 — including while already on `/login` — creating an infinite reload loop that hammered `/api/auth/me` and exhausted the rate limiter, making login itself unusable. `384bd19` (2026-05-29) added auto-detection of local LLM runtimes (Ollama, LM Studio, Jan, LocalAI, vLLM) with a runtime model selector, and `9375dae` (2026-05-29) added the always-present floating AI chat bubble. `7187385` (2026-05-29) introduced a full custom tool registry — CRUD for arbitrary CLI tools with a shell-metacharacter guard and private-IP scope guard on the test-fire endpoint — so hunters could register their own probes without touching code. `88ad803` (2026-05-29), auto-discovering 100+ Kali tools with zero config, has no body beyond its title.

### May 30: hardware tuning and reasoning visibility

`10a449a` (2026-05-30) is a bare title ("fix: chat model selection — respect user choice, return full model tag"). `ec6f2b0` (2026-05-30) tuned the whole platform for a specific machine (RTX 4070 Super / i7-14700KF): GPU offload settings, solver concurrency raised 3→8, and hunt limits (observations, hypotheses, probes, budget, timeouts) all raised substantially — a clear signal the author was now running longer, heavier hunts on dedicated hardware rather than a laptop. `d14cf6f` (2026-05-30) instrumented every AI call in HunterEngine to surface its reasoning live in the activity feed as collapsible cards, including parsing DeepSeek-R1's `<think>` chain-of-thought separately from its final answer. `e87b632` (2026-05-30) added a writeup/CVE scraper (HackerOne disclosed reports + NVD) feeding into the RAG context, plus a BFS deep-crawl replacing the old single-page crawler.

### May 31: a security remediation pass

`83218c6` (2026-05-31) fixed four distinct issues with explicit root causes: Settings-UI config changes to Ollama/HackerOne endpoints weren't taking effect for in-flight hunts because several modules read `process.env` directly instead of the runtime config (and mutating `process.env` would have polluted global state); the scope-verification cache had a 5-minute TTL, meaning a scope change via the API could be bypassed for up to 5 minutes (TOCTOU) — cut to 30s plus explicit invalidation on program update; the temporal-decay engine's per-key cap of 500 could reach 250K objects in the worst case, tightened to 100/50K; and SimHash dedup didn't include sorted query-parameter names in its anchor, so `?q=` and `?query=` with identical payload text could produce colliding hashes and bypass dedup. `49a7c85` (2026-05-31) documents these plus the earlier May 30 work.

`0a44da6` (2026-05-31) is the biggest single security/correctness sweep in this chunk, grouped into five buckets. The critical-security bucket alone: `/nuclei/run` was building a raw shell string for `execSync` (command-injection RCE) — replaced with `execFile` and an args array; the workspace file store had a path-traversal hole via `req.params.id`; `GET /settings` was returning secret values in plaintext; and `SESSION_SECRET` wasn't required in production. The correctness bucket fixed a nuclei DB query that was always-true regardless of its filter, and added a unique index so the 24h scrape job stopped accumulating duplicate rows. Efficiency and frontend-memory buckets capped retained activity events and moved several blocking `execSync` calls to async. `4facc9d` (2026-05-31) added a "CMD sentinel" letting the AI chat launch Kali tools directly on the operator's machine from natural-language requests. `badb296` (2026-05-31) closed what the commit calls the "Shared Infrastructure Illusion": a CNAME chain could pivot through a shared SaaS platform (Salesforce, Shopify, Zendesk, etc.) while still passing scope checks, since only the first hop was validated. The fix follows the full CNAME chain (up to 10 hops) and classifies the terminal host as block/warn/ok against a list of known multi-tenant platforms and CDNs, and feeds a `SHARED_INFRA_DETECTED` signal back into the meta-reasoning layer — closing what had been a one-way signal broadcast.

### June 1: target fragility detection and the attack graph

`0c13bd5` (2026-06-01) built a 3-phase "reaction matrix" that clamps hunt aggressiveness when a target shows signs of struggling (latency spikes, 5xx cascades, consecutive failures) — hard clamp, soft clamp, then monitor-only, with recovery gated on consecutive normalized cycles so a single good reading can't fake recovery on a still-failing target. `b867640` (2026-06-01) closed what it explicitly calls a "brain/nervous-system disconnect": the fragility clamp above was throttling HTTP execution, but the strategy layer kept generating aggressive hypotheses anyway, burning LLM budget on tasks that would just get dropped — fixed by having the dispatcher fall back to a static passive playbook while a hunt is flagged fragile. `7fd39cf` (2026-06-01) turned the previously passive attack-graph audit log into an active input to tool selection: new pivot-edge mappings (e.g., SSRF → internal network, SQLi/LFI → credential dump) plus a write-through cache to avoid recomputing PageRank/path-enumeration on every tick, feeding a +0.25/+0.15 score boost to tools on high-value attack paths. `f0ed631` (2026-06-01) rendered that graph's exploit chains into the generated markdown reports. `2779a9b` (2026-06-01) documents the four Jun 1 features. `1c4330e` (2026-06-01) is the largest commit of the day: a dynamic egress route allocator (proxy pool with per-target health scoring, burns a route on hard-ban), and a "learning-resistant governance immunizer" — a SHA-256-signed frozen policy baseline that is hash-verified on every startup, with a tiered WARN → CLAMP → FULL_RESET response if runtime governance drifts more than 10/20/40 percentage points from that baseline, explicitly designed so the governance system's own learning loop can't quietly erode its safety thresholds over time.

### June 2: wiring the UI to reality, and the first tests

`bb9be1e` (2026-06-02) surfaced the new egress routing in the UI. `722d53d` (2026-06-02) fixed a real, clearly-diagnosed bug: HuntConsole started hunts via the REST endpoint, but that route never wired Socket.IO listeners onto the resulting engine, so all ~30 `hunt:*` events fired into a Node EventEmitter with nobody listening — the activity feed silently received nothing. The fix introduced a shared `activeHuntSessions` map and a `wireHuntEngineToSocket()` helper. `6ab466a` (2026-06-02) diagnosed a related flicker bug: a hard `window.location.href` redirect on every 401 caused a visible INITIALIZING→login→INITIALIZING flash loop on first load — replaced with a soft-navigation custom event. `00f3fdc` (2026-06-02) is a notable design realization: the platform had been writing every strategy pivot decision to a `decision_journal` table but never reading outcomes back into future decisions, making it "stateless across restarts despite recording all the data needed to learn" — a `StrategyWeightLearner` was added to close that loop with a Bayesian weight nudge based on recorded outcome scores. `13aeab4` (2026-06-02) is the first meaningful test suite in the project's history — the commit message states plainly that zero tests existed for the 4-layer verification pipeline, "the highest-risk code path in the platform since a bug there causes false-positive submissions to bug bounty programs," and adds 48 tests across SimHash and VerifierAgent.

The rest of June 2 was mostly XBOW benchmark work and chat polish: `834407f` replaced inert stub challenges with 5 self-contained Node.js vulnerable apps (no Docker needed) so flags could actually be captured; `a253d40` then wired the benchmark to the real 104-challenge `validation-benchmarks` repo via Docker Compose; `35e5cc3` synced the UI to a backend field rename with no further explanation; `32fecc7` fixed a root-caused bug where XBOW challenge IDs didn't exist as lab profiles, so the hunt was created directly against the spawned challenge's port instead of going through the profile lookup. `c3141dc` (2026-06-02) fixed three compounding chat bugs (circuit breaker never recovering after Ollama came up late, a 30s client timeout too short for cold model loads, and stale model-status checks) — worth noting as a case of three separate bugs conspiring to produce one user-visible symptom. `cabc970` (2026-06-02) added markdown rendering to chat responses. `55a78ff` (2026-06-02) added a script to expand the 1,785-entry prompt dataset using the Anthropic API.

### June 3: local labs, an embedded terminal, and the Claude Code bridge

`afb11a2` (2026-06-03) removed a real usability blocker: Hunt Console, Orchestration, and Hunter all refused to launch unless a HackerOne/Bugcrowd program was selected, making it impossible to point the platform at Juice Shop or a local CTF box — fixed with a synthetic "Custom / Local Lab" program (id `-1`) auto-created on first use, plus a ScopeGuard carve-out so a bare `"*"` scope skips DNS-rebinding checks. `c2f48ed` (2026-06-03) added a full embedded terminal (xterm.js + node-pty) piped over the existing Socket.IO connection, explicitly so `claude` could be launched from inside the platform with full access to project state. `0b37555` (2026-06-03) is the commit that effectively created this project's meta-loop: `ClaudeBridge` invokes `claude --print -p` as a subprocess for hard reasoning tasks (with the ModelRouter falling back to Ollama if the CLI isn't present), `context-writer.ts` starts writing live hunt state to the `context/` files, and a comprehensive `CLAUDE.md` is added so Claude Code has "full situational awareness from the moment it opens" — this is the direct origin of the `context/hunt-live.json`, `claude-tasks.jsonl`, and CLAUDE.md structure this very journal was written under. `3bc6a8c` (2026-06-03) added a `model_selection` RL domain so the router could learn, per vuln class, whether Claude or Ollama produces more confirmed findings, and route accordingly after enough samples. `3bd210f` (2026-06-03) added a live hypothesis stats bar, per-hypothesis model-source badges, and RAG injection of framework-specific attack methodology hints pulled from the prompt knowledge base.

### June 4–6: token efficiency, vision, ZAP, and the run-up to dataset day

`95945ed` (2026-06-04) added a compact digest file and an alerts stream specifically so "Claude Code [could] observe long hunts without burning tokens on full JSON reads" — a direct concession to the cost of the Claude-bridge loop introduced the day before. `48fc257` (2026-06-04, author `kali`, not the usual `Claude` bot identity — the first commit in this era not authored via a Claude session) fixed terminal PTY persistence across panel switches and made a couple of engine tweaks (CORS wildcard detection, swapping dalfox for nuclei on XSS scans). `6ce5cd6` (2026-06-05) added a proper nuclei JSONL parser (replacing a minimal JSON.parse loop), a failure-prediction engine that pre-skips hypotheses with >82% predicted failure probability, an effort-scaling module that sets probe/iteration budgets from target complexity, and fixed the XBOW deserialization challenge which had been GET-only and therefore unsolvable via RCE. `cdb4e0c` (2026-06-05) split model auto-detection into LLM/embed/vision categories and wired vision-model screenshot description into both hunt observation and Layer 4 verification. `40987197` (2026-06-05) added OWASP ZAP as a first-pass prober and fixed a real latent bug: the blind XXE prober's async lambda was missing its IIFE call `()` at the end, meaning it had been silently never executing on any hunt. The era ends at `ed21dc7` (2026-06-06), which adds the dataset-expansion (1,785 → ~10,000 Q&A entries via batched `claude -p` calls) and fine-tune export scripts that feed into the next era's dataset-generation day.

### Thin record

- `f29a168` (2026-05-22, verify-ui.js script) and `88ad803` (2026-05-29, Kali tool catalog auto-discovery) — feature-sized commits with no body beyond the title; no stated rationale for the design choices inside.
- `10a449a` (2026-05-30, chat model selection fix) and `35e5cc3` (2026-06-02, XBOW UI field-rename sync) — one-line bug-fix titles with no explanation of how the bug was found or why the chosen fix was correct.
- The `docs:` commits (`b28ea96`, `7fa8bfa`, `73b8666`, `49a7c85`, `2779a9b`, `9520315`) are all README updates that restate what shipped; none add new reasoning beyond what's in the feature commits they follow.
- Package-lock-only commits carry zero rationale by nature.
- **The two multi-week silent gaps — 2026-02-19 to 2026-04-11, and 2026-04-11 to 2026-05-22 — have no commits at all bridging them; whatever design discussion or exploration happened in between (if any) left no trace in this history.**

---

<a id="jun-6-7-2026"></a>

## 2. Jun 6–7 2026: Taming the Overnight Datagen Pipeline, Then a Visual-Tagging Detour

This chunk (126 commits, `4a1ac81`..`60a76d7`) is dominated by unattended, background RAG-corpus generation — three JSON prompt files (`access-level-scenarios.json`, `api-auth-chains.json`, `attack-paths.json`) being grown batch-by-batch via repeated `claude -p` subprocess calls. Buried in the first few hours of Jun 6 is a real engineering thread about making that background process survive unattended, plus a same-day detour to add a new "visual tagging" observation feature.

### Fixing the unattended datagen loop (early Jun 6)

The run opens with a cluster of fixes addressing the same underlying problem: a `claude -p` subprocess loop that generates dataset batches was colliding with the repo's git-state "stop hook" (a hook that checks for a clean working tree before allowing a session to stop).

- `4a1ac81` (2026-06-06, 00:29) sets `SENTINEL_DATAGEN=1` on the subprocess calls so the stop hook skips its git-cleanliness check during background generation, and switches the generation model to Haiku for speed/cost.
- `90c7672` (2026-06-06, 00:30) is a checkpoint commit whose body explicitly says the expansion run was **paused** because of the stop-hook conflict, with a note that it would resume using an auto-commit-per-file approach.
- `2733460` (2026-06-06, 00:30) implements that approach: commit and push each file immediately after it hits its target entry count, so no long-lived uncommitted state exists during the run.
- `921fe1e` (2026-06-06, 01:02) tightens this further — commit after every batch, not just after a file finishes, closing the same class of "stop hook sees dirty tree" problem at finer granularity.
- `c1f67d6` (2026-06-06, 01:09) attacks a different failure mode, subprocess timeouts: batch size cut 30→15, example `expected_answers` trimmed to 120 chars to shrink prompt size, subprocess timeout raised 240s→360s, inter-call delay bumped to 8s.
- `c15303c` (2026-06-06, 09:39) escalates the timeout mitigation with an adaptive strategy: default batch size reduced to 10, and each retry after a timeout halves the batch size (down to a floor of 3) so the generator always eventually succeeds rather than looping on a batch too large to finish in time.

Together these five commits read as a single debugging session: get an autonomous long-running generation job to coexist with a hook designed to guard against ending a session with uncommitted work, then fight subprocess timeouts by shrinking work units adaptively.

### Visual-tag observation feature (mid-day Jun 6)

Two feat commits interrupt the data-batch grind with an actual product feature:

- `9c75ef1` (2026-06-06, 09:54) adds a Playwright-injected `VISUAL_OBSERVER_SCRIPT`, run via `addInitScript` before any page JS executes, that watches crawled pages for DOM mutations, XHR/fetch calls, JS dialogs (alert/confirm/prompt), cookie names visible from JS (an HttpOnly-missing signal), console errors, and static-valued hidden form fields (a CSRF heuristic). The design rationale given: tags are text-only so the 3B local model can reason over them directly without needing a vision model. A mapping function (`visualTagsToHypotheses()`) converts tag patterns into weighted hypotheses (e.g. an XSS dialog → 0.92 confidence, a SQL-error DOM mutation → 0.75, a CORS-related console error → 0.60).
- `e8d5dc0` (2026-06-06, 10:04) wires this feature into the dataset pipeline: a new seed file `visual-tag-reasoning.json` (30 entries covering XSS/SQLi/CSRF/IDOR/info-disclosure/broken-auth/SSRF/SSTI) is registered in the expansion config with a target of 300 entries, and the fine-tune export script is updated to emit a "Browser Visual Tags:" section in training examples when the field is present.

### Bulk RAG-corpus growth

The remainder of the chunk is almost entirely mechanical batch commits growing three prompt files, each following the pattern `data: <file>.json batch N → M entries`, with no per-batch rationale:

- `access-level-scenarios.json`: batches 4–43, run mostly across Jun 6 (01:12 through 23:58), growing from 217 to 600 entries, with a multi-hour gap between roughly 10:09 and 22:53 (likely a paused/resumed session).
- Alongside it, `16e492c` (2026-06-06, 07:04) is a one-off milestone commit adding `finetune-dataset.jsonl`, a 3.1 MB ShareGPT-format export of 1,932 training conversations generated from all 17 prompt files, intended for Unsloth fine-tuning of Qwen2.5-3B-Instruct.
- `api-auth-chains.json`: batches 1–52, run Jun 7 00:01–02:05, growing from 110 to 620 entries.
- `attack-paths.json`: batches 1–24, run Jun 7 02:05–02:43 (end of this chunk), growing from 210 to 441 entries.

This is mechanical growth with no per-batch reasoning recorded — each commit is a bare one-line progress marker.

### Thin record

- All ~110 `access-level-scenarios.json batch N → M entries` commits: no body beyond the entry count, no explanation of what scenarios were added or why.
- All ~52 `api-auth-chains.json batch N → M entries` commits: same — bare progress markers only.
- All ~24 `attack-paths.json batch N → M entries` commits ending this chunk: same, no rationale recorded.
- The multi-hour gap in the `access-level-scenarios` run between roughly 10:09 and 22:53 is unexplained in the commit record — no commit marks why the session paused or resumed.

---

<a id="jun-7-8-2026"></a>

## 3. Jun 7–8 2026: Dataset Grind, Real-CVE Scraping, and the Phase 0 Recon Pipeline

This chunk is the tail of a marathon single-day (into early next-day) session, running from 02:44 UTC on Jun 7 through 00:51 UTC on Jun 8. Most of the commit volume is RAG-corpus batch grinding, but three real engineering threads are buried in it: a switch from synthetic to *real* vulnerability data via NVD/OSV scraping, a new training-data category for every model call site in the engine, and a genuine architecture addition (passive OSINT recon firing at hunt start).

### Bulk data batches (collapsed)

- `attack-paths.json` batches 25→50, `c481fa5`–`c141e18` (Jun 7, 02:44–03:26), taking the file from 451 to 700 entries. No bodies beyond the batch counter.
- `bounty-patterns.json` first-pass batches 1→35, `2dc578a`–`e12a1a8` (Jun 7, 03:56–05:11), taking the file from 110 to 451 entries. No bodies.
- `chain-scenarios.json` batches 1→30, `ebdd5f8`–`491dea9` (Jun 7, 05:32–06:34), taking the file from 260 to 529 entries, interleaved with the feature commits described below. No bodies.
- `bounty-patterns.json` second-pass batches 1→7, `9eaf217`–`5a832a7` (Jun 7 16:27–20:33), taking the file from 461 to 514 entries. No bodies.

### Real CVE/advisory scraping replaces synthetic-only data

`780d63b` (2026-06-07) added an HF dataset importer pulling airoboros-3.1 (hacking category) and a CyberNative cybersecurity set, deduplicating into a ShareGPT-format supplement file that the export script auto-merges.

That didn't survive contact with reality: `092918d` (2026-06-07) found the CyberNative and SecQA datasets didn't actually exist on HF, so the importer was rewritten to keyword-filter *all* categories of airoboros-3.1 plus WizardLM_evol_instruct_V2_196k, yielding roughly 376 filtered entries.

`ef054fc` (2026-06-07) went further and added a real vulnerability scraper (`scrape-bounty-data.py`) pulling actual CVE/advisory data from NVD (25 web CWEs), OSV.dev (50 web packages), and optionally a local GitHub advisory-database clone — converting each into a bug-bounty-style Q&A (attack chain, impact, remediation). Built resume-safe via a progress JSON since the scrape was expected to run long/in background.

The resume logic had a real bug, caught and fixed in `6f62e6f` (2026-06-07): CWE-79 (XSS) had been falsely marked complete after a mid-run HTTP 429 set its `totalResults` field to the already-seen count, silently truncating ~26k CVEs. The fix wires in `NVD_API_KEY` support (10x rate limit, 2000 results/page vs unauthenticated 1/page-with-6.5s-delay), adds proper 429 retry with 35s backoff instead of dropping pages, and resets CWE-79's resume index so the remaining XSS CVEs actually get scraped on the next authenticated run.

Progress was narrated in checkpoint commits rather than code changes, ending with `729e31b` (2026-06-07) confirming the full authenticated run completed — all CWEs done, ~27k XSS + ~12k SQLi CVEs included, for 46,693 total Q&A pairs. The resulting `bounty-scrape.jsonl` was 131MB and gitignored rather than committed.

Related hygiene: `0c07c63` (2026-06-07) added the generated JSONL files (`finetune-dataset.jsonl`, `hf-supplement.jsonl`, `bounty-scrape.jsonl`) to `.gitignore` since they're large regeneratable artifacts, and `11fd8fb` immediately removed the copies that were already tracked before the ignore rule existed. `9632332` (2026-06-07) later did the same cleanup for a stale `.expand-progress.json` once that expansion run had finished.

### New training-data categories for the engine's actual call sites

`b0a456f` (2026-06-07) added 52 seed entries of "platform-specific schema training data" explicitly modeled on every one of the six JSON/format contracts the hunt engine sends to the local Ollama model: HunterEngine's hypothesis JSON, SolverPool's endpoint-task JSON, VerifierAgent's layer-4 confirm/reasoning JSON, ReportGenerator's summary/impact JSON, the chat `[CMD:...]` sentinel format, confidence calibration, and multi-iteration pivoting (avoiding repeated rejected hypotheses).

`df6979d` (2026-06-07) added a separate 26-entry "bubble chat" training set for the FloatingChat operator interface — tool-output interpretation, payload crafting, finding escalation chains, bug-bounty strategy, live-hunt-state analysis, report writing, and recon methodology — explicitly called out as distinct from the CMD-sentinel training since it covers the full conversational experience rather than tool-execution mechanics.

`f49adcda` (2026-06-07) added a 16-entry "web intelligence gathering" (WI-*) set covering OSINT recon techniques (crt.sh, Shodan/Censys, Wayback CDX, GitHub dorking, JS bundle analysis, DNS/ASN discovery, a reusable `ResilientScraper` pattern).

### Phase 0: passive recon becomes a real pipeline, not just training data

`56cdfa67` (2026-06-07, 15:40) turned the OSINT training-data theme into an actual engine feature: a new `ReconRunner` (`server/src/lib/recon/recon-runner.ts`) that fires concurrently with the very first `observe()` call at hunt start, hitting crt.sh (certificate transparency) and the Wayback Machine CDX API to build a real attack surface before the model ever hypothesizes. `HunterEngine` launches the recon promise at `startHunt()`, injects it as a structured `attack_surface` Observation when it lands, and — if it's still running by `hypothesize()` — waits up to 8 seconds before proceeding so the model can target specific discovered subdomains and historically-interesting paths instead of just the root URL.

### expand-dataset.py's hang problem, fixed twice

`23f85ebc` (2026-06-07, 20:29) diagnosed why the dataset-expansion script kept stalling: `subprocess.run(timeout=360)` sent SIGTERM to the `claude` CLI, but its child processes kept pipes open and the parent never actually died, causing indefinite hangs. First fix: switch to `Popen` with `start_new_session=True` to isolate a process group, `killpg(SIGKILL)` the whole tree on timeout (not just the parent), cut the hard timeout from 6 minutes to 90 seconds, and cap retry backoff at 30s.

That fix wasn't sufficient — `7ea214d` (2026-06-07, 22:52) found that `communicate()` itself blocks when CLI grandchild processes hold pipes open, making Python's own `TimeoutExpired` unreliable. The real fix: run `communicate()` on a daemon thread, `join()` from the main thread for the timeout duration, and `killpg(SIGKILL)` the process group if the thread hasn't returned — a mechanism guaranteed to unblock regardless of pipe state, rather than relying on subprocess-level timeout semantics.

The chunk closes with `68bb3c7` (2026-06-08, 00:51), a one-line bump of `CALL_TIMEOUT` to 150s "for slow API periods" — a small tuning commit with a one-line reason but no deeper explanation of what triggered it.

### Thin record

- All `attack-paths.json` batch commits (batches 25–50): no bodies beyond the batch counter.
- All first-pass `bounty-patterns.json` batch commits (batches 1–35): no bodies.
- All `chain-scenarios.json` batch commits (batches 1–30): no bodies.
- All second-pass `bounty-patterns.json` batch commits (batches 1–7): no bodies.
- `68bb3c7` (CALL_TIMEOUT bump to 150s): states the symptom ("slow API periods") but not what was observed or measured to arrive at 150s specifically.

---

<a id="jun-8-21-2026"></a>

## 4. Jun 8–21 2026: Claude Becomes the Real Tier-0 Brain, Then the Verification Pipeline Gets Torn Apart and Rebuilt

This is the era where the platform stopped treating Claude as an occasional CLI fallback and made it the primary reasoning engine, then spent two solid weeks discovering — and fixing — how many of its "closed loops" (learning, verification, RL credit, budget control) were actually silently dead. A late-chunk thread of postmortems reads almost like a live-fire incident log: a real hunt against Juice Shop turned up false positives, false negatives, dead learning tables, and race conditions, and each was chased to a root cause rather than patched blind.

### Claude SDK as tier-0 (Jun 8)

The dataset-expansion pipeline kept stalling on subprocess/pipe-hangs, so `35c952e` (2026-06-08) rewrote `expand-dataset` to call the Anthropic SDK directly instead of shelling out to `claude -p`, removing process-group and git-lock issues. A companion watchdog (`01d6618`, 2026-06-08) auto-restarts the expander when its log goes stale, since manual restarts after git-lock collisions had become routine.

The bigger move was wiring `ClaudeClient` — a direct Anthropic SDK wrapper — as the tier-0 reasoning engine, attempted three times in one day (`8bb25f3`, `3fb9931`, `077b0c3`, all 2026-06-08) after apparently being lost across a rebase; the final version routes `reason()` to Sonnet and `oneShot()` to Haiku, gives each hunt session its own conversation thread for cross-iteration memory, and falls back to the old CLI bridge and then Ollama. The same session added `SynthesisAgent` (asks Claude to find attack chains across multiple confirmed findings) and `LogicExploitAgent` (Claude drives Playwright via tool-use to confirm stateful exploits like IDOR/auth-bypass that scanners can't verify). `3e39fff` (2026-06-09) upgraded LogicExploitAgent into a more deliberate "map normal state, then deviate surgically" attacker with tools for cookie forging, mid-flight request interception, hidden-element scrubbing, dual-account IDOR testing, and race-condition firing — replacing what had been aimless UI wandering. `d22a5bc` (2026-06-09) added AI-written reproduction steps from raw HTTP evidence, secondary-account auth for dual-context IDOR, and a persistent (not tmpdir) video PoC directory.

### Security hardening and closing dead loops (Jun 9)

`1a1fd1a` (2026-06-09) fixed three real holes in one pass: Socket.IO had no auth at all (any client could spawn PTY shells or start hunts), SolverPool's sqlmap call used shell string interpolation of an attacker-controlled endpoint (command injection), and custom-tool templates substituted URLs into a whitespace-split command string (argument injection). All three were fixed with session-gated `io.use()`, `execFile` with arg arrays, and a proper tokenizing template builder.

`db3d214` (2026-06-09) traced why the cross-hunt learning flywheel was entirely inert: three tables (`decision_journal`, `threshold_history`, `cortex_signals`) that the RL/journal code depended on were never created, and separately `HunterEngine` never initialized a meta-reasoner hunt state, so the evaluation step aborted immediately and journaled nothing — both were fixed together to close the loop end-to-end. `8aea91d` (2026-06-09) fixed several related leaks: SolverPool was resetting the request budget to zero instead of pre-charging (double-spending the quota), the verifier's AI-down fallback wrongly required both L2 and L3 instead of distinguishing "L3 ran" from "L3 unavailable," WAF-bypass stubs were firing raw payloads while claiming to be evasion variants, and an `X-Forwarded-For` spoof always ended in a detectable `.0.1`. `8aee840` (2026-06-09) stopped logging a cracked JWT secret in plaintext and added a startup check reporting which Kali tools are actually installed. `aa81909` (2026-06-09) discovered Haiku had been built but never called (100% of spend was Sonnet), wired real model tiering, added a per-hunt LLM call budget, and made the previously write-only tool-success-rate data actually drive tool selection via a new `ReinforcementWiring.getBestTool()`.

### Closing the RL/synthesis feedback loops (Jun 9–11)

A run of tightly-scoped fixes chased miscalibrated or dead feedback signals: `47b06fb` (2026-06-10) added cross-finding synthesis proper (Claude reasons over combined confirmed findings for chain hypotheses); `4cb05ec` (2026-06-10) added log-secret redaction and fixed SolverPool bypassing the per-hunt LLM budget; `7425651` (2026-06-10) fixed L6 calibration reading the engine's pre-verification confidence instead of the verifier-adjusted value; `9689927` (2026-06-10) found the Brier calibration was only scoring confirmed findings, never rejected ones, making the RL systematically overconfident — added the missing `confirmed=false` arm; `071f338` (2026-06-10) found synthesized chain hypotheses carried no `chainedFrom` provenance, so the RL was learning to ignore chaining entirely because credit landed only on the closing tool. `9e43623` (2026-06-11) is the second act of the dead-table bug: even after adding `decision_journal`/`threshold_history` earlier, they still weren't in the boot DDL, so the whole loop was still dead-on-arrival; added both with the exact columns/indexes the code needed. `bf766b9` (2026-06-11) then replaced silent `catch(_err){}` blocks across the four core learning files with `logger.warn`/`debug`, on the reasoning that the same silent-failure pattern was exactly what had kept the tables dead for months without anyone noticing.

### Dead code removal and the verifier overhaul (Jun 13–14)

`9598aef` (2026-06-13) deleted ~600 lines of governance-adjacent modules (`desktop-agent-governance.ts`, `governance-proxy.ts`) that were instantiated but never actually called by any business logic — the real enforcement already lived in `command-executor.ts` and `scopeGuard`.

A dense verifier-correctness sequence followed. `28d5066` (2026-06-13) fixed the XSS browser oracle: it had a fallback that treated payload presence in page content as confirmation when no dialog fired within 2 seconds, which both false-positived on inert/encoded reflections and false-negatived on DOM XSS where the payload gets transformed — replaced with an execution-only, event-driven oracle using an exposed sentinel function. `7188f1a` (2026-06-13) added sentinel-calling XSS payload variants so DOM execution could be proven the same way, though it explicitly flagged that pure DOM XSS never reaching the HTTP layer still can't reach the browser oracle. `39111a0` (2026-06-13) found the verifier was being handed a numeric target ID instead of a URL, so every L2/L3 reprobe failed structurally regardless of vuln class — fixed by persisting and threading a real `affected_url`. `dd3d1b9` (2026-06-13) replaced the verdict logic's flat "L2 required, L4 ignored" rule with per-class oracle authority (browser-verifiable classes require L3 execution proof; HTTP-observable classes trust L2+L4), and fixed a concurrency bug where L4 verification calls with no session ID shared one thread and interleaved/corrupted each other's message arrays. `cd3b388` (2026-06-14) found BlindXXEProber was raising findings on XML parser error text alone (normal parser rejection, not evidence of XXE) rather than requiring an actual OOB callback or metadata leak. `e4974d9` (2026-06-14) discovered widespread frontend/backend drift in the Bounty panel — six endpoint families were never mounted at all — and wired them up against real data sources rather than stubs.

### Tool integrations, chat, and access controls (Jun 14–15)

`03cf96c` (2026-06-14, author `kali`) wired tplmap, corsy, nosqlmap, ssrfmap, xsser, jwt_tool, and smuggler into the engine as first-class tools, fixing two tools that had been silently pointing at the wrong binary (jwt_tool was proxying to nuclei; smuggler pointed at a nonexistent path). `c5c3a35` (2026-06-15) fixed wrong CLI flags for ssrfmap/nosqlmap auth injection that had been silently ignoring the auth header entirely. `0cc49ed` (2026-06-15) rewired the chat bubble to call `ClaudeClient.oneShot()` directly with live hunt context instead of routing through a generic model-router prompt that discarded the operator system prompt. `d5d5e57` (2026-06-15) extended the chat shell-command timeout to 5 minutes for package installs (the 30s default was killing `apt`/`pip` mid-download). `859e084` (2026-06-15) added auth-cookie/bearer-token injection threaded through every tool and HTTP probe. `41fecbc` (2026-06-15) added a tool preflight endpoint/UI so operators can see which of the 15 hunt tools are actually installed before launching.

### OOB, post-exploitation, and architecture docs (Jun 15–17)

`fb48a94` (2026-06-15) added interactsh-client as the primary out-of-band callback layer (with the local server as fallback), since the prior localhost-only OOB server meant blind XXE/SSRF/RCE could never be confirmed against real internet targets. `4f06ebb` (2026-06-17) added `PostExploitAgent`, running bounded, scope-guarded read-only probes after a finding is confirmed to demonstrate real-world impact for reports, only escalating severity upward on proof. Two commits (2026-06-17) added an ARCHITECTURE.md reference doc and then corrected several inaccuracies in it (verifier is post-hoc, not an inline gate; verdict logic is per-class not consensus) — also adding a 90s hard timeout to Claude SDK calls that could otherwise hang the hunt loop forever.

A second verifier deep-dive followed quickly: `f106595` (2026-06-17) found console-launched hunts bypassed the orchestrator's verification layer entirely, leaving findings permanently "pending," and separately found the manual verify endpoint passed a numeric ID as a URL; `6095ed0` (2026-06-17) fixed re-verification being falsely rejected as a duplicate because L1's dedup cache doesn't know the difference between "someone else already found this" and "you're re-checking your own finding." `d46f1af` (2026-06-17) is the key structural fix: stateful findings discovered by LogicExploitAgent (IDOR, auth_bypass, business_logic) were being voted on by a stateless single-GET L2 reprobe that structurally cannot reproduce multi-step/multi-identity exploits — added a third oracle-authority category so these classes route straight to L4 reasoning over the captured session instead. `f50d5a0` (2026-06-17) caught a sequencing trap in the fix before it: PostExploitAgent's severity escalation ran before verification completed, so unverified (and sometimes later-rejected) findings got inflated severity — deferred the write until a "confirmed" verdict lands. `0424268` (2026-06-17) then wrote regression tests for both fixes and refreshed six stale tests that still encoded the pre-refactor verdict model.

### Token pacing, circuit breakers, and live-hunt postmortems (Jun 17–20)

`74cdcf4` (2026-06-17) fixed four issues surfaced by an actual live hunt: a message-array race in `ClaudeClient.reason()` causing 400 errors under concurrent calls, a DB constraint violation on duplicate findings (fixed by a distinct `deduplicated` verdict), a token-bucket rate limiter to avoid blowing the org's per-minute input-token ceiling, and DB pool timeouts too aggressive for long hunts. `8fffdf8` (2026-06-17) found the backward-mode attack planner was passing `"account_compromise"` as a goal string that never matched the canonical `"Account Takeover"` path name, silently producing zero seeded hypotheses — added a goal-alias map. `1058886` (2026-06-18) found the token pacer from the prior commit only gated one of three Claude call paths, and its check-and-reserve wasn't atomic across concurrent callers, so unpaced callers still triggered 429s — serialized all reservations through one promise chain. `6f0b604` (2026-06-18) found the tool-selection decision engine had no visibility into circuit-breaker state, so it kept re-selecting a tool whose circuit had already tripped open — added a side-effect-free availability check consulted at decision time. `d8adfe4` (2026-06-18, kali) fixed hunt session foreign-key violations caused by defaulting to session ID 0 instead of the real DB session ID. `2464568` (2026-06-18) is a careful diagnosis showing that a probe's 120s timeout was being silently eaten by shared token-pacer queue wait time, so the agent sometimes burned most of its budget before doing any real work — fixed by tracking active-vs-pacer time separately and raising the hard safety wall to 360s.

`75e9594` (2026-06-19) found three compounding reasons L4 was rejecting valid stateful findings: L2's misleading bare-GET result was shown to L4 unfiltered, the raw HTTP evidence proving the exploit was truncated out of the evidence window, and a mock response field was hardcoded empty. `896d456` (2026-06-19, kali) captured a golden-run fixture set from an actual hunt session to lock in the stateful-oracle regression contract going forward. `d84d7aa` (2026-06-20) traced three separate reasons PostExploitAgent kept returning `steps:0` (empty URL guard on collection endpoints, treating a 401 on an auth-bypass probe as failure when it's actually proof the endpoint is gated, and a missing probe for race-condition class) and fixed all three against fixtures pulled from a real hunt.

### Concurrency, abort control, and UI trust (Jun 20–21)

`2db15d3` (2026-06-20, kali) added a 409 guard against starting a second hunt against a dirty target. `ca29402` (2026-06-20, kali) found the abort button was a no-op in two different ways — the frontend was hitting a DB-only stub route, and even REST-started orchestrators were never actually listening for the stop event. `7bfc9c1` (2026-06-20) closed the remaining gaps: abort wasn't propagating mid-layer (a stop during the long engine layer let it keep spending until the layer finished naturally), and single-flight protection only covered the REST hunt path, missing orchestrations, both socket launch paths, and the scheduled re-scan — unified into one shared registry all five launch paths reserve through synchronously. `25f16a8` (2026-06-20, kali) fixed nuclei parsing silently returning nothing because v3.8 renamed `-severity`/`-json` to `-s`/`-j`. `abec065` (2026-06-21) made the UI wait for backend confirmation (socket events or 200 responses) before flipping launch/stop button state, rather than optimistically updating on click. `fe9978d` (2026-06-21) closed out the PostExploitAgent gap for three classes with no probe at all, distinguishing "intentionally not demonstrable" (xss, sqli, rce, csrf, business_logic, etc., which aren't safe to auto-demonstrate) from genuine missing-probe gaps, and adding three new safe read-only probes (CORS reflection, missing security headers, rate-limit-bypass reachability).

### Thin record

- Several `data: bounty-patterns.json batch N` commits (2026-06-08) are bare dataset-size bumps with no rationale beyond the count.
- A handful of documentation-only commits (README/HANDOFF updates, a typo fix, `.gitignore`) from 2026-06-08/17 describe what changed, not why.
- Two moderately-described route/wiring commits from 2026-06-14/15 read as routine cleanup rather than a diagnosed bug.
- Two small NVD timeout/wiring tweaks (2026-06-18, kali) have only brief one-line justifications ("NIST servers are slow").
- One short, self-explanatory field-mapping fix (2026-06-17, kali) has no deeper investigation recorded beyond the immediate symptom.

---

<a id="jun-23-jul-8-2026"></a>

## 5. Jun 23–Jul 8 2026: Honesty Audits — Impact Verification, Scope Enforcement, and Tool Invocation All Get the Same Treatment

This era reads as a sustained campaign of "stop lying to yourself" fixes: several different subsystems (post-exploit impact assessment, corpus enrichment, verifier layers, rate limiting, Kali tool invocations, scope matching) each get audited for cases where the code was silently reporting a false signal — either a false positive dressed as confirmed, or a real negative dressed as a malfunction. Interleaved with this is a long tail of mechanical bulk data-loading commits, a decision to drop Ollama entirely in favor of Claude-only routing, and two rounds of "state lost on UI panel navigation" bugs.

### Post-exploit impact assessment honesty (Jun 23)

`aa39c97` (2026-06-23) diagnosed a confusing `steps:1, impactProven:false` pattern: it turned out to be a correct true-negative (a probe ran cleanly but `proves()` legitimately returned false) that looked like a malfunction because there was no way to distinguish it from other failure shapes. The fix added an explicit `demonstrationOutcome` enum (`impact_proven` / `attempted_not_proven` / `not_demonstrable`) so a clean true-negative is now legible instead of silent, plus broadened the info-disclosure secret matcher (PEM keys, AWS/Google/Slack tokens, JWTs, credentialed connection strings) since the narrow 4-shape matcher was part of the problem.

`fbaf43a` (2026-06-23) found that PostExploitAgent was throwing away the response body and HTTP log the confirming probe had already captured, and blindly re-fetching the URL instead — wasteful and sometimes wrong if the live state had changed. It added `tryWithCaptured()` to check captured evidence first, falling back to a live re-fetch only for probes that need live headers.

`49c1c61` (2026-06-23) closed a gap in that fix: `security_headers`' `proves()` checks for header *absence*, so passing it an empty headers object (from captured-body-only calls) made it always return true — every security_headers finding would report `impactProven:true` regardless of the real response. Added a `requiresLiveHeaders` flag on `cors` and `security_headers` so those probes always force the live re-fetch path.

### Scope ingestion and enforcement (Jun 23, Jun 27)

`961dda8` (2026-06-23) is a docs/handoff commit mapping the scope data flow end-to-end and flagging a hole: the Program Manager import form never sent scope/out-of-scope data to the backend, so UI-imported programs got `scope:[]` and ScopeGuard blocked everything. It called out a non-negotiable safety rule: path-level out-of-scope entries must be rejected server-side, never silently collapsed to a host-only pattern (which would make them inert against the hostname-only matcher).

`e726c18` (2026-06-23) implemented that handoff: wired in/out-of-scope textareas into the Import form, and added server-side rejection (400) of any out-of-scope entry with a path component, since the matcher at the time couldn't enforce paths and silently storing them would be a real scope-violation risk.

`cdf751a` (2026-06-23) fixed a subtler scope bug: entries stored with an `http://` prefix never matched the clean hostname extracted from incoming URLs, so the out-of-scope check silently missed and the in-scope wildcard let the host through — a real scope escape. Fixed by normalizing scheme and path off both sides before matching.

`8f5698c` (2026-06-27) revisited scope matching again, this time to fix the opposite problem: the governance gate was rejecting valid scoped localhost hunts. Two causes — a port mismatch (extractHostname drops the port but stored scope entries like `localhost:5000` kept it) and the DNS-rebinding guard blocking `127.0.0.1` even for non-wildcard scopes. This commit also added real path-level scope enforcement (host+path patterns restrict to that subtree, boundary-safe so `/api/Addresss` doesn't match `/api/AddressBook`), finally delivering the path-matcher the Jun 23 handoff had deferred.

### Corpus data ingestion (mechanical)

A long run of bulk data-loading commits landed the security Q&A/pattern corpus: `bounty-patterns.json` batches 12–20, `business-logic.json` batches 1–73, and `chain-scenarios.json` batches 1–32 — all one-line "batch N → M entries" commits with no reasoning in the body, purely mechanical corpus growth.

### Corpus enrichment: measure it, then turn it off (Jun 25)

`40572dc` (2026-06-25) is a $0 fixture-validation pass: it exercised the novelty/disclosure detector through a mocked-fetch seam using real HackerOne API shapes, and separately closed a gap where the report-export path dropped PoC payload and CVSS data a triager would need.

A four-commit arc then interrogated whether the corpus-enrichment feature (injecting security-pattern context into hypothesis prompts) actually helped:
- `155fd0e` (2026-06-25) added a `CORPUS_ENRICHMENT` toggle and an A/B test proving the verifier's verdicts were identical with enrichment on or off.
- `b4f54c0` (2026-06-25) noticed that "invariance" was trivially guaranteed by construction (the verifier never reads the toggle) rather than actually measured, so it built a second experiment feeding genuinely different enriched vs. non-enriched SolverResults through the verifier — confirming the mandatory XSS L3 gate holds structurally regardless of enrichment, and stating plainly that prompt injection of corpus content is not the same as proven quality improvement (that needs live model tokens to assess).
- `de872c0` and `8d9fd89` (2026-06-25) built out the feature properly: a per-hunt corpus toggle threaded end-to-end, and a relevance-scoring layer (cosine similarity with a 0.45 threshold, fail-open relaxation, keyword fallback) with UI visibility into which corpus entries were used and their scores.
- `18c5e89` (2026-06-25) then flipped the default to OFF: with a frontier model that already knows general web-vuln patterns, the corpus's keyword-fallback mode was assessed as adding noise rather than signal against untested/post-cutoff content. The toggle stays available for future use.

### WAF evasion wiring, export gating, and reliability fixes (Jun 25)

`d2c4817` (2026-06-25) wired two previously-inert subsystems into the live path: AI-generated WAF-evasion payload variants were being computed but discarded (now merged with library variants before the bypass loop), and the `autoAdjuster` stealth-mode brain was never actually being called after responses (now fed via `getDetectionSignal` after every probe).

`d047bb9` (2026-06-25) added a hard export gate: report export now requires a DB-backed `findingId` and enforces `verificationStatus === "confirmed"`, explicitly failing closed (403) for pending/rejected/inconclusive/deduplicated states — inconclusive was called out by name since partial oracle agreement must never be treated as export-ready.

`6572666` (2026-06-25) fixed a real crash: binary HTTP responses (e.g. PNGs) decode via Playwright's `res.text()` without throwing, producing strings with embedded null bytes that Postgres rejects (error 22P05) in any text/jsonb column. Fixed by stripping nulls at the point of capture.

### Dropping Ollama, Claude-only routing (Jun 26)

`02bcd89` (2026-06-26) removed the Ollama fallback path and vision support entirely from ModelRouter, HunterEngine, VerifierAgent, and related files. Claude failures now abort the hunt loudly (`ClaudeUnavailableError`) instead of silently degrading to generic default hypotheses — a deliberate trade of graceful-but-silent degradation for loud, honest failure.

### Settings, UI state persistence, and lab controls (Jun 27)

`005a93b` (2026-06-27) fixed a save bug where the Settings page's masked secret values (`••••1234`) were being re-POSTed on every save, so editing one API key silently overwrote all the others with mask strings. Fixed by tracking dirty fields client-side and adding a server-side mask-sentinel skip as defense in depth.

`d51059c` (2026-06-27) diagnosed why the Hunt Console lost its live event stream when switching panels: the socket listeners writing into the module-level store lived inside a `useEffect` that got torn down on unmount, so events arriving while the panel was off-screen were simply dropped. Fixed by lifting the store to an observable singleton with listeners mounted once above the route layer (`huntEventBridge`), independent of which panel is displayed.

`c311e6b` (2026-06-27) bundled several UI-honesty fixes: a calibration-tab crash from an API shape mismatch, an audit-trail view expecting fields the store never wrote, a fabricated "analysis report" replaced with one computed from real stored findings, and program-scoped finding tagging so lab hunts (against Juice Shop) can't be co-mingled with real-program data. Also added `reset-learning.ts`, a script to wipe RL/learning state for a clean slate between hunts.

### Tool invocation robustness sweep (Jun 27–28)

A short chain of fixes addressed hunts stalling on tool invocations that were subtly wrong for real-world targets:

`5324667` (2026-06-27) found `curl_probe` used `HEAD`, and apps that implement GET but not HEAD (common on hand-built targets) never respond, so curl waited the full 10s timeout every call until the circuit breaker tripped. Switched to `GET` with headers-only output.

`9358ae9` (2026-06-27) found the same stalling class had moved to `nuclei`: with no template filter it scanned the entire default template store and hit the 60s tool ceiling every time, tripping the breaker after 3 timeouts. Fixed by tagging the invocation by hypothesis vuln class with a bounded fallback.

`3b19def` (2026-06-28) audited all 16 built-in tools after those two fixes and corrected several more broken invocations: nmap was scanning a hardcoded port list and ignoring the target's actual port; nikto was passing an invalid `-Format json` flag; ffuf used a non-existent `-json` flag and double-slashed URLs; sqlmap and tplmap lacked bounds that let them run past the 60s ceiling.

### WAF adaptation tuning (Jul 1)

`4d5f399` (2026-07-01) built a simulated-clock harness driving the real rate limiter against a mock WAF with a churning policy, measuring detection latency, recovery time, and false-adaptation cost. It surfaced that sporadic single 429s were each costing a flat 30s backoff even when the sustained rate limit was fine.

`ec0f9fc` (2026-07-01) fixed exactly that: a 429 with no `Retry-After` header now only triggers backoff once 3+ arrive within a 10-second window, treating a lone 429 as noise. An explicit `Retry-After` is still always honored immediately.

### False-positive reduction and verifier honesty (Jul 1)

`e269701` (2026-07-01) reduced false positives in three places based on a stated data point (~0% true conversion across 636 log entries for one class): the 2FA-bypass prober now requires an explicit success signal instead of treating any 200 as a bypass; the SQLI L2 regex was tightened so bare "sql" in unrelated filenames stops triggering false confirmations.

`bd79200` (2026-07-01) fixed a logging-honesty bug: the Playwright L3 browser layer was echoing `result.found` as `confirmed:true` for non-xss/ssrf/open_redirect vuln classes even when the browser actually got a 400. The verdict logic itself was unaffected — this fix was purely about making the logs stop lying.

### Hypothesis pipeline honesty and OOB proof-of-execution (Jul 4–8)

`d6bf36f` (2026-07-04) is a large bundled fix rolling up several problems: hypotheses are now generated per discovered endpoint instead of bucketed by base URL; the failure-prediction engine was silently vetoing entire vuln classes based on prior alone with no real observed failures, so it now requires actual failures before skipping; a bug leaving deserialize-probe hits stuck in "pending" instead of "probing" caused unbounded re-probing; and a new "deferred" hypothesis status was added so never-probed hypotheses are distinguishable from tested-and-negative ones.

`27fce06` (2026-07-05) upgraded the blind-RCE OOB probe from proving mere execution (a bare callback ping) to capturing an actual PoC: the payload now folds `whoami`/`id` output into the callback URL itself.

`1f67390` (2026-07-05) broadened that OOB-RCE technique: the original probe only injected on the base URL via GET with raw payloads. Real injection usually needs breakout syntax (`; | && $() `` \n`), so this built a bounded burst across breakout contexts, common param names, and GET/POST, capped at 24 attempts.

`b0291ba` (2026-07-05) applied the same store-lifting fix as the earlier Hunt Console bug (`d51059c`) to the Orchestration panel — its live execution stream was also living in component state that died on unmount.

`e417a64` (2026-07-08) closed out the OOB work: it made a successfully-fired OOB beacon hit an authoritative verifier oracle for blind vuln classes (rce/ssrf/xxe/blind-sqli/rfi/ssti), reasoning that a callback firing is definitional proof of execution that a stateless L2 reprobe can't replay. The real fix was plumbing: inline OOB hits never reached the callback route because the finding row didn't exist yet during the probe's wait, so the `oobHitReceived` flag was never true at verify time — now `HunterEngine` marks `ProbeResult.oobConfirmed` explicitly and persists it at finding-write time, with the oracle branch placed after the mandatory XSS L3 gate so it can never override that safety check.

### Thin record

- The bulk corpus data-loading commits (roughly 44 commits spanning bounty-patterns/business-logic/chain-scenarios batches) are one-line "batch N → M entries" messages with zero reasoning.
- `18c5e89` (default corpus enrichment to OFF) has a short rationale in its body but no discussion of what triggered the decision (no linked measurement run beyond the preceding A/B commits).
- `ec0f9fc` mentions "Item 2 (620s quarantine recovery) left conservative by design — see chat" — the actual design rationale for that deferral is not in the repo history, only referenced.

---

<a id="jul-8-12-2026"></a>

## 6. Jul 8–12 2026: The Evidence-Discarding Bug Sweep, the Workflow Split, and the RCE-Only Pivot

This is the most densely-documented stretch of the project's history: five days that started with routine false-positive gating and UI polish, moved through a governance-wiring pass, narrowed hunt scope to RCE with a real allowlist mechanism, and ended in a multi-day sweep of "evidence gets thrown away before verification" bugs across nearly every specialized prober. Partway through Jul 10 the commit authorship visibly changes from `Claude <noreply@anthropic.com>` (cloud session, `Claude Opus 4.8` co-author) to `kali <kali@kali>` (local session, `Claude Sonnet 5` co-author) — matching the two-session workflow (local hands-on fixes, cloud review) established for this era. Almost every commit from Jul 9 onward carries a "verified live" claim against a real target or fixture server, not just a description of intended behavior.

### Jul 8: false-positive gates and UI polish

- `5b6c593` (2026-07-08): Node resolves `localhost` to `::1` first, but dev targets (Replit/Flask/Express) bind IPv4-only, so every axios/fetch call threw `AggregateError`. Forced `dns.setDefaultResultOrder("ipv4first")` at boot, and made HunterEngine loudly flag an empty (but non-throwing) login session instead of proceeding to hunt unauthenticated and reporting misleading "0 verified" results.
- `164d6ee` (2026-07-08): LFI/RFI had no dedicated Layer-2 reprobe case, so it fell into a generic `status<400` catch-all — false-positiving on "not found" pages. Added a content oracle that confirms only on an exact file-disclosure signature.
- `7efe717` (2026-07-08): The business-logic probe confirmed "accepted" on a bare 2xx with no baseline, so any endpoint that 2xx's everything (SPA catch-all, body-ignoring API) fabricated a vuln for every technique tried — traced to a live flood of "102 accepted vulns" on localhost:5000. Fixed with a per-endpoint control probe: POST nonsense first, suppress findings if the control also 2xx's.
- Two commits (2026-07-08) fixed a UI polish batch — missing favicon, a Dashboard ROI panel stuck permanently on "Loading," a stripped keyboard focus ring, and 13 icon-only nav-rail buttons missing `aria-label`.
- `180b37d` (2026-07-08): Removed the unused CTF/XBOW/JuiceShop benchmark feature, including its 1,602-line `CTFBenchmark.tsx` god-component and four dead server routes.
- `cb0739f` (2026-07-08): `cn()` was a plain filter+join, so passing an override `className` emitted both base and override classes with an arbitrary CSS winner. Replaced with `twMerge(clsx(...))`.

### Jul 9: chain-seeding, honesty gates, governance wiring, and evidence-discard round 1

- `b868807` (2026-07-09): Chain-seeded follow-on hypotheses (idor→sqli, lfi→ssrf→rce) were seeded with the hunt's bare root URL instead of the parent's actual exploited endpoint+query, so every chained finding reprobed the homepage and could never verify — 0/4 verified in the live hunt that surfaced it.
- `e465f7d` (2026-07-09): Two silent failure paths let a dead/crashed Playwright worker masquerade as "tested, found nothing," which the XSS gate then turned into a false REJECTED instead of INCONCLUSIVE.
- `8edfe53` (2026-07-09): Added a standalone Playwright health check at server startup, independent of VerifierAgent's own worker.
- `a5ad042` (2026-07-09): RFISolver treated `status === 0` — BaseSolver's own catch-all for a failed request (ECONNREFUSED/DNS/timeout) — as evidence the target reached `evil.com`, fabricating an RFI finding on any flaky/dead target.
- `9af549d` (2026-07-09): Two more honesty gaps mirroring the Layer-3 fix: OOB probing silently fell back to a local callback server against public targets that structurally can't reach it (now emits `hunt:oob_degraded`), and a missing tool binary was mislabeled as a plain timeout with no logging.
- `76207d4` (2026-07-09): WAF bypass ran unconditionally on every hunt with no toggle. Added a per-hunt `wafBypassEnabled` toggle plus a `programs.wafBypassPolicy` column that hard-blocks WAF bypass when a program explicitly disallows it.
- `d53b68e` (2026-07-09): Backward-mode's Layer-3 attack plan was computed and persisted but never actually read back by Layer 4, so "backward" mode behaved identically to "forward" for every orchestrated hunt.
- `495336a` (2026-07-09): Goal matching used raw `string.includes()`, so "achieve remote code execution" never matched "execute" and silently fell into the wrong attack tree. Rewrote as word-boundary regex with broader synonyms, added a `customVulnPriority` path.
- `0595dbe` (2026-07-09): Every `programId === -1` (custom target) hunt reused one shared "Custom / Local Lab" program scoped to `["*"]` forever — effectively unscoped for any typo'd or deliberately out-of-scope domain. Now creates a distinct scoped program per hostname.
- `dbe4678` (2026-07-09): `routes/hunt.ts`'s REST route and the `hunt:start` socket handler construct HunterEngine directly, bypassing CampaignOrchestrator's governance gate entirely — so recon traffic could fire with zero scope check. Added a root-target scope check at `startHunt()` for every caller.
- `8f9bf28` (2026-07-09): A flagged prompt-injection verdict was computed correctly but then just logged and ignored — the content was used anyway. Now a flagged response throws or returns the errored/needs-review shape.
- `6753806` (2026-07-09): `coreGovernance.recordDecision()` — what the governance API actually reads — had exactly one caller; the real per-hunt scope/budget gates wrote only to an in-memory array, so the API showed "0 violations" regardless of what happened. Wired both real gate points to call `recordDecision()`, activated a fully-built but never-invoked WAL/NDJSON decision logger.
- `4fe960e` (2026-07-09): The immunizer's `full_reset` recomputed a baseline hash from the same unchanged in-memory object — a tautological no-op. Fixed to genuinely rebuild pillar sensitivities/thresholds. Explicitly flagged, not fixed: the drift broadcast has zero UI subscribers, deliberately left unwired pending a product decision.
- `fca0ddd` (2026-07-09): `calculateRateChange()` had no minimum sample size, so a baseline of 0 decisions vs. 1 recent decision could swing 100 percentage points and blow past the reset threshold — normal for this platform's episodic solo usage, not real drift. Added minimum-sample floors, wired a distinct `governance:drift_alert` toast.
- `fdd71f4` / `85ff7b6` (2026-07-09): The first big evidence-discard sweep — 18 specialized probers ran real attacks with concrete per-finding evidence and endpoints, but HunterEngine's hand-off hardcoded `evidence: []` and pointed `targetUrl` at the hunt's root URL — discarding proof and misdirecting re-verification.

### Jul 10: RCE-only allowlist, schema safety, and detection upgrades

- `08ae001` (2026-07-10): Six runtime-bootstrapped tables were never declared in `schema.ts`, so `drizzle-kit push:pg` would have proposed dropping all six live tables. Added matching `pgTable` declarations, verified against a throwaway Postgres DB.
- `c0d0c20` (2026-07-10): Layer-5 re-verification and Layer-2 reprobe sent no auth data, so any finding behind a login wall was wrongly rejected regardless of whether it was real.
- `6c6b92c` (2026-07-10): The LFI content oracle only recognized `/etc/passwd` and `win.ini`. Extended it to also accept PostExploitAgent's existing sensitive-disclosure matcher.
- `80736af` (2026-07-10): Proven live against a real target that a double-submit CSRF scheme (cookie === header, no server-side tie) is trivially defeatable with zero auth. Added a shared `csrf-aware-request` helper.
- `708e9e9` (2026-07-10): AuthBypassSolver only fired when baseline was already 401/403, silently dropping routes reachable with zero credentials at all. Added a confirmatory check distinguishing "no auth enforcement" from "auth middleware present but validates nothing."
- `d66bcfc` (2026-07-10): Proven live that a config "test connection" field was a genuine SSRF sink invisible to the existing param list and GET-only probing. Centralized and widened the SSRF param list, added a bounded POST-JSON-body fallback.
- `3d8c281` (2026-07-10): Proven live that hardcoded creds and filesystem paths leaked in error messages across ~6 routes, but secret-scanner explicitly excludes non-200 responses. Added `error-disclosure-prober.ts`, provoking exceptions with malformed input.
- `1a1f543` (2026-07-10): Pillar drift compared raw activity counts across unequal windows (1h "recent" vs 23h "baseline"), so a steady, busy prior session naturally read as a huge "drop" purely from window-size mismatch — the actual cause of repeated FULL_RESETs during a quieter hunt after hours of earlier activity. Normalized both windows to per-snapshot rates before comparing.
- `c22fc03` (2026-07-10): L1 dedup treated any prior finding with a matching hash as a permanent duplicate regardless of its verdict, and cached every novel hash before the verdict was even known — so a rejected finding could never be re-attempted even after a verifier fix that could now confirm it. Changed to only treat CONFIRMED-verdict matches as duplicates.
- `8d6a1ad` (2026-07-10): **The RCE-only scope decision.** `focusVulnClasses` was additive-only — there was no real way to restrict a hunt to one vuln class. Added `vulnClassAllowlist` as a genuine exclusionary filter at the single PROBE-phase choke point.
- `64dc1e4` (2026-07-10): TechPayloadSelector built real tailored RCE/SSTI payloads per fingerprinted framework but HunterEngine only carried the description string forward, throwing away the actual payload. Added `tech-payload-prober.ts` to actually send them, using a fresh random product per SSTI probe rather than a guessable static "7*7."
- `49edb83` (2026-07-10): The same evidence-discard bug reappeared in that very night's own new code — ssti/exposed_admin hypotheses had no dedicated PROBE-phase branch. Added `reprobeHypothesis()`, replaying the exact original technique with a fresh random product.
- `90d8369` (2026-07-10): Docs-only — updated the allowlist UI hint since a bare "rce" filters out the very precursor classes (ssti, ssrf, lfi/rfi, auth_bypass, exposed_admin, prototype_pollution) that RCE typically chains through.

### Jul 10 evening – Jul 11: workflow shifts local; tool-integration bugs

Author identity switches here from the cloud `Claude` account to the local `kali <kali@kali>` session (co-authored by Claude Sonnet 5), matching the two-session split.

- `33a9ac7` (2026-07-10): `huntStore.activeSessions` was in-memory only, so a page reload orphaned an already-running hunt behind a passive banner with no live feed.
- `cacb609` (2026-07-10): `curl_probe`'s "success" was counted for any vuln class regardless of relevance, inflating pre-verification confidence to 0.9+ for e.g. LFI/SQLi. Gating success on the tool's declared vulnClasses surfaced several stale tool/vulnClass mappings.
- `e4d2728` (2026-07-10): probeDeserialize's RCE oracle matched bare `root`/`executed` substrings — so posting to a nonexistent endpoint on an SPA with catch-all routing (whose `<div id="root">` mount point alone satisfies the regex) produced 0.96-0.98 confidence RCE hypotheses on completely unrelated frontend apps.
- `ea91b9f` (2026-07-10 late): The prompt-injection detector's bare "system:" keyword sat exactly at the block threshold with no word boundary, so any benign AI explanation mentioning "operating system:" got its own Layer-4 verdict discarded.
- `2a4e8ef` (2026-07-11): ssrfmap was integrated against a CLI it doesn't have (confirmed via `--help`); every invocation errored and printed its own usage banner containing the word "SSRF," which the parser then matched as a false positive. Removed entirely rather than patched.
- `b3e339f` (2026-07-11): feroxbuster's catalog command used a nonexistent `--no-progress` flag, so every invocation errored before making a request — confirmed live on a completed DVWA hunt. Also fixed the shared "lines" parser (used by 8+ catalog tools) which hardcoded `found: true` unconditionally.

### Jul 12: self-confirmed prober wiring, three new RCE probers, and the SPA catch-all sweep

- `da02410` (2026-07-12): 13 OBSERVE-phase probers already did real active testing with 1:1-confirmed hypotheses, but HunterEngine re-routed all of them through generic tool dispatch anyway. Added a `SELF_CONFIRMED_SOURCES` short-circuit that must run before every other dispatch branch.
- `2519dc5` (2026-07-12): `isOAuthIndicator()` flagged literally any 200 response as a discovered OAuth endpoint, confirmed against Juice Shop returning byte-identical 200s for real and bogus paths. Fixed with a bogus-baseline diff.
- `72967ab` (2026-07-12): mass-assignment-probe and two-factor-bypass stored a bare relative path as `endpoint` even though a full URL was already computed in scope.
- `22ac9c4` (2026-07-12): websocket-probe used axios, which cannot observe Node's 'upgrade' event for a real HTTP 101 — every technique timed out and was silently discarded. Replaced with a raw http/https helper; verified against a fixture that went from 0 findings to 16.
- `9d18faf` (2026-07-12): Added a deterministic vuln fixture server — the tool that actually surfaced the oauth/mass-assignment/2FA/websocket bugs fixed in the immediately preceding commits.
- `fc71a03` (2026-07-12): All four MAX_HYPOTHESES truncation call sites sorted purely by priority×confidence, so an already-resolved hypothesis could keep outranking and evicting a still-pending one forever. Confirmed live: allowlist-deferred `race_condition` hypotheses permanently starved `crlf_injection` out of the 150-slot array across two hunts. Added `truncationRank()`.
- `dfe3b19` (2026-07-12): Removed the now-dead ssrfmap catalog/knowledge entries left over from the earlier removal from dispatch.
- `31d614e` (2026-07-12): Added the last missing test — a mocked unit test for cloud-bucket-probe.
- `59bbc83` (2026-07-12): Added deserialization-prober (the 14th self-confirmed prober) — real ysoserial URLDNS/phpggc gadget chains. Verified live: PHP 16/16 confirmed via OOB, Java 16/16 via fallback.
- `c006722` (2026-07-12): Added file-upload-to-webshell prober (15th) — uploads webshells across extension-filter bypass variants, confirming execution via an arithmetic canary rather than a reflected substring.
- `0936d9c` (2026-07-12): Added blind OS command injection prober (16th) — closing the biggest remaining RCE-coverage gap. Found and fixed a real bug along the way: the payload's base argument was an invalid ping target that itself hung 10+ seconds, starving the timeout.
- `c926e52` (2026-07-12): race-condition-detector's blind 13-path guess list flagged every path as a race condition on a SPA catch-all target — went from 13 false flags to 0 after adding a bogus-baseline-diff.
- `a0d513a` (2026-07-12): Same catch-all false-positive class in mass-assignment-probe. All 17 findings from one live hunt were confirmed false positives via source inspection.
- `2c7ffb5` (2026-07-12): Layer 5's rejection of a finding never reached `hunt-findings.json` — it stayed listed "confirmed" indefinitely even after real browser replay + AI review both failed to reproduce it. Added `retractFinding()`/`updateFindingConfidence()`.
- `c9d4bd5` (2026-07-12): Seeded priority hypotheses kept pure scheduling-metadata text as their permanent description even when a probe later genuinely confirmed them. Added `describeFromProbe()`.
- `1fb728c` (2026-07-12, final commit of this era): Traced why xss/csrf/ssti/info_disclosure/open_redirect kept false-confirming even after the prober-level fixes — root cause was in the generic tool-dispatch layer: tplmap's parser matched its own startup banner text; curl_probe declared vulnClasses it has no real detection logic for; xsstrike used the generic "lines" parser so its own banner lines always read as `found:true`. Fixed all three against each tool's real documented positive-only markers.

### Thin record

- One pure UI variant addition (2026-07-09) — mechanical restatement of what was added with no debugging narrative.
- The 2026-07-08 UI polish batch — real fixes but shallow one-line reasoning each (missing dir, stuck loading state, missing focus ring).
- `dfe3b19` (2026-07-12, ssrfmap catalog cleanup) — mostly a mechanical follow-up removing dead references left over from an earlier decision; no new reasoning beyond "finish the job."

---

## Aggregated known gaps in this record

- **Two multi-week silent gaps with zero commits**: 2026-02-19 → 2026-04-11, and 2026-04-11 → 2026-05-22. Whatever exploration or discussion happened in between left no trace.
- **Bulk mechanical commits** (RAG-corpus data-batch growth, package-lock bumps, pure docs restatements) make up a large fraction of total commit count but carry no reasoning by nature — they're intentionally collapsed above rather than itemized.
- **Reasoning that lived only in chat** (with either a local terminal session or a cloud session) and never made it into a commit body is permanently unrecoverable from this method. This document can only reconstruct what got written down somewhere in the repo.
- A handful of individual commits per era are flagged in each section's own **Thin record** as bare one-liners with no stated rationale.

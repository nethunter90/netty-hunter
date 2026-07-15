# Sentinel Primordial / Netty Hunter — Full System Handoff

> Audience: another Opus instance (or senior engineer) picking up this codebase cold.
> This is the single source of truth for *how the whole thing actually works* — every
> loop, every gate, every entry point — plus the traps that have already bitten us.
> Where the code contradicts older docs (CLAUDE.md, ARCHITECTURE.md), **this file
> reflects the code as it is on `claude/debug-visibility-issue-0in6N`.**

---

## 0. One-paragraph mental model

This is an autonomous web bug-bounty platform on Kali. The heart is the **Hunter
Engine**, which runs an **Observe → Hypothesize → Probe → Update (OHPU)** reasoning
loop: it fingerprints a target, asks an LLM for vulnerability hypotheses, fires Kali
tools / HTTP probes at them, then updates confidence and confirms findings. Around
that engine sits the **Campaign Orchestrator**, a 6-layer pipeline that adds
governance, target intel, strategy, verification, and reporting. Confirmed findings
are run through the **VerifierAgent**, a 4-layer anti-hallucination pipeline ending in
a Playwright browser replay. An LLM **ModelRouter** routes reasoning to Claude first
(SDK → CLI bridge) and falls back to local Ollama. Everything outbound passes a
fail-closed **ScopeGuard**. A **governance** subsystem audits and immunizes the
decision-making against drift/tampering.

---

## 1. The single most important thing to understand: TWO entry paths

There are **two ways a hunt starts**, and they behave differently. This is the #1
source of confusion and bugs.

### Path A — Orchestrated (the "full" pipeline)
`POST /api/orchestration/run` or socket `orchestration:run`
→ `CampaignOrchestrator.orchestrate()`
→ runs **6 layers**, one of which (**Layer 5**) is the VerifierAgent gate.
Findings get verified, disclosure-checked, CVE-enriched, and reported **automatically**.

### Path B — Direct engine (the "console" hunt)
`POST /api/hunt/start` or socket `hunt:start`
→ `HunterEngine.startHunt()` directly (the route in `server/src/routes/hunt.ts`)
→ runs **only the OHPU loop**. The orchestrator's 6 layers are **bypassed**.

**Historic gap (now fixed in this branch):** Path B never ran Layer 5, so console-
launched hunts left every finding at `verificationStatus: "pending"` and the operator
had to click "Verify" on each one manually. We fixed this by adding an **auto-verify
pass** to **both** `hunt:complete` handlers (forward and backward) in `hunt.ts`, using
a shared helper `verifyPendingForSession()`. See §11.

Note: the backward hunt handler was initially missed in the first fix pass — it only
had `metaReasoner` + `strategyWeightLearner` calls, no verify IIFE. That gap is now
closed.

**Takeaway for the next engineer:** if you change verification behavior, you must
touch it in **two** places — `CampaignOrchestrator.layer5_verificationGate` AND the
`hunt.ts` auto-verify pass / shared helper `server/src/lib/verification/verify-finding.ts`.

---

## 2. Repository layout (what lives where)

```
netty-hunter/
  server/src/
    index.ts                     # Express + Socket.IO + PTY boot. PORT defaults to 3001 (NOT 3000).
    agents/
      HunterEngine.ts            # 2845 lines. The OHPU loop. The core.
      CampaignOrchestrator.ts    # 1312 lines. The 6-layer pipeline wrapping a hunt.
      VerifierAgent.ts           # 4-layer verification (dedup → reprobe → playwright → AI).
      SolverPool.ts              # Parallel per-endpoint/per-class solvers (p-queue).
      PostExploitAgent.ts        # Read-only impact demonstration after a finding confirms.
      LogicExploitAgent.ts       # Claude-directed Playwright for stateful idor/auth/business_logic.
      SynthesisAgent.ts          # Cross-finding chain synthesis.
    intelligence/
      ModelRouter.ts             # Claude-first → Ollama tier routing + circuit breaker (Ollama only).
      ROIModel.ts, PromptKnowledgeBase.ts, JsonPromptLoader.ts, MetaReasoner, ...
    governance/                  # Core governance engine + per-request enforcement.
      index.ts                   # Wires + exports the singletons. Import governance from HERE.
      core-governance.ts, pillars.ts, drift-detector.ts, self-attestation.ts,
      decision-logger.ts, types.ts, enforcement/prompt-injection-detector.ts
    lib/
      claude-client.ts           # Anthropic SDK wrapper (Sonnet for reason, Haiku for classify/chat). Budgeted.
      claude-bridge.ts           # `claude --print -p` CLI bridge (tier 0b). 120s timeout.
      context-writer.ts          # Writes context/*.json live state for the CLI-invoked Claude.
      verification/verify-finding.ts   # SHARED verify helper (auto + manual). NEW this session.
      governance/governance-immunizer.ts  # The immunizer watchdog (depends on DB + huntCortex bus).
      intelligence/hunt-cortex.ts  # huntCortex — the platform-wide signal bus (EventEmitter singleton).
      tools/, recon/, oob/, stealth/, hunter/, services/, parsers/   # probes + support
      shell/                     # command execution sandbox
    middleware/scopeGuard.ts     # fail-closed scope validation. NEVER weaken.
    routes/                      # Express routers (see §10)
    db/schema.ts                 # Drizzle ORM / PostgreSQL. 20 tables.
  client/src/
    pages/                       # React pages (see §13)
    components/                  # LiveActivityFeed, FloatingChat, bounty/, missions/, ...
  context/                       # live hunt state, written at runtime, read by CLI-Claude
  server/data/prompts/           # ~1785 security Q&A entries used for RAG
```

---

## 3. Boot sequence (`server/src/index.ts`, PORT 3001)

In order:
1. `dotenv/config`; create `logs/`.
2. **Settings load** — reads `reinforcement_store` rows (`domain like "settings"`) → `runtimeConfig.loadAll()`. (API keys set after startup are picked up lazily.)
3. **`initLearningSchema()`** — creates journal/threshold/cortex tables. Must precede brain + hunts.
4. **`checkBinariesAtStartup()`** — logs which Kali binaries are present.
5. **`initializeAutonomousBrain()`** (synchronous).
6. Express `app` + `httpServer`; `PORT = env.PORT || 3001`.
7. **Socket.IO** server (CORS, pingTimeout); `app.set("io", io)`; egress allocator wired to emit over io.
8. Middleware: helmet → cors → json/urlencoded (10mb) → production `SESSION_SECRET` guard.
9. **PG-backed session middleware**; shared with Socket.IO via `io.engine.use(...)`; `io.use(...)` rejects unauthenticated sockets.
10. `requireAuth` defined; rate limiters mounted (`/api`, `/api/hunt/start`, `/api/orchestration/run`).
11. **Routes registered** (§10).
12. Public OOB receiver `app.all("/api/callback/:beaconId", ...)` (no auth, per-IP limited) + `/health` + 404 + error handler.
13. `io.on("connection")` handlers (§12), including the **PTY terminal** handler.
14. Scheduled re-scan `setInterval` (15 min); writeup scraper (+30s then every 24h).
15. `httpServer.listen(PORT)`.

> ⚠️ **Port mismatch:** CLAUDE.md says port 3000; the code defaults to **3001**. The
> Juice Shop curl example in CLAUDE.md targets `:3000` (Juice Shop's own port) — don't
> confuse it with the server port.

---

## 4. The OHPU loop — `HunterEngine` (the core)

Entry: `startHunt(params)` → spins up DB `huntSessions` row, loads custom/Kali-catalog
tools, auth, kicks off **Phase 0 passive recon** (concurrent), then `runLoop()`.

`runLoop()` iterates while: `iteration < maxIterations` AND `requestsMade < maxRequests`
AND `elapsed < maxTime` AND `!hardBanned`. It `yieldToEventLoop()` (`setImmediate`)
between phases so concurrent hunts/sockets aren't starved. State machine on
`state.phase`:

### Phase 1 — Observe (`observe()`)
- Fingerprints target: `whatweb`, `curl_probe` (security headers/CORS), `waf_intel` (WAFBypass synthesizer).
- Builds `Observation[]` with an **anomaly score** each, **sorts anomaly-first**.
- Injects Phase-0 recon (subdomains/wayback) as an observation once available.
- **First iteration only**, fires a large fan-out of specialized probes that *seed
  hypotheses*: CVE seeding (from whatweb tech, allow/block-listed), GraphQL introspection,
  secret scanner, change detector, websocket, cloud bucket, prototype pollution, race
  condition, host-header, CRLF, cookie flags, JS/SPA deep crawl, vision screenshot.
  Each pushes `status:"pending"` hypotheses.

### Phase 2 — Hypothesize (`hypothesize()`)
- Compresses old observations (`observationCompressor`) to bound prompt growth.
- Builds a RAG-enriched prompt: KB chain template + semantic domain knowledge
  (`jsonPromptLoader`, 7 hits) + RL framework priorities + promptKB methodology hints
  + recon summary.
- Calls `modelRouter.reason(prompt, sessionId)` → expects a JSON array of 3–5 hypotheses.
- Runs the model's **output** through `promptInjectionDetector` (defense-in-depth).
- Parses (capped at 64 KB), normalizes confidence/priority, tags `modelSource`, sorts
  by `priority*confidence`, caps at `MAX_HYPOTHESES=150`.
- On failure → `generateDefaultHypotheses()` (common-class fallback).

### Phase 3 — Probe (`probe()`)
- Refreshes auth session if configured (30-min TTL).
- Takes top 8 pending hypotheses by `priority*confidence`.
- Per hypothesis, in order:
  - **Budget pre-flight** (`isBudgetExhausted`) → emits `hunt:budget_exhausted`, breaks.
  - **Failure prediction** → `shouldSkip` rejects low-probability probes early.
  - **`scopeGuard.isInScope(targetUrl, programId)`** → reject if not allowed.
  - **Deserialization POST probe** for `rce`/`deserialization` (fires before tool dispatch).
  - **LogicExploitAgent** (Claude-directed Playwright) for `business_logic`/`idor`/`auth_bypass`
    when `ClaudeClient.isAvailable()` — handles stateful/chained/dual-context probes.
  - Else **`runTool(tool, url, hypothesis)`** where `tool = hypothesis.toolHint || selectToolRL(vulnClass)`.
    On retries, injects WAF-bypass payload mutations.
  - **OOB beacon probe** for blind classes (`ssrf/xss/sqli/rce/xxe`) when no immediate signal.
  - **Hard-ban detection:** after 5 consecutive failures, a canary HEAD; 403 or network
    drop (`ETIMEDOUT/ECONNRESET/...`) sets `hardBanned` and ends the hunt early.

### Phase 4 — Update (`update()`)
- For each `probing` hypothesis: gather successful probes → `updateConfidence()` (AI-assisted).
  - **`confidence > 0.7` → confirmed.** Builds `HypothesisConfirmed`, pushes to findings,
    emits `hunt:finding_confirmed`, writes context, **`persistFinding()`** (DB insert),
    then **non-blocking** `postExploitAgent.demonstrate(...)` (§7), notifications, and
    SSRF-pivot / exploit-chain seeding.
  - **`confidence < 0.2` → rejected.**
  - **Gray zone (0.2–0.7) → re-queue** with an alternate tool, up to 2 retries, then inconclusive.
- Next phase: if pending hypotheses remain → `probe`; else → `observe` (re-observe with new knowledge).
- Every 3rd iteration: `metaReasoner.evaluateEnriched()` may inject a **strategy pivot**
  (backward-planner paths) — this also keeps the decision journal fed for cross-hunt learning.

### Completion
`phase = complete` → clears compressor/Claude session, invalidates auth session,
RL `onHuntComplete`, **`persistResults()`** (updates `huntSessions`, creates an
`exploitChains` row if ≥2 findings), emits **`hunt:complete`**.

> Note: `persistFinding` writes `verificationStatus:"pending"` and does NOT set `dedupHash`
> (the verifier sets it later); it now returns the new row id so the post-exploit escalation
> can target the finding by `id` and stash its proven escalation for apply-on-confirm (§7, §16#8).

---

## 5. The 6-layer Campaign Orchestrator — `CampaignOrchestrator.orchestrate(params)`

Each layer runs through a `runLayer()` wrapper that emits `orchestration:layer_start/complete/error`
and writes an audit entry. Between L1 and L2 it also does subdomain expansion
(`subfinder`) + a non-blocking subdomain-takeover scan.

| # | Layer | Method | What it does |
|---|-------|--------|--------------|
| 1 | **Governance gate** | `layer1_governance` | Find-or-create program (`programId -1` → synthetic local program), check active, **scope validation (fail-closed)**, **BUDGET GUARD**, create/resume campaign, reconcile `findingsCount`, register target row. `!passed` → abort. |
| 2 | **Target intelligence** | `layer2_targetIntelligence` | `targetSelector.scorePrograms()`, `roiModel.rankVulnClasses()`, computes `priorityVulns` (focus override or top-8). |
| 3 | **Strategy planning** | `layer3_strategyPlanning` | Backward: `backwardHunt.createPlan()` (falls back to forward). Forward: `HuntStrategyBuilder.build()`. Persists strategy to campaign. |
| 4 | **Execution engine** | `layer4_executionEngine` | Instantiates `HunterEngine`, wires events, `startHunt()`, awaits `hunt:complete`. SolverPool supplement when findings sparse + budget remains; abbreviated sub-hunts on discovered subdomains (concurrency 2). **Budget accounting:** pre-charges SolverPool with engine spend so it draws from *remaining* quota (no double-spend). |
| 5 | **Verification gate** | `layer5_verificationGate` | Per finding → `verifierAgent.verify(mockResult)` (§6). Confirmed → disclosure check, screenshot archive to disk, DB write (status/log/confidence/dedupHash/cweId), NVD CVE enrichment, optional platform report submission, `finding_verified`. Rejected/inconclusive → DB write + `finding_rejected`. **Idempotent resume:** already-`confirmed` findings are promoted to `verified` without re-running. |
| 6 | **Intelligence harvest** | `layer6_intelligenceHarvest` | Draft reports + Nuclei templates per verified finding, RL/bounty-intel/autonomy updates, confidence calibration, exploit-chain extraction, mark campaign `complete`. |

**Budget guard (NEVER remove — governance rule):** in L1,
`budget = params.budget || {maxRequests:2000, maxTime:3600}`; rejects fail-closed if
`maxRequests` outside `[10, 50000]`.

**Events:** `orchestration:*` lifecycle; `l4:*` (re-emitted hunt events, prefixed);
`l5:verifying/public_duplicate/verified/rejected/report_queued`; `l6:report_generated/...`.
(A verified finding is queued for human review, not auto-submitted — see ARCHITECTURE.md's
L5 section. `report_submitted`/`report_submit_failed` fire later, from the approve route.)
Shared bus: `eventBus.publish('vulnerability_found' | 'finding_verified' | 'finding_rejected', ...)`.

**Export:** the class only (`export default CampaignOrchestrator`) — **no module singleton.**
Routes/sockets `new CampaignOrchestrator()` per run.

---

## 6. The 4-layer VerifierAgent — `verify(result, options?)`

The anti-hallucination gate. `result` is a `SolverResult`. **NEW this session:**
`options.skipDedupHash` lets operator re-verification bypass Layer 1 (see §11/§14).

- **Layer 1 — Static dedup** (`Layer1Dedup`): SHA-256 over `{endpoint(no query), vulnClass, payload[:100]}`
  + SimHash near-dup (endpoint-anchored so identical payloads at different endpoints don't
  collide). Checks an in-memory `hashCache` (preloaded with last 500 DB hashes on init)
  AND the DB. **Duplicate → immediate `rejected`, confidence 0.** `skipDedupHash` (when it
  equals the computed hash) skips all three checks so a finding can be re-verified.
- **Layer 2 — HTTP reprobe** (`Layer2Reprobe`): replays `result.request` (falls back to
  `result.endpoint` if request isn't an http URL). Re-checks class-specific signals.
- **Layer 3 — Browser replay** (`Layer3BrowserReplay`): Playwright in a **worker thread**
  (so the page lifecycle never blocks the main loop). 35s timeout. `layer3Available` flag
  distinguishes "offline" from "unconfirmed".
- **Layer 4 — AI confirmation** (`Layer4AIConfirmation`): builds an evidence prompt (incl.
  vision analysis of the L3 screenshot if available), `modelRouter.reason()`, parses JSON
  `{confirmed, reasoning, confidenceAdjustment}`. Uses a **stateless per-finding session**
  (`verify-<taskId>`) to avoid races. On parse/transport failure → `errored:true`
  (routes to *inconclusive*, never a silent reject).

### Final verdict — oracle authority by DISCOVERY method, not just class (important and subtle)
There are now **three** authority categories. The selector is `result.discoveryTool`
(or `result.evidence.tool` fallback) first, then vuln class:
- **Stateful agent-discovered (`discoveryTool === "logic_exploit_agent"`):** these
  `idor`/`auth_bypass`/`business_logic` findings only exist inside a live multi-step /
  multi-identity browser session. **L2 is barred from voting** — a contextless GET can't
  replay them (it falsely rejects `auth_bypass` on 401/403 and falsely confirms `idor` on a
  200). The discovery run was itself a Playwright oracle with hard-evidence requirements, so
  authority passes to **L4 over the captured `rawHttpLog`**. L4 confirmed → `confirmed`;
  L4 dissent/error → `inconclusive` (human review), never an auto-reject. (`STATEFUL_ORACLE_TOOLS`
  in VerifierAgent.)
- **Browser-verifiable classes (`xss`, `dom_xss`):** L3 is the **mandatory oracle** (unchanged).
  - L3 offline → `inconclusive` (if L4 believes) or `rejected`. **Never auto-confirmed without a real browser execution.**
  - L3 confirmed → `confirmed`. L4-only (L3 didn't prove) → `inconclusive`. Neither → `rejected`.
- **HTTP-observable classes (everything else):** **L2 is authoritative, L4 corroborates, L3 does not vote.**
  - L2 && L4 → `confirmed`. Exactly one → `inconclusive`. Neither → `rejected`.
- **L4 errored + verdict would be rejected → bumped to `inconclusive`** (a dead reasoning
  backstop must not refute a finding).

> Governance rule: **do not bypass the Playwright gate.** Neither `skipDedupHash` nor the
> stateful-oracle category touches the `xss`/`dom_xss` L3 mandatory gate — the stateful
> category only governs classes L3 never gated, and those findings were already proven by a
> real Playwright run (LogicExploitAgent) at discovery.

---

## 7. PostExploitAgent — read-only impact demonstration

Singleton `postExploitAgent`. Runs **after** a finding confirms (non-blocking IIFE in
`HunterEngine.update()`, and from the manual `/api/exploit/demonstrate/:findingId` route).
Demonstrates *impact* without exploiting destructively, to justify report severity.

- **Hard limits:** `MAX_STEPS=4`, `STEP_TIMEOUT_MS=8_000`, `TOTAL_BUDGET_MS=30_000`.
- **Every outbound URL re-validated through `ScopeGuard.isInScope` (fail-closed).** Blocked → step recorded as `proved:false`, no request sent.
- **Per-class probes (benign/read-only):** ssrf→cloud metadata (169.254.169.254) + internal reach; lfi→/etc/passwd, /etc/hostname; idor→adjacent id ±1; auth_bypass/exposed_admin→strip auth + re-request (200 = proven); open_redirect→inject + check `Location` (no-follow); info_disclosure/misconfig→secret/private-key regex. **sqli/rce/xss → no replay** (left to sandboxed tooling + AI narrative).
- **Severity escalation: upward only, one rank, capped per class.** CVSS = `max(base, CVSS_BY_SEVERITY[escalated])`. Only when `impactProven`.
- **Emits:** `postexploit:start/step/complete`; engine re-emits `hunt:impact_demonstrated`.
- **Method:** `demonstrate(input, baseSeverity, baseCvss): Promise<ImpactAssessment>`.
- **Escalation ordering (important):** post-exploit runs in `update()`, *before* the finding
  is verified (Path B verifies at `hunt:complete`, Path A at L5). So it does **not** write
  the severity bump to the row — it **stashes** the proven escalation as an
  `{type:"impact_escalation", severity, cvssScore, impact, proven:true}` entry in the
  finding's `evidence`. The bump is applied **only on a `confirmed` verdict**, by
  `pendingEscalation()` (in `verify-finding.ts`) at both verify sites (Path B helper + L5).
  This prevents inflating severity on a finding the verifier later rejects.

---

## 8. ModelRouter — tier routing (Claude FIRST) + circuit breaker

`ModelRouter.getInstance()`. All public methods funnel through `generate(prompt, taskType, options)`.
`lastProvider` records which tier served the last call (used for RL model scoring).

- **`reason` / `analyze`:**
  1. **Tier 0a — Claude SDK (Sonnet 4.6)** via `ClaudeClient.reason()` (if `isAvailable()`).
  2. **Tier 0b — Claude CLI bridge** `claude --print -p` via `ClaudeBridge.reasonWithHuntContext()`
     (if SDK unavailable/failed). An RL override can skip straight to Ollama if local has historically won.
  3. **Tier 1 — Ollama** (`/api/chat`, 2 retries + backoff).
- **`classify` / `chat` / `summarize`:** Tier 0c **Claude Haiku** (`ClaudeClient.oneShot`) → Ollama.
- **`code`:** Ollama only.
- **Vision (`describeScreenshot`):** **Ollama-only** (llava/moondream/etc.), no Claude vision fallback.

**Circuit breaker** (`CLOSED/OPEN/HALF_OPEN`, threshold 3, recovery 30s) gates **ONLY the
Ollama tier** (and the Ollama vision path). The Claude SDK/CLI tiers are never gated by it.
So "Circuit OPEN — Ollama is unavailable" only blocks the local fallback.

> Operator note: the user moved Claude to first deliberately — local models couldn't
> complete challenges solo. Claude-first is intentional, not a bug.

### ClaudeClient budget (`lib/claude-client.ts`)
- Per-hunt **LLM call budget** `MAX_LLM_CALLS_PER_HUNT` (default 150). `tryConsumeBudget()`
  is consulted by every Claude caller (incl. LogicExploitAgent) so one place counts spend.
  Exceeding throws `LLMBudgetExceededError`.
- `reason()` keeps a per-session conversation thread (trimmed to 20 msgs) and has a
  **90s hard timeout** on `messages.create()` (added this session — prevents an indefinite
  loop stall if the API hangs).

---

## 9. ScopeGuard & Governance (do not weaken)

**ScopeGuard** (`middleware/scopeGuard.ts`, `getInstance()`): fail-closed in-scope check,
DNS CNAME following, private-IP blocking. Called before **every** outbound probe in the
engine, in PostExploitAgent, and in L1 of the orchestrator. **Governance rule: never
weaken it.**

**Governance subsystem** — import the singletons from `server/src/governance` (the index):
- `coreGovernance` — central decision/audit recorder; broadcasts `governance:event` over Socket.IO.
- `decisionLogger` — crash-safe WAL → daily NDJSON.
- `selfAttestationService` — records *why* each agent acted.
- `driftDetector` — rolling snapshots; `analyze()` compares recent vs baseline windows for behavioral drift.
- `promptInjectionDetector` — `detect(input)`; **safe = score < 40**; 4 detector layers
  (keywords/patterns/semantic/structural). Used on LLM *output* in HunterEngine + VerifierAgent.
- `governanceImmunizer` (in `lib/governance/`, **not** re-exported by the index) — a 90s
  watchdog that hashes a frozen policy baseline and tier-escalates `none→warn→clamp→full_reset`
  if governance silently weakens (block-rate collapse, a high-sensitivity pillar going silent,
  or a hash mismatch). Publishes governance signals on **`huntCortex`** (the platform signal bus).

DB persistence: `governance_baselines`, `governance_snapshots`, `immunization_events`.

> Governance rule: **do not remove or weaken** the immunizer, drift detector, or decision logger.

---

## 10. REST routes (all under `/api`, all `requireAuth` except where noted)

`auth` (no auth), `hunt`, `bounty`, `orchestration`, `hunter`, `governance`, `missions`,
`bounty-intelligence`, `reasoning`, `graph`, `intelligence`, `juiceshop`, `xbow`,
`settings`, `chat`, `tools`, `ctf`, `adaptive-scan`, `findings`, `evidence`,
`report-export`, `exploit`.
Plus public `app.all("/api/callback/:beaconId")` (OOB receiver, per-IP limited) and `/health`.

Key endpoints to know:
- `POST /api/hunt/start` — direct engine hunt (Path B).
- `POST /api/hunt/findings/:id/verify` — **the finding "Verify" button** (manual re-verify).
- `POST /api/orchestration/run` — orchestrated hunt (Path A).
- `POST /api/exploit/demonstrate/:findingId` — manual PostExploit run.

---

## 11. Verification wiring (what we fixed this session — read before touching verify)

Shared helper: **`server/src/lib/verification/verify-finding.ts`**
- `deriveVerificationUrl(finding, fallbackUrl)` — reconstructs a **real http(s) URL** to
  re-probe: tries `affectedUrl`, then scans `evidence` JSON for a same-host URL, then the
  title, then falls back. (The old manual endpoint passed the numeric `targetId` as the
  URL — L2/L3 had nothing valid to hit.)
- `verifyAndPersistFinding(verifier, finding, fallbackUrl)` — builds a `mockResult` with the
  real URL in **both `endpoint` and `request`** (L2 replays `request`; empty `request`
  short-circuited L2 to "No replayable URL"), calls `verify()` with
  **`{ skipDedupHash: finding.dedupHash }`** (so re-verify isn't rejected as a self-duplicate),
  persists verdict/log/confidence/dedupHash.
- `verifyPendingForSession(verifier, sessionUuid, fallbackUrl)` — looks up the session,
  verifies each non-`confirmed` finding **sequentially** (avoids N concurrent Playwright
  replays), returns `{verified, confirmed}`.

Used by:
- **Auto-verify (Path B):** both `hunt:complete` handlers in `hunt.ts` now emit
  `hunt:verifying`, call `verifyPendingForSession()`, emit `hunt:verification_complete`.
- **Manual verify button:** `POST /api/hunt/findings/:id/verify` now looks up the real
  target URL and calls `verifyAndPersistFinding()`.

**The Layer-1 self-dedup fix (latest commit):** the first verification adds a finding's
hash to L1's in-memory `hashCache`. Clicking "Verify" again matched that hash → false
`rejected`. `verify(result, { skipDedupHash })` skips L1 when the computed hash equals the
finding's own stored `dedupHash`. The **hunt loop never passes `skipDedupHash`**, so
cross-hunt dedup is unchanged.

---

## 12. Socket.IO events (client ↔ server)

Connection requires an authenticated session (`io.use` gate). Handlers:
- `subscribe:hunt` → joins `hunt:<uuid>`, replays state from `activeHuntSessions`.
- `subscribe:orchestration` → orchestration room.
- `orchestration:run` → builds orchestrator, forwards `orchestration:*` / `l4:*` / `l5:*` / `l6:*` / `hunt:*`.
- `hunt:start` → new HunterEngine, `wireHuntEngineToSocket`, registers in `activeHuntSessions`.
- `solver:spawn` → new `SolverPool(8)`, forwards solver events.
- **PTY terminal:** `terminal:create` (spawns `$SHELL || /bin/bash` via node-pty), `terminal:input/resize/destroy`; killed on `disconnect`.

Hunt event names the client listens for: `hunt:started/phase/observations/hypotheses/probing/probe_result/ai_reasoning/finding_confirmed/impact_demonstrated/budget_exhausted/hard_banned/complete`, plus the auto-verify pair `hunt:verifying` / `hunt:verification_complete`.

---

## 13. Client (React, Vite, port 5173)

Pages (`client/src/pages/`):
- **`HuntConsole.tsx`** — live OHPU loop view (the hunt console).
- **`Orchestration.tsx`** — the 6-layer pipeline view.
- **`TerminalPage.tsx`** — xterm.js PTY terminal over Socket.IO.
- **`Findings.tsx`** — findings list + the **VERIFY** button (single + bulk). Calls
  `hunterAPI.verifyFinding(id)` → `POST /api/hunt/findings/:id/verify` (see `client/src/lib/api.ts`).
- `Hunter.tsx`, `Missions.tsx`, `Bounty.tsx` (→ `BountyViewRouter`), `Dashboard.tsx`,
  `Intelligence.tsx`, `Reports.tsx`, `Programs.tsx`, `Tools.tsx`, `Settings.tsx`, `Login.tsx`.

Components: `LiveActivityFeed.tsx` (renders hunt events), `FloatingChat.tsx`,
`bounty/*` (large workspace: PoCLab, Submissions, DraftReports, CTFBenchmark, ScopeManager,
HuntReplay, CVEIntel, AuditTrail, ...), `missions/*` (MissionBoard, LiveHuntMonitor,
AttackPathVisualizer, ...).

> Note: a *second* verify path exists in `bounty/CTFBenchmark.tsx` → `POST /api/findings/verify-browser`
> (browser-oracle for CTF benchmarking). The normal finding button is `/hunt/findings/:id/verify`.

---

## 14. Database schema (`db/schema.ts`, PostgreSQL/Drizzle, 20 tables)

Hierarchy: `programs → targets/campaigns → huntSessions → findings/solverResults`.
Run `npm run db:push` from `server/` after schema edits.

Key tables:
- **`programs`** — `id`, `name`, `platform`, `programHandle`, `scope`/`outOfScope` jsonb,
  payout/ROI metrics, `active`, `authConfig` (typed jsonb). **`programId -1` = local lab.**
- **`targets`** — FK `programId`; `url`, `type`, `fingerprint`, `attackSurface`, `priority`, `status`.
- **`campaigns`** — FK `programId`; `goal`, `status`, `huntMode`, `strategy`, `budget` jsonb, `progress`.
- **`huntSessions`** (`hunt_sessions`) — FKs `campaignId`/`targetId`; `sessionUuid` (unique),
  `phase`, jsonb loop state (`hypotheses/observations/probes/reasoningLog/solverResults`), `status`.
- **`findings`** — FKs (nullable) `campaignId/huntSessionId/targetId`; `title`, `vulnType`,
  `severity`, `confidence`, `cvssScore`, `evidence` jsonb, `exploitPayload`, **`affectedUrl`**
  (re-probed by verifier), **`verificationStatus`** (default "pending"), **`verificationLog`**,
  **`dedupHash`** (unique), `status`, `disclosureCheckStatus`/`publicDisclosureUrl`,
  OOB cols (`oobBeaconId/oobHitReceived/oobHitAt`), `cweId`/`cveId`, `nucleiTemplate`,
  `reportDraft`, `submittedAt`.
- **`solverResults`**, **`exploitChains`**, **`attackPlans`**, **`customTools`** (runtime-addable
  Kali tools), **`reinforcementStore`** (RL key/value), **`autonomyMetrics`**,
  **`scrapedIntelligence`** (RAG), **`wafProfiles`**, **`egressRouteMetrics`**,
  **`missionMemorySnapshots`**, governance: **`governanceBaselines`/`governanceSnapshots`/`immunizationEvents`**.

---

## 15. Context files (read by the CLI-invoked Claude)

Written at runtime by `context-writer.ts`:
```
context/hunt-live.json       # current phase, iteration, finding count, errors
context/hunt-findings.json   # all confirmed findings so far
context/errors.jsonl         # real-time error log (tail -f)
context/claude-tasks.jsonl   # prompts the engine sent to Claude (CLI bridge appends here)
```
These are how the `claude --print -p` bridge gets live hunt state prepended to its prompt
(`reasonWithHuntContext`).

---

## 16. Known gotchas / things commonly misinterpreted

1. **Two entry paths (Path A vs B).** Verification, disclosure checks, reporting only run
   automatically in Path A's Layer 5 — Path B relies on the auto-verify pass we added in
   `hunt.ts`. Change verification in both places.
2. **Port is 3001, not 3000.** CLAUDE.md is stale on this.
3. **Claude is tier 0 (first), not Ollama.** ModelRouter is Claude-first by design.
4. **The circuit breaker only gates Ollama.** "Circuit OPEN" never blocks Claude.
5. **L1 dedup `rejected` ≠ "not a vuln."** It means "we've seen this hash." Re-verify uses
   `skipDedupHash` to avoid self-collision.
6. **VerifierAgent authority is by DISCOVERY method, not just class.** Three categories:
   stateful agent-discovered (`discoveryTool === "logic_exploit_agent"` → L2 barred, L4 over
   captured proof); `xss`/`dom_xss` (L3 mandatory); HTTP-observable (L2 authoritative). A bare
   stateless L2 GET **cannot** verify a stateful idor/auth_bypass/business_logic finding —
   that was the root verification bug. A browser-verifiable finding is *never* auto-confirmed
   when Playwright is offline.
7. **L4 `errored` routes to `inconclusive`, never auto-reject.** A dead reasoning backstop
   must not refute a possibly-real finding.
8. **Post-exploit escalation is deferred to verification (was a latent bug, now fixed).**
   `persistFinding()` returns the new row id; the impact escalation is **stashed** in
   `evidence` as `{type:"impact_escalation",...}` during `update()` and applied to
   `severity/cvssScore/impact` **only on a `confirmed` verdict** via `pendingEscalation()`
   at both verify sites. (The old code keyed the patch on `findings.dedupHash = hypothesis.id`
   — a UUID against a null column — so it silently never persisted; the interim "fix" that
   keyed on `findings.id` then inflated severity on *unverified* findings. The stash-and-apply
   ordering resolves both.)
9. **`CampaignOrchestrator` has no singleton.** It's `new`-ed per run; don't look for a shared instance.
10. **Governance import surface:** singletons come from `server/src/governance` (index), but
    `governanceImmunizer` lives in `server/src/lib/governance/` and is imported separately.
11. **Budget is accounted across engine + SolverPool** in L4 (pre-charge) — don't reset it.
12. **`skipDedupHash` is a precise key match**, not a flag — it only skips L1 when the
    computed hash equals the finding's own stored hash, so it can't be abused to bypass dedup
    for genuinely new findings.

---

## 17. Governance rules (hard constraints — do not violate)

- Never weaken `server/src/middleware/scopeGuard.ts`.
- Never remove the budget guard in `CampaignOrchestrator.ts`.
- Never bypass the Playwright verification gate in `VerifierAgent.ts`.
- Never remove/weaken the immunizer, drift detector, or decision logger in `server/src/governance/`.

---

## 18. Running & debugging

```bash
npm run dev            # server (3001) + client (5173)
npm run dev:server     # server only
cd server && npx tsc --noEmit   # type check (a moduleResolution=node10 deprecation warning is expected/benign)
cd server && npm run db:push    # push schema changes

# Live state
cat context/hunt-live.json | jq .
cat context/hunt-findings.json | jq .
tail -f context/errors.jsonl

# Start a local hunt (programId -1 = local lab). Direct engine (Path B):
curl -X POST http://localhost:3001/api/hunt/start \
  -H "Content-Type: application/json" \
  -d '{"programId":-1,"targetUrl":"http://localhost:3000","mode":"forward","maxIterations":10}'

# Ollama health (local fallback tier)
curl http://localhost:11434/api/tags | jq '.models[].name'
```

---

## 19. Recent work on this branch (`claude/debug-visibility-issue-0in6N`)

1. **PostExploitAgent** built + wired non-blocking into `HunterEngine.update()` + REST route `/api/exploit/demonstrate/:id`.
2. **ARCHITECTURE.md** authored, then corrected (Claude-first routing; verifier only at L5; L5 reject now writes DB).
3. **ClaudeClient.reason** got a 90s hard timeout.
4. **CampaignOrchestrator L5 rejection** now persists the verdict to the DB row (was in-memory only).
5. **Verification pipeline fixed:** shared `verify-finding.ts` helper; Path B (forward + backward) auto-verify on `hunt:complete`; manual verify endpoint now uses a real URL (was passing numeric `targetId`); `request` field populated so L2 actually replays.
6. **Layer-1 self-dedup fix:** `verify(result, { skipDedupHash })` so re-verifying a finding isn't rejected as its own duplicate.
7. **Post-exploit severity escalation — key fixed, then ordering fixed:** `persistFinding()` returns the DB row id; the impact patch first moved from `eq(findings.dedupHash, hypothesis.id)` (UUID vs null column, silent no-op) to `eq(findings.id, dbFindingId)`. That surfaced a sequencing trap (escalation persisted before verification), so escalation is now **stashed in evidence and applied only on a `confirmed` verdict** via `pendingEscalation()` at both verify sites (Path B helper + Path A L5).
8. **Backward hunt auto-verify added:** the backward hunt `hunt:complete` handler was missing the auto-verify IIFE that the forward hunt had — backward-mode console hunts never ran the 4-layer pipeline.
9. **Nuclei template + report URL fields fixed:** `POST /findings/:id/nuclei-template` and `POST /findings/:id/report` were passing `String(finding.targetId)` (e.g. "5") as the `endpoint` and `targetUrl` for the mock `SolverResult`. Templates were targeting a numeric DB id rather than the actual URL. Fixed to `finding.affectedUrl`.
10. **CLAUDE.md port corrected:** server defaults to 3001, not 3000. The Juice Shop `targetUrl` in the curl example remains `:3000` (Juice Shop's own port).
11. **Stateful verification mismatch fixed (root bug):** stateless L2 reprobe no longer votes on `idor`/`auth_bypass`/`business_logic` findings discovered by the Claude-directed Playwright agent — authority passes to L4 over the captured proof. The `xss`/`dom_xss` L3 mandatory gate is untouched. (§6.)

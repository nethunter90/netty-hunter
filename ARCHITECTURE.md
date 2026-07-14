# NETTY-HUNTER — COMPLETE ARCHITECTURE REFERENCE

> Reflects the code as it actually is on `claude/debug-visibility-issue-0in6N` (audited
> section-by-section against source in July 2026). Where this contradicts CLAUDE.md or
> older mental models — e.g. "Ollama is the fallback model" or "there's a CTF benchmark
> page" — this file wins. See `HANDOFF.md` for a more narrative walkthrough and
> `BUILD_JOURNAL.md` for the historical why.

---

## TOP-LEVEL DIRECTORY STRUCTURE

```
netty-hunter/
  server/                         # Node.js / Express backend (TypeScript)
  │  src/
  │  │  index.ts                  # App entry: Express, Socket.IO, PTY terminal, all routes
  │  │  agents/                   # HunterEngine, CampaignOrchestrator, VerifierAgent,
  │  │  │                         #   SolverPool, PostExploitAgent, LogicExploitAgent, SynthesisAgent
  │  │  intelligence/              # ModelRouter (Claude-only), ROI/autonomy/RL, PromptKnowledgeBase
  │  │  lib/                      # tools/ (40+ probers), stealth/ (23 files), hunter/, governance/,
  │  │  │                         #   orchestration/ (unwired — see note below), recon/, oob/, shell/
  │  │  routes/                   # 18 Express route handlers (see boot section)
  │  │  db/                       # Drizzle ORM schema (22 tables) + migrations
  │  │  middleware/               # scopeGuard.ts — fail-closed scope enforcement
  │  │  governance/               # Policy enforcement, audit trail, drift detection, immunizer
  │  │  utils/                    # Logger
  │  │  workers/                  # Playwright worker thread (VerifierAgent Layer 3)
  │  │  fixtures/                 # Deterministic vulnerable fixture apps for prober tests
  │  └─ __tests__/                # Vitest unit tests
  client/                         # React + TypeScript frontend (Vite, port 5173)
  │  src/
  │  │  pages/                    # 14 page components (no CTF/XBOW/JuiceShop pages — removed)
  │  │  components/               # LiveActivityFeed, FloatingChat, AttackPathVisualizer,
  │  │  │                         #   bounty/ (22 files), missions/ (9 files), ui/ (shadcn primitives)
  │  │  context/                  # SocketContext (global Socket.IO connection)
  │  │  hooks/                    # use-toast
  │  │  lib/                      # API bindings, socket factory, event bridges, utils
  │  └─ services/                 # HTTP API service layer
  context/                        # Runtime state files (written during hunts, read by Claude)
  server/data/prompts/            # ~1785+ security Q&A entries used for RAG
  scripts/                        # Build / setup / dataset-expansion scripts
```

**Note on `lib/orchestration/`:** this directory (`layer1..6-*.ts`, `mission-chain-manager.ts`,
etc.) exists and is a fully-built alternate 6-layer implementation with its own Ollama-calling
`callOllama()` bridge — but it is **not wired into anything**. `CampaignOrchestrator.ts` has its
own identically-named layer methods (`layer4_executionEngine`, `layer5_verificationGate`, ...)
that do not import from this folder, and nothing outside `lib/orchestration/` imports it either.
Treat it as dead/orphaned code, not a second live pipeline.

---

## SERVER ENTRY POINT: index.ts

**Boot sequence (in order):**
1. `dns.setDefaultResultOrder("ipv4first")` — Node resolves `localhost` to `::1` first by
   default, but IPv4-only dev targets (Replit/Flask/Express) never respond to that; this
   forces IPv4 resolution first for every outbound call the server makes.
2. Create `logs/` dir if missing.
3. Load persisted settings from DB (`reinforcement_store` rows) → `RuntimeConfig` (async).
4. `initLearningSchema()` — creates the self-bootstrapped learning tables (async).
5. `checkBinariesAtStartup()` — logs which Kali/CLI tools are actually present (async).
6. `initializeAutonomousBrain()` (sync).
7. Create Express app + HTTP server; `PORT = parseInt(process.env.PORT || "3001")`.
8. Create Socket.IO server; `app.set("io", io)`; wire egress-allocator emitter.
9. Middleware stack (below); route mounts (below); OOB callback endpoint; `/health`; 404; error handler.
10. Socket.IO `connection` handlers (below).
11. Scheduled re-scan `setInterval` (every 15 min); writeup scraper (`setTimeout` 30s, then every 24h).
12. `httpServer.listen(PORT)`.
13. `checkPlaywrightHealth()` (async, after listen) — a standalone browser-launch check
    independent of VerifierAgent's own worker, so a broken Playwright install is visible in
    the startup log immediately rather than discovered mid-hunt.

**Middleware stack (in order):**
```
helmet()                                     (CSP disabled)
cors()                                       (origin: CLIENT_URL || http://localhost:5173)
express.json / express.urlencoded            (10mb limit)
Production SESSION_SECRET guard              (refuses to boot without it in prod)
PostgreSQL-backed session (connect-pg-simple), shared into Socket.IO via io.engine.use(...)
Socket.IO auth gate: io.use(...) rejects any connection without session.userId
requireAuth                                  (applied per-route below)
Rate limiters: apiLimiter (/api), huntLimiter (/api/hunt/start), orchestrationLimiter (/api/orchestration/run)
```

**Route mounts (18 total, all `requireAuth` except `/api/auth`):**
```
/api/auth                 authRoutes                (no auth required)
/api/hunt                 huntRoutes
/api/bounty               bountyRoutes
/api/orchestration        orchestrationRoutes
/api/hunter               hunterRoutes
/api/governance           governanceRoutes
/api/missions             missionsRoutes
/api/bounty-intelligence  bountyIntelligenceRoutes
/api/reasoning            reasoningRoutes
/api/graph                graphRoutes
/api/intelligence         intelligenceRoutes
/api/settings             settingsRoutes
/api/chat                 chatRoutes
/api/tools                toolsRoutes
/api/findings             findingsRoutes
/api/evidence             evidenceRoutes
/api/report-export        reportExportRoutes
/api/exploit              exploitRoutes             ← PostExploitAgent
```
`ctf`, `xbow`, `juiceshop`, and `adaptive-scan` are **gone** — removed 2026-07-08 along with
the unused CTF/XBOW/JuiceShop benchmark feature (`CTFBenchmark.tsx`, docker-lab modules).
Do not re-add references to them.

**OOB callback server:** `app.all("/api/callback/:beaconId", ...)` — no auth, per-IP rate
limited, mounted separately for external beacon hits (blind SSRF/XXE/RCE/deserialization confirmation).

---

## CORE AGENT LAYER: server/src/agents/

### HunterEngine.ts — The Main Loop (~3,870 lines)

The entire hunt runs inside one `runLoop()` call. It is a `while` loop bounded by:
- `iteration < maxIterations`
- `requestsMade < budget.maxRequests`
- `elapsed < budget.maxTime`
- `!this.hardBanned` (network-level IP block detected)

It calls `yieldToEventLoop()` (`setImmediate`) between phases so concurrent hunts and
socket callbacks aren't starved during model inference.

**4-phase OHPU cycle per iteration:**

```
OBSERVE  →  HYPOTHESIZE  →  PROBE  →  UPDATE
   ↑                                      |
   └──────── next iteration ──────────────┘
```

#### Phase 1 — OBSERVE

Runs sequentially: `whatweb` (fingerprint) → `curl_probe` (headers/CORS) → `waf_intel`
(only if `wafBypassEnabled` for this hunt — otherwise skipped entirely, not just
gated by budget). Observations are pushed anomaly-score-sorted. Phase-0 passive recon
(crt.sh + Wayback CDX subdomain/URL discovery, started concurrently at `startHunt()`) is
injected as an observation once it resolves.

**First iteration only**, a large concurrent fan-out seeds hypotheses directly (one
`Promise.allSettled([...])` of ~20 probers, plus CVE seeding and GraphQL introspection run
separately just before it):
secret scanner, error-disclosure prober (provokes exceptions, scans error bodies for
leaked creds/paths — `secretScanner` itself skips non-200 responses), change detector,
websocket prober (raw `http`/`https` upgrade-event listener — not axios, which cannot
observe an HTTP 101), cloud bucket enumeration, prototype pollution, race condition
detection (bogus-baseline-diffed against a SPA catch-all), host header injection, CRLF
injection, cookie flag checking, JS/SPA deep crawl, backward-planner attack-path seeding,
tech-stack payload selection + probing (real tailored SSTI/RCE payloads per fingerprinted
framework, not just a description string), parameter discovery, OAuth probing
(baseline-diffed), mass assignment (baseline-diffed, per-HTTP-method), business logic
(control-probed against a baseline), 2FA bypass, JWT confusion, open-redirect chains,
blind XXE, **deserialization** (Java via ysoserial URLDNS OOB, PHP via phpggc gadget
chains OOB, both with a fingerprint-only fallback), **file-upload-to-webshell** (uploads
real PHP/JSP/ASP webshells across extension-filter bypass variants, confirms execution via
an arithmetic canary — not a reflected-substring match), **blind OS command injection**
(polyglot shell-breakout payload, OOB-confirmed with real exfiltrated `whoami`/`id`
output), and OWASP ZAP passive scan.

#### Phase 2 — HYPOTHESIZE

```
observations[] → ModelRouter.generate(prompt, "reason")
                      ↓
              Claude SDK (ClaudeClient.reason) → Claude CLI bridge → throw ClaudeUnavailableError
                      ↓
              Runs the model's OUTPUT through promptInjectionDetector (defense-in-depth)
              Parse JSON (capped 64KB) → Hypothesis[] with confidence scores
              Push to state.hypotheses[], sort by priority*confidence, cap MAX_HYPOTHESES=150
              Emit hunt:hypothesis_generated per hypothesis
              On total failure → generateDefaultHypotheses() (common-class fallback)
```

**`vulnClassAllowlist` vs `focusVulnClasses` — not the same mechanism:**
- `focusVulnClasses` is purely **additive**: `seedFocusHypotheses()` pushes new
  priority-9/confidence-0.6 *placeholder* hypotheses ("`X` is a priority for this hunt").
  It never excludes or touches any other hypothesis. (Their placeholder text gets replaced
  by `describeFromProbe()` once a real probe confirms them — see Phase 4.)
- `vulnClassAllowlist` is a genuine **hard exclusionary filter**, added to support
  RCE-only (or any single-class) hunts. The exported pure function
  `applyVulnClassAllowlist(hypotheses, allowlist)` marks every `pending` hypothesis whose
  `vulnClass` isn't in a non-empty allowlist as **`"deferred"`** — not dropped, not silently
  re-filtered, permanently visible as deferred. Applied at the very top of `probe()`, before
  the top-8-by-score slice is even built. Recon/discovery probers still run regardless of
  the allowlist, since any vuln class needs to know what endpoints exist. A bare `["rce"]`
  allowlist is almost never what you want — RCE chains through precursor classes (ssti,
  ssrf, lfi/rfi, auth_bypass, exposed_admin, prototype_pollution), so the UI hints at
  including those too.

**`truncationRank(h)`** — every `MAX_HYPOTHESES` truncation/splice site (4 of them) sorts by
this instead of raw `priority*confidence`: `(pending/probing ? 1_000_000 : 0) +
priority*confidence`. This exists because a resolved (confirmed/rejected/deferred)
hypothesis with a high raw score could otherwise permanently evict a still-pending one from
the 150-slot array — confirmed live to be starving allowlist-deferred-but-still-tracked
hypotheses out of existence across hunts.

#### Phase 3 — PROBE

```
Apply vulnClassAllowlist (deferred hypotheses excluded from this point on)
For each of the top-8 pending hypotheses (by priority*confidence):
    Abort check → budget pre-flight → failure-prediction skip (low P(success)) →
    ScopeGuard.isInScope(hypothesis.targetUrl, programId)   ← MANDATORY, fail-closed

    ── SELF_CONFIRMED_SOURCES short-circuit (fires FIRST, before anything else) ──
    If hypothesis.evidence[].source is one of the 16 self-confirming OBSERVE-phase
    probers (see list below), synthesize a successful ProbeResult directly from the
    already-captured evidence — these probers already did real, specific active testing
    at OBSERVE time with a hardcoded oracle (baseline diff, arithmetic canary, real OOB
    callback, ...) that no generic tool dispatch could replay. This must run before
    LogicExploitAgent too, which would otherwise "steal" e.g. JWT/2FA-tagged auth_bypass
    hypotheses and re-probe them with an unaware, structurally-blind Playwright session.
    ──────────────────────────────────────────────────────────────────────────────

    Else tech-payload-prober reprobe (ssti/exposed_admin — replays the exact original
    technique with a fresh random product, never a stale/guessable value)
    Else deserialize POST probe (rce/deserialization classes, Node node-serialize gadgets)
    Else LogicExploitAgent (Claude-directed Playwright) for business_logic/idor/auth_bypass
    Else SolverPool.dispatch() → generic tool selection (RL-weighted) → execFile → parse

    OOB beacon probe (only if the above found nothing AND vulnClass is
    ssrf/xss/sqli/rce/xxe — an authoritative confirming oracle, see below)

    Emit hunt:probing / hunt:probe_result; push ProbeResult; hypothesis.status = "probing"
```

**The 16 self-confirmed OBSERVE-phase probers (`SELF_CONFIRMED_SOURCES`):**
`race_condition_detector`, `cookie_flag_checker`, `host_header_probe`, `oauth_probe`,
`mass_assignment_probe`, `two_factor_bypass_probe`, `jwt_confusion_probe`,
`prototype_pollution_probe`, `cloud_bucket_probe`, `websocket_probe`,
`open_redirect_chain_probe`, `blind_xxe_probe`, `crlf_probe`, `deserialization_prober`,
`file_upload_webshell_prober`, `blind_command_injection_prober`.

**OOB beacon confirmation** (`runOOBProbe`, gated to `ssrf/xss/sqli/rce/xxe`): for `rce`
specifically, fires a bounded multi-vector burst (`buildRceOobAttempts()` — breakout
syntaxes `; | && $() `` \n `` across common param names, GET+POST, capped at 24 attempts)
each folding `$(whoami)` into the shared callback URL. A hit's `exfil` query params are
decoded into real command output (whoami/id), so a confirmed RCE finding carries actual
proof, not just "the callback fired." **A successful OOB hit is treated as an
authoritative confirming oracle** — it sets `ProbeResult.oobConfirmed = true`, which
downstream forces `success = true` regardless of the dispatched tool, and VerifierAgent's
final-verdict logic (see below) trusts it outright for the OOB-eligible classes, since a
fired callback is definitional proof of execution that a stateless HTTP reprobe
structurally cannot replay.

If the network drops hard (TCP RST/ICMP unreachable matching the canary hostname, or 5
consecutive tool failures followed by a 403/timeout canary), `this.hardBanned = true` and
the loop breaks immediately — distinguished from a plain loopback-target crash, which is
not treated as a ban.

#### Phase 4 — UPDATE

```
For each hypothesis where status === "probing":
    successful = relatedProbes where success === true
    If successful.length > 0:
        newConfidence = updateConfidence(hypothesis, successful)  ← AI-assisted

        If newConfidence > 0.7:
            hypothesis.status = "confirmed"
            hypothesis.reasoning = describeFromProbe(hypothesis, successful[0])
                ── replaces a seeded placeholder ("X is a priority for this hunt")
                   with what the successful probe actually observed; leaves real
                   prober-written reasoning untouched if evidence already exists ──
            confirmed = buildConfirmedFinding(hypothesis, successful)
            state.confirmedFindings.push(confirmed)
            Emit hunt:finding_confirmed
            dbFindingId = persistFinding(confirmed)      ← DB insert, called FIRST now
            contextWriter.addFinding({ ..., dbId: dbFindingId })  ← so a later Layer-5
                rejection can retractFinding(dbId) / updateFindingConfidence(dbId, ...)
                and hunt-findings.json stops silently showing a rejected finding as confirmed

            ── PostExploitAgent (non-blocking async) — see below ──

        Else if newConfidence < 0.2:
            hypothesis.status = "rejected"
        Else (0.2–0.7 gray zone):
            retryCount++; retry with alternate tool (up to 2), then "inconclusive"
```

After UPDATE, MetaReasoner (every 3rd iteration) evaluates hunt health and may inject a
strategy pivot via the backward planner.

---

### CampaignOrchestrator.ts — 6-Layer Pipeline

`export class CampaignOrchestrator extends EventEmitter` — **no module singleton**; every
launch path (`index.ts` REST + socket, `routes/orchestration.ts`) does `new
CampaignOrchestrator()` per run.

```
Layer 1 — l1_governance
  Resolve/find-or-create program (programId -1 → synthetic local-lab program)
  ScopeGuard.validate() — fail-closed
  BUDGET GUARD: budget = params.budget || {maxRequests:2000, maxTime:3600}
                rejects if maxRequests outside [10, 50000]      ← NEVER REMOVE
  Create/resume campaign; reconcile findingsCount; register target row
  FAIL → abort with governance rejection

Layer 2 — l2_intelligence
  ROIModel.rankVulnClasses(); TargetSelectionIntelligence.scorePrograms()
  priorityVulns = focus override or top-8
  FAIL → abort (no viable targets)

Layer 3 — l3_strategy
  Backward: BackwardHuntEngine.createPlan() (falls back to forward if 0 viable paths)
  Forward: HuntStrategyBuilder.build()
  Persists strategy to campaign row
  FAIL → abort (no viable strategy)

Layer 4 — l4_execution
  new HunterEngine(...), wired events, startHunt({ ..., vulnClassAllowlist,
      wafBypassEnabled, ... }), awaits hunt:complete
  SolverPool supplement when findings sparse + budget remains — pre-charged with
      engine spend so it draws from remaining quota, no double-spend
  Abbreviated sub-hunts on discovered subdomains (concurrency 2)
  FAIL → partial (findings from completed iterations saved)

Layer 5 — l5_verification
  Per finding: VerifierAgent.verify(mockResult) — 4-layer pipeline (see below)
  Confirmed → disclosure check, screenshot archive, DB write (status/log/confidence/
      dedupHash/cweId), NVD CVE enrichment, optional report submission
  Rejected/inconclusive → DB write (never left as "pending")
  Idempotent resume: already-confirmed findings promoted to "verified" without re-running
  FAIL (rejected) → finding marked rejected, not silently dropped

Layer 6 — l6_harvest
  Draft reports + Nuclei templates per verified finding
  RL / bounty-intel / autonomy updates, confidence calibration, exploit-chain extraction
  COMPLETE → campaign status = completed
```

Each layer emits `orchestration:layer_start/layer_complete/layer_error`. Also emits
`l4:*` (re-broadcast hunt events), `l5:verifying/verified/rejected/public_duplicate/
report_submitted/report_submit_failed`, `l6:report_generated/autonomy_updated/
chains_extracted`, and publishes to a shared `eventBus` (`vulnerability_found`,
`finding_verified`, `finding_rejected`). Note: `routes/orchestration.ts`'s Socket.IO
re-broadcast only forwards a subset of these — some `l5`/`l6`/`orchestration:*` events
are internal-only unless that route is extended.

---

### VerifierAgent.ts — 4-Layer Anti-Hallucination Pipeline

**POSITION: Layer 5 of CampaignOrchestrator only.** Findings from HunterEngine are
persisted as `verificationStatus:"pending"`; VerifierAgent runs post-hoc when the
orchestrator reaches L5. Hunts launched via `/api/hunt/start` standalone (Path B, no
orchestrator) get an **auto-verify pass** on `hunt:complete` instead (a shared helper,
`verifyPendingForSession()` in `lib/verification/verify-finding.ts`) — see HANDOFF.md §11
for the exact wiring if you're touching this.

```
Layer 1 — Static Dedup
  SHA-256 hash of {endpoint (no query), vulnClass, payload[:100]} + endpoint-anchored SimHash
  In-memory cache (preloaded with last 500 DB hashes) + DB check
  Blocks ONLY on a prior CONFIRMED verdict for this hash — a rejected/inconclusive prior
      attempt no longer permanently blocks retrying the same finding after a verifier fix.
  dedupHash is only persisted to the findings row on an actual confirmation
      (recordIfConfirmed()) — not on every novel hash seen.
  options.skipDedupHash: when it equals the finding's own stored dedupHash, skips all
      three dedup checks entirely — lets a manual re-verify avoid self-collision.
  Duplicate → immediate { verdict: "rejected" }

Layer 2 — Dynamic Reprobe (HTTP-observable classes)
  Replays result.request (falls back to result.endpoint); class-specific signal checks
      (rce nonce-echo oracle, xss/sqli/ssrf/lfi/rfi content checks, generic status<400 else)

Layer 3 — Playwright Browser Replay (xss / dom_xss ONLY)
  Worker thread, 35s timeout. layer3Available distinguishes "offline" from "unconfirmed".
  MANDATORY for xss/dom_xss — never auto-confirmed without a real browser execution.

Layer 4 — AI Confirmation
  ClaudeClient with vision analysis of the L3 screenshot when available
  Screens the response through promptInjectionDetector before trusting it
  L4 errors → routes to "inconclusive", never auto-rejected (a dead reasoning backstop
      must not refute a possibly-real finding)

Final verdict — FOUR oracle-authority categories, checked in this order:

  1. Browser-verifiable (xss, dom_xss):
       L3 confirmed             → "confirmed" (+L4 bonus if it also agrees)
       L3 not confirmed, L4 yes → "inconclusive" (human review)
       L3 not confirmed, L4 no  → "rejected"
       Playwright offline       → "inconclusive" (never auto-confirmed)

  2. OOB-confirmed (result.oobConfirmed === true, and vulnClass in
     {rce, ssrf, xxe, sqli, rfi, ssti}):
       → "confirmed", unconditionally. A fired OOB callback is definitional proof of
         execution; L2 can't "recheck" a beacon that already fired, so it's barred from
         voting here and L4 dissent doesn't downgrade it.

  3. Stateful agent-discovered (discoveryTool === "logic_exploit_agent" — i.e. idor,
     auth_bypass, business_logic findings that only exist inside a live multi-step /
     multi-identity browser session):
       L2 is barred from voting (a contextless GET falsely rejects auth_bypass on
       401/403 and falsely confirms idor on a bare 200). Authority passes to L4 over the
       captured rawHttpLog from the original Playwright discovery run.
       L4 confirmed → "confirmed". L4 dissent/error → "inconclusive", never auto-reject.

  4. Everything else (HTTP-observable):
       L2 && L4 confirmed → "confirmed"
       L2 || L4 confirmed → "inconclusive" (one signal, needs review)
       neither confirmed  → "rejected"

  L4 errored + verdict would be "rejected" → bumped to "inconclusive" in all four cases.

Rejection and inconclusive verdicts both write back to the DB row's verificationStatus —
neither is left as the default "pending".
```

**Note on self-confirmed probers and VerifierAgent:** the 16 `SELF_CONFIRMED_SOURCES`
probers get **no special treatment** here — by the time a hunt reaches L5, they're an
ordinary finding whose `discoveryTool` simply isn't `"logic_exploit_agent"`. They fall
into category 2 (if OOB-backed, e.g. deserialization/blind command injection) or category
4 (HTTP-observable, e.g. mass assignment, race condition) like anything else. The
short-circuit in HunterEngine only prevents wasted/incorrect re-dispatch during PROBE —
it doesn't grant an exemption from verification.

---

### SolverPool.ts — Parallel Probe Dispatch

Unchanged in shape from prior versions: `dispatch(task)` → p-queue (configurable
concurrency) → tool selection from `ToolKnowledge` by vulnClass → `PayloadMutator`
(tech-stack aware) → behavioral-mimicry headers + per-domain rate limiter →
`execFile(bin, args)` (never shell interpolation) → tool-specific parser →
`SolverResult { found, confidence, evidence, payload, request, response }`. Does **not**
make strategy decisions — it only executes what HunterEngine dispatches.

### WAFBypass.ts (IntelligenceSynthesizer)

Runs inside PROBE when a WAF was detected during OBSERVE — but OBSERVE's `waf_intel` step
itself now only runs when `wafBypassEnabled` is set for the hunt (a per-hunt opt-in toggle;
`programs.wafBypassPolicy` can hard-block it at "disallowed" regardless of the per-hunt
choice). Techniques: encoding mutations, header spoofing, payload fragmentation, timing
variation — fed back to SolverPool as alternate payloads.

### PostExploitAgent.ts — Bounded, Read-Only Impact Demonstration

Runs non-blocking after a finding confirms (`HunterEngine.update()`) and from the manual
`POST /api/exploit/demonstrate/:findingId` route. Hard limits: 4 steps max, 8s/step, 30s
total wall-clock. Every outbound URL is re-validated through `ScopeGuard` (fail-closed) —
this is intentional double-validation with the original probe's own scope check, not a bug.

Per-class probes (read-only only — sqli/rce/xss get no replay, left to AI narrative):
`ssrf` → cloud metadata + internal reach; `lfi` → /etc/passwd, /etc/hostname;
`idor` → adjacent-ID walk; `auth_bypass`/`exposed_admin` → strip auth + re-request;
`open_redirect` → inject + check Location (no-follow); `info_disclosure`/`misconfig` →
secret/credential regex.

**Escalation ordering (subtle, was a real bug):** PostExploitAgent runs *before*
verification completes. It does not write severity/CVSS directly — it **stashes** the
proven escalation as an `{type:"impact_escalation", ...}` entry in the finding's
`evidence`. The bump to `severity`/`cvssScore`/`impact` is applied **only on a `confirmed`
verdict**, by `pendingEscalation()` in `verify-finding.ts`, at both verify sites (the Path
B auto-verify helper and CampaignOrchestrator's L5). This prevents inflating severity on a
finding the verifier later rejects.

---

## INTELLIGENCE LAYER: server/src/intelligence/

### ModelRouter.ts — Claude-Only Tier Routing (Ollama fully removed)

**Ollama is gone from the reasoning path.** A 2026-06-26 change ("drop Ollama entirely in
favor of Claude-only routing") removed the Ollama fallback and vision support from
`ModelRouter`, `HunterEngine`, and `VerifierAgent`. There is **no circuit breaker in
ModelRouter anymore** — that concept doesn't apply once there's only one provider.
(A same-named but unrelated `circuit-breaker.ts` exists in `lib/intelligence/` — it gates
recon **tool** selection, e.g. skipping a nuclei/nmap/ffuf/nikto invocation whose circuit
has tripped, and has nothing to do with LLM routing.)

```
reason / analyze:
    Claude SDK Sonnet — ClaudeClient.reason(sessionId, prompt)
        On failure → fall through
    Claude CLI bridge — ClaudeBridge.reasonWithHuntContext(prompt)
        execFile("claude", ["--print", "-p", prompt], { timeout: 120_000 })
        logs to context/claude-tasks.jsonl
        On failure → throw ClaudeUnavailableError

classify / chat / summarize / code:
    Claude Haiku — ClaudeClient.oneShot(systemPrompt, prompt)
        On failure → throw ClaudeUnavailableError

Vision / screenshot description: NO PATH EXISTS. There is no vision task type and no
    describeScreenshot() anymore — it was removed with Ollama, which was the only vision
    provider. Do not assume screenshots get AI-described outside of VerifierAgent's L4,
    which still passes a screenshot directly to Claude's vision-capable messages API.
```

Claude failures now **abort loudly** (`ClaudeUnavailableError`) instead of silently
degrading to generic default hypotheses — a deliberate trade of graceful-but-silent
degradation for honest, visible failure. This is intentional, not a regression: local
models could not reliably complete real hunts solo, so Claude-first became Claude-only.

**Dead but harmless leftovers, not part of the live routing path:** a few files still
reference "ollama" in comments or field names (`chat.ts`, `observation-ingestion.ts`,
`ReinforcementStore.ts`) without making any real Ollama HTTP call; `settings.ts` and
`runtime-config.ts` still declare `OLLAMA_BASE_URL`/`OLLAMA_DEFAULT_MODEL` config keys that
nothing reads anymore. Two genuinely-live Ollama HTTP clients remain in the codebase —
`JsonPromptLoader.ts`'s embedding call (`/api/embeddings`, used for RAG corpus retrieval,
unrelated to reasoning) and `lib/orchestration/layer6-ai-bridge.ts`'s `callOllama()` — but
the latter belongs to the orphaned `lib/orchestration/` module described above and is not
reachable from any live code path.

### ClaudeClient (`lib/claude-client.ts`)
- `reason()`: `claude-sonnet-4-6`, per-hunt conversation thread (trimmed to 20 msgs), **90s
  hard timeout** on `messages.create()`.
- `oneShot()`: `claude-haiku-4-5`, stateless.
- Per-hunt LLM call budget: `MAX_LLM_CALLS_PER_HUNT` (default 150, env-overridable),
  enforced via `tryConsumeBudget()` — every Claude caller (including LogicExploitAgent)
  funnels through this one counter. Exceeding throws `LLMBudgetExceededError`.

### ClaudeBridge (`lib/claude-bridge.ts`)
Still present as the CLI fallback tier: `execFile("claude", ["--print", "-p", prompt],
{ timeout: 120_000 })`, logs every call to `context/claude-tasks.jsonl`.

### PromptKnowledgeBase.ts
Expert prompt templates covering recon, scanning, exploitation (SQLi, XSS, SSRF, IDOR,
auth bypass), credential testing, intelligence gathering, CVSS scoring, and report writing.

### Other Intelligence Exports

| Class/File | Purpose |
|---|---|
| `ExploitChain.ts` + `ATTACK_TREES` | Predefined multi-step exploitation trees |
| `ROIModel.ts` | Score programs/vuln-classes by payout / response time / success rate |
| `BackwardHuntEngine.ts` | Reverse-engineer attack path from a confirmed finding |
| `TargetSelectionIntelligence` | Rank targets within a program |
| `AutonomyTracker` | Autonomy maturity level (L0–L5); per-domain natural ceilings |
| `ReinforcementStore` | Persist RL signals to DB for cross-hunt learning |
| `NucleiGenerator` | Auto-generate Nuclei templates from confirmed findings |
| `ReportGenerator` | Draft bug bounty report (markdown + structured JSON) |
| `MetaReasoner` | Evaluate hunt health, recommend strategy pivots |
| `ObservationCompressor` | Trim `state.observations[]` to stay within LLM context |

---

## DATABASE SCHEMA: server/src/db/schema.ts

All tables use Drizzle ORM. PostgreSQL only. 22 declared tables plus a `sessions` table
created ad-hoc by `connect-pg-simple` (not in `schema.ts`).

```
users                 id, username, passwordHash, role, createdAt
programs               id, name, platform, programHandle, scope[], outOfScope[],
                       maxPayout, roiScore, active, authConfig (typed jsonb)
                       — programId -1 = synthetic local-lab program
targets                id, programId, url, type, fingerprint, attackSurface, priority, status
campaigns              id, programId, goal, status, huntMode, strategy, budget, progress
huntSessions           id, campaignId, targetId, sessionUuid (unique), phase,
                       hypotheses/observations/probes/reasoningLog/solverResults (jsonb), status
findings               id, campaignId, huntSessionId, targetId, title, vulnType, severity,
                       confidence, cvssScore, description, evidence[], reproductionSteps[],
                       impact, remediation, cweId, cveId, exploitPayload, affectedUrl,
                       verificationStatus, verificationLog[], dedupHash (unique),
                       nucleiTemplate, reportDraft, submittedAt, status,
                       disclosureCheckStatus, publicDisclosureUrl, publicDisclosureNote,
                       oobBeaconId, oobHitReceived, oobHitAt, programId, createdAt, updatedAt
wafProfiles            id, vendor, targetDomain, detectionSignals, bypassTechniques,
                       blockedPatterns, evasionMatrix, blockRate
exploitChains          id, chainId, startVulnType, endVulnType, steps[], roiScore
attackPlans            id, campaignId, goal, plan (jsonb)
customTools            id, name, commandTemplate, parser, vulnClasses[]
solverResults          id, taskId, endpoint, vulnClass, found, confidence, evidence
reinforcementStore     id, domain, key, value
autonomyMetrics        id, domain, level, score, ceiling
scrapedIntelligence    id, source, content, embedding (RAG corpus)
governanceBaselines    id, hash, thresholds (jsonb), createdAt
governanceSnapshots    id, timestamp, pillarActivity, verdictRates (jsonb)
immunizationEvents     id, tier, reason, snapshot (jsonb), createdAt
egressRouteMetrics     id, route, health, burnCount
missionMemorySnapshots id, campaignId, state (jsonb)
decisionJournal        id, hunterSessionId, decision, outcome, weight
thresholdHistory       id, domain, threshold, changedAt
cortexSignals          id, sourceSystem, signal, value, timestamp
graphNodes             id, campaignId, nodeType, data (jsonb)     — attack graph
graphEdges             id, campaignId, sourceId, targetId, edgeType, weight
decisionTraces         id, campaignId, trace (jsonb)
sessions               (connect-pg-simple session store — not in schema.ts)
```

> `decisionJournal`/`thresholdHistory`/`cortexSignals`/`graphNodes`/`graphEdges`/
> `decisionTraces` are formal declarations for tables that the RL/governance/graph code
> also self-bootstraps at runtime — both need to agree, or `drizzle-kit push:pg` will
> propose dropping live tables it thinks are orphaned.

---

## LIVE HUNT STATE FILES: context/

Written continuously during active hunts. Read by Claude Code (via the CLI bridge, which
prepends this state to its prompt) and the frontend.

```
context/hunt-live.json      Current session id, phase, iteration, findings count,
                             active model, last error, budget used
context/hunt-findings.json  All confirmed findings: id, dbId, vulnClass, severity,
                             confidence, endpoint, payload, description, confirmedAt
                             — retracted via dbId if Layer 5 later rejects the finding
context/errors.jsonl        Append-only error log: { timestamp, phase, message, stack }
context/hunt-digest.txt     Single line: "Session X | Phase: probe | Iter 3/10 | 2 findings"
context/alerts.jsonl        Key events only: phase changes, new findings, hard bans
context/claude-tasks.jsonl  Every prompt sent to the Claude CLI bridge + truncated response
```

These are ephemeral — written at runtime, not committed to git, and do not persist across
server restarts (except whatever the DB independently holds).

---

## GOVERNANCE LAYER

### server/src/governance/

```
core-governance.ts    CoreGovernance — in-memory decisions[]/auditLog[] (capped 10k/50k),
                      recordDecision() computes risk, forwards to decisionLogger, broadcasts
                      governance:event over Socket.IO. verifyScope() defers to ScopeGuard.
decision-logger.ts    Crash-safe WAL (decisions-wal.ndjson) written before buffering,
                      flushed every 5s or 50 items to daily NDJSON files; replays WAL on boot.
drift-detector.ts     Periodic snapshots (default every 5 min); analyze() compares recent vs
                      baseline windows using PER-SNAPSHOT RATES (not raw counts — fixed after
                      a steady-but-busy prior session read as a false "drop" purely from
                      window-size mismatch). Minimum-sample floors before declaring drift:
                      ≥5 decisions for verdict-rate comparison, ≥3 for pillar-activity.
self-attestation.ts   Records *why* each agent acted — justification, alternatives
                      rejected, risk factors — to daily NDJSON.
pillars.ts            8 GOVERNANCE_PILLARS (Kinetic Clause, Recursive Loop, Ethical
                      Boundary, Hardware Sovereignty, Multi-Agent Quorum, Safety Controls,
                      Prompt Injection Detection, Blue Team Oversight) with sensitivities.
enforcement/
  prompt-injection-detector.ts   detect(input) — keyword/pattern/semantic/structural
                      layers, safe = score < 40. (A bare "system:" keyword used to
                      false-positive on benign AI text mentioning "operating system:" —
                      removed; structured injection syntax like [system]/<system>/code
                      fences is still caught by the pattern layer.)
index.ts              Wires + exports all singletons above; imports governanceImmunizer
                      from lib/governance/ for internal wiring only — NOT re-exported.
```

`desktop-agent-governance.ts` and `governance-proxy.ts` (~600 lines) were deleted as dead
code — instantiated but never actually called by any business logic. Do not re-add them;
real enforcement lives in `scopeGuard.ts` and the modules above.

### server/src/lib/governance/

```
governance-immunizer.ts   Watchdog runs every 90s: driftDetector.analyze() then a hash
                          check against a frozen policy baseline (SHA-256 over thresholds/
                          sensitivities). Tier-escalates none → warn → clamp → full_reset
                          on hash mismatch, block-rate collapse (>40pp), or a
                          high-sensitivity pillar (Ethical Boundary / Prompt Injection)
                          going silent. Publishes on huntCortex (the platform-wide signal
                          bus), persists to governance_baselines/governance_snapshots/
                          immunization_events. Must be imported directly from this file —
                          it is not part of the governance/index.ts export surface.
```

**`coreGovernance.recordDecision()` is now actually wired to real gate points** — it used
to have exactly one caller (the injection detector), so `/api/governance/stats` always
read "0 violations" regardless of what the platform actually did. Real per-hunt scope/
budget gates in both `CampaignOrchestrator.ts` (Layer 1) and `HunterEngine.ts` (root
scope check) now call it directly.

**Rules that MUST NOT be broken:**
- `scopeGuard.ts` — never weaken scope validation
- `CampaignOrchestrator.ts` — never remove the budget guard
- `VerifierAgent.ts` — never bypass the Playwright verification gate (xss/dom_xss L3)
- `governance/` and `lib/governance/` — never remove or weaken any governance file

---

## STEALTH LAYER: server/src/lib/stealth/

23 files. All outbound traffic passes through this layer to avoid detection.

```
index.ts                  StealthCoordinator (lives here, not a separate file) —
                           orchestrates timing/mimicry/AI-WAF-evasion/warmup/normalization
behavioral-mimicry.ts      Per-domain stable UA + referrer-chain sessions
dynamic-rate-limiter.ts    Adaptive request pacing (backs off on sustained 429s, not a
                           single lone one — noise vs. real rate-limit signal is distinguished)
egress-route-allocator.ts  Pool of proxy routes; rotates/burns per domain health
traffic-normalizer.ts      Humanizes request timing (think-time simulation)
browser-fingerprint.ts     Realistic user-agent + Playwright launch-arg generation
agent-awareness.ts         Detects when the target is detecting the scanner
auto-adjuster.ts           Real-time tuning of stealth parameters from detection signal
network-stealth.ts         DNS over HTTPS, SOCKS5 support
log-scrubber.ts            Sanitize sensitive data from logs before submission
ai-waf-evasion.ts          AI-generated WAF-evasion payload variants (merged with library
                           variants before the bypass loop — was built but discarded before wiring)
agent-ui-interactor.ts     humanSimulator — simulated human browsing interaction
cleanup-manager.ts, session-warmup.ts, stealth-alert-state.ts, stealth-analyzer.ts,
stealth-logger.ts, timing-engine.ts, timing-obfuscation.ts, tool-priority.ts,
tool-runner.ts, training-integration.ts, vision-agent.ts, window-manager.ts
```

Emits `egress:route_changed` Socket.IO events when the proxy pool rotates.

---

## SCOPE GUARD: server/src/middleware/scopeGuard.ts

**Called before every outbound probe (HunterEngine, PostExploitAgent, Orchestrator L1).
Fail-closed.**

```
ScopeGuard.isInScope(url, programId)
    extractHostname(url) — port-free via URL API
    Path-level matching: host+path scope patterns restrict to that subtree, boundary-safe
        (a pattern for /api/AddressBook does NOT match /api/Addresss) — this closed a real
        gap where only hostname-level matching existed
    Check hostname (+path) against outOfScope[] → REJECT if match (out-of-scope takes
        precedence over any in-scope match)
    Check hostname (+path) against inScope[] → REJECT if no match
    Follow CNAME chain (up to 10 hops, loop-guarded):
        Each hop checked against outOfScope[] → REJECT if any hop matches
    Classify terminal hostname against known multi-tenant SaaS/CDN lists:
        "block" (e.g. Salesforce, Shopify, Stripe) → REJECT
        "warn"  (CDN edge node) → ALLOW with sharedInfraWarning
    Resolve A records on terminal hostname:
        Any private IP (RFC 1918, loopback) → REJECT (DNS rebinding protection)
        Skipped when scope is local-lab ("*") or hostname is a recognized localhost alias
    ALLOW → proceed with probe
```

Cache TTL: **30 seconds** (tightened from an earlier 5-minute TTL that allowed a scope
change via the API to be bypassed for up to 5 minutes). `invalidateCache(programId)` fires
on scope changes. The `programId -1` / localhost carve-out is mostly resolved **upstream**
of ScopeGuard now, via `resolveCustomTargetProgram()` (creates a distinct, correctly-scoped
program per hostname rather than one shared `["*"]` program for every custom target) —
ScopeGuard's own bypass is just the local-lab/`"*"`-scope check on the resolved program.

---

## REAL-TIME EVENT SYSTEM

**Socket.IO connection requires an authenticated session** (`io.use(...)` rejects any
socket without `session.userId`, sharing the same session store as HTTP).

**Connection handlers:** `subscribe:hunt`, `subscribe:orchestration`, `orchestration:run`,
`hunt:start`, `solver:spawn`, `terminal:create`/`terminal:input`/`terminal:resize`/
`terminal:destroy` (PTY over Socket.IO), `disconnect`.

**Representative event families** (not exhaustive — new probers add their own
`hunt:<finding-type>_found`-style events):
```
hunt:started / phase / observations / hypothesis_generated / probing / probe_result /
     ai_reasoning / finding_confirmed / impact_demonstrated / budget_exhausted /
     hard_banned / complete / pivot / error / chain_seeded / ssrf_pivot /
     secrets_found / endpoints_discovered / oob_hit / cve_seeded / graphql_schema /
     verifying / verification_complete (Path B auto-verify pair)
     + one *_found/*_vulns event per specialized prober (mass_assignment, race_condition,
       host_header, crlf, cookie_flags, 2fa_bypass, jwt_vulns, xxe_found,
       proto_pollution, bucket_exposed, ws_vulns, changes_detected, ...)
orchestration:started / layer_start / layer_complete / layer_error / audit / complete /
     aborted / targets_expanded / takeover_found / created / error
l4:hunt_started / phase / observations / hypotheses / probing / probe_result /
     finding_raw / strategy_update / solver_finding / error       (orchestrator re-broadcast)
l5:verifying / verified / rejected / public_duplicate / report_submitted /
     report_submit_failed
l6:report_generated / autonomy_updated / chains_extracted
layer:status               { layer, phase, startedAt, completedAt }
egress:route_changed       { route, target }
governance:event           (CoreGovernance broadcast)
postexploit:start / step / complete
```

**Frontend subscriptions:**
- `LiveActivityFeed.tsx` — subscribes to all hunt/orchestration events, renders timeline
- `HuntConsole.tsx` — hunt:started, hunt:phase, hunt:complete, verification pair
- `Orchestration.tsx` — the full `orchestration:*`/`l4:*`/`l5:*`/`l6:*` layer stream
- `MissionBoard.tsx` — hunt:finding_confirmed
- `EgressPoolPanel.tsx` — egress:route_changed

Note: `routes/orchestration.ts`'s Socket.IO re-broadcast only forwards a subset of the L5/L6
events above — if you add a new orchestrator event and need it client-visible, check that
route forwards it.

---

## CLIENT PAGES: client/src/pages/ (14 files)

| Page | Purpose |
|---|---|
| `Dashboard.tsx` | Programs, campaigns, findings stats, autonomy tracker |
| `HuntConsole.tsx` | Start hunts, monitor active sessions, live activity feed |
| `Findings.tsx` | Query / filter / export findings; the Verify button (single + bulk) |
| `Hunter.tsx` | Detailed hunt state: observations, hypotheses, probes, findings |
| `Bounty.tsx` | Bug bounty program management + intelligence (→ `BountyViewRouter`) |
| `Missions.tsx` | Mission board + execution UI |
| `Orchestration.tsx` | Layer-by-layer orchestration status |
| `Intelligence.tsx` | Model routing, prompt KB, hypothesis scores |
| `Reports.tsx` | Draft report viewer + editor |
| `Programs.tsx` | Program list + scope editor |
| `Tools.tsx` | Tool validation + readiness checks |
| `Settings.tsx` | Runtime configuration editor |
| `TerminalPage.tsx` | Live PTY terminal for Kali tool output |
| `Login.tsx` | Authentication form |

**No CTF/XBOW/JuiceShop pages exist** — the whole benchmark feature (including a
1,602-line `CTFBenchmark.tsx` god-component, its server routes, and docker-lab modules)
was removed 2026-07-08 as unused surface area unrelated to live hunting.

---

## CLIENT COMPONENTS: client/src/components/

**Core (top-level):**
```
LiveActivityFeed.tsx         Real-time event feed (all hunt events, findings, errors)
FloatingChat.tsx              Conversational AI widget (calls /api/chat)
AttackPathVisualizer.tsx      Exploit chain diagram
```
Plus directories: `bounty/`, `missions/`, `layout/`, `sidebar/`, `ui/` (shadcn/Tailwind
primitives), and top-level `EgressPoolPanel.tsx`/`ProxyRouteChip.tsx`/`ActivityBar.tsx`.

**`components/missions/` (9 files):** `MissionBoard.tsx`, `MissionDetails.tsx`,
`LaunchMissionModal.tsx`, `FindingsPanel.tsx`, `LiveHuntMonitor.tsx`,
`OffensiveGraphPanel.tsx`, `StealthIndicator.tsx`, `ToolValidator.tsx`,
`AttackPathVisualizer.tsx` (a second, mission-scoped copy).

**`components/bounty/` (22 files, no CTFBenchmark/XBOW/JuiceShop):**
```
BountyViewRouter.tsx    AIAdvisor.tsx           Analysis.tsx
AuditTrail.tsx          BackwardHunt.tsx        BountyIntelligence.tsx
BrowserView.tsx         CVEIntel.tsx            CampaignIntelligence.tsx
Deadlines.tsx           DraftReports.tsx        HuntReplay.tsx
NucleiTemplates.tsx     Payloads.tsx            PlaybookLibrary.tsx
PoCLab.tsx              ScopeManager.tsx        StrategyAdvisor.tsx
Submissions.tsx         SyncStatus.tsx          TaskPlanning.tsx
ToolReadiness.tsx       WorkflowBuilder.tsx
```

---

## LIBRARY SUBSYSTEMS QUICK REFERENCE

### lib/hunter/
```
kali-catalog.ts        ~77-tool catalog (subdomain enum, port/vuln scanners, fuzzers,
                       injection tools, credential tools, OSINT — ssrfmap intentionally
                       removed; it was integrated against a CLI it doesn't have)
tool-knowledge.ts      A smaller, ~38-profile TOOL_PROFILES set feeding AI prompt context
                       (distinct from the full kali-catalog roster)
binary-check.ts        Startup availability check — 14 tiered tools (critical: nmap,
                       nuclei, ffuf, sqlmap; important: nikto, gobuster, whatweb, dalfox,
                       tplmap; optional: jwt_tool, xsser, nosqlmap, corsy, smuggler)
hunt-strategy.ts       Strategy builder and mode selector
autonomy-maturity.ts   Autonomy level scoring (L0–L5), per-domain natural ceilings
hunt-cortex.ts         huntCortex — real-time hunt health + platform-wide signal bus
reinforcement-wiring.ts RL reward integration
temporal-decay.ts      Decay older hypotheses in priority
custom-target-program.ts  Per-hostname scoped program creation for programId -1 targets
```

### lib/tools/ (40+ probe files)
Includes all OBSERVE-phase probers listed under HunterEngine above, plus:
`csrf-aware-request.ts` (shared helper — retries once with a self-minted CSRF token on a
double-submit-cookie-shaped rejection, used by 5+ probers), `payload-mutator.ts`
(`findInjectableParams`/`injectPayload`, tech-stack-aware), `tech-payload-selector.ts` +
`tech-payload-prober.ts` (fingerprint-aware SSTI/RCE payloads, actually sent — not just
described), `deserialization-prober.ts`, `file-upload-webshell-prober.ts`,
`blind-command-injection-prober.ts` (the 3 newest self-confirmed RCE probers).

### lib/intelligence/ (20+ files)
```
meta-reasoning.ts             Hunt health → strategy pivot decisions
backward-planner.ts           Optimal exploitation path planning
observation-compressor.ts     Trim observations to fit LLM context
nvd-client.ts                 Query NVD for CVE enrichment
public-disclosure-detector.ts Check if finding is already public
simhash.ts                    Locality-sensitive hashing for near-dedup
writeup-scraper.ts            Fetch public CVE writeups for context
circuit-breaker.ts             Gates RECON TOOL selection (nuclei/nmap/ffuf/nikto) —
                               unrelated to the (now Claude-only) LLM routing tier
report-submitter.ts           Submit findings to bug bounty platforms
offensive-graph-db.ts         Attack graph persistence
```

### lib/stealth/ — see Stealth Layer section above (23 files)

### lib/orchestration/ (13 files) — ORPHANED, not wired into any live path
A complete alternate 6-layer implementation (`layer1..6-*.ts`, `mission-chain-manager.ts`,
`agent-registry.ts`, ...) including its own Ollama-calling bridge. `CampaignOrchestrator.ts`
does not import it. Do not assume anything in this folder actually runs during a hunt.

### lib/bounty-intelligence/
Payout optimization, failure prediction, triage, cross-campaign learning, tool synergy scoring.

### lib/oob/
Out-of-band callbacks: Interactsh + `callback-server.ts` (local fallback). Used for blind
SSRF/XXE/RCE/deserialization confirmation. `generateBeacon()`/`waitForHit()`/`recordHit()`;
exfiltrated query params (e.g. `whoami` output) are captured on a hit.

### lib/recon/
Phase-0 passive OSINT recon (`ReconRunner`) — crt.sh certificate transparency + Wayback
Machine CDX, fired concurrently at hunt start.

### lib/verification/
`verify-finding.ts` — shared helper used by both the Path B auto-verify pass and the
manual re-verify endpoint. `deriveVerificationUrl()`, `verifyAndPersistFinding()`,
`verifyPendingForSession()`, `pendingEscalation()` (applies PostExploitAgent's stashed
severity bump only on a confirmed verdict).

### lib/shell/
Command executor sandbox with timeout enforcement.

### lib/claude-bridge.ts / lib/claude-client.ts / lib/context-writer.ts
See Intelligence Layer section above.

---

## IMPORTANT: THINGS COMMONLY MISINTERPRETED

**1. Ollama is not a fallback anymore — it's gone from the reasoning path.**
`ModelRouter` is Claude-only (SDK → CLI bridge → throw). This was a deliberate
2026-06-26 decision, not a regression — local models couldn't reliably complete hunts.
There's no vision-model fallback either; only VerifierAgent's L4 uses vision, via Claude
directly. A few stray comments/config keys still mention Ollama; they're dead, not live.

**2. PostExploitAgent does NOT run exploits.**
Read-only probes only, to demonstrate impact for a report. No writes, no deletes, no
reverse shells. Severity escalation is *stashed* during `update()` and only actually
applied once the finding is later verified as `confirmed` — never before.

**3. SolverPool does NOT make strategy decisions.**
It only executes what HunterEngine dispatches. Strategy is centralized in HunterEngine
(Single-Brain Architecture).

**4. `programId: -1` is a valid special value**, but it no longer means "one shared,
forever-`*`-scoped program for every custom target." Each hostname now gets its own
distinct, correctly-scoped program via `resolveCustomTargetProgram()`.

**5. The 16 `SELF_CONFIRMED_SOURCES` probers bypass generic tool dispatch, not
verification.** They short-circuit PROBE-phase re-testing (since generic tools can't
replay their specific oracle), but VerifierAgent's Layer 5 treats them exactly like any
other finding — they just aren't `logic_exploit_agent`-discovered, so they land in the
OOB-confirmed or HTTP-observable verdict category like anything else.

**6. VerifierAgent's final verdict has FOUR oracle-authority categories, not three.**
Browser-verifiable (xss/dom_xss, L3 mandatory) → **OOB-confirmed** (rce/ssrf/xxe/sqli/
rfi/ssti with a fired callback, unconditionally authoritative) → stateful agent-discovered
(`logic_exploit_agent`, L2 barred) → everything else (L2+L4 consensus). The OOB category
is easy to miss since it's newer than the other three.

**7. `vulnClassAllowlist` and `focusVulnClasses` are different mechanisms.** The allowlist
hard-excludes (marks `"deferred"`); focus classes only add priority-boosted placeholder
hypotheses. Don't confuse "focus on X" with "only hunt X."

**8. There is no CTF/XBOW/JuiceShop benchmark page or routes anymore.** Removed
2026-07-08 as unused surface area. If you see a reference to `CTFBenchmark.tsx` or
`/api/ctf`/`/api/xbow`/`/api/juiceshop`, it's stale — those files don't exist.

**9. `lib/orchestration/`'s layer1-6 files are dead code.** `CampaignOrchestrator.ts` has
its own same-named layer methods and does not import from that folder. Don't go looking
for the "real" 6-layer pipeline there.

**10. VerifierAgent is post-hoc (Layer 5), NOT an inline gate in HunterEngine.**
`HunterEngine.update()` persists findings as `verificationStatus:"pending"`.
`VerifierAgent.verify()` runs only at CampaignOrchestrator's Layer 5 (Path A) or via the
auto-verify pass on `hunt:complete` (Path B). Hunts started via `/api/hunt/start`
standalone still get verified now — that used to be a gap, it's fixed.

**11. `context/` files are ephemeral runtime state, not committed to git.**

**12. CampaignOrchestrator layers are sequential gates, not parallel.**

**13. `execFile` is used everywhere tool commands run — never `exec` or shell
interpolation.** Tool args are always `string[]` arrays.

**14. The governance immunizer watchdog runs every 90s regardless of hunt state**, and
its drift comparisons are rate-based (per-snapshot averages), not raw counts — a fix
after busy-vs-quiet session length differences caused false drift alerts.

---

## EXTERNAL TOOL DEPENDENCIES (Kali Linux)

The full roster lives in `server/src/lib/hunter/kali-catalog.ts` (~77 tools) — far larger
than any short list can usefully capture. `binary-check.ts` checks a tiered 14-tool subset
at startup (critical: nmap, nuclei, ffuf, sqlmap; important: nikto, gobuster, whatweb,
dalfox, tplmap; optional: jwt_tool, xsser, nosqlmap, corsy, smuggler) and logs which are
actually present — missing tools are warnings, they do not prevent server start. Broad
categories covered by the full catalog: subdomain/asset enumeration (subfinder, amass,
dnsx, assetfinder, findomain, gau, waybackurls, hakrawler, gospider, katana), network/port
scanning (nmap, masscan, httpx, httprobe), vulnerability scanning (nuclei, nikto, wapiti,
skipfish, wpscan, joomscan), TLS (testssl, sslscan, sslyze), fuzzing (ffuf, gobuster,
feroxbuster, dirsearch, wfuzz, dirb, arjun), injection (sqlmap, dalfox, commix, xsstrike,
tplmap, corsy, nosqlmap, xsser, jwt_tool, smuggler, sqlninja, crlfuzz), secrets/OSINT
(secretfinder, trufflehog, gitleaks, gitrob, theHarvester, shodan, maltego), auth/creds
(hydra, medusa, ncrack, patator, john, hashcat), plus interactsh-client for OOB callbacks
and OWASP ZAP for passive scanning. **`ssrfmap` was deliberately removed** — its real CLI
requires a raw captured HTTP request file, which the integration never provided, so every
invocation errored and the parser matched its own usage-banner text as a false positive.

---

## KEY DESIGN PATTERNS SUMMARY

| Pattern | Where | What it prevents |
|---|---|---|
| Single-Brain Architecture | HunterEngine owns all strategy | Conflicting probes, wasted budget |
| Self-Confirmed Source Short-Circuit | 16 probers, gated before all other PROBE dispatch | Re-testing with a tool that structurally can't replay the original oracle |
| 4-Layer Verification, 4 Oracle Categories | VerifierAgent | False positives in reports |
| OOB Beacon as Authoritative Oracle | VerifierAgent + HunterEngine's `oobConfirmed` | Requiring a stateless reprobe to "recheck" a callback that already fired |
| Hard vulnClass Allowlist | `applyVulnClassAllowlist()` | Scope creep when a hunt should stay RCE-only (or any single focus) |
| Claude-Only, Fail-Loud | ModelRouter | Silent degradation to low-quality default hypotheses |
| Scope Guard Fail-Closed, Path-Aware | scopeGuard.ts (every probe) | Out-of-scope testing, including path-level out-of-scope entries |
| No Shell Interpolation | All execFile calls | Command injection via URLs |
| Observation Compression | ObservationCompressor | LLM context overflow |
| RL Cross-Hunt Learning | ReinforcementStore + weight learner | Repeating failed strategies |
| Deferred Escalation | PostExploitAgent stash + `pendingEscalation()` | Inflating severity on a later-rejected finding |
| Governance Watchdog, Rate-Based Drift | governance-immunizer.ts + drift-detector.ts | Unauthorized behavior drift, false alerts from session-length mismatch |

# NETTY-HUNTER — COMPLETE ARCHITECTURE REFERENCE

---

## TOP-LEVEL DIRECTORY STRUCTURE

```
netty-hunter/
  server/                         # Node.js / Express backend (TypeScript)
  │  src/
  │  │  index.ts                  # App entry: Express, Socket.IO, all routes
  │  │  agents/                   # Core autonomous hunting agents (5 files)
  │  │  intelligence/             # AI model routing, prompt KB, reasoning
  │  │  lib/                      # Libraries: tools, stealth, learning, orchestration
  │  │  routes/                   # 23 Express route handlers
  │  │  db/                       # Drizzle ORM schema + migrations
  │  │  middleware/               # ScopeGuard scope enforcement
  │  │  governance/               # Policy enforcement, audit trail, drift detection
  │  │  utils/                    # Logger
  │  │  workers/                  # Playwright worker thread
  │  └─ __tests__/                # Unit tests
  client/                         # React + TypeScript frontend
  │  src/
  │  │  pages/                    # 14 page components
  │  │  components/               # 48 UI/feature components
  │  │  context/                  # SocketContext (global Socket.IO connection)
  │  │  hooks/                    # use-toast
  │  │  lib/                      # API bindings, socket factory, utils
  │  └─ services/                 # HTTP API service layer
  context/                        # Runtime state files (written during hunts, read by Claude)
  scripts/                        # Build / setup scripts
```

---

## SERVER ENTRY POINT: index.ts

**Boot sequence (in order):**
1. Load `.env` via dotenv
2. Create Express app + HTTP server + Socket.IO server
3. Load persisted settings from DB → `RuntimeConfig`
4. Initialize learning schema tables
5. Check Kali binary availability (`checkBinariesAtStartup`)
6. Initialize autonomous brain (`initializeAutonomousBrain`)
7. Wire Socket.IO to `EgressAllocator` for stealth pool events

**Middleware stack (in order):**
```
Helmet (security headers)
CORS  (configurable via CLIENT_URL env)
express.json / express.urlencoded
Session (PostgreSQL-backed via connect-pg-simple)
Rate limiters (global /api, stricter /api/hunt/start, strictest /api/orchestration/run)
```

**All route registrations:**
```
/api/auth              authRoutes            (no auth required)
/api/hunt              huntRoutes            requireAuth
/api/bounty            bountyRoutes          requireAuth
/api/orchestration     orchestrationRoutes   requireAuth
/api/hunter            hunterRoutes          requireAuth
/api/governance        governanceRoutes      requireAuth
/api/missions          missionsRoutes        requireAuth
/api/bounty-intelligence  bountyIntelligenceRoutes  requireAuth
/api/reasoning         reasoningRoutes       requireAuth
/api/graph             graphRoutes           requireAuth
/api/intelligence      intelligenceRoutes    requireAuth
/api/juiceshop         juiceshopRoutes       requireAuth
/api/xbow              xbowRoutes            requireAuth
/api/settings          settingsRoutes        requireAuth
/api/chat              chatRoutes            requireAuth
/api/tools             toolsRoutes           requireAuth
/api/ctf               ctfRoutes             requireAuth
/api/adaptive-scan     adaptiveScanRoutes    requireAuth
/api/findings          findingsRoutes        requireAuth
/api/evidence          evidenceRoutes        requireAuth
/api/report-export     reportExportRoutes    requireAuth
/api/exploit           exploitRoutes         requireAuth   ← PostExploitAgent
```

**OOB callback server:** no auth — mounted separately for external beacon hits.

---

## CORE AGENT LAYER: server/src/agents/

### HunterEngine.ts — The Main Loop

The entire hunt runs inside one `runLoop()` call. It is a `while` loop bounded by:
- `iteration < maxIterations`
- `requestsMade < budget.maxRequests`
- `elapsed < budget.maxTime`
- `!this.hardBanned` (network-level IP block detected)

**4-phase OHPU cycle per iteration:**

```
OBSERVE  →  HYPOTHESIZE  →  PROBE  →  UPDATE
   ↑                                      |
   └──────── next iteration ──────────────┘
```

#### Phase 1 — OBSERVE

Entry: `observe()` (~line 698)

Runs sequentially:
1. `whatweb` — technology fingerprinting
2. `curl_probe` — HTTP headers, security checks
3. `waf_intel` — WAF / IDS detection
4. Supplemental recon (only if enough iteration budget remains):
   - Secret scanning (`secretScanner`)
   - Change detection (`changeDetector`)
   - WebSocket probing (`webSocketProber`)
   - Cloud bucket enumeration (`cloudBucketProber`)
   - Prototype pollution (`prototypePollutionProber`)
   - Race condition detection (`raceConditionDetector`)
   - Host header injection (`hostHeaderProber`)
   - CRLF injection (`crlfProber`)
   - Cookie flag checking (`cookieFlagChecker`)
   - JS/SPA crawling (`jsSPACrawler`, `deepCrawl`)
   - Attack plan seeding (`backwardPlanner`)
   - Tech-stack payload selection (`techPayloadSelector`)
   - Parameter discovery (`parameterDiscovery`)
   - OAuth probing (`oauthProber`)
   - Mass assignment (`massAssignmentProber`)
   - Business logic (`businessLogicProber`)
   - 2FA bypass (`twoFactorBypassProber`)
   - JWT confusion (`jwtConfusionProber`)
   - Blind XXE (`blindXXEProber`)
   - ZAP scan (`zapScanner`)

Each tool run emits: `hunt:probing` then `hunt:probe_result` via Socket.IO.

Observations are appended to `state.observations[]`. The observation compressor
periodically shrinks them to keep AI context bounded.

#### Phase 2 — HYPOTHESIZE

Entry: `hypothesize()` (~line 1533 after observe completes)

```
observations[] → ModelRouter.generateHypotheses(prompt)
                      ↓
              If Ollama healthy (circuit CLOSED):
                  POST http://localhost:11434/api/generate
                  ─ recordSuccess() → circuit stays CLOSED
              Else (circuit OPEN or failure):
                  ClaudeBridge.reason(prompt)
                  ─ execFile("claude", ["--print", "-p", prompt])
                  ─ logs to context/claude-tasks.jsonl
              Else (neither available):
                  Built-in fallback model
                      ↓
              Parse JSON → Hypothesis[] with confidence scores
              Push to state.hypotheses[]
              Emit hunt:hypothesis_generated per hypothesis
```

#### Phase 3 — PROBE

Entry: `probe()` (~line 1712)

```
For each hypothesis where status === "pending":
    ScopeGuard.isInScope(hypothesis.targetUrl, programId)   ← MANDATORY, fail-closed
    If out of scope → skip, log

    SolverPool.dispatch(task)
        ↓
    SolverPool selects tool(s) based on vulnClass
    Behavioral mimicry headers applied (consistent UA + referrer chain)
    Per-domain rate limiter applied
    Tool executed via execFile (never shell interpolation)
    Output parsed by tool-specific parser
    Returns SolverResult { found, confidence, evidence, payload, request, response }

    Emit hunt:probing
    Emit hunt:probe_result
    Push ProbeResult to state.probes[]
    hypothesis.status = "probing"
```

If the network drops hard (TCP RST / ICMP unreachable matching canary hostname),
`this.hardBanned = true` and the loop breaks immediately.

#### Phase 4 — UPDATE

Entry: `update()` (~line 1910)

```
For each hypothesis where status === "probing":
    relatedProbes = state.probes filtered by hypothesisId
    successful = relatedProbes where success === true

    If successful.length > 0:
        newConfidence = updateConfidence(hypothesis, successful)  ← AI-assisted

        If newConfidence > 0.7:
            hypothesis.status = "confirmed"
            rlWiring.onHypothesisOutcome(vulnClass, confidence, true)
            confirmed = buildConfirmedFinding(hypothesis, successful)
            state.confirmedFindings.push(confirmed)
            Emit hunt:finding_confirmed
            contextWriter.addFinding(...)          → context/hunt-findings.json
            persistFinding(confirmed)              → findings table in DB

            ── PostExploitAgent (non-blocking async) ──────────────────────
            postExploitAgent.demonstrate(confirmed)
              Runs read-only scope-guarded probes per vulnClass:
                ssrf     → cloud metadata read, internal service reach
                lfi      → /etc/passwd, /etc/hostname
                idor     → adjacent numeric ID walk
                auth_bypass / exposed_admin → unauthenticated resource access
                open_redirect → attacker-controlled destination check
                info_disclosure / misconfig → sensitive file check
              If impactProven:
                Escalates severity/CVSS (only upward, capped per-class)
                AI writes business-impact narrative
                PATCH findings table: severity, cvssScore, impact
              Emits hunt:impact_demonstrated
            ───────────────────────────────────────────────────────────────

            notificationService.notifyIfWorthy(...)
            SSRF chain pivot (if vulnClass === "ssrf"):
                ssrfChainProber.probe() → new pivot hypotheses pushed to state
            Exploit chain seeding:
                ATTACK_TREES lookup → seed next-step hypothesis if chain match

        Else if newConfidence < 0.2:
            hypothesis.status = "rejected"
            rlWiring.onHypothesisOutcome(vulnClass, confidence, false)

        Else (0.2–0.7 gray zone):
            hypothesis.retryCount++
            If retryCount < 2:
                hypothesis.status = "pending"   ← re-queued with alternate tool
                hypothesis.toolHint = getAlternateTool()
            Else:
                hypothesis.status = "inconclusive"  ← exhausted retries
```

After UPDATE, MetaReasoner evaluates hunt health. If confidence is stagnant or
tool diversity is low, it recommends a strategy pivot — new hypotheses are seeded
and the loop continues.

---

### CampaignOrchestrator.ts — 6-Layer Pipeline

Wraps an entire hunt campaign. Each layer is a gate: failure aborts the campaign.

```
Layer 1 — l1_governance
  ScopeGuard.validate()
  CoreGovernance policy check (mode, autonomy level)
  DecisionLogger records rationale
  FAIL → abort with governance rejection

Layer 2 — l2_intelligence
  ROIModel scores the program (payout, response time, historical success)
  TargetSelectionIntelligence ranks targets within program
  FAIL → abort (no viable targets)

Layer 3 — l3_strategy
  HuntStrategyBuilder selects mode (forward / backward / exploit-chain)
  ExploitChainIntelligence picks applicable attack trees
  BackwardPlanner seeds reverse-path hypotheses if mode=backward
  FAIL → abort (no viable strategy)

Layer 4 — l4_execution
  HunterEngine.startHunt() — runs full OHPU loop
  SolverPool dispatches parallel probes
  WAFBypass applied if WAF detected
  FAIL → partial (findings from completed iterations saved)

Layer 5 — l5_verification
  VerifierAgent.verify() — 4-layer anti-hallucination pipeline
  (see VerifierAgent detail below)
  FAIL → finding marked inconclusive, not rejected

Layer 6 — l6_harvest
  ReinforcementWiring persists metrics
  AutonomyTracker updates autonomy level
  NucleiGenerator creates templates from confirmed findings
  ReportGenerator drafts the bug bounty report
  CrossCampaignLearner updates strategy weights
  COMPLETE → campaign status = completed
```

Each layer emits: `layer:status { layer, phase, startedAt, completedAt }` via Socket.IO.

---

### VerifierAgent.ts — 4-Layer Anti-Hallucination Gate

Called from `update()`. **No finding is confirmed without passing this gate.**

```
Layer 1 — Static Dedup
  SHA-256 hash of (endpoint + vulnClass + payload)
  SimHash near-duplicate check (locality-sensitive)
  Pre-loaded last 500 hashes from DB on init
  If duplicate → return { verdict: "rejected" }

Layer 2 — Dynamic Reprobe
  HTTP re-request the exploit URL
  Check response code + body for vulnerability signals
  vuln-class-specific logic (sqli: error strings, xss: payload reflection, etc.)

Layer 3 — Playwright Browser Replay  ← MANDATORY GATE
  Worker thread (playwright-worker.ts) with fingerprint hardening
  Navigate to endpoint, inject payload
  Monitor: console alerts, DOM mutations, network requests
  Capture screenshot
  35s timeout — if unavailable, verdict degrades to L2+L4 consensus only
  If confidence > 0.7 OR vulnClass in [xss, sqli, rce, ssrf] → MUST pass

Layer 4 — AI Confirmation
  Sends L2+L3 evidence to ModelRouter.reason()
  Screens AI output for prompt injection (promptInjectionDetector)
  Returns: { confirmed, reasoning, confidenceAdjustment }
  Failure degrades gracefully to L2+L3 consensus

Final verdict:
  L2+L3+L4 all confirmed → "confirmed",  confidence += 0.1  (max 0.98)
  L2+L4 confirmed        → "confirmed",  confidence unchanged (max 0.90)
  L2+L3 both rejected    → "rejected",   confidence -= 0.3
  Otherwise              → "inconclusive"
```

---

### SolverPool.ts — Parallel Probe Dispatch

```
SolverPool.dispatch(task: SolverTask)
    ↓
pQueue (concurrent, configurable concurrency)
    ↓
solve(endpoint, vulnClass, confidence, context)
    Select tool(s) from ToolKnowledge by vulnClass
    Build payload via PayloadMutator (tech-stack aware)
    Apply behavioral mimicry headers (stable UA + referrer per domain)
    Apply per-domain rate limiter (max 2 req/s per hostname)
    execFile(bin, args)         ← no shell — args are array, never interpolated
    Parse output via tool-specific parser
    Return SolverResult { found, confidence, evidence, payload, request, response }
    Emit hunt:solver_result
```

SolverPool does NOT make strategy decisions. It only executes what HunterEngine dispatches.

---

### WAFBypass.ts (IntelligenceSynthesizer)

Runs inside the PROBE phase when a WAF is detected during OBSERVE.
Techniques: encoding mutations, header spoofing, payload fragmentation, timing variation.
Results fed back to SolverPool as alternate payloads.

---

### PostExploitAgent.ts — Bounded Impact Demonstration

Runs **non-blocking** after a finding is confirmed. Hard limits:
- Max 4 steps
- 8s per step
- 30s total wall-clock budget
- Every outbound URL re-validated through ScopeGuard (fail-closed)
- Read-only probes ONLY — no writes, no deletes, no lateral movement

```
demonstrate(input, baseSeverity, baseCvss)
    probesFor(vulnClass) → ImpactProbe[]
    For each probe (up to MAX_STEPS, within TOTAL_BUDGET_MS):
        url = probe.buildUrl(targetUrl)
        ScopeGuard.isInScope(url, programId)   ← MANDATORY re-check
        If blocked → step recorded as blocked, continue
        axios.GET(url, { timeout: 8000, ... })
        proved = probe.proves(body, status, location)
    impactProven = steps.some(s => s.proved)
    If impactProven:
        escalatedSeverity = bump one rank, capped per-class ceiling
        CVSS updated upward only
    AI narrative via ModelRouter.reason()
    Emit hunt:impact_demonstrated
    PATCH findings table if impactProven
```

Per-class probes:
- `ssrf`           → cloud metadata (169.254.169.254), internal service reach
- `lfi`            → /etc/passwd, /etc/hostname
- `idor`           → walk numeric ID ±1
- `auth_bypass`    → strip auth headers, re-request protected resource
- `open_redirect`  → inject example.org URL, check Location header (no-follow)
- `info_disclosure`/ `misconfig` → regex scan for keys/credentials in response

---

## INTELLIGENCE LAYER: server/src/intelligence/

### ModelRouter.ts — Circuit Breaker + Tier Routing

```
Task arrives (taskType: reason | classify | code | chat | generate)
    ↓
Check circuit breaker state:
    CLOSED  → try Ollama first
    OPEN    → skip Ollama, go to Claude
    HALF_OPEN → send one probe request to Ollama

Ollama path:
    Select model by taskType priority:
        deepseek-r1:7b → deepseek-r1:1.5b → llama3.2:3b → llama3.2
        → llama3.1:8b → mistral:7b → codellama:7b → phi3:mini
    POST http://localhost:11434/api/generate
    On success → recordSuccess() → circuit CLOSED
    On failure → recordFailure()
        3 consecutive failures → circuit OPEN
        Recovery after 30s → HALF_OPEN

Claude path (circuit OPEN or Ollama failure):
    ClaudeBridge.isAvailable() → check `claude` CLI on PATH
    execFile("claude", ["--print", "-p", prompt], { timeout })
    Log to context/claude-tasks.jsonl
    On failure → fall back to built-in model

Filtering: embedding models (nomic-embed-text, mxbai-embed-large) are excluded
from routing — never used for reasoning tasks.
```

### PromptKnowledgeBase.ts

22 expert prompt templates covering: recon, scanning, exploitation (SQLi, XSS,
SSRF, IDOR, auth bypass), credential testing, intelligence gathering, CVSS scoring,
and report writing. Each template has required variables and a confidence threshold.

### Other Intelligence Exports

| Class/File | Purpose |
|---|---|
| `ExploitChain.ts` + `ATTACK_TREES` | Predefined multi-step exploitation trees |
| `ROIModel.ts` | Score programs by payout / response time / success rate |
| `BackwardHuntEngine.ts` | Reverse-engineer attack path from a confirmed finding |
| `TargetSelectionIntelligence` | Rank targets within a program |
| `AutonomyTracker` | Autonomy maturity level (L0–L5); gates tool access |
| `ReinforcementStore` | Persist RL signals to DB for cross-hunt learning |
| `NucleiGenerator` | Auto-generate Nuclei templates from findings |
| `ReportGenerator` | Draft bug bounty report (markdown + structured JSON) |
| `MetaReasoner` | Evaluate hunt health, recommend strategy pivots |
| `ObservationCompressor` | Trim state.observations[] to stay within LLM context |

---

## DATABASE SCHEMA: server/src/db/schema.ts

All tables use Drizzle ORM. PostgreSQL only.

```
users            id, username, passwordHash, role, createdAt
programs         id, name, platform, scope[], outOfScope[], maxPayout, roiScore, authConfig
targets          id, programId, url, type, fingerprint, attackSurface, priority, lastScanned
campaigns        id, programId, name, goal, huntMode, strategy, budget, progress, startedAt
huntSessions     id, campaignId, targetId, sessionUuid, phase, hypotheses, observations,
                 probes, solverResults, status, completedAt
findings         id, campaignId, huntSessionId, targetId,
                 title, vulnType, severity, confidence, cvssScore,
                 description, evidence[], reproductionSteps[], impact,
                 remediation, cweId, cveId, exploitPayload,
                 verificationStatus, verificationLog[], dedupHash,
                 nucleiTemplate, reportDraft, submittedAt, status,
                 disclosureCheckStatus, publicDisclosureUrl,
                 oobBeaconId, oobHitReceived, oobHitAt,
                 createdAt, updatedAt
wafProfiles      id, vendor, targetDomain, detectionSignals, bypassTechniques,
                 blockedPatterns, evasionMatrix, blockRate
exploitChains    id, chainId, startVulnType, endVulnType, steps[], roiScore
customTools      id, name, commandTemplate, parser, vulnClasses[]
solverResults    id, taskId, endpoint, vulnClass, found, confidence, evidence
reinforcementStore  id, domain, key, value
missions         id, campaignId, goal, status, tasks[]
sessions         (connect-pg-simple session store)
```

Indices: `findings_vuln_type_idx`, `findings_severity_idx`, `findings_status_idx`,
`findings_campaign_idx`, `programs_platform_idx`, `programs_roi_idx`.

---

## LIVE HUNT STATE FILES: context/

Written continuously during active hunts. Read by Claude Code and the frontend.

```
context/hunt-live.json      Current session id, phase, iteration, findings count,
                            active model (ollama/claude), last error, budget used
context/hunt-findings.json  All confirmed findings: id, vulnClass, severity,
                            confidence, endpoint, payload, description, confirmedAt
context/errors.jsonl        Append-only error log: { timestamp, phase, message, stack }
context/hunt-digest.txt     Single line: "Session X | Phase: probe | Iter 3/10 | 2 findings"
context/alerts.jsonl        Key events only: phase changes, new findings, hard bans
context/claude-tasks.jsonl  Every prompt sent to Claude bridge + truncated response
```

---

## GOVERNANCE LAYER

### server/src/governance/

```
core-governance.ts          Policy enforcement, pillar counts, verdict tracking
decision-logger.ts          Audit trail — every hunt decision logged with rationale
drift-detector.ts           Snapshot baseline config; alert on 90s watchdog deviation
self-attestation.ts         Compliance self-attestation reports
pillars.ts                  5 pillars: rules, detection, response, audit, autonomy
enforcement/
  prompt-injection-detector.ts  Detect injections in user-supplied params and AI inputs
```

### server/src/lib/governance/

```
governance-immunizer.ts     Frozen snapshot of hunt behavior baseline
                            Watchdog fires every 90s — compares live state to snapshot
                            Persists snapshots to DB
                            Detects unauthorized changes (e.g., scope bypass attempts)
```

**Rules that MUST NOT be broken:**
- `scopeGuard.ts` — never weaken scope validation
- `CampaignOrchestrator.ts` — never remove budget guard
- `VerifierAgent.ts` — never bypass Playwright verification gate
- `governance/` and `lib/governance/` — never remove or weaken any governance file

---

## STEALTH LAYER: server/src/lib/stealth/

The stealth layer wraps all outbound traffic to avoid detection.

```
stealthCoordinator          Master coordinator — applies all stealth modules
BehavioralMimicry           Per-domain stable UA + referrer chain sessions
DynamicRateLimiter          Adaptive request rate (backs off on 429s, IDS signals)
EgressRouteAllocator        Pool of proxy routes; rotates per domain
TrafficNormalizer           Humanizes request timing (think-time simulation)
BrowserFingerprint          Realistic user-agent generation (OS/browser combos)
AgentAwareness              Detects when target is detecting the scanner
AutoAdjuster                Real-time tuning of stealth parameters
NetworkStealth              DNS over HTTPS, SOCKS5 support
LogScrubber                 Sanitize sensitive data from logs before submission
```

Emits `egress:route_changed` Socket.IO events when proxy pool rotates.

---

## SCOPE GUARD: server/src/middleware/scopeGuard.ts

**Called before every outbound probe. Fail-closed.**

```
ScopeGuard.isInScope(url, programId)
    Parse URL → extract hostname
    Check hostname against outOfScope[] patterns → REJECT if match
    Check hostname against inScope[] patterns → REJECT if no match
    Follow CNAME chain (DNS resolution):
        Each hop checked against outOfScope[] → REJECT if any hop matches
    Classify terminal hostname:
        "block" (shared-tenant SaaS) → REJECT
        "warn"  (CDN edge node) → ALLOW with sharedInfraWarning
    Resolve A records on terminal hostname:
        Any private IP (RFC 1918, loopback) → REJECT (DNS rebinding protection)
        Exception: programId -1 (local lab, scope contains "*") → ALLOW
    ALLOW → proceed with probe
```

Cache TTL: 30 seconds. `invalidateCache(programId)` on scope changes.

---

## REAL-TIME EVENT SYSTEM

**All Socket.IO events emitted by the server:**

```
hunt:started             { sessionId, targetUrl }
hunt:phase               { phase, iteration }
hunt:probing             { hypothesisId, vulnClass, tool }
hunt:probe_result        { hypothesisId, tool, output, success }
hunt:observations        { count, observations }
hunt:hypothesis_generated{ hypothesis, confidence }
hunt:solver_result       { taskId, endpoint, vulnClass, found }
hunt:finding_confirmed   { finding, severity, confidence }
hunt:impact_demonstrated { sessionId, findingId, vulnClass, severity, cvssScore, steps }
hunt:complete            { sessionId, findings, iterations }
hunt:pivot               { sessionId, reason, newHypotheses }
hunt:error               { phase, error, timestamp }
hunt:hard_banned         { target, reason }
hunt:chain_seeded        { sessionId, chainId, chainName, step, vulnClass }
hunt:ssrf_pivot          { sessionId, reachable, cloudMeta, newHypotheses }
hunt:secrets_found       { sessionId, count, ... }
hunt:endpoints_discovered{ sessionId, count, endpoints }
hunt:ai_reasoning        { sessionId, ... }
layer:status             { layer, phase, startedAt, completedAt }   (CampaignOrchestrator)
egress:route_changed     { route, target }                          (EgressAllocator)
```

**Frontend subscriptions:**
- `LiveActivityFeed.tsx` — subscribes to all events, renders timeline
- `HuntConsole.tsx` — hunt:started, hunt:phase, hunt:complete
- `MissionBoard.tsx` — hunt:finding_confirmed
- `EgressPoolPanel.tsx` — egress:route_changed

---

## CLIENT PAGES: client/src/pages/

| Page | Purpose |
|---|---|
| `Dashboard.tsx` | Programs, campaigns, findings stats, autonomy tracker |
| `HuntConsole.tsx` | Start hunts, monitor active sessions, live activity feed |
| `Findings.tsx` | Query / filter / export findings by severity, program, date |
| `Hunter.tsx` | Detailed hunt state: observations, hypotheses, probes, findings |
| `Bounty.tsx` | Bug bounty program management + intelligence |
| `Missions.tsx` | Mission board + execution UI |
| `Orchestration.tsx` | Layer-by-layer orchestration status |
| `Intelligence.tsx` | Model routing, prompt KB, hypothesis scores |
| `Reports.tsx` | Draft report viewer + editor |
| `Programs.tsx` | Program list + scope editor |
| `Tools.tsx` | Tool validation + readiness checks |
| `Settings.tsx` | Runtime configuration editor |
| `TerminalPage.tsx` | Live PTY terminal for Kali tool output |
| `Login.tsx` | Authentication form |

---

## CLIENT COMPONENTS: client/src/components/

**Core:**
```
LiveActivityFeed.tsx         Real-time event feed (all hunt events, findings, errors)
FloatingChat.tsx             Conversational AI widget (calls /api/chat)
AttackPathVisualizer.tsx     Exploit chain diagram
EgressPoolPanel.tsx          Stealth proxy pool visualization
ProxyRouteChip.tsx           Individual proxy route chip
ActivityBar.tsx              Top bar with hunt status
```

**Mission components:**
```
MissionBoard.tsx             Mission grid overview
MissionDetails.tsx           Detailed mission inspector
LaunchMissionModal.tsx       Mission launch dialog
FindingsPanel.tsx            Findings viewer per mission
LiveHuntMonitor.tsx          Real-time hunt progress bar
OffensiveGraphPanel.tsx      Attack graph renderer
StealthIndicator.tsx         Stealth level display
ToolValidator.tsx            Tool readiness checker
```

**Bounty components (inside Bounty page):**
```
BountyViewRouter.tsx         Tab router for bounty sub-views
BountyIntelligence.tsx       Program rankings, ROI data
Analysis.tsx                 Finding impact analysis
AuditTrail.tsx               Audit log viewer
BackwardHunt.tsx             Backward hunt visualization
BrowserView.tsx              Target website preview
CVEIntel.tsx                 CVE data + writeups
CampaignIntelligence.tsx     Campaign metrics
DraftReports.tsx             Report editor
HuntReplay.tsx               Hunt replay / review
NucleiTemplates.tsx          Generated Nuclei templates viewer
Payloads.tsx                 Payload library
PlaybookLibrary.tsx          Attack playbook collection
PoCLab.tsx                   PoC testing lab
ScopeManager.tsx             In / out-of-scope editor
StrategyAdvisor.tsx          Strategy recommendations
Submissions.tsx              Bug bounty submissions tracker
TaskPlanning.tsx             Task breakdown + planning
ToolReadiness.tsx            Kali tool availability
WorkflowBuilder.tsx          Workflow customization
```

**ShadUI / Tailwind primitives:**
`badge`, `button`, `card`, `input`, `label`, `scroll-area`, `select`, `textarea`

---

## LIBRARY SUBSYSTEMS QUICK REFERENCE

### lib/hunter/ (13 files)
```
tool-knowledge.ts            39 tool profiles + 10 chain pipelines
hunt-strategy.ts             Strategy builder and mode selector
autonomy-maturity.ts         Autonomy level scoring (L0–L5)
hunt-cortex.ts               Real-time hunt health + signal metrics
reinforcement-wiring.ts      RL reward integration
temporal-decay.ts            Decay older hypotheses in priority
plan-memory.ts               Hypothesis / strategy persistence
validation-gate.ts           Pre-probe sanity checks
static-analysis.ts           JS / source code analysis
binary-check.ts              Startup Kali tool availability check
```

### lib/intelligence/ (20+ files)
```
meta-reasoning.ts            Hunt health → strategy pivot decisions
backward-planner.ts          Optimal exploitation path planning
observation-compressor.ts    Trim observations to fit LLM context
nvd-client.ts                Query NVD for CVE enrichment
public-disclosure-detector.ts Check if finding is already public
simhash.ts                   Locality-sensitive hashing for near-dedup
writeup-scraper.ts           Fetch public CVE writeups for context
mitre-prereq-tree.ts         MITRE ATT&CK prerequisite trees
report-submitter.ts          Submit findings to bug bounty platforms
offensive-graph-db.ts        Attack graph persistence
```

### lib/stealth/ (20+ files) — see Stealth Layer section above

### lib/tools/ (30+ probe files) — see Phase 1 OBSERVE for full list

### lib/orchestration/ (13 files)
```
layer1-hunt-orchestrator.ts  Entry for hunt execution
layer2-agent-loop.ts         Main event loop dispatcher
layer3-event-bus.ts          Pub/sub inter-agent communication
layer4-cognitive-agents.ts   Orchestrator, task planner, analyst
layer5-meta-agents.ts        Recon, scanning, exploit, support meta-agents
layer6-ai-bridge.ts          Claude at orchestration level
mission-chain-manager.ts     Multi-mission chaining and sequencing
mission-memory.ts            Cross-mission learning state
endpoint-claims.ts           Endpoint ownership tracking
agent-registry.ts            Agent capability registry
temporal-event-bus.ts        Time-aware event scheduling
```

### lib/bounty-intelligence/ 
Payout optimization, failure prediction, triage, cross-campaign learning,
tool synergy scoring.

### lib/oob/
Out-of-band callbacks: Interactsh + custom callback server. Used for blind
SSRF/XXE/RCE confirmation where no direct response is possible.

### lib/recon/
Passive + active OSINT recon runner (subdomain enum, DNS, WHOIS, Shodan).

### lib/learning/
Strategy weight learner — aggregates cross-hunt RL signals and updates
per-vulnClass tool selection weights.

### lib/shell/
Command executor sandbox with timeout enforcement.

### lib/claude-bridge.ts
CLI-based Claude invocation: `execFile("claude", ["--print", "-p", prompt])`.
Logs every call to `context/claude-tasks.jsonl`. Used as tier-0 fallback when
Ollama circuit is OPEN.

### lib/claude-client.ts
SDK-based Claude client for multi-turn per-hunt conversation threads.
Supports token counting and streaming.

### lib/context-writer.ts
Streams live hunt state to the `context/` directory files in real time.

---

## DATA FLOW: HUNT START TO CONFIRMED FINDING

```
POST /api/hunt/start { programId, targetUrl, mode, maxIterations }
    ↓
hunt.ts route:
    Validate schema
    Resolve or create program (programId -1 → local lab auto-create)
    Create campaign + target DB records
    ↓
HunterEngine.startHunt(params)
    Init state: { sessionId, phase: "observe", hypotheses: [], observations: [],
                  probes: [], confirmedFindings: [], iteration: 0, budget }
    Emit hunt:started
    Create huntSession DB record
    Start runLoop() in background (non-blocking)
    ↓
runLoop() [while loop]
    ├─ observe()          → Observation[] appended to state.observations
    │      Emit hunt:probe_result per tool
    ├─ hypothesize()      → Hypothesis[] appended to state.hypotheses
    │      ModelRouter → Ollama or Claude → parse JSON
    │      Emit hunt:hypothesis_generated per hypothesis
    ├─ probe()            → ProbeResult[] appended to state.probes
    │      SolverPool.dispatch() per hypothesis
    │      execFile(tool, args) — no shell interpolation
    │      Emit hunt:probing + hunt:probe_result
    ├─ update()           → state.confirmedFindings[] updated
    │      VerifierAgent.verify() — 4-layer pipeline
    │      persistFinding() → INSERT findings table
    │      postExploitAgent.demonstrate() → PATCH findings (non-blocking)
    │      Emit hunt:finding_confirmed
    │      contextWriter.addFinding() → context/hunt-findings.json
    └─ [loop end conditions met]
    persistResults() → UPDATE huntSessions table
    Emit hunt:complete
```

---

## IMPORTANT: THINGS COMMONLY MISINTERPRETED

**1. PostExploitAgent does NOT run exploits.**
It runs read-only probes to *demonstrate* impact for a report. No writes, no
deletes, no reverse shells, no destructive commands. The word "exploit" in its
name refers to impact demonstration, not exploitation.

**2. SolverPool does NOT make strategy decisions.**
It only executes what HunterEngine dispatches. Strategy is centralized in
HunterEngine (Single-Brain Architecture). SolverPool is a parallel executor, not
an autonomous agent.

**3. VerifierAgent Layer 3 (Playwright) is MANDATORY for high-confidence findings.**
If `confidence > 0.7` OR `vulnClass in [xss, sqli, rce, ssrf]`, the finding
MUST pass browser replay. If Playwright worker is unavailable, the verdict
degrades — it does NOT skip the gate.

**4. `programId: -1` is a valid special value.**
It auto-creates a local lab program with `scope: ["*"]`. It is NOT an error.
Used for local Juice Shop / XBOW / custom targets.

**5. ModelRouter falls back gracefully — hunts never hard-fail on model unavailability.**
Ollama down → Claude CLI → built-in fallback. The hunt continues under degraded
reasoning quality, not a crash.

**6. ScopeGuard is called twice for post-exploit probes.**
Once in HunterEngine before the original probe, and again inside PostExploitAgent
for each impact demonstration URL. Both are fail-closed. This is intentional
double-validation, not a bug.

**7. The circuit breaker is on Ollama, not on Claude.**
Claude (via CLI or SDK) has no circuit breaker — it is the fallback, not the
primary. If Claude is slow, the hunt blocks. If Ollama is slow, the circuit
breaker trips and routes around it.

**8. `context/` files are written at runtime, not committed to git.**
They are ephemeral state. Reading them gives current hunt status. They do NOT
persist across server restarts (except what is in the DB).

**9. CampaignOrchestrator layers are sequential gates, not parallel.**
Layer 2 does not start until Layer 1 passes. A failure at Layer 3 aborts the
campaign — it does not skip to Layer 4.

**10. Reinforcement learning is cross-hunt, not within a hunt.**
Within a single hunt, `rlWiring` records outcomes. Between hunts,
`CrossCampaignLearner` aggregates and updates weights. A single hunt does not
benefit from its own RL signals in real time.

**11. `execFile` is used everywhere tool commands run — never `exec` or shell interpolation.**
Tool args are always `string[]` arrays. Attacker-controlled URLs in tool args
cannot inject shell commands. This is enforced throughout — do not change it.

**12. The governance immunizer watchdog runs every 90s regardless of hunt state.**
It snapshots and diffs autonomously. It is not gated on a hunt being active.

---

## EXTERNAL TOOL DEPENDENCIES (Kali Linux)

```
nmap          Network port scanning + service fingerprinting
masscan        Fast port scanning
nuclei         Templated vulnerability scanning (+ custom generated templates)
ffuf           Web fuzzing (directories, parameters, subdomains)
sqlmap         SQL injection testing
whatweb        Web technology fingerprinting
curl           HTTP probing
nikto          Web server vulnerability scanning
wafw00f        WAF fingerprinting
dig            DNS queries
OWASP ZAP      Active web application scanning
```

All binaries checked at startup via `checkBinariesAtStartup()`.
Missing tools are logged as warnings — they do not prevent server start.

---

## KEY DESIGN PATTERNS SUMMARY

| Pattern | Where | What it prevents |
|---|---|---|
| Single-Brain Architecture | HunterEngine owns all strategy | Conflicting probes, wasted budget |
| 4-Layer Verification Gate | VerifierAgent | False positives in reports |
| Circuit Breaker | ModelRouter (Ollama) | Cascading model failures |
| Scope Guard Fail-Closed | scopeGuard.ts (every probe) | Out-of-scope testing |
| No Shell Interpolation | All execFile calls | Command injection via URLs |
| Observation Compression | ObservationCompressor | LLM context overflow |
| Temporal Decay | temporal-decay.ts | Stale hypotheses clogging queue |
| RL Cross-Hunt Learning | CrossCampaignLearner | Repeating failed strategies |
| Double Scope Validation | HunterEngine + PostExploitAgent | Scope bypass in post-exploit |
| Governance Watchdog | governance-immunizer.ts | Unauthorized behavior drift |

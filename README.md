# Netty Hunter – Sentinel Primordial

**Bug Bounty Intelligence Platform** – Autonomous, reasoning-driven vulnerability discovery with multi-agent governance.

---

## Architecture

### Backend (Express + TypeScript + PostgreSQL)

---

#### Core Hunt Loop

- **Hunter Engine**: Observe → Hypothesize → Probe → Update reasoning loop with anomaly-first scanning and real-time strategy adaptation; after 5 consecutive tool failures a canary HEAD request fires against the target — a 403 response or network-level drop (ETIMEDOUT/ECONNRESET/ECONNREFUSED) sets `hardBanned = true`, emits `hunt:hard_banned`, and breaks the main loop via a while-condition guard; CLI tools are also skipped pre-emptively if the rate limiter has already flagged the target
- **SolverPool**: Dynamic solver spawning per endpoint-per-vulnerability-class; `httpProbe()` calls `dynamicRateLimiter.recordResponse()` after every HTTP probe so 403 status codes feed the ban detector; `isHardBanned()` is checked before each probe so solver tasks skip instantly against a banned target instead of burning a 10-second timeout
- **Campaign Orchestrator**: 6-layer orchestration model — Governance Gate → Target Intelligence → Strategy Planning → Execution Engine → Verification Gate → Intelligence Harvest; each layer fail-closed with full audit trail; supports `resumeCampaignId` to reopen an interrupted campaign and continue from the exact DB state rather than starting over; registers `hunt:hard_banned` in the Promise race so a detected IP ban resolves the hunt gracefully rather than hanging; SolverPool supplement is skipped entirely when `isHardBanned()` returns true
- **Single-Brain Architecture**: `StrategyCoordinator` as sole decision-maker using confidence-driven dispatch for exploits, hypothesis tests, solver spawning, or pivoting; observation payloads are condensed via `summariseObservations()` before being injected into the strategy prompt so the coordinator never receives an oversized context
- **Async Phase Transitions**: `HunterEngine.runLoop()` yields to the Node.js event loop via `setImmediate` between every phase transition — concurrent hunts, socket.io callbacks, and DB writes all receive CPU cycles during model inference, eliminating head-of-line blocking in multi-hunt scenarios

---

#### Orchestration Layer (`lib/orchestration/`)

A full 6-layer multi-agent hunt pipeline with event-driven coordination, distributed locking, and AI-powered cognitive agents.

- **Layer 1 — Hunt Orchestrator**: Central coordinator managing hunt lifecycle across recon, scanning, exploitation, and reporting phases; drives dynamic phase transitions and integrates with meta-reasoner and decision trace logger
- **Layer 2 — Agent Loop**: Agent lifecycle management — creation, tool queue execution, scan completion tracking, and results ingestion for all 39 integrated tools; imports stealth flags and timing profiles per tool invocation
- **Layer 3 — Event Bus**: Typed pub-sub with specialized publication methods for findings, endpoint characterizations, defense detections, and phase completions; persists event history per hunt; also carries `finding_verified` and `finding_rejected` events from the Campaign Orchestrator so graph-wiring can reconcile verification outcomes with graph state
- **Layer 4 — Cognitive Agents**: AI-powered OrchestratorAgent, TaskPlannerAgent, AnalystAgent, ResearcherAgent, CoverageValidatorAgent — all backed by the AI bridge and mission memory; TaskPlannerAgent.createPlan() is called at scanning phase entry to build a structured scan plan from discovered endpoints; AnalystAgent.findPatterns() is called before report generation to surface cross-finding patterns; ResearcherAgent.lookupCVE() is wired to the NVD API — real CVE records, CVSS scores, and exploit references returned for any query
- **Layer 5 — Meta Agents**: 10 specialized concrete agents — ReconAgent, ExploitAgent, CredentialAgent, IntelAgent, BlueTeamAgent, PivotAgent, ReportAgent, WordlistAgent, SimGenAgent, SmartAgent; each with metadata profiles and tool chain awareness
- **Layer 5 — CodeGen Agent**: Self-modifying agent for code generation and TypeScript validation with approval gates and risk classification; writes and validates its own output before committing
- **Layer 6 — AI Bridge**: Ollama integration for agent prompting with template management, confidence thresholds, and simulation fallback when no model is available
- **Mission Memory**: Central per-hunt memory store — tracks domains, subdomains, endpoints, technologies, vulnerabilities, credentials, and notes; backed by the `mission_memory_snapshots` PostgreSQL table via atomic `INSERT … ON CONFLICT DO UPDATE` so state survives container restarts and redeploys; `initialize()` is async and restores from DB as the authoritative source before seeding fresh state; snapshot writes on every `addVulnerabilities` / `addEndpoints` call are fire-and-forget so they never block the hunt; `clear()` deletes the DB row
- **Agent Registry**: Tracks all active agents — status management, claim tracking, invocation recording, hunt-scoped queries
- **Endpoint Claims**: Distributed lock manager with timeout-based claim expiration to prevent duplicate work across concurrent agents
- **Tool Parsers**: 20+ parsers for nmap, nuclei, sqlmap, nikto, whatweb output → standardized vulnerability and endpoint data structures
- **Pass-K Evaluator**: Runs exploit agents up to k times and selects the best result by confidence threshold; k is dynamically resolved per-agent and per-resource-class — `enterprise` → base+1 (max 4), `standard` → base, `lightweight` → floor(base/2); payout override: ≥$5k→k=3, ≥$1k→k=2, <$1k→k=1; retries stop early when confidence ≥ 0.8; deterministic agents (recon, scanner) always run once
- **Prompt Loader**: Template management with file persistence, variable substitution, and per-template confidence thresholds
- **Temporal Event Bus**: Urgency-decay event correlation with dead-letter queue; preemptive signaling for critical findings; integrates with Hunt Cortex
- **Mission Chain Manager**: Stub interface for exploit chain management and endpoint injection (full implementation pending desktop-agent cognitive modules)

---

#### Governance Layer (`/api/governance`)

An independent 8-pillar governance system that audits, constrains, and monitors all agent behavior.

- **CoreGovernance**: Central decision recorder enforcing 8 named pillars — Kinetic Clause, Recursive Loop, Ethical Boundary, Hardware Sovereignty, Multi-Agent Quorum, Safety Controls, Prompt Injection Detection, Blue Team Oversight
- **GovernanceProxy**: Network-level enforcement — SSRF/internal-IP blocking, per-agent domain contracts, per-minute rate limits, stealth delay injection; all requests validated before tool execution; fronted by `ScopeVerifyCache` — a 5-minute TTL hash cache keyed by `hostname:huntId` that serves repeated requests to already-verified endpoints from an O(1) Map lookup, bypassing the full 8-pillar `verifyScope()` call; `ALWAYS_ALLOWED_DOMAINS` (nvd.nist.gov, shodan.io, etc.) skip even the cache and go straight to approval; cache evicts stale entries lazily and caps at 2,000 entries to bound memory growth
- **PromptInjectionDetector**: 35 trigger keywords, 12 regex patterns, 4 semantic categories (jailbreak, role override, data exfil, system bypass); scores and flags all agent inputs
- **DesktopAgentGovernance**: Path traversal detection, dangerous command blocking, tool allowlist validation for any host-level agent actions
- **DriftDetector**: Snapshot-based drift analysis — compares recent verdict/risk/pillar distributions against rolling baseline; auto-snapshots every 5 minutes
- **DecisionLogger**: Daily NDJSON decision log files with write-ahead log (WAL) for crash safety — every decision is written to `decisions-wal.ndjson` before entering the in-memory buffer; the WAL is cleared only after a successful flush to the daily log; on startup, any unflushed WAL entries are replayed into the daily log before normal operation resumes, enabling full Mission Memory reconstruction after an abrupt crash; `getStats()` exposes live WAL entry count
- **SelfAttestationService**: Agents justify their own decisions with confidence scores; builds per-agent justification trails queryable by pillar
- **14 REST endpoints**: stats, pillars, decisions, logged decisions, audit log, drift analysis, proxy requests/stats/contracts, injection stats/check, attestations

---

#### Intelligence & Planning

- **Meta-Reasoner**: Bayesian hypothesis confidence tracking with information-gain rate monitoring; detects plateaus and executes weighted strategy pivots via a 10-node strategy graph with historical success weighting; integrates backward planner and decision journal for past-hunt replay
- **Contextual Tool Selector**: Cosine similarity ranking across 39 tools using multi-dimensional context vectors (goal alignment, tech stack, phase, past success rates, circuit breaker state); tools on open circuits are filtered from results before ranking is returned — open-circuit tools are dropped and their configured fallback tool is substituted if one exists
- **BackwardPlanner**: Goal-first attack path ranking — works backward from target objective using expected-value weighted attack trees; suggests pivots when current strategy is exhausted
- **Hunt Cortex**: Signal bus with composite hunt health scoring across 5 dimensions (novelty, missed events, verification degradation, negative evidence, signal count); publishes typed signals to all subscribers
- **MITRE Prerequisite Tree**: ATT&CK technique dependency graph — identifies prerequisite chains, choke points, and technique orderings; queryable by capability or technique ID
- **Offensive Graph DB**: In-memory + PostgreSQL attack graph with typed nodes (endpoint, vulnerability, technique, tool, credential) and weighted edges (exploits, targets, discovered_by, derived_from, produces); full traversal and shortest-path queries
- **Graph Wiring**: Event-driven graph population — listens to `vulnerability_found`, `tool_completed`, `phase_changed`, `endpoint_characterized`, `finding_verified`, and `finding_rejected` events and automatically builds and reconciles the attack graph in real time; verification outcomes are merged into existing vulnerability nodes using a `verificationId` idempotency key — the first event for a given finding ID wins, preventing duplicate events or out-of-order delivery from corrupting the confirmed/rejected state
- **NVD CVE Client** (`lib/intelligence/nvd-client.ts`): Live integration with the NIST National Vulnerability Database API 2.0 — keyword search by tech name + version, CWE-based lookup, CVSS score extraction with V31→V30→V2 fallback chain; sliding-window rate limiter (4 req/30s without key, 45/30s with `NVD_API_KEY`); 1-hour session cache per query key; all methods fail open (return `[]`) on any error or timeout; CVE seeding fires on the first observe pass — WhatWeb-detected server-side technologies (Apache, Nginx, WordPress, Tomcat, etc.) are cross-referenced against NVD and any CVEs with CVSS ≥ 7.0 are injected as high-priority hypotheses (confidence 0.7, priority 8–10) before the generic hunt loop starts; confirmed findings are automatically tagged with `cweId` (static map: XSS→CWE-79, SQLi→CWE-89, etc.) and `cveId` (NVD lookup by CWE, best match with CVSS ≥ 6.0) — fields that previously always stored NULL
- **Hunt Lab Runner**: Runs hunts against lab profiles (OWASP Juice Shop) with determinism checking, outcome scoring, and adaptive threshold feedback
- **Offline Fallback**: Tiered fallback decision logic when orchestrator is unavailable — uses reasoning engine, hunt cortex signals, and tool fallback chains from seed knowledge
- **Hunt Strategy Builder**: Auto-populates structured execution plans based on hunt goals, selects optimal tool chains, orders steps by phase, and supports dynamic step injection and mid-hunt adaptation
- **Hunt Template Library**: 10 built-in templates (recon_first, xss_focus, api_abuse, sqli_hunt, ssrf_hunt, auth_testing, cloud_exposure, logic_flaws, subdomain_takeover, full_spectrum) with seed hypotheses and intelligence overrides
- **Tool Knowledge System**: Structured profiles for 39 integrated security tools and 10 tool chain pipelines, injected into the AI reasoning loop at runtime
- **Static Analysis Feed**: Lightweight pre-hunt pattern matching — route extraction for 5 frameworks, 24+ dangerous sink patterns, dependency CVE checking, config scanning; generates seed hypotheses for the Hunter Engine
- **External Plan Memory**: Attack plans stored outside context window, retrieved at budget checkpoints with auto-adaptation to maintain strategic coherence
- **External APIs**: VirusTotal, AbuseIPDB, Shodan, MITRE ATT&CK clients with simulated fallbacks when no API key is configured; used for passive enrichment during target intelligence phase

---

#### WAF & Evasion

- **WAF Bypass System**: 7-module architecture — Detection → Fingerprint → Evasion Library → Executor → Rule Correlation → Cross-Session Vendor Profiles → Intelligence Synthesizer
- **Cross-Session Vendor Evasion Profiles**: Aggregates all evasion data across sessions per vendor, generating ranked technique profiles
- **Rule Correlation Matrix**: Identifies shared WAF rules across attack categories and assesses ruleset complexity
- **Intelligence Synthesizer**: Meta-layer combining all 7 WAF intelligence sources into a single `UnifiedIntelligence` package for optimal technique rankings, risk assessment, pacing recommendations, and chain recommendations
- **Anomaly Detection**: Detects block rate spikes, response time shifts, new WAF status codes, and pattern breaks to inform mid-hunt adaptation

---

#### Stealth Layer (`lib/stealth/`)

Two complementary stealth systems merged into one module — the existing WAF/behavioral evasion layer plus a new operational stealth layer for tool execution, network presence, and agent self-awareness.

**Existing evasion modules:**
- **StealthCoordinator**: Full probe preparation pipeline — timing (decay-aware) → mimicry headers → AI WAF evasion variants → traffic normalization; per-domain session management with 30-minute rotation
- **BehavioralMimicry**: Human-like request patterns, referrer chains, and browser fingerprint simulation
- **AI WAF Evasion**: AI-generated payload variants ranked by confidence for WAF bypass
- **TimingEngine**: Decay-aware probe timing with anomaly score tracking
- **SessionWarmup**: Pre-hunt session establishment to build baseline traffic profile; automatically triggered via `stealthCoordinator.runWarmup()` at the start of every `HunterEngine.startHunt()` call so WAF/CDN fingerprinting is pre-loaded before the first probe
- **TrafficNormalizer**: URL and request normalization toward expected baseline
- **Temporal Decay Engine**: Models how WAF/bot-management systems decay their anomaly memory over time; vendor profiles for Cloudflare, Akamai, AWS WAF, Imperva, F5 BIG-IP, and generic; per-session-domain history is capped at 500 entries per key and evicted after a 2-hour TTL when the Map exceeds 200 entries, preventing unbounded memory growth in long-running hunts

**New operational stealth modules:**
- **Tool Runner**: Executes all 39 tools with per-tool stealth flags (rate limits, delays, randomization, proxy routing); 4 stealth profiles — aggressive, balanced, stealth, ultrastealth
- **Timing Obfuscation**: Circadian-aware delay injection with jitter, burst penalty, and risk multipliers across recon/exploit/scan action types
- **Tool Priority**: Dynamic tool priority scoring based on stealth mode, past success, and WAF detection state
- **Network Stealth**: Request routing, proxy management, and network-level evasion for all outbound probe traffic
- **Stealth Analyzer**: Real-time detection risk scoring across all active probes; feeds auto-adjuster
- **Stealth Alert State**: Alert level state machine — tracks escalating detection signals and recommends mode changes
- **Auto-Adjuster**: Automatic stealth mode upgrades when alert state rises; downgrades after quiet periods
- **Dynamic Rate Limiter**: Per-domain adaptive rate limiting with sliding-window quota discovery, exponential backoff on 429s, and hard IP ban detection; tracks consecutive 403 responses per target — after 5 consecutive 403s the target is flagged with a 1-hour ban (logged as `hard_ip_ban_detected`); `isHardBanned(target)` is the circuit-break signal used by both HunterEngine (pre-tool check) and SolverPool (pre-probe check) to skip requests against banned targets immediately; 429 quarantine (separate from the ban) fires after 5 consecutive 429s at 10-minute default duration, doubled on repeat
- **Agent Awareness**: Agent self-monitoring — tracks own footprint, request patterns, and detection probability
- **Log Scrubber**: Removes sensitive data from all log output before persistence
- **Cleanup Manager**: Post-hunt artifact cleanup — temp files, cached payloads, session state
- **Training Integration**: Records tool execution outcomes for reinforcement learning feedback loop
- **Vision Agent**: Screen/viewport capture integration for UI-based vulnerability validation
- **Window Manager**: Application window management for desktop agent UI interactions
- **Agent UI Interactor**: Playwright-based UI automation for browser-level agent actions

---

#### Verification & Validation

- **VerifierAgent**: 4-layer anti-hallucination pipeline — Dedup → HTTP Reprobe → Playwright Browser Replay → AI Confirmation; Layer 1 dedup preloads the 500 most-recent `dedupHash` values from DB on startup so the in-memory cache is warm after a process restart; runs exact SHA-256 hash first, then a SimHash near-duplicate pass — findings with Hamming distance ≤ 3 bits (same vuln class, similar endpoint/payload) are collapsed to one; Layer 4 AI response is scanned by PromptInjectionDetector before the parsed verdict is trusted
- **Playwright Worker Thread** (`workers/playwright-worker.ts`): Layer 3 browser replay runs in a dedicated `worker_threads` Worker so Playwright's page lifecycle — navigation, dialog interception, screenshot capture, content extraction — never blocks the main event loop during concurrent verifications; a message-passing protocol carries serialized `SolverResult` objects to the worker and returns structured replay results; 35-second per-replay timeout with clean pending-promise drain on `close()`; dev (tsx) and prod (compiled JS) paths are both handled by runtime path detection in `spawnWorker()`
- **SimHash Near-Duplicate Engine** (`lib/intelligence/simhash.ts`): 64-bit FNV-1a-based weighted shingle fingerprinting; catches near-duplicates the exact hash misses (e.g. same XSS payload on `/search?q=` vs `/search?query=`); Hamming-distance comparison across a bounded 5,000-entry ring buffer keeps memory flat across long hunts
- **ObservationCompressor** (`lib/intelligence/observation-compressor.ts`): historical state vector for context window management; once a session accumulates more than 20 observations the compressor retains the 8 most-recent observations verbatim and condenses older ones into a compact state vector — dominant anomaly signals (tag-frequency weighted by anomaly score), source coverage breakdown, average and peak anomaly scores; the vector is merged across iterations so no information is lost, only recoded as a dense string; injected into `hypothesize()` above the raw observation block, keeping prompt length bounded across arbitrarily long hunts
- **Public Disclosure Detector** (`lib/intelligence/public-disclosure-detector.ts`): Before a confirmed finding is submitted, checks whether the same vulnerability has already been publicly disclosed by another hunter on the same program — calls HackerOne (Basic auth), Bugcrowd (Token auth), and Intigriti (Bearer auth) APIs with a per-run session cache; two-tier matching: `confirmed_duplicate` (vuln type AND target domain both match) routes the finding to the rejected array and emits `l5:public_duplicate`; `likely_duplicate` (vuln type only) passes through to `verified` with a warning event; `skipped` when no API token is configured; findings are tagged with `disclosureCheckStatus`, `publicDisclosureUrl`, and `publicDisclosureNote` in the DB regardless of outcome
- **Verification Lifecycle**: TTL-based finding staleness tracking; findings degrade over time if not re-verified, triggering automatic re-probe queues and cortex signals
- **Hypothesis Conflict Detector**: Detects semantic conflicts between template intelligence overrides and empirical data, annotating hypotheses with conflict context and reducing confidence
- **ScopeGuard**: Fail-closed scope validation at every tool invocation — DB-backed, wildcard support, 5-minute cache

---

#### Bounty Intelligence (`lib/bounty-intelligence/`)

Pre-hunt and cross-hunt analytics for program selection, payout maximization, and duplicate avoidance. All data persisted to `server/workspace/bounty-intelligence/`.

- **Program Fetcher**: Monitors bug bounty programs for scope changes, new targets, and rule updates; maintains fetch history and change records per program; pre-seeded with HackerOne, Bugcrowd, Intigriti, YesWeHack, Tesla, and security program configs
- **Cross-Campaign Learning**: Learns attack patterns across multiple campaigns — technique similarity detection, technology-specific playbook recommendations, and campaign outcome indexing; 6 pre-seeded campaign profiles
- **Tool Synergy Engine**: Maps which tool combinations produce the highest finding rates for specific vulnerability types and target tech stacks; generates ranked playbook recommendations; pre-seeded tool effectiveness data
- **Failure Prediction Engine**: ML-based prediction of tool and technique failure modes based on historical execution data; pre-seeded base rates, conditional probabilities, and model accuracy data
- **Payout Optimization**: Estimates expected payout per vulnerability class and target type; generates escalation chains to maximize bounty value from a confirmed finding
- **Predictive Duplicate Avoidance**: Heatmap-based duplicate prediction — tracks which vulnerability classes have been heavily reported on a given program and steers the hunt away; `addKnownFinding()` is called automatically from `CampaignOrchestrator.layer6_intelligenceHarvest()` for every verified finding so the duplicate knowledge base grows with each completed hunt
- **Triage Predictor**: Predicts triage outcomes (accepted/duplicate/informational/N/A) based on submission timing, program history, and finding type
- **Intelligence Types**: Shared type definitions — CampaignOutcome, ExecutionPhase, HuntGoal, IntelligenceEvent, DefenseProfile, and 15+ supporting interfaces

---

#### Missions (`/api/missions`)

User-driven mission board for launching and tracking structured security missions. All data persisted to `server/workspace/missions/` as `msn-*.json` files.

- **Mission CRUD**: Create, list, get, update, delete missions with full schema — name, target, type, priority, goal, threat level, stealth config, in/out-of-scope
- **Mission Types**: 4 templates with pre-built tool step chains — `recon` (subfinder→nmap→whatweb→ffuf), `full-scan` (nmap→nuclei→nikto), `vulnerability` (nuclei→sqlmap→dalfox), `exploitation` (searchsploit→commix)
- **Step Execution Tracking**: Per-step status, output, timing, and duration; progress auto-computed; mission auto-completes when all steps finish
- **Evidence & Findings**: Append evidence items and findings to running missions; each with typed ID, timestamp, and step reference
- **Attack Path**: Auto-generated attack path visualization data mirroring the step sequence
- **Pre-seeded**: 2 completed missions in workspace — full recon run on testsite.com, nmap scan on Juice Shop localhost

---

#### Workspace (`server/workspace/`)

Persistent file-based storage for all runtime data. Survives server restarts. Organized by feature area.

```
workspace/
├── bounty-intelligence/     # Program configs, campaign profiles, ML training data, synergy scores
├── missions/                # msn-*.json mission records with steps, findings, evidence
├── deadlines/               # Bug bounty program deadlines
├── payloads/                # Payload library entries (pre-seeded with XSS, SQLi, SSRF, etc.)
├── submissions/             # Submission tracking records
├── tasks/                   # Task planning items
├── workflows/               # Workflow definitions and execution history
├── poc-results/             # Proof-of-concept execution results
├── reports/                 # Saved report drafts
├── analysis/                # Hunt analysis output
├── scopes/                  # Scope definitions
├── nuclei-templates/        # Custom Nuclei YAML templates
├── extensions/              # Installed extensions manifest
├── exploit-development/     # Python exploit scaffolding, XSS/SQLi payload lists, PoC stubs
├── sentinel-recon/          # Python port/service scanner with async scan engine and tests
├── test-project/            # HTML/JS/CSS test project workspace
└── react---vite/            # React+Vite project workspace
```

- **exploit-development/**: Python exploit framework scaffold with `exploit.py`, `requirements.txt`, XSS and SQLi payload wordlists, and PoC directory
- **sentinel-recon/**: Full async Python scanner (`scanner.py`, `main.py`) with banner grabbing, service detection, JSON output, and unit tests; includes a saved scan result
- **Extensions**: Plugin manifest at `extensions/installed.json`; currently tracks installed tools (e.g., prettier)

---

#### Learning & Self-Improvement

- **Decision Journal**: DB-backed similarity search across past hunt decisions; retrieves the most similar past context vector and its outcome, enabling strategy replay for known-good pivots
- **Adaptive Threshold Tuner**: Learns per-goal-type optimal thresholds (health floor, novelty floor, max degraded verifications, max missed events) from hunt outcome scores; persists and evolves per target class
- **Decision Trace Logger**: 17-event-type audit trail (hunt_start, meta_pivot, meta_evaluation, hunt_complete, etc.) with confidence-at-event recording; feeds calibration analysis and pivot pattern extraction
- **Hunt Cortex Health Metrics**: Real-time composite hunt health scoring; integrated with meta-reasoner to trigger stabilize/accelerate/pivot decisions when health subsystems degrade
- **Closed RL Feedback Loop**: `brain.recordActionResult()` is called in `HunterEngine.runTool()` on both success and failure paths, so the circuit breaker and reasoning engine receive tool outcome signals and adapt tool selection in subsequent iterations; when a circuit opens, a `FALLBACK_USED` signal is broadcast to Hunt Cortex, degrading the composite health score and triggering the meta-reasoner; every 3 iterations `HunterEngine.runLoop()` checks hunt health — if below 0.4, calls `metaReasoner.evaluateEnriched()` and injects `backwardPlanner` pivot paths as new hypotheses when the decision is `pivot`
- **Post-Hunt Extraction Pipeline**: Wires the Reasoning Reinforcement flywheel into hunt completion — Phase 1 captures confidence calibration per finding, Phase 2 extracts high-scoring operational chains, Phase 3 aggregates cross-hunt patterns and emits ROI-ranked chain stats
- **Unified Reinforcement Store**: Cross-hunt self-learning across 5 domains: Tool Success Rates, Framework-Vuln Matrix, Program Type Heuristics, Confidence Calibration, and Exploration Tracking — all with temporal decay; all writes use a single atomic `INSERT … ON CONFLICT (domain, key) DO UPDATE SET successCount = successCount + N` so concurrent hunts recording outcomes for the same key never lose increments; `getToolRecommendation()` uses an epsilon-greedy policy (ε=0.15) — 15% of calls swap the last tool slot for a randomly-selected tool with fewer than 10 historical attempts for that vuln class, ensuring novel tools get exposure before RL history can permanently suppress them
- **Exploit Chain Intelligence**: Tracks the full lifecycle of multi-step attack sequences across sessions — chain success/failure rates, replay recommendations, pattern avoidance, cross-hunt ROI ranking
- **Unified Temporal Decay System**: Standardizes intelligence aging across three domains with named decay profiles for consistent, tunable aging
- **ROI Model**: Calculates expected value per vulnerability type and auto-tunes confidence thresholds based on historical verification pass rates; uses a Beta(1,3) Bayesian prior — `(successCount + 1) / (totalCount + 4)` — so at zero observations the prior mean is 0.25 (encouraging exploration), at 5 failed attempts the rate is ~0.11 (cautious but not zero), and the prior dissolves smoothly as data accumulates; a cliff-edge drop to 0.0 at any data boundary is impossible, preventing unproven exploit classes from being permanently gated out before a fair trial
- **Autonomy Maturity Tracking System**: Tracks genuine autonomy maturity via Brier snapshots, rolling trend analysis, reinforcement noise detection, and exploration suffocation guard; produces composite Autonomy Maturity Score with auto-generated milestone reports
- **Per-Domain Autonomy Gating**: Tracks autonomy independently across 6 operational domains — global autonomy level capped by the weakest-performing domain; each domain has a `naturalCeiling` constant that normalizes structurally-limited domains (e.g. exploit chain depth caps at 0.6 on most programs) so a permanently hard domain cannot indefinitely suppress global deployment mode; CAMS and regression alerts still use raw scores
- **Lab Profiles**: OWASP Juice Shop ground-truth vulnerability profiles (32 challenges across 7 categories) with LabScorer — measures finding quality against known-answer datasets for calibration validation
- **Juice Shop Lab** (`/api/juiceshop/*`): Full Docker lifecycle management for the OWASP Juice Shop CTF lab — spawn/stop container, poll readiness, run hardcoded or adaptive benchmark scans against 32 challenges, persist run history to `workspace/lab-runs/`; CTFBenchmark UI provides Start Lab / Stop Lab buttons and live scan results with difficulty and category breakdowns
- **XBOW CTF Benchmark** (`/api/xbow/*`): Per-challenge Docker container lifecycle for XBOW CTF challenges — each challenge spawns its own container on a dedicated port (18000+), probes common paths for `flag{…}` patterns, and tears down in a finally block; 5 built-in stub challenges (sqli-basic, xss-reflect, idor-user, ssrf-internal, rce-deserialization) serve the UI when Docker or the XBOW repo is unavailable; adaptive mode uses `huntLabRunner.runHunt()` when Ollama is available; run history persisted to `workspace/lab-runs/xbow-*.json`

---

#### AI Reasoning Knowledge Base

- **JsonPromptLoader**: Singleton prompt knowledge base with semantic retrieval via `nomic-embed-text` embeddings — pre-computes 768-dim embeddings for all 1,785 prompt entries at startup, caches to disk, and retrieves the 7 most contextually relevant examples per hypothesis cycle via cosine similarity; falls back to keyword/domain filtering when embedding model is unavailable
- **18 Prompt Datasets (1,785 total entries)**:
  - kali-tool-reasoning — tool selection and execution reasoning (100)
  - kali-tool-interpretation — tool output interpretation (100)
  - kali-tools — tool profiles and capability mapping (50)
  - api-auth-chains — JWT, OAuth2, SAML, CORS, MFA, GraphQL auth chains (100)
  - cloud-security — AWS, GCP, Azure, Kubernetes attack scenarios (100)
  - business-logic — fintech, marketplace, SaaS logic flaw patterns (100)
  - engagement-signals — defensive signal recognition and response (100)
  - access-level-scenarios — privilege escalation and access boundary testing (100)
  - vulnerability-severity-reasoning — impact and severity assessment (100)
  - tool-chain-reasoning — multi-tool orchestration and pivot logic (100)
  - engagement-decision-reasoning — 5 complexity levels × 9 engagement contexts (100)
  - attack-paths — multi-step attack path construction (200)
  - chain-scenarios — full exploit chain scenarios (255)
  - bounty-patterns — program-specific hunting patterns (100)
  - core-security-logic — fundamental security reasoning primitives (100)
  - cybersec-reasoning — general security analysis reasoning (50)
  - defensive-awareness — blue team detection awareness (30)
- **Seed Knowledge**: Hardcoded MITRE ATT&CK techniques, attack paths, tool fallback chains, tool categories, intent patterns, goal payout data, hunt goal paths, and pivot playbooks — injected at module load, no DB required

---

#### Observability

- **Live Reasoning Observability**: Real-time window into the Hunter Engine's thinking — hypothesis rankings, active probe status, conflict annotations, temporal decay status, active intelligence sources, and mental model state
- **Real-time Socket.IO Events**: All agent events streamed to subscribed frontend rooms — hunt phases, observations, hypotheses, probes, findings, orchestration layer transitions, meta-reasoner decisions

---

#### Output Generation

- **Nuclei Template Generator**: Auto-generates Nuclei YAML templates from verified findings for immediate redeployment
- **Draft Report Generator**: Auto-generates submission-ready bug bounty reports from verified findings with platform-aware formatting (HackerOne, Bugcrowd, Intigriti, Synack, YesWeHack)
- **Target Selection Intelligence**: Pre-hunt program scoring and ROI ranking based on program metadata, historical payout data, and cost advantage

---

#### Routing

- **ModelRouter**: Intelligent Ollama model routing by task type (reason, code, analyze, classify, chat, summarize) with auto-discovery and 60-second model cache

---

### Frontend (React + Vite + TypeScript + Tailwind)

- Dark hacker aesthetic with green terminal accents
- **Live Activity Feed** (`components/LiveActivityFeed.tsx`): Replaces flat timestamped text logs in both HuntConsole and Orchestration pages with a real-time typed event stream; distinct visual treatment per event type — hypothesis cards (Brain icon, confidence bar, collapsible reasoning), probe rows that animate while in-flight and resolve ✓/✗ with elapsed time, prominent finding cards (orange border, severity chip, payload snippet), CVE-seeded cards (cyan border, CVE ID badges colored by CVSS severity), public duplicate cards (orange = blocked submission, yellow = warning), strategy pivot cards, hard IP ban alerts; auto-scrolls to bottom on new events; `▸ scanning…` pulse when hunt is running but idle for >3s
- Dashboard with ROI charts, autonomy metrics, recent findings
- Program management with scope configuration
- Findings panel with 4-layer verification workflow
- Hunter page: session manager with Attack Path Visualizer, WAF Intel tab, Reports tab
- Intelligence suite: autonomy radar charts, RL stats, WAF profiles, exploit chains
- Reports & AI chat assistant
- **Bounty section** (10 nav items): BountyIntelligence, Analysis, Submissions, Scope, DraftReports, NucleiTemplates, Payloads, Deadlines, BackwardHunt, ToolReadiness, BrowserView, AuditTrail, AIAdvisor, WorkflowBuilder, TaskPlanning, CVEIntel, PoCLab, HuntReplay, CTFBenchmark, SyncStatus — plus standalone CampaignIntelligence, PlaybookLibrary, StrategyAdvisor views
- **Missions section**: MissionBoard with live hunt monitor, mission details panel, offensive graph visualization, stealth indicator, tool validator, and launch modal

---

## API Surface

| Prefix | Description |
|---|---|
| `POST /api/auth/*` | Login, logout, register |
| `GET/POST /api/hunt/*` | Hunt sessions, start/stop, state, findings |
| `GET/POST /api/bounty/*` | Programs, ROI ranking, RL stats, autonomy, exploit chains, WAF profiles, hunt templates, AI chat, analysis, audit trail, browser, CVE intel, deadlines, nuclei, payloads, PoC lab, scope, submissions, tasks, tool readiness, workflows |
| `POST /api/orchestration/run` | Start full 6-layer orchestrated hunt |
| `GET /api/orchestration/:id` | Live orchestration state |
| `GET /api/hunter/*` | Hunter engine sessions, strategies, solvers, validation gate, plan memory, backward hunt, ROI, target selection, static analysis, exploit chains, reinforcement, autonomy maturity |
| `GET/POST /api/missions/*` | Mission CRUD, start/stop, step updates, findings, evidence |
| `GET/POST /api/bounty-intelligence/*` | Scope analysis, payout estimation, duplicate detection, report coaching, submission optimization, program fetcher, campaign learning, tool synergy, triage prediction, full pipeline |
| `GET/POST /api/reasoning/*` | Decision traces, calibration stats, hunt cortex health, lab runs, adaptive thresholds, divergence analysis |
| `GET/POST /api/juiceshop/*` | Juice Shop Docker lifecycle (spawn/stop/status), challenge list, benchmark run (hardcoded/adaptive/hybrid), abort, run history |
| `GET/POST /api/xbow/*` | XBOW CTF Docker lifecycle (status, clone-repo), challenge list, benchmark run/abort, run history |
| `GET/POST /api/graph/*` | Offensive graph nodes/edges, shortest path, per-hunt summaries |
| `GET/POST /api/intelligence/*` | Playbooks, tool selection, strategy planning, attack paths, MITRE techniques, pivot evaluation |
| `GET /api/governance/stats` | Governance decision counts by pillar/verdict/risk |
| `GET /api/governance/pillars` | All 8 pillar definitions |
| `GET /api/governance/decisions` | Filterable decision log |
| `GET /api/governance/audit` | Audit event log |
| `GET /api/governance/drift` | Behavioral drift analysis |
| `GET /api/governance/proxy/stats` | Network request governance stats |
| `POST /api/governance/injection/check` | Prompt injection detection |
| `GET /api/governance/attestations` | Agent self-attestation trail |

---

## Setup

### Requirements

- Node.js 20+
- PostgreSQL 15+
- Ollama with at least one reasoning model: `ollama pull llama3.2`
- Ollama embedding model for semantic prompt retrieval: `ollama pull nomic-embed-text`
- Kali Linux recommended (for tool integrations: nmap, nuclei, sqlmap, ffuf, gobuster, nikto, whatweb, httpx)

### Install

```bash
# Install dependencies
npm install

# Configure environment
cp server/.env.example server/.env
# Edit server/.env with your database URL and secrets

# Push database schema
npm run db:push

# Start development
npm run dev
```

The `server/workspace/` directory is pre-seeded with bounty programs, campaign profiles, ML training data, missions, payloads, and project scaffolding — no manual setup required.

The `mission_memory_snapshots` table is created automatically at server startup via an idempotent `CREATE TABLE IF NOT EXISTS` statement — no manual migration step needed for this table.

### Environment Variables

```
DATABASE_URL=postgresql://postgres:password@localhost:5432/netty_hunter
SESSION_SECRET=your-random-secret-minimum-32-chars
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_DEFAULT_MODEL=llama3.2
OLLAMA_REASONING_MODEL=deepseek-r1:7b
PORT=3001

# Enables real Kali tool execution (default: mock mode)
REAL_TOOLS=true

# Embedding model for semantic prompt retrieval (~274MB, CPU-friendly)
EMBED_MODEL=nomic-embed-text

# Optional — external threat intel
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=

# Optional — NVD CVE database (free account gives 45 req/30s vs 4 req/30s anonymous)
NVD_API_KEY=

# Optional — bug bounty platform APIs for public disclosure checking
HACKERONE_USERNAME=
HACKERONE_API_TOKEN=
BUGCROWD_API_TOKEN=
INTIGRITI_API_TOKEN=

# Optional — XBOW CTF challenge repo
XBOW_REPO_URL=https://github.com/xbow-org/challenges
```

---

## Security Tools Integration

The platform integrates with 39 Kali Linux security tools across 8 categories:

| Category | Tools |
|---|---|
| Recon | nmap, amass, subfinder, assetfinder, httpx |
| Fuzzing | ffuf, gobuster, feroxbuster, dirsearch, wfuzz |
| Vulnerability | nuclei, nikto, whatweb, wapiti |
| Injection | sqlmap, commix, xsstrike, dalfox |
| Auth | hydra, medusa, patator |
| Network | masscan, zmap, netcat |
| Exploitation | metasploit, searchsploit |
| Misc | curl, wget, jq, git |

All tools are executed through the **Tool Runner** stealth layer — each invocation gets per-tool stealth flags, timing profile delays, and optional proxy routing based on the active stealth mode. Tool availability is queryable live via `GET /api/bounty/tools/readiness`.

---

## Architecture Principles

- **Fail-closed scope validation** — ScopeGuard and GovernanceProxy block all out-of-scope requests at every invocation; governance is never optional
- **8-pillar governance** — every agent decision is audited against named ethical and operational pillars with full replay data
- **6-layer orchestration** — every hunt passes through a structured pipeline from governance gate to intelligence harvest; no layer can be bypassed
- **Mandatory browser validation** — high-severity findings MUST pass Playwright replay before reporting
- **Anti-hallucination pipeline** — 4-layer deduplication prevents false positives; Layer 1 combines exact SHA-256 and SimHash near-duplicate detection so same-vuln/similar-endpoint findings are collapsed before verification; verification lifecycle degrades stale findings automatically
- **Adversarial graph reasoning** — findings, techniques, tools, and endpoints are nodes in a live attack graph updated in real time; verification outcomes are reconciled back into graph nodes using first-write-wins idempotency so duplicate events or out-of-order delivery cannot corrupt confirmed/rejected state
- **Goal-first backward planning** — strategy selection starts from the desired vulnerability class and works backward through prerequisite chains
- **Operational stealth by default** — all tool executions go through the stealth layer; timing, flags, and rate limits are never caller-controlled
- **File-backed workspace persistence** — deadlines, payloads, submissions, tasks, workflows, missions, and audit log survive server restarts; no DB migration required for operational data
- **Crash-safe audit trail** — DecisionLogger WAL ensures no governance decision is lost even on abrupt server termination; WAL is replayed on next startup before normal operation begins
- **Budget-aware inference** — Pass-K Evaluator scales exploit agent retries by resource class and expected payout so a $500 target on a lightweight scan costs 1 LLM call while a $10k target on enterprise class gets up to 4 attempts
- **No mocks on Kali Linux** — real tool execution when `REAL_TOOLS=true`
- **Self-learning** — every hunt improves model calibration via the Unified Reinforcement Store, Adaptive Threshold Tuner, Decision Journal, and Cross-Campaign Learning
- **Atomic reinforcement writes** — all RL store updates use a single `INSERT … ON CONFLICT DO UPDATE` statement so concurrent hunts recording the same key never race; no get-then-update pattern anywhere in the learning path
- **Epsilon-greedy exploration** — `getToolRecommendation()` reserves a 15% probability slot for tools with fewer than 10 historical attempts on the current vuln class; proven high-EV tools still fill the first 4 slots, but novel tools are guaranteed periodic exposure so RL history cannot permanently suppress techniques that haven't been fairly evaluated
- **Bayesian prior on sparse data** — the ROI model uses a Beta(1,3) posterior `(successCount+1)/(totalCount+4)` rather than a flat sparse prior; at zero data points the effective rate is 0.25 (optimistic exploration); as observations accumulate the prior dissolves into the empirical rate; no cliff-edge transition means a technique that fails its first few attempts degrades gradually, not catastrophically
- **Hard IP ban detection** — the Dynamic Rate Limiter tracks consecutive 403 responses per target hostname separately from 429 backoff; after 5 consecutive 403s the target is hard-banned for 1 hour; a broad network-level block (ETIMEDOUT/ECONNRESET) in the HunterEngine canary also sets the ban; `isHardBanned()` is checked before every tool execution in HunterEngine and before every HTTP probe in SolverPool; the CampaignOrchestrator skips the SolverPool supplement entirely for banned targets
- **CVE-kickstarted hunting** — on the first observe pass WhatWeb-detected server-side technologies (Apache, Nginx, WordPress, Tomcat, etc.) are cross-referenced against the NVD in real time; CVEs with CVSS ≥ 7.0 are injected as high-priority hypotheses (confidence 0.7, priority 8–10) before the generic hypothesis loop begins, eliminating cold-start guessing against targets running known-vulnerable software; confirmed findings are automatically tagged with CWE IDs and CVE IDs for richer submission reports
- **Public disclosure gate** — before any confirmed finding reaches the submission queue, the platform checks whether the same vulnerability type has already been publicly disclosed by another hunter on the same program via HackerOne, Bugcrowd, and Intigriti APIs; `confirmed_duplicate` findings are dropped silently; `likely_duplicate` findings pass through with a warning flag; the gate fails open (skipped status) when no API token is configured so it never blocks a hunt
- **Temporal decay** — intelligence ages uniformly across all reinforcement domains to prevent stale data from biasing decisions; per-session probe history is bounded to 500 entries per domain and evicted after a 2-hour TTL so decay model accuracy degrades gracefully rather than silently clipping
- **Prompt injection hardening** — all LLM outputs in the hot path (HunterEngine hypothesis generation, VerifierAgent Layer 4 AI confirmation) are scanned by PromptInjectionDetector before parsing; untrusted model responses are flagged and logged before their content is trusted
- **Semantic reasoning examples** — the AI loop receives the 7 most contextually relevant prompt examples per hypothesis cycle via embedding-based retrieval, not keyword matching
- **Bounded context window** — ObservationCompressor and StrategyCoordinator `summariseObservations()` together ensure no model call ever receives an unbounded prompt regardless of hunt length; old observations are recoded as dense state vectors, deep arrays are truncated with count annotations, total observation payload is capped at 1,200 characters before injection into the strategy prompt
- **Non-blocking orchestration** — every phase transition in the 6-layer hunt loop yields to the Node.js event loop so model inference time on one hunt does not add latency to sibling hunts or socket event processing running on the same process; Playwright browser replay is isolated to a dedicated worker thread so page lifecycle operations never block the main process
- **Governance fast-path** — repeated requests to the same target hostname within a hunt pay the full 8-pillar governance cost exactly once; subsequent calls within the 5-minute TTL window take a single O(1) cache lookup, keeping governance overhead off the probe hot path
- **Durable mission state** — hunt context (endpoints, technologies, vulnerabilities) is persisted to PostgreSQL on every significant write via atomic upsert; `initialize()` restores from DB before seeding, so a restarted container or redeployed pod resumes from the exact state the hunt was in, not from scratch
- **Idempotent resume** — campaigns support `resumeCampaignId`; Layer 5 promotes already-confirmed findings directly to the verified list without re-running Playwright or AI confirmation, making crash-then-resume safe and free of duplicate verification billing
- **One representation of truth** — each piece of state has a single authoritative store: DB for mission memory and verification status, a worker process boundary for browser execution, in-memory counters reconciled from DB at layer boundaries; checkpoint data (snapshots, counters) always yields to the authoritative source on resume

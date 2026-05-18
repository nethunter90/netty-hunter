# Netty Hunter – Sentinel Primordial

**Bug Bounty Intelligence Platform** – Autonomous, reasoning-driven vulnerability discovery with multi-agent governance.

---

## Architecture

### Backend (Express + TypeScript + PostgreSQL)

---

#### Core Hunt Loop

- **Hunter Engine**: Observe → Hypothesize → Probe → Update reasoning loop with anomaly-first scanning and real-time strategy adaptation
- **SolverPool**: Dynamic solver spawning per endpoint-per-vulnerability-class
- **Campaign Orchestrator**: 6-layer orchestration model — Governance Gate → Target Intelligence → Strategy Planning → Execution Engine → Verification Gate → Intelligence Harvest; each layer fail-closed with full audit trail
- **Single-Brain Architecture**: `StrategyCoordinator` as sole decision-maker using confidence-driven dispatch for exploits, hypothesis tests, solver spawning, or pivoting

---

#### Governance Layer (`/api/governance`)

An independent 8-pillar governance system that audits, constrains, and monitors all agent behavior.

- **CoreGovernance**: Central decision recorder enforcing 8 named pillars — Kinetic Clause, Recursive Loop, Ethical Boundary, Hardware Sovereignty, Multi-Agent Quorum, Safety Controls, Prompt Injection Detection, Blue Team Oversight
- **GovernanceProxy**: Network-level enforcement — SSRF/internal-IP blocking, per-agent domain contracts, per-minute rate limits, stealth delay injection; all requests validated before tool execution
- **PromptInjectionDetector**: 35 trigger keywords, 12 regex patterns, 4 semantic categories (jailbreak, role override, data exfil, system bypass); scores and flags all agent inputs
- **DesktopAgentGovernance**: Path traversal detection, dangerous command blocking, tool allowlist validation for any host-level agent actions
- **DriftDetector**: Snapshot-based drift analysis — compares recent verdict/risk/pillar distributions against rolling baseline; auto-snapshots every 5 minutes
- **DecisionLogger**: Daily NDJSON decision log files with full replay data — reconstruct any historical governance decision with complete context
- **SelfAttestationService**: Agents justify their own decisions with confidence scores; builds per-agent justification trails queryable by pillar
- **14 REST endpoints**: stats, pillars, decisions, logged decisions, audit log, drift analysis, proxy requests/stats/contracts, injection stats/check, attestations

---

#### Intelligence & Planning

- **Meta-Reasoner**: Bayesian hypothesis confidence tracking with information-gain rate monitoring; detects plateaus and executes weighted strategy pivots via a 10-node strategy graph with historical success weighting; integrates backward planner and decision journal for past-hunt replay
- **Contextual Tool Selector**: Cosine similarity ranking across 39 tools using multi-dimensional context vectors (goal alignment, tech stack, phase, past success rates, circuit breaker state)
- **BackwardPlanner**: Goal-first attack path ranking — works backward from target objective using expected-value weighted attack trees; suggests pivots when current strategy is exhausted
- **Hunt Cortex**: Signal bus with composite hunt health scoring across 5 dimensions (novelty, missed events, verification degradation, negative evidence, signal count); publishes typed signals to all subscribers
- **MITRE Prerequisite Tree**: ATT&CK technique dependency graph — identifies prerequisite chains, choke points, and technique orderings; queryable by capability or technique ID
- **Offensive Graph DB**: In-memory + PostgreSQL attack graph with typed nodes (endpoint, vulnerability, technique, tool, credential) and weighted edges (exploits, targets, discovered_by, derived_from, produces); full traversal and shortest-path queries
- **Graph Wiring**: Event-driven graph population — listens to `vulnerability_found`, `tool_completed`, `phase_changed`, `endpoint_characterized` events and automatically builds the attack graph in real time
- **Hunt Strategy Builder**: Auto-populates structured execution plans based on hunt goals, selects optimal tool chains, orders steps by phase, and supports dynamic step injection and mid-hunt adaptation
- **Hunt Template Library**: 10 built-in templates (recon_first, xss_focus, api_abuse, sqli_hunt, ssrf_hunt, auth_testing, cloud_exposure, logic_flaws, subdomain_takeover, full_spectrum) with seed hypotheses and intelligence overrides
- **Tool Knowledge System**: Structured profiles for 39 integrated security tools and 10 tool chain pipelines, injected into the AI reasoning loop at runtime
- **Static Analysis Feed**: Lightweight pre-hunt pattern matching — route extraction for 5 frameworks, 24+ dangerous sink patterns, dependency CVE checking, config scanning; generates seed hypotheses for the Hunter Engine
- **Backward Hunt Engine**: Goal-first hunting methodology working backward from desired outcomes using pre-built attack trees
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

#### Verification & Validation

- **VerifierAgent**: 4-layer anti-hallucination pipeline — Dedup → HTTP Reprobe → Playwright Browser Replay → AI Confirmation
- **Verification Lifecycle**: TTL-based finding staleness tracking; findings degrade over time if not re-verified, triggering automatic re-probe queues and cortex signals
- **Hypothesis Conflict Detector**: Detects semantic conflicts between template intelligence overrides and empirical data, annotating hypotheses with conflict context and reducing confidence
- **ScopeGuard**: Fail-closed scope validation at every tool invocation — DB-backed, wildcard support, 5-minute cache

---

#### Learning & Self-Improvement

- **Decision Journal**: DB-backed similarity search across past hunt decisions; retrieves the most similar past context vector and its outcome, enabling strategy replay for known-good pivots
- **Adaptive Threshold Tuner**: Learns per-goal-type optimal thresholds (health floor, novelty floor, max degraded verifications, max missed events) from hunt outcome scores; persists and evolves per target class
- **Decision Trace Logger**: 17-event-type audit trail (hunt_start, meta_pivot, meta_evaluation, hunt_complete, etc.) with confidence-at-event recording; feeds calibration analysis and pivot pattern extraction
- **Hunt Cortex Health Metrics**: Real-time composite hunt health scoring; integrated with meta-reasoner to trigger stabilize/accelerate/pivot decisions when health subsystems degrade
- **Post-Hunt Extraction Pipeline**: Wires the Reasoning Reinforcement flywheel into hunt completion — Phase 1 captures confidence calibration per finding, Phase 2 extracts high-scoring operational chains, Phase 3 aggregates cross-hunt patterns and emits ROI-ranked chain stats
- **Unified Reinforcement Store**: Cross-hunt self-learning across 5 domains: Tool Success Rates, Framework-Vuln Matrix, Program Type Heuristics, Confidence Calibration, and Exploration Tracking — all with temporal decay
- **Exploit Chain Intelligence**: Tracks the full lifecycle of multi-step attack sequences across sessions — chain success/failure rates, replay recommendations, pattern avoidance, cross-hunt ROI ranking
- **Unified Temporal Decay System**: Standardizes intelligence aging across three domains with named decay profiles for consistent, tunable aging
- **ROI Model**: Calculates expected value per vulnerability type and auto-tunes confidence thresholds based on historical verification pass rates
- **Autonomy Maturity Tracking System**: Tracks genuine autonomy maturity via Brier snapshots, rolling trend analysis, reinforcement noise detection, and exploration suffocation guard; produces composite Autonomy Maturity Score with auto-generated milestone reports
- **Per-Domain Autonomy Gating**: Tracks autonomy independently across 6 operational domains — global autonomy level capped by the weakest-performing domain to prevent subsystem degradation
- **Lab Profiles**: OWASP Juice Shop ground-truth vulnerability profiles with LabScorer — measures finding quality against known-answer datasets for calibration validation

---

#### AI Reasoning Knowledge Base

- **JsonPromptLoader**: Singleton prompt knowledge base loading all `*.json` from `server/data/prompts/` — grouped by vulnerability type, engagement context, and domain; used to inject structured reasoning examples into the AI loop at runtime
- **10 Prompt Datasets (T1–T10)**:
  - T1 – Recon & OSINT (100 entries)
  - T2 – Injection vulnerabilities (100 entries)
  - T3 – Authentication & session (100 entries)
  - T4 – Logic flaws (100 entries)
  - T5 – API security (100 entries)
  - T6 – Client-side (100 entries)
  - T7 – Infrastructure (100 entries)
  - T8 – Governance & compliance (100 entries)
  - T9 – Exploit chain reasoning (100 entries)
  - T10 – Engagement decision reasoning across 5 complexity levels and 9 engagement contexts (100 entries)
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
- Real-time hunt console with Socket.IO live updates
- Dashboard with ROI charts, autonomy metrics, recent findings
- Program management with scope configuration
- Findings panel with 4-layer verification workflow
- Hunter page: session manager with Attack Path Visualizer, WAF Intel tab, Reports tab
- Intelligence suite: autonomy radar charts, RL stats, WAF profiles, exploit chains
- Reports & AI chat assistant

---

## API Surface

| Prefix | Description |
|---|---|
| `POST /api/auth/*` | Login, logout, register |
| `GET/POST /api/hunt/*` | Hunt sessions, start/stop, state |
| `GET/POST /api/bounty/*` | Programs, targets, findings |
| `POST /api/orchestration/run` | Start full 6-layer orchestrated hunt |
| `GET /api/orchestration/:id` | Live orchestration state |
| `GET /api/hunter/*` | Hunter engine state, strategies |
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
- Ollama (with at least one model: `ollama pull llama3.2`)
- Kali Linux recommended (for tool integrations: nmap, nuclei, sqlmap, ffuf, gobuster, nikto, whatweb)

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

### Environment Variables

```
DATABASE_URL=postgresql://postgres:password@localhost:5432/netty_hunter
SESSION_SECRET=your-random-secret-minimum-32-chars
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_DEFAULT_MODEL=llama3.2
PORT=3001

# Optional — enables real Kali tool execution
REAL_TOOLS=true

# Optional — external threat intel
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=
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

---

## Architecture Principles

- **Fail-closed scope validation** — ScopeGuard and GovernanceProxy block all out-of-scope requests at every invocation; governance is never optional
- **8-pillar governance** — every agent decision is audited against named ethical and operational pillars with full replay data
- **Mandatory browser validation** — high-severity findings MUST pass Playwright replay before reporting
- **Anti-hallucination pipeline** — 4-layer deduplication prevents false positives; verification lifecycle degrades stale findings automatically
- **Adversarial graph reasoning** — findings, techniques, tools, and endpoints are nodes in a live attack graph updated in real time
- **Goal-first backward planning** — strategy selection starts from the desired vulnerability class and works backward through prerequisite chains
- **No mocks on Kali Linux** — real tool execution when `REAL_TOOLS=true`
- **Self-learning** — every hunt improves model calibration via the Unified Reinforcement Store, Adaptive Threshold Tuner, and Decision Journal
- **Temporal decay** — intelligence ages uniformly across all reinforcement domains to prevent stale data from biasing decisions
- **Prompt injection hardening** — all external input to agents passes through the PromptInjectionDetector before AI processing

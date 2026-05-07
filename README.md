# Netty Hunter – Sentinel Primordial

**Bug Bounty Intelligence Platform** – Autonomous, reasoning-driven vulnerability discovery.

## Architecture

### Backend (Express + TypeScript + PostgreSQL)

**Core Hunt Loop**
- **Hunter Engine**: Observe → Hypothesize → Probe → Update reasoning loop with anomaly-first scanning and real-time strategy adaptation
- **SolverPool**: Dynamic solver spawning per endpoint-per-vulnerability-class
- **Single-Brain Architecture**: `StrategyCoordinator` as sole decision-maker using confidence-driven dispatch for exploits, hypothesis tests, solver spawning, or pivoting

**Intelligence & Planning**
- **Hunt Strategy Builder**: Auto-populates structured execution plans based on hunt goals, selects optimal tool chains, orders steps by phase, and supports dynamic step injection and mid-hunt adaptation
- **Hunt Template Library**: 10 built-in templates (recon_first, xss_focus, api_abuse, sqli_hunt, ssrf_hunt, auth_testing, cloud_exposure, logic_flaws, subdomain_takeover, full_spectrum) with seed hypotheses and intelligence overrides
- **Tool Knowledge System**: Structured profiles for 39 integrated security tools and 10 tool chain pipelines, injected into the AI reasoning loop at runtime
- **Static Analysis Feed**: Lightweight pre-hunt pattern matching — route extraction for 5 frameworks, 24+ dangerous sink patterns, dependency CVE checking, config scanning; generates seed hypotheses for the Hunter Engine
- **Backward Hunt Engine**: Goal-first hunting methodology working backward from desired outcomes using pre-built attack trees
- **External Plan Memory**: Attack plans stored outside context window, retrieved at budget checkpoints with auto-adaptation to maintain strategic coherence

**WAF & Evasion**
- **WAF Bypass System**: 7-module architecture — Detection → Fingerprint → Evasion Library → Executor → Rule Correlation → Cross-Session Vendor Profiles → Intelligence Synthesizer
- **Cross-Session Vendor Evasion Profiles**: Aggregates all evasion data across sessions per vendor, generating ranked technique profiles
- **Rule Correlation Matrix**: Identifies shared WAF rules across attack categories and assesses ruleset complexity
- **Intelligence Synthesizer**: Meta-layer combining all 7 WAF intelligence sources into a single `UnifiedIntelligence` package for optimal technique rankings, risk assessment, pacing recommendations, and chain recommendations
- **Anomaly Detection**: Detects block rate spikes, response time shifts, new WAF status codes, and pattern breaks to inform mid-hunt adaptation

**Verification & Validation**
- **VerifierAgent**: 4-layer anti-hallucination pipeline — Dedup → HTTP Reprobe → Playwright Browser Replay → AI Confirmation
- **Hypothesis Conflict Detector**: Detects semantic conflicts between template intelligence overrides and empirical data, annotating hypotheses with conflict context and reducing confidence
- **ScopeGuard**: Fail-closed scope validation at every tool invocation

**Observability**
- **Live Reasoning Observability**: Real-time window into the Hunter Engine's thinking — hypothesis rankings, active probe status, conflict annotations, temporal decay status, active intelligence sources, and mental model state

**Learning & Self-Improvement**
- **Post-Hunt Extraction Pipeline**: Wires the Reasoning Reinforcement flywheel into hunt completion — Phase 1 captures confidence calibration per finding, Phase 2 extracts high-scoring operational chains from multi-finding sessions, Phase 3 aggregates cross-hunt patterns and emits ROI-ranked chain stats
- **Unified Reinforcement Store**: Cross-hunt self-learning system across 5 domains: Tool Success Rates, Framework-Vuln Matrix, Program Type Heuristics, Confidence Calibration, and Exploration Tracking — all with temporal decay
- **Exploit Chain Intelligence**: Tracks the full lifecycle of multi-step attack sequences across sessions — chain success/failure rates, replay recommendations, pattern avoidance, cross-hunt ROI ranking
- **Unified Temporal Decay System**: Standardizes intelligence aging across three domains with named decay profiles for consistent, tunable aging
- **ROI Model**: Calculates expected value per vulnerability type and auto-tunes confidence thresholds based on historical verification pass rates
- **Autonomy Maturity Tracking System**: Tracks genuine autonomy maturity via Brier snapshots, rolling trend analysis, reinforcement noise detection, and exploration suffocation guard; produces composite Autonomy Maturity Score with auto-generated milestone reports
- **Per-Domain Autonomy Gating**: Tracks autonomy independently across 6 operational domains — global autonomy level capped by the weakest-performing domain to prevent subsystem degradation

**Output Generation**
- **Nuclei Template Generator**: Auto-generates Nuclei YAML templates from verified findings for immediate redeployment
- **Draft Report Generator**: Auto-generates submission-ready bug bounty reports from verified findings with platform-aware formatting (HackerOne, Bugcrowd, Intigriti, Synack, YesWeHack)
- **Target Selection Intelligence**: Pre-hunt program scoring and ROI ranking based on program metadata, historical payout data, and cost advantage

**Routing**
- **ModelRouter**: Intelligent Ollama model routing by task type with auto-discovery and task mapping

### Frontend (React + Vite + TypeScript + Tailwind)
- Dark hacker aesthetic with green terminal accents
- Real-time hunt console with Socket.IO live updates
- Dashboard with ROI charts, autonomy metrics, recent findings
- Program management with scope configuration
- Findings panel with 4-layer verification workflow
- Hunter page: session manager with Attack Path Visualizer, WAF Intel tab, Reports tab
- Intelligence suite: autonomy radar charts, RL stats, WAF profiles, exploit chains
- Reports & AI chat assistant

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
```

## Security Tools Integration

The platform integrates with 39 Kali Linux security tools across 8 categories. Key tools used by the Hunter Engine:
- `nuclei` – Multi-template vulnerability scanner
- `sqlmap` – Automated SQL injection
- `ffuf` – Web fuzzer
- `gobuster` – Directory brute-forcer
- `nikto` – Web server scanner
- `nmap` – Network scanner
- `whatweb` – Technology fingerprinter

## Architecture Principles
- **Fail-closed scope validation** – ScopeGuard blocks all out-of-scope requests at every tool invocation
- **Mandatory browser validation** – High-severity findings MUST pass Playwright replay
- **Anti-hallucination pipeline** – 4-layer deduplication prevents false positives
- **No mocks on Kali Linux** – Real tool execution when running on production
- **Self-learning** – Every hunt improves model calibration via the Unified Reinforcement Store and Post-Hunt Extraction Pipeline
- **Temporal decay** – Intelligence ages uniformly across all 3 reinforcement domains to prevent stale data from biasing decisions

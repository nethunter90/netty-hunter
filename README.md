# Netty Hunter – Sentinel Primordial

**Bug Bounty Intelligence Platform** – Autonomous, reasoning-driven vulnerability discovery.

## Architecture

### Backend (Express + TypeScript + PostgreSQL)
- **Hunter Engine**: Observe → Hypothesize → Probe → Update reasoning loop
- **SolverPool**: Dynamic solver spawning per endpoint-per-vulnerability-class
- **WAF Bypass System**: 7-module architecture (Detection → Fingerprint → Evasion Library → Executor → Rule Correlation → Cross-Session Profiles → Intelligence Synthesizer)
- **VerifierAgent**: 4-layer anti-hallucination pipeline (Dedup → HTTP Reprobe → Playwright Browser Replay → AI Confirmation)
- **Target Selection Intelligence**: Pre-hunt program scoring and ROI ranking
- **ROI Model**: Expected value calculation with auto-tuned confidence thresholds
- **Unified Reinforcement Store**: 5-domain cross-hunt self-learning system
- **Autonomy Maturity Tracker**: CAMS scoring across 6 operational domains
- **Exploit Chain Intelligence**: Multi-step attack tracking with pre-built attack trees
- **Backward Hunt Engine**: Goal-first hunting using attack trees
- **Nuclei Template Generator**: Auto-generate templates from verified findings
- **Draft Report Generator**: AI-enhanced submission-ready bug bounty reports
- **ScopeGuard**: Fail-closed scope validation at every tool invocation
- **ModelRouter**: Intelligent Ollama model routing by task type

### Frontend (React + Vite + TypeScript + Tailwind)
- Dark hacker aesthetic with green terminal accents
- Real-time hunt console with Socket.IO live updates
- Dashboard with ROI charts, autonomy metrics, recent findings
- Program management with scope configuration
- Findings panel with 4-layer verification workflow
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

The platform integrates with 39 Kali Linux security tools. Key tools used by the Hunter Engine:
- `nuclei` – Multi-template vulnerability scanner
- `sqlmap` – Automated SQL injection
- `ffuf` – Web fuzzer
- `gobuster` – Directory brute-forcer
- `nikto` – Web server scanner
- `nmap` – Network scanner
- `whatweb` – Technology fingerprinter

## Architecture Principles
- **Fail-closed scope validation** – ScopeGuard blocks all out-of-scope requests
- **Mandatory browser validation** – High-severity findings MUST pass Playwright replay
- **Anti-hallucination pipeline** – 4-layer deduplication prevents false positives
- **No mocks on Kali Linux** – Real tool execution when running on production
- **Self-learning** – Every hunt improves model calibration via reinforcement store

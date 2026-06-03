# Sentinel Primordial — Bug Bounty Intelligence Platform

You are operating inside an autonomous bug bounty hunting platform running on Kali Linux.
You have full access to the codebase, live hunt state, findings, and all security tools.

## What This Platform Does

Runs autonomous vulnerability hunts against web targets using an Observe → Hypothesize →
Probe → Update loop. The hunt engine orchestrates Kali tools (nmap, ffuf, sqlmap, etc.),
generates hypotheses about vulnerabilities, probes them, verifies findings via Playwright,
and produces submission-ready bug bounty reports.

## Your Role Here

You are the **tier-0 reasoning engine**. When the local Ollama model fails or produces
low-quality hypotheses, the hunt engine invokes you via `claude -p`. You also operate
interactively in this terminal to debug, fix, and improve the platform in real time.

## Live Hunt State — Read This First

These files are updated automatically during active hunts:

```bash
cat context/hunt-live.json       # current phase, iteration, finding count, errors
cat context/hunt-findings.json   # all confirmed findings so far
cat context/errors.jsonl         # real-time error log (tail -f this)
cat context/claude-tasks.jsonl   # prompts sent to you by the hunt engine
```

To watch errors as they happen:
```bash
tail -f context/errors.jsonl
```

## Architecture — Key Files

### Hunt Engine (the core loop)
- `server/src/agents/HunterEngine.ts` — main observe/hypothesize/probe/update loop
- `server/src/agents/SolverPool.ts` — parallel vulnerability solvers
- `server/src/agents/VerifierAgent.ts` — Playwright-based finding verification

### AI / Model Layer
- `server/src/intelligence/ModelRouter.ts` — routes tasks to Claude (tier-0) or Ollama
- `server/src/lib/claude-bridge.ts` — how the engine invokes you via CLI
- `server/src/lib/context-writer.ts` — writes live state to context/ files

### Orchestration
- `server/src/agents/CampaignOrchestrator.ts` — 6-layer orchestration pipeline
- `server/src/routes/hunt.ts` — REST endpoints for starting/stopping hunts
- `server/src/index.ts` — Express + Socket.IO server, PTY terminal handler

### Database
- `server/src/db/schema.ts` — Drizzle ORM schema (programs, campaigns, findings, etc.)
- Uses PostgreSQL. Run `npm run db:push` from server/ to push schema changes.

### Client
- `client/src/pages/` — React pages (HuntConsole, Orchestration, TerminalPage, etc.)
- `client/src/components/LiveActivityFeed.tsx` — real-time hunt event renderer

## Common Tasks

### Check what the hunt is doing right now
```bash
cat context/hunt-live.json | jq .
```

### See all findings from the current hunt
```bash
cat context/hunt-findings.json | jq .
```

### Restart the server after a code change
```bash
npm run dev:server
# or if already running via nodemon, it auto-reloads on .ts file changes
```

### Run a type check before restarting
```bash
cd server && npx tsc --noEmit
```

### Check recent server logs
```bash
tail -100 server/logs/app.log 2>/dev/null || echo "no log file — check terminal output"
```

### Start a hunt against Juice Shop
```bash
curl -X POST http://localhost:3000/api/hunt/start \
  -H "Content-Type: application/json" \
  -d '{"programId":-1,"targetUrl":"http://localhost:3000","mode":"forward","maxIterations":10}'
```

### Check Ollama status
```bash
curl http://localhost:11434/api/tags | jq '.models[].name'
```

## How to Write a New Probe

Probes live in `server/src/agents/HunterEngine.ts` in the `probe()` method.
Each probe takes a hypothesis and returns a `ProbeResult`.

Pattern to follow:
1. Add a new case in the probe dispatch switch on `hypothesis.vulnClass`
2. Use `execFile` (already imported) to run a Kali tool or `axios` for HTTP probes
3. Return `{ success: boolean, output: string, tool: string, duration: number }`
4. Keep it under 50 lines — complexity goes in the tool, not the probe

## Governance Rules — Don't Break These

- Never modify `server/src/middleware/scopeGuard.ts` to weaken scope validation
- Never remove the budget guard in `CampaignOrchestrator.ts`
- Never bypass the Playwright verification gate in `VerifierAgent.ts`
- The governance pillars in `server/src/lib/governance/` are immutable contracts

## Error Patterns and Fixes

**"Circuit OPEN — Ollama is unavailable"**
→ `curl http://localhost:11434/api/tags` to check if Ollama is running
→ If down: `ollama serve &` in another terminal

**"Program not found"**
→ Use programId: -1 for custom/local targets (auto-creates a local lab program)

**TypeScript errors after editing**
→ `cd server && npx tsc --noEmit` to see all errors before restarting

**Hunt produces 0 hypotheses**
→ Check `context/hunt-live.json` for the active model
→ If Ollama, the model likely failed — Claude bridge should have kicked in
→ Check `context/claude-tasks.jsonl` to see if Claude was invoked

## Development Commands

```bash
npm run dev          # start both server + client
npm run dev:server   # server only (port 3000)
npm run dev:client   # client only (port 5173)
cd server && npx tsc --noEmit  # type check
```

## Project Structure

```
netty-hunter/
  server/src/
    agents/          # HunterEngine, SolverPool, VerifierAgent, CampaignOrchestrator
    intelligence/    # ModelRouter, PromptKnowledgeBase, MetaReasoner
    lib/
      claude-bridge.ts    # YOU are invoked from here
      context-writer.ts   # writes live state for you to read
      governance/         # immutable governance contracts
      shell/              # command execution sandbox
    routes/          # Express routes (hunt, chat, orchestration, etc.)
    db/              # Drizzle schema + migrations
  client/src/
    pages/           # React pages
    components/      # UI components including LiveActivityFeed, FloatingChat
  context/           # live hunt state (written at runtime, read by you)
  server/data/prompts/  # 1785 security Q&A entries used for RAG
```

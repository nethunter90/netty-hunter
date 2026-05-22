import { Router, Request, Response } from "express";
import { execSync } from "child_process";
import fs from "fs/promises";
import path from "path";
import { db } from "../db";
import { programs, targets, wafProfiles, reinforcementStore, autonomyMetrics, exploitChains, huntSessions, findings } from "../db/schema";
import { eq, desc, like, or } from "drizzle-orm";
import { z } from "zod";
import TargetSelectionIntelligence from "../intelligence/TargetSelection";
import ROIModel from "../intelligence/ROIModel";
import UnifiedReinforcementStore from "../intelligence/ReinforcementStore";
import AutonomyMaturityTracker from "../intelligence/AutonomyTracker";
import ExploitChainIntelligence from "../intelligence/ExploitChain";
import { ModelRouter } from "../intelligence/ModelRouter";
import { HuntStrategyBuilder } from "./huntStrategy";
import logger from "../utils/logger";

const router = Router();

// ── File-backed workspace stores ─────────────────────────────────────────────
const WS = path.join(process.cwd(), "workspace");
const STORE_DIRS: Record<string, string> = {
  deadlines:   path.join(WS, "deadlines"),
  submissions: path.join(WS, "submissions"),
  tasks:       path.join(WS, "tasks"),
  workflows:   path.join(WS, "workflows"),
  payloads:    path.join(WS, "payloads"),
  audit:       path.join(WS, "audit"),
};

async function wsEnsure(dir: string) {
  await fs.mkdir(dir, { recursive: true });
}

async function wsReadAll(store: string): Promise<any[]> {
  const dir = STORE_DIRS[store];
  await wsEnsure(dir);
  const files = await fs.readdir(dir).catch(() => [] as string[]);
  const items = await Promise.all(
    files.filter(f => f.endsWith(".json")).map(async f => {
      try { return JSON.parse(await fs.readFile(path.join(dir, f), "utf8")); }
      catch { return null; }
    })
  );
  return items.filter(Boolean);
}

async function wsWrite(store: string, id: string, data: any) {
  const dir = STORE_DIRS[store];
  await wsEnsure(dir);
  await fs.writeFile(path.join(dir, `${id}.json`), JSON.stringify(data, null, 2));
}

async function wsDelete(store: string, id: string) {
  await fs.unlink(path.join(STORE_DIRS[store], `${id}.json`)).catch(() => {});
}

async function wsFind(store: string, id: string): Promise<any | null> {
  try {
    return JSON.parse(await fs.readFile(path.join(STORE_DIRS[store], `${id}.json`), "utf8"));
  } catch { return null; }
}

// Audit log (append-only, single file)
const AUDIT_FILE = path.join(WS, "audit", "log.json");
async function appendAudit(entry: any) {
  await wsEnsure(STORE_DIRS.audit);
  let log: any[] = [];
  try { log = JSON.parse(await fs.readFile(AUDIT_FILE, "utf8")); } catch {}
  log.push(entry);
  if (log.length > 1000) log = log.slice(-1000);
  await fs.writeFile(AUDIT_FILE, JSON.stringify(log, null, 2));
}
async function readAudit(): Promise<any[]> {
  try { return JSON.parse(await fs.readFile(AUDIT_FILE, "utf8")); } catch { return []; }
}
const targetSelection = new TargetSelectionIntelligence();
const roiModel = new ROIModel();
const rlStore = UnifiedReinforcementStore.getInstance();
const autonomyTracker = AutonomyMaturityTracker.getInstance();
const exploitChainIntel = new ExploitChainIntelligence();

// ── Programs ──────────────────────────────────────────────────────────────────
const ProgramSchema = z.object({
  name: z.string().min(1).max(200),
  platform: z.enum(["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "other"]),
  programHandle: z.string().optional(),
  scope: z.array(z.string()).default([]),
  outOfScope: z.array(z.string()).default([]),
  maxPayout: z.number().int().min(0).default(0),
  avgPayout: z.number().min(0).default(0),
  responseTime: z.number().min(0).default(72),
  tags: z.array(z.string()).default([]),
});

router.get("/programs", async (_req: Request, res: Response) => {
  const allPrograms = await db.select().from(programs).orderBy(desc(programs.roiScore));
  return res.json(allPrograms);
});

router.post("/programs", async (req: Request, res: Response) => {
  const parsed = ProgramSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const [program] = await db.insert(programs).values(parsed.data).returning();
  return res.status(201).json(program);
});

router.get("/programs/:id", async (req: Request, res: Response) => {
  const [program] = await db.select().from(programs).where(eq(programs.id, parseInt(req.params.id))).limit(1);
  if (!program) return res.status(404).json({ error: "Program not found" });

  const targetList = await db.select().from(targets).where(eq(targets.programId, program.id));
  return res.json({ program, targets: targetList });
});

router.patch("/programs/:id", async (req: Request, res: Response) => {
  const parsed = ProgramSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const [updated] = await db.update(programs)
    .set({ ...parsed.data, updatedAt: new Date() })
    .where(eq(programs.id, parseInt(req.params.id))).returning();
  if (!updated) return res.status(404).json({ error: "Not found" });
  return res.json(updated);
});

router.delete("/programs/:id", async (req: Request, res: Response) => {
  await db.update(programs).set({ active: false }).where(eq(programs.id, parseInt(req.params.id)));
  return res.json({ ok: true });
});

// ── Target Selection Intelligence ─────────────────────────────────────────────
router.get("/rank-programs", async (_req: Request, res: Response) => {
  const scores = await targetSelection.scorePrograms();
  // Persist computed ROI scores back to the programs table
  await Promise.all(scores.map(s =>
    db.update(programs).set({ roiScore: s.roiScore }).where(eq(programs.id, s.programId))
  ));
  return res.json(scores);
});

router.get("/recommend-target", async (req: Request, res: Response) => {
  const exclude = req.query.exclude ? String(req.query.exclude).split(",").map(Number) : [];
  const recommendation = await targetSelection.recommendNextTarget(exclude);
  return res.json(recommendation);
});

// ── ROI Model ─────────────────────────────────────────────────────────────────
router.get("/roi/:vulnClass", async (req: Request, res: Response) => {
  const maxPayout = parseInt(String(req.query.maxPayout || "10000"));
  const programId = req.query.programId ? parseInt(String(req.query.programId)) : undefined;
  const roi = await roiModel.calculateExpectedValue(req.params.vulnClass, maxPayout, programId);
  return res.json(roi);
});

router.get("/roi-ranking", async (req: Request, res: Response) => {
  const maxPayout = parseInt(String(req.query.maxPayout || "10000"));
  const programId = req.query.programId ? parseInt(String(req.query.programId)) : undefined;
  const ranking = await roiModel.rankVulnClasses(maxPayout, programId);
  return res.json(ranking);
});

// ── Reinforcement Learning Store ───────────────────────────────────────────────
router.get("/rl-stats", async (_req: Request, res: Response) => {
  const stats = await rlStore.getStats();
  const brierScore = await rlStore.computeBrierScore();
  return res.json({ stats, brierScore });
});

router.post("/rl-record", async (req: Request, res: Response) => {
  const { domain, key, success } = req.body;
  if (!domain || !key) return res.status(400).json({ error: "domain and key required" });
  const validDomains = ["tool_success", "framework_vuln", "program_type", "confidence_calibration", "exploration"];
  if (!validDomains.includes(domain)) return res.status(400).json({ error: "invalid domain" });
  await rlStore.record(domain, key, Boolean(success));
  return res.json({ ok: true });
});

// ── Autonomy Maturity ─────────────────────────────────────────────────────────
router.get("/autonomy", async (_req: Request, res: Response) => {
  const report = await autonomyTracker.getLatestReport();
  return res.json(report);
});

router.get("/autonomy/history", async (req: Request, res: Response) => {
  const limit = parseInt(String(req.query.limit || "20"));
  const history = await autonomyTracker.getProgressHistory(limit);
  return res.json(history);
});

// ── Exploit Chains ─────────────────────────────────────────────────────────────
router.get("/exploit-chains", async (_req: Request, res: Response) => {
  const chains = await db.select().from(exploitChains).orderBy(desc(exploitChains.createdAt));
  return res.json(chains);
});

router.post("/exploit-chains", async (req: Request, res: Response) => {
  const { campaignId, name, steps, finalObjective } = req.body;
  const chain = await exploitChainIntel.createChain({ campaignId, name, steps, finalObjective });
  return res.status(201).json(chain);
});

router.get("/exploit-chains/prebuilt", (_req: Request, res: Response) => {
  const { ATTACK_TREES } = require("../intelligence/ExploitChain");
  return res.json(ATTACK_TREES);
});

// ── WAF Profiles ───────────────────────────────────────────────────────────────
router.get("/waf-profiles", async (_req: Request, res: Response) => {
  const profiles = await db.select().from(wafProfiles).orderBy(desc(wafProfiles.lastUpdated));
  return res.json(profiles);
});

// ── Hunt Templates ─────────────────────────────────────────────────────────────
router.get("/hunt-templates", (_req: Request, res: Response) => {
  return res.json(HuntStrategyBuilder.getTemplates());
});

// ── AI Chat ────────────────────────────────────────────────────────────────────
router.post("/ai/chat", async (req: Request, res: Response) => {
  const { message, context } = req.body;
  if (!message) return res.status(400).json({ error: "message required" });

  const modelRouter = ModelRouter.getInstance();
  const systemContext = context ? `Context: ${JSON.stringify(context)}\n\n` : "";

  try {
    const response = await modelRouter.chat(`${systemContext}${message}`);
    return res.json({ response });
  } catch (err) {
    return res.status(500).json({ error: "AI unavailable", details: String(err) });
  }
});

// ── Models ─────────────────────────────────────────────────────────────────────
router.get("/models", async (_req: Request, res: Response) => {
  const modelRouter = ModelRouter.getInstance();
  const models = await modelRouter.getModels();
  return res.json(models);
});

// ── Analysis ──────────────────────────────────────────────────────────────────
router.get("/analysis/:sessionId", async (req: Request, res: Response) => {
  try {
    const [session] = await db.select().from(huntSessions)
      .where(eq(huntSessions.sessionUuid, req.params.sessionId)).limit(1);
    if (!session) return res.status(404).json({ error: "Session not found" });
    return res.json({
      sessionId: req.params.sessionId,
      reasoningLog: session.reasoningLog,
      hypotheses: session.hypotheses,
      status: session.status,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/analysis/:sessionId/generate", async (req: Request, res: Response) => {
  try {
    const [session] = await db.select().from(huntSessions)
      .where(eq(huntSessions.sessionUuid, req.params.sessionId)).limit(1);
    if (!session) return res.status(404).json({ error: "Session not found" });
    return res.json({
      sessionId: req.params.sessionId,
      reasoningLog: session.reasoningLog,
      hypotheses: session.hypotheses,
      generated: true,
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── Audit Trail ───────────────────────────────────────────────────────────────
router.get("/audit", async (_req: Request, res: Response) => {
  const log = await readAudit();
  return res.json(log.slice(-200));
});

router.post("/audit", async (req: Request, res: Response) => {
  const { action, details } = req.body;
  const entry = {
    id: `aud-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    action,
    details,
    timestamp: new Date().toISOString(),
  };
  await appendAudit(entry);
  return res.status(201).json(entry);
});

// ── Browser ───────────────────────────────────────────────────────────────────
router.get("/browser/status", (_req: Request, res: Response) => {
  return res.json({ status: "available", engine: "headless-placeholder" });
});

router.post("/browser/navigate", async (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "url required" });
  if (process.env.REAL_TOOLS) {
    try {
      const response = await fetch(url);
      const text = await response.text();
      const titleMatch = text.match(/<title[^>]*>([^<]*)<\/title>/i);
      const title = titleMatch ? titleMatch[1] : "";
      return res.json({ status: response.status, title, url });
    } catch (err: any) {
      return res.status(502).json({ error: err.message });
    }
  }
  return res.json({ status: 200, title: "Mock Page", url, mock: true });
});

router.get("/browser/history", (_req: Request, res: Response) => {
  return res.json({ history: [] });
});

// ── CVE Intel ─────────────────────────────────────────────────────────────────
router.get("/cve/search", (req: Request, res: Response) => {
  const q = String(req.query.q || "");
  const mockCves = [
    { id: "CVE-2024-0001", description: `SQL Injection in web application ${q}`, cvss: 9.8, published: "2024-01-15" },
    { id: "CVE-2024-0002", description: `XSS vulnerability in login page ${q}`, cvss: 6.1, published: "2024-02-10" },
    { id: "CVE-2024-0003", description: `SSRF in file upload handler ${q}`, cvss: 8.2, published: "2024-03-05" },
    { id: "CVE-2024-0004", description: `IDOR in user profile endpoint ${q}`, cvss: 7.5, published: "2024-04-01" },
    { id: "CVE-2024-0005", description: `Auth bypass via JWT manipulation ${q}`, cvss: 9.1, published: "2024-05-20" },
  ];
  return res.json({ results: mockCves, query: q, count: mockCves.length });
});

router.get("/cve/:id", (req: Request, res: Response) => {
  return res.json({
    id: req.params.id,
    description: `Mock CVE data for ${req.params.id}`,
    cvss: 7.0,
    published: "2024-01-01",
    references: [],
    cwe: "CWE-79",
  });
});

// ── Deadlines ─────────────────────────────────────────────────────────────────
router.get("/deadlines", async (_req: Request, res: Response) => {
  return res.json(await wsReadAll("deadlines"));
});

router.post("/deadlines", async (req: Request, res: Response) => {
  const { programId, title, dueDate, priority, notes } = req.body;
  const id = `deadline-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const entry = { id, programId, title, dueDate, priority, notes: notes || "", createdAt: new Date().toISOString() };
  await wsWrite("deadlines", id, entry);
  return res.status(201).json(entry);
});

router.patch("/deadlines/:id", async (req: Request, res: Response) => {
  const existing = await wsFind("deadlines", req.params.id);
  if (!existing) return res.status(404).json({ error: "Not found" });
  const updated = { ...existing, ...req.body, id: req.params.id };
  await wsWrite("deadlines", req.params.id, updated);
  return res.json(updated);
});

router.delete("/deadlines/:id", async (req: Request, res: Response) => {
  await wsDelete("deadlines", req.params.id);
  return res.json({ ok: true });
});

// ── Nuclei Extended ───────────────────────────────────────────────────────────
router.get("/nuclei/templates", async (req: Request, res: Response) => {
  try {
    const { search, severity, tags } = req.query;
    let rows = await db.select().from(findings);
    if (severity) rows = rows.filter((r: any) => r.severity === severity);
    if (search) rows = rows.filter((r: any) => r.nucleiTemplate && r.nucleiTemplate.includes(String(search)));
    if (tags) rows = rows.filter((r: any) => r.nucleiTemplate);
    const templates = rows
      .filter((r: any) => r.nucleiTemplate)
      .map((r: any) => ({ id: r.id, template: r.nucleiTemplate, severity: r.severity, endpoint: r.endpoint }));
    return res.json({ templates });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/nuclei/run", async (req: Request, res: Response) => {
  const { templateId, target } = req.body;
  if (process.env.REAL_TOOLS) {
    try {
      const result = execSync(`nuclei -t ${templateId} -u ${target} -json 2>/dev/null`, { encoding: "utf8", timeout: 30000 });
      return res.json({ result, executed: true });
    } catch (err: any) {
      return res.status(500).json({ error: err.message });
    }
  }
  return res.json({ executed: true, mock: true, templateId, target, findings: [] });
});

router.delete("/nuclei/templates/:id", (_req: Request, res: Response) => {
  return res.json({ ok: true, message: "template removed" });
});

// ── Payloads ──────────────────────────────────────────────────────────────────
router.get("/payloads", async (req: Request, res: Response) => {
  let items = await wsReadAll("payloads");
  if (req.query.type) items = items.filter((p: any) => p.type === req.query.type);
  if (req.query.search) {
    const s = String(req.query.search).toLowerCase();
    items = items.filter((p: any) => (p.name || "").toLowerCase().includes(s) || (p.payload || "").toLowerCase().includes(s));
  }
  return res.json(items);
});

router.post("/payloads", async (req: Request, res: Response) => {
  const { name, type, payload, tags } = req.body;
  const id = `payload-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const entry = { id, name, type, payload, tags: tags || [], createdAt: new Date().toISOString() };
  await wsWrite("payloads", id, entry);
  return res.status(201).json(entry);
});

router.patch("/payloads/:id", async (req: Request, res: Response) => {
  const existing = await wsFind("payloads", req.params.id);
  if (!existing) return res.status(404).json({ error: "Not found" });
  const updated = { ...existing, ...req.body, id: req.params.id };
  await wsWrite("payloads", req.params.id, updated);
  return res.json(updated);
});

router.delete("/payloads/:id", async (req: Request, res: Response) => {
  await wsDelete("payloads", req.params.id);
  return res.json({ ok: true });
});

// ── PoC Lab ───────────────────────────────────────────────────────────────────
router.get("/poc/results", (_req: Request, res: Response) => {
  return res.json([]);
});

router.post("/poc/run", async (req: Request, res: Response) => {
  try {
    const { findingId, target } = req.body;
    let finding = null;
    if (findingId) {
      const [row] = await db.select().from(findings).where(eq(findings.id, parseInt(findingId))).limit(1);
      finding = row || null;
    }
    return res.json({
      executed: true,
      findingId,
      target: target || finding?.exploitPayload?.split('\n')[0] || 'unknown',
      result: "mock PoC execution completed",
      output: finding ? `PoC for ${finding.vulnType}` : "Generic PoC",
      timestamp: new Date().toISOString(),
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── Scope Manager ─────────────────────────────────────────────────────────────
router.post("/programs/:id/activate", async (req: Request, res: Response) => {
  try {
    const [updated] = await db.update(programs)
      .set({ active: true, updatedAt: new Date() })
      .where(eq(programs.id, parseInt(req.params.id)))
      .returning();
    if (!updated) return res.status(404).json({ error: "Program not found" });
    return res.json(updated);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.patch("/programs/:id/scope", async (req: Request, res: Response) => {
  try {
    const { scope, outOfScope } = req.body;
    const updateData: any = { updatedAt: new Date() };
    if (scope !== undefined) updateData.scope = scope;
    if (outOfScope !== undefined) updateData.outOfScope = outOfScope;
    const [updated] = await db.update(programs)
      .set(updateData)
      .where(eq(programs.id, parseInt(req.params.id)))
      .returning();
    if (!updated) return res.status(404).json({ error: "Program not found" });
    return res.json(updated);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── Submissions ───────────────────────────────────────────────────────────────
router.get("/submissions", async (_req: Request, res: Response) => {
  return res.json(await wsReadAll("submissions"));
});

router.post("/submissions", async (req: Request, res: Response) => {
  const { findingId, platform, title, severity, status } = req.body;
  const id = `sub-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const entry = { id, findingId, platform, title, severity, status: status || "draft", createdAt: new Date().toISOString() };
  await wsWrite("submissions", id, entry);
  return res.status(201).json(entry);
});

router.patch("/submissions/:id", async (req: Request, res: Response) => {
  const existing = await wsFind("submissions", req.params.id);
  if (!existing) return res.status(404).json({ error: "Not found" });
  const updated = { ...existing, ...req.body, id: req.params.id };
  await wsWrite("submissions", req.params.id, updated);
  return res.json(updated);
});

router.delete("/submissions/:id", async (req: Request, res: Response) => {
  await wsDelete("submissions", req.params.id);
  return res.json({ ok: true });
});

// ── Task Planning ─────────────────────────────────────────────────────────────
router.get("/tasks", async (_req: Request, res: Response) => {
  return res.json(await wsReadAll("tasks"));
});

router.post("/tasks", async (req: Request, res: Response) => {
  const { title, type, priority, huntId, assignee, dueDate } = req.body;
  const id = `task-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const entry = { id, title, type, priority, huntId, assignee, dueDate, createdAt: new Date().toISOString() };
  await wsWrite("tasks", id, entry);
  return res.status(201).json(entry);
});

router.patch("/tasks/:id", async (req: Request, res: Response) => {
  const existing = await wsFind("tasks", req.params.id);
  if (!existing) return res.status(404).json({ error: "Not found" });
  const updated = { ...existing, ...req.body, id: req.params.id };
  await wsWrite("tasks", req.params.id, updated);
  return res.json(updated);
});

router.delete("/tasks/:id", async (req: Request, res: Response) => {
  await wsDelete("tasks", req.params.id);
  return res.json({ ok: true });
});

// ── Tool Readiness ────────────────────────────────────────────────────────────
router.get("/tools/readiness", (_req: Request, res: Response) => {
  const toolList = [
    "nmap", "nuclei", "sqlmap", "ffuf", "gobuster", "nikto",
    "whatweb", "amass", "subfinder", "httpx", "dalfox", "commix",
    "feroxbuster", "dirsearch",
  ];
  const tools = toolList.map((name) => {
    try {
      const path = execSync(`which ${name} 2>/dev/null`, { encoding: "utf8" }).trim();
      let version: string | undefined;
      try {
        version = execSync(`${name} --version 2>&1 | head -1`, { encoding: "utf8", timeout: 3000 }).trim();
      } catch { /* version not available */ }
      return { name, available: !!path, path: path || undefined, version };
    } catch {
      return { name, available: false };
    }
  });
  return res.json({ tools });
});

// ── Workflows ─────────────────────────────────────────────────────────────────
router.get("/workflows", async (_req: Request, res: Response) => {
  return res.json(await wsReadAll("workflows"));
});

router.post("/workflows", async (req: Request, res: Response) => {
  const { name, steps, trigger, description } = req.body;
  const id = `wf-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const entry = { id, name, steps: steps || [], trigger, description, createdAt: new Date().toISOString() };
  await wsWrite("workflows", id, entry);
  return res.status(201).json(entry);
});

router.patch("/workflows/:id", async (req: Request, res: Response) => {
  const existing = await wsFind("workflows", req.params.id);
  if (!existing) return res.status(404).json({ error: "Not found" });
  const updated = { ...existing, ...req.body, id: req.params.id };
  await wsWrite("workflows", req.params.id, updated);
  return res.json(updated);
});

router.delete("/workflows/:id", async (req: Request, res: Response) => {
  await wsDelete("workflows", req.params.id);
  return res.json({ ok: true });
});

router.post("/workflows/:id/execute", async (req: Request, res: Response) => {
  const workflow = await wsFind("workflows", req.params.id);
  if (!workflow) return res.status(404).json({ error: "Workflow not found" });
  return res.json({
    executed: true,
    workflowId: req.params.id,
    stepsCount: (workflow.steps || []).length,
    timestamp: new Date().toISOString(),
  });
});

// ── Strategy / Advisor ────────────────────────────────────────────────────────
router.post("/advisor/chat", async (req: Request, res: Response) => {
  const { message, context } = req.body;
  if (!message) return res.status(400).json({ error: "message required" });

  const modelRouter = ModelRouter.getInstance();
  const systemContext = context ? `Context: ${JSON.stringify(context)}\n\n` : "";

  try {
    const response = await modelRouter.chat(`${systemContext}${message}`);
    return res.json({ response });
  } catch (err) {
    return res.status(500).json({ error: "AI unavailable", details: String(err) });
  }
});

router.get("/advisor/hints", (_req: Request, res: Response) => {
  return res.json({
    hints: [
      "Focus on API endpoints with auth",
      "Test for IDOR in /api/user/:id",
      "Check for SSRF in URL parameters",
      "Look for mass assignment vulnerabilities in PUT/PATCH endpoints",
      "Test JWT implementation for algorithm confusion attacks",
      "Enumerate hidden endpoints via JS file analysis",
      "Check for GraphQL introspection and batch query attacks",
    ],
  });
});

export default router;

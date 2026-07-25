import { Router, Request, Response } from "express";
import { Server as SocketServer } from "socket.io";
import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";
import { db } from "../db";
import { scopedHttp, OutOfScopeError } from "../lib/net/scoped-http";
import { dispatchTool, ToolOutOfScopeError } from "../lib/net/dispatch-tool";
import { resolveCustomTargetProgram } from "../lib/hunter/custom-target-program";
import { installScopeRoute } from "../lib/net/scoped-browser-route";
import { programs, targets, wafProfiles, autonomyMetrics, exploitChains, huntSessions, findings, campaigns } from "../db/schema";
import { eq, desc, like, or, inArray } from "drizzle-orm";
import { KALI_CATALOG, KaliCategory } from "../lib/hunter/kali-catalog";
import { isCrossCampaignEligible, resolveProvenance } from "../lib/hunter/custom-target-program";
import { z } from "zod";
import TargetSelectionIntelligence from "../intelligence/TargetSelection";
import ROIModel from "../intelligence/ROIModel";
import UnifiedReinforcementStore from "../intelligence/ReinforcementStore";
import AutonomyMaturityTracker from "../intelligence/AutonomyTracker";
import ExploitChainIntelligence from "../intelligence/ExploitChain";
import { ModelRouter } from "../intelligence/ModelRouter";
import { HuntStrategyBuilder } from "./huntStrategy";
import { ScopeGuard } from "../middleware/scopeGuard";
import logger from "../utils/logger";
import { nvdClient, cvssToSeverity } from "../lib/intelligence/nvd-client";
import { submissionQueue } from "../lib/intelligence/submission-queue";
import { ProgramFetcher, type ProgramMetadata } from "../lib/bounty-intelligence/program-fetcher";
import { runtimeConfig } from "../lib/runtime-config";

const router = Router();
const execFileAsync = promisify(execFile);

// ── File-backed workspace stores ─────────────────────────────────────────────
const WS = path.join(process.cwd(), "workspace");
const STORE_DIRS: Record<string, string> = {
  deadlines:   path.join(WS, "deadlines"),
  submissions: path.join(WS, "submissions"),
  tasks:       path.join(WS, "tasks"),
  workflows:   path.join(WS, "workflows"),
  payloads:    path.join(WS, "payloads"),
  audit:       path.join(WS, "audit"),
  reports:     path.join(WS, "reports"),
  poc:         path.join(WS, "poc"),
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

// Reject any id that could escape the store directory (path traversal guard).
// Only flat alphanumeric/underscore/hyphen ids are valid record names.
function assertSafeId(id: string): void {
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]+$/.test(id)) {
    throw new Error("Invalid id");
  }
}

async function wsWrite(store: string, id: string, data: any) {
  assertSafeId(id);
  const dir = STORE_DIRS[store];
  await wsEnsure(dir);
  await fs.writeFile(path.join(dir, `${id}.json`), JSON.stringify(data, null, 2));
}

async function wsDelete(store: string, id: string) {
  // Guard without throwing — an invalid id has nothing to delete anyway,
  // and this runs in async route handlers with no try/catch (Express 4).
  if (typeof id !== "string" || !/^[A-Za-z0-9_-]+$/.test(id)) return;
  await fs.unlink(path.join(STORE_DIRS[store], `${id}.json`)).catch(() => {});
}

async function wsFind(store: string, id: string): Promise<any | null> {
  try {
    assertSafeId(id);
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
  wafBypassPolicy: z.enum(["allowed", "disallowed", "unspecified"]).default("unspecified"),
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

// Auto-discover every program the authenticated HackerOne account has access
// to and insert any not already tracked directly into the real programs
// table — the one ScopeGuard and hunts actually read from (not the separate
// file-based ProgramFetcher store bounty-intelligence.ts's routes use, which
// has no connection to the DB at all). Requires HACKERONE_USERNAME/TOKEN to
// be set and the platform not to be disconnected; returns an empty result
// rather than an error when either is missing, matching listAccessiblePrograms()'s
// own fail-open-to-empty behavior.
router.post("/programs/sync-hackerone", async (_req: Request, res: Response) => {
  try {
    if (!runtimeConfig.isPlatformEnabled("hackerone")) {
      return res.json({ total: 0, added: [], alreadyTracked: 0, skippedNoRealScope: [], failed: [], disabled: true });
    }
    const fetcher = new ProgramFetcher();
    const accessible = await fetcher.listAccessiblePrograms();
    if (accessible.length === 0) {
      return res.json({ total: 0, added: [], alreadyTracked: 0, skippedNoRealScope: [], failed: [] });
    }

    const existingRows = await db.select({ programHandle: programs.programHandle })
      .from(programs).where(eq(programs.platform, "hackerone"));
    const existingHandles = new Set(existingRows.map(r => r.programHandle).filter((h): h is string => !!h));

    const newPrograms = accessible.filter(p => !existingHandles.has(p.handle));
    const results = await Promise.allSettled(newPrograms.map(async (prog) => {
      const fetched = await fetcher.fetchHackerOne({
        id: prog.handle, name: prog.name, platform: "hackerone",
        url: `https://hackerone.com/${prog.handle}`, handle: prog.handle,
        enabled: true, addedAt: Date.now(),
      });
      // Never insert a program whose scope/rules came from the synthetic
      // fallback template — that's how 591 programs ended up with identical
      // numbers before. Skip it instead; the caller can retry sync later
      // once the underlying fetch (auth/handle/rate-limit) is fixed.
      if (!fetched.realDataFound) {
        return { handle: prog.handle, status: "skipped" as const };
      }
      const metadata: ProgramMetadata = {
        scopeAssets: { inScope: fetched.scope.inScope, outOfScope: fetched.scope.outOfScope },
        submissionState: fetched.rules.submissionState,
        offersBounties: fetched.rules.offersBounties,
        policyDescription: fetched.description,
        lastSyncedAt: new Date().toISOString(),
      };
      // avgPayout: a real midpoint when both bounds are known, whichever
      // single bound is available otherwise, honest 0 (not a guess) when
      // neither came back from the authenticated fetch.
      const avgPayout = fetched.rules.maxBounty !== undefined && fetched.rules.minBounty !== undefined
        ? (fetched.rules.maxBounty + fetched.rules.minBounty) / 2
        : fetched.rules.maxBounty ?? fetched.rules.minBounty ?? 0;
      await db.insert(programs).values({
        name: prog.name,
        platform: "hackerone",
        programHandle: prog.handle,
        scope: fetched.scope.inScope.map(a => a.identifier).filter(Boolean),
        outOfScope: fetched.scope.outOfScope.map(a => a.identifier).filter(Boolean),
        maxPayout: fetched.rules.maxBounty ?? 0,
        avgPayout,
        // No real numeric hours estimate available from the authenticated
        // fetch (response_efficiency_percentage is a %, not an hours figure)
        // — an honest default, not a computed-looking placeholder.
        responseTime: 72,
        tags: [],
        wafBypassPolicy: "unspecified",
        metadata,
      });
      return { handle: prog.handle, status: "added" as const };
    }));

    const isFulfilled = <T>(r: PromiseSettledResult<T>): r is PromiseFulfilledResult<T> => r.status === "fulfilled";

    const added: string[] = [];
    const skippedNoRealScope: string[] = [];
    const failed: string[] = [];
    results.forEach((r, i) => {
      const handle = newPrograms[i].handle;
      if (!isFulfilled(r)) { failed.push(handle); return; }
      (r.value.status === "added" ? added : skippedNoRealScope).push(handle);
    });

    return res.json({
      total: accessible.length,
      added,
      alreadyTracked: accessible.length - newPrograms.length,
      // Fetched OK but only synthetic fallback data was available (auth
      // missing/failed, handle mismatch, or HackerOne returned no structured
      // scope) — nothing fake was inserted for these; re-run sync later.
      skippedNoRealScope,
      failed,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// NOTE: must be registered before "/programs/:id" so the literal path wins (ScopeManager.tsx).
router.get("/programs/list", async (_req: Request, res: Response) => {
  const rows = await db.select().from(programs).orderBy(desc(programs.roiScore));
  return res.json({ programs: rows.map(shapeProgramForScopeUI) });
});

router.get("/programs/:id", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid program id" });
  const [program] = await db.select().from(programs).where(eq(programs.id, id)).limit(1);
  if (!program) return res.status(404).json({ error: "Program not found" });

  const targetList = await db.select().from(targets).where(eq(targets.programId, program.id));
  return res.json({ program, targets: targetList });
});

router.patch("/programs/:id", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid program id" });
  const parsed = ProgramSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
  const [updated] = await db.update(programs)
    .set({ ...parsed.data, updatedAt: new Date() })
    .where(eq(programs.id, id)).returning();
  if (!updated) return res.status(404).json({ error: "Not found" });
  // Invalidate scope cache so updated scope patterns take effect immediately
  ScopeGuard.getInstance().invalidateCache(id);
  return res.json(updated);
});

router.delete("/programs/:id", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid program id" });
  await db.update(programs).set({ active: false }).where(eq(programs.id, id));
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
  const provenance = await resolveProvenance(programId);
  const roi = await roiModel.calculateExpectedValue(req.params.vulnClass, maxPayout, provenance, programId);
  return res.json(roi);
});

router.get("/roi-ranking", async (req: Request, res: Response) => {
  const maxPayout = parseInt(String(req.query.maxPayout || "10000"));
  const programId = req.query.programId ? parseInt(String(req.query.programId)) : undefined;
  const provenance = await resolveProvenance(programId);
  const ranking = await roiModel.rankVulnClasses(maxPayout, provenance, programId);
  return res.json(ranking);
});

// ── Reinforcement Learning Store ───────────────────────────────────────────────
router.get("/rl-stats", async (_req: Request, res: Response) => {
  const stats = await rlStore.getStats();
  const brierScore = await rlStore.computeBrierScore();
  return res.json({ stats, brierScore });
});

router.post("/rl-record", async (req: Request, res: Response) => {
  const { domain, key, success, programId } = req.body;
  if (!domain || !key) return res.status(400).json({ error: "domain and key required" });
  const validDomains = ["tool_success", "framework_vuln", "program_type", "confidence_calibration", "exploration"];
  if (!validDomains.includes(domain)) return res.status(400).json({ error: "invalid domain" });
  // Manual/admin write with no hunt context — resolve provenance from an
  // optional programId in the body, fail closed to "unknown" (never a
  // silent "real") when absent, matching every other RL write site.
  const provenance = await resolveProvenance(typeof programId === "number" ? programId : undefined);
  await rlStore.record(domain, key, Boolean(success), provenance);
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

// Per-vuln-type remediation hints (mirrors the report-export REMEDIATION map).
const ANALYSIS_REMEDIATION: Record<string, string> = {
  xss: "Apply context-aware output encoding and a strict Content-Security-Policy.",
  sqli: "Use parameterized queries / prepared statements and least-privilege DB accounts.",
  ssrf: "Allowlist outbound destinations; block private IP ranges and cloud metadata.",
  idor: "Enforce server-side authorization on every object access; use non-sequential ids.",
  auth_bypass: "Harden authentication/authorization checks and review session handling.",
  open_redirect: "Allowlist redirect destinations; never redirect to user-controlled input.",
  info_disclosure: "Remove sensitive data from responses and restrict verbose errors.",
  rce: "Eliminate unsafe deserialization/command execution; sandbox and validate all input.",
};

/** Compute a real analysis from the stored findings of one hunt session. */
async function computeAnalysis(session: typeof huntSessions.$inferSelect) {
  const rows = await db.select().from(findings).where(eq(findings.huntSessionId, session.id));

  const severity_distribution: Record<string, number> = {};
  const surface = new Set<string>();
  const vulnTypes = new Set<string>();
  for (const f of rows) {
    const sev = (f.severity || "info").toLowerCase();
    severity_distribution[sev] = (severity_distribution[sev] || 0) + 1;
    if (f.affectedUrl) {
      try { surface.add(new URL(f.affectedUrl).host); } catch { surface.add(f.affectedUrl); }
    }
    if (f.vulnType) vulnTypes.add(f.vulnType.toLowerCase());
  }

  const recommendations = Array.from(vulnTypes).map(vt =>
    ANALYSIS_REMEDIATION[vt] || `Review and remediate ${vt} findings per OWASP guidance.`);

  return {
    total_findings: rows.length,
    severity_distribution,
    attack_surface: Array.from(surface),
    recommendations,
    generatedAt: new Date().toISOString(),
  };
}

router.get("/analysis/:sessionId", async (req: Request, res: Response) => {
  try {
    const [session] = await db.select().from(huntSessions)
      .where(eq(huntSessions.sessionUuid, req.params.sessionId)).limit(1);
    if (!session) return res.status(404).json({ success: false, error: "Session not found" });
    return res.json({ success: true, sessionId: req.params.sessionId, analysis: await computeAnalysis(session) });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.post("/analysis/:sessionId/generate", async (req: Request, res: Response) => {
  try {
    const [session] = await db.select().from(huntSessions)
      .where(eq(huntSessions.sessionUuid, req.params.sessionId)).limit(1);
    if (!session) return res.status(404).json({ success: false, error: "Session not found" });
    return res.json({ success: true, sessionId: req.params.sessionId, analysis: await computeAnalysis(session) });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
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
  const { url, programId } = req.body;
  if (!url) return res.status(400).json({ error: "url required" });
  if (process.env.REAL_TOOLS) {
    try {
      const response = await scopedHttp.get(url, {}, programId);
      const text = String(response.data ?? "");
      const titleMatch = text.match(/<title[^>]*>([^<]*)<\/title>/i);
      const title = titleMatch ? titleMatch[1] : "";
      return res.json({ status: response.status, title, url });
    } catch (err: any) {
      if (err instanceof OutOfScopeError) {
        return res.status(403).json({ error: "Out of scope", reason: err.reason });
      }
      return res.status(502).json({ error: err.message });
    }
  }
  return res.json({ status: 200, title: "Mock Page", url, mock: true });
});

router.get("/browser/history", (_req: Request, res: Response) => {
  return res.json({ history: [] });
});

// ── CVE Intel ─────────────────────────────────────────────────────────────────
router.get("/cve/search", async (req: Request, res: Response) => {
  const query = String(req.query.query || req.query.q || "").trim();
  const severity = String(req.query.severity || "all");
  const year = String(req.query.year || "all");

  if (!query) return res.json({ success: false, error: "query is required", cves: [] });

  try {
    const records = await nvdClient.lookupByKeywordFiltered(query, { severity, year });
    const cves = records.map(r => ({
      cveId: r.id,
      name: r.description.split('.')[0].slice(0, 120),
      description: r.description,
      severity: cvssToSeverity(r.cvssScore),
      cvss: r.cvssScore,
      publishedDate: r.publishedDate,
      exploitAvailable: r.exploitAvailable,
      affectedProducts: r.cweIds,
      references: r.references,
    }));
    return res.json({ success: true, cves, count: cves.length });
  } catch (err: any) {
    logger.warn('[bounty/cve/search] NVD lookup failed', { query, err: err.message });
    return res.json({ success: false, error: 'NVD lookup failed', cves: [] });
  }
});

router.get("/cve/:id", async (req: Request, res: Response) => {
  const cveId = req.params.id;
  try {
    const record = await nvdClient.lookupById(cveId);
    if (!record) return res.json({ success: false, error: 'CVE not found', cve: null });
    return res.json({
      success: true,
      cve: {
        cveId: record.id,
        name: record.description.split('.')[0].slice(0, 120),
        description: record.description,
        severity: cvssToSeverity(record.cvssScore),
        cvss: record.cvssScore,
        publishedDate: record.publishedDate,
        exploitAvailable: record.exploitAvailable,
        affectedProducts: record.cweIds,
        references: record.references,
      },
    });
  } catch (err: any) {
    logger.warn('[bounty/cve/:id] NVD lookup failed', { cveId, err: err.message });
    return res.json({ success: false, error: 'NVD lookup failed', cve: null });
  }
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
  const { templateId, target, programId: bodyProgramId } = req.body as { templateId?: string; target?: string; programId?: number };

  // Validate inputs — these flow into a subprocess, so reject anything that
  // isn't a plain template path / a well-formed http(s) URL.
  if (typeof templateId !== "string" || !/^[\w./-]+$/.test(templateId)) {
    return res.status(400).json({ error: "Invalid templateId" });
  }
  let targetUrl: URL;
  try {
    targetUrl = new URL(String(target));
    if (!["http:", "https:"].includes(targetUrl.protocol)) throw new Error("bad protocol");
  } catch {
    return res.status(400).json({ error: "Invalid target — must be an http(s) URL" });
  }

  if (process.env.REAL_TOOLS) {
    try {
      // 2026-07-22: this endpoint had NO scope check at all (one of the
      // originally-audited chokepoint-bypass sites) — dispatchTool() now
      // scope-checks targetUrl against a real program before exec. Callers
      // that already know which program this target belongs to should pass
      // programId explicitly; otherwise resolveCustomTargetProgram() finds-
      // or-creates one scoped to targetUrl's own host, same as the ad-hoc/
      // custom-target launch path.
      const programId = bodyProgramId ?? await resolveCustomTargetProgram(targetUrl.toString());
      const { stdout } = await dispatchTool({
        tool: "nuclei",
        target: targetUrl.toString(),
        args: ["-t", templateId, "-u", "{url}", "-jsonl"], // nuclei v3+ removed -json; -jsonl is current
        programId,
        timeoutMs: 30000,
      });
      return res.json({ result: stdout, executed: true });
    } catch (err: any) {
      if (err instanceof ToolOutOfScopeError) {
        return res.status(403).json({ error: `Out of scope: ${err.reason}` });
      }
      return res.status(500).json({ error: err.message });
    }
  }
  return res.json({ executed: true, mock: true, templateId, target: targetUrl.toString(), findings: [] });
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
router.get("/poc/results", async (_req: Request, res: Response) => {
  const results = await wsReadAll("poc");
  results.sort((a: any, b: any) => String(b.timestamp || "").localeCompare(String(a.timestamp || "")));
  return res.json({ success: true, results });
});

router.post("/poc/run", async (req: Request, res: Response) => {
  try {
    const result = await runPoc(req.body);
    return res.json({ success: true, result });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── Scope Manager ─────────────────────────────────────────────────────────────
router.post("/programs/:id/activate", async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid program id" });
    const [updated] = await db.update(programs)
      .set({ active: true, updatedAt: new Date() })
      .where(eq(programs.id, id))
      .returning();
    if (!updated) return res.status(404).json({ error: "Program not found" });
    return res.json(updated);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.patch("/programs/:id/scope", async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid program id" });
    const { scope, outOfScope } = req.body;
    const updateData: any = { updatedAt: new Date() };
    if (scope !== undefined) updateData.scope = scope;
    if (outOfScope !== undefined) updateData.outOfScope = outOfScope;
    const [updated] = await db.update(programs)
      .set(updateData)
      .where(eq(programs.id, id))
      .returning();
    if (!updated) return res.status(404).json({ error: "Program not found" });
    return res.json(updated);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── Submissions ───────────────────────────────────────────────────────────────
router.get("/submissions", async (_req: Request, res: Response) => {
  return res.json({ success: true, submissions: await wsReadAll("submissions") });
});

router.post("/submissions", async (req: Request, res: Response) => {
  const { findingId, platform, title, severity, status } = req.body;
  const id = `sub-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const entry = { id, findingId, platform, title, severity, status: status || "draft", createdAt: new Date().toISOString() };
  await wsWrite("submissions", id, entry);
  return res.status(201).json({ success: true, submission: entry });
});

async function updateSubmissionHandler(req: Request, res: Response) {
  const existing = await wsFind("submissions", req.params.id);
  if (!existing) return res.status(404).json({ success: false, error: "Not found" });
  const updated = { ...existing, ...req.body, id: req.params.id };
  await wsWrite("submissions", req.params.id, updated);
  return res.json({ success: true, submission: updated });
}
router.patch("/submissions/:id", updateSubmissionHandler);
router.put("/submissions/:id", updateSubmissionHandler);

// Human review gate — this is the ONLY code path that actually sends a
// queued report to a live bug bounty platform. Findings verified during a
// hunt land here as status "pending_review" (see submission-queue.ts) and
// stay inert until an operator calls this endpoint.
router.post("/submissions/:id/approve", async (req: Request, res: Response) => {
  try {
    const outcome = await submissionQueue.approveAndSubmit(req.params.id);
    if (!outcome) return res.status(404).json({ success: false, error: "Not found or not pending review" });

    // The queue emits nothing itself (it's a plain data-layer module with no
    // socket access) — this is the only point where an operator watching the
    // live feed learns the approval actually went through, instead of the
    // feed going silent forever after "queued for review".
    const io = req.app.get("io") as SocketServer | undefined;
    if (io) {
      const base = { findingId: outcome.entry.findingId, platform: outcome.entry.platform, submissionId: outcome.entry.id };
      if (outcome.result.success) {
        io.emit("l5:report_submitted", { ...base, reportId: outcome.result.reportId, reportUrl: outcome.result.reportUrl });
      } else {
        io.emit("l5:report_submit_failed", { ...base, error: outcome.result.error });
      }
    }

    return res.json({ success: outcome.result.success, submission: outcome.entry, result: outcome.result });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.post("/submissions/:id/reject", async (req: Request, res: Response) => {
  try {
    const entry = await submissionQueue.reject(req.params.id);
    if (!entry) return res.status(404).json({ success: false, error: "Not found or not pending review" });
    return res.json({ success: true, submission: entry });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.delete("/submissions/:id", async (req: Request, res: Response) => {
  await wsDelete("submissions", req.params.id);
  return res.json({ success: true });
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
const TOOL_READINESS_LIST = [
  "nmap", "nuclei", "sqlmap", "ffuf", "gobuster", "nikto",
  "whatweb", "amass", "subfinder", "httpx", "dalfox", "commix",
  "feroxbuster", "dirsearch",
];
let toolReadinessCache: { at: number; tools: unknown[] } | null = null;
const TOOL_READINESS_TTL = 5 * 60 * 1000; // 5 min

async function computeToolReadiness(): Promise<unknown[]> {
  if (toolReadinessCache && Date.now() - toolReadinessCache.at < TOOL_READINESS_TTL) {
    return toolReadinessCache.tools;
  }
  // Async + parallel so the lookups don't block the event loop. Tool names
  // are a fixed allowlist (not user input), and execFile uses an args array.
  const tools = await Promise.all(TOOL_READINESS_LIST.map(async (name) => {
    try {
      const { stdout } = await execFileAsync("which", [name]);
      const toolPath = stdout.trim();
      let version: string | undefined;
      try {
        const v = await execFileAsync(name, ["--version"], { timeout: 3000 });
        version = (v.stdout || "").split("\n")[0].trim() || undefined;
      } catch { /* version not available */ }
      return { name, available: !!toolPath, path: toolPath || undefined, version };
    } catch {
      return { name, available: false };
    }
  }));
  toolReadinessCache = { at: Date.now(), tools };
  return tools;
}

router.get("/tools/readiness", async (_req: Request, res: Response) => {
  const tools = await computeToolReadiness();
  return res.json({ tools });
});

// ── Full Tool Arsenal (ToolReadiness.tsx) ───────────────────────────────────────
// Backed by the real KALI_CATALOG metadata + live `which` detection of every binary.
// The client buckets tools into 8 UI categories — map the catalog's categories onto them.
const KALI_CATEGORY_TO_UI: Record<KaliCategory, string> = {
  recon: "recon",
  scanning: "vuln",
  fuzzing: "enum",
  exploitation: "exploit",
  web: "recon",
  credential: "secrets",
  network: "enum",
  reporting: "util",
};
const RISK_TO_STEALTH: Record<string, string> = {
  low: "low",
  medium: "medium",
  high: "high",
};
let toolArsenalCache: { at: number; payload: any } | null = null;

async function computeToolArsenal(): Promise<any> {
  if (toolArsenalCache && Date.now() - toolArsenalCache.at < TOOL_READINESS_TTL) {
    return toolArsenalCache.payload;
  }
  // Detect every catalog binary in parallel (fixed allowlist, execFile args array).
  const detected = await Promise.all(KALI_CATALOG.map(async (entry) => {
    try {
      const { stdout } = await execFileAsync("which", [entry.binary]);
      const toolPath = stdout.trim();
      let version: string | undefined;
      if (toolPath) {
        try {
          const v = await execFileAsync(entry.binary, ["--version"], { timeout: 3000 });
          version = (v.stdout || "").split("\n")[0].trim() || undefined;
        } catch { /* version not available */ }
      }
      return { entry, installed: !!toolPath, path: toolPath || undefined, version };
    } catch {
      return { entry, installed: false, path: undefined, version: undefined };
    }
  }));

  const tools = detected.map(({ entry, installed, path: toolPath, version }) => ({
    name: entry.name,
    installed,
    path: toolPath,
    version,
    category: KALI_CATEGORY_TO_UI[entry.category] || "util",
    critical: entry.riskLevel === "high" || ["nmap", "nuclei", "sqlmap", "ffuf", "httpx"].includes(entry.name),
    description: entry.description,
    stealthImpact: RISK_TO_STEALTH[entry.riskLevel] || "unknown",
    useCases: entry.vulnClasses || [],
    commandCount: entry.commandTemplate ? 1 : 0,
    requiresRoot: entry.category === "network" && entry.name === "nmap",
  }));

  const categories: Record<string, number> = {};
  const categoriesInstalled: Record<string, number> = {};
  for (const t of tools) {
    categories[t.category] = (categories[t.category] || 0) + 1;
    if (t.installed) categoriesInstalled[t.category] = (categoriesInstalled[t.category] || 0) + 1;
  }
  const installed = tools.filter(t => t.installed).length;
  const summary = {
    total: tools.length,
    installed,
    missing: tools.length - installed,
    criticalMissing: tools.filter(t => t.critical && !t.installed).length,
    categories,
    categoriesInstalled,
  };

  const payload = { success: true, tools, summary };
  toolArsenalCache = { at: Date.now(), payload };
  return payload;
}

router.get("/tools", async (_req: Request, res: Response) => {
  const payload = await computeToolArsenal();
  return res.json(payload);
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

// ── Hunts (BackwardHunt.tsx / Analysis.tsx / AIAdvisor.tsx) ──────────────────────
// Backed by real DB rows: hunt_sessions joined to their campaign (goal/status) and
// target (url). A hunt's stable id is its sessionUuid. Creating a hunt here records
// real campaign + target + hunt_session rows; it does not spawn the heavy
// HunterEngine (that lives behind POST /api/hunt/start with full socket wiring).
async function shapeHunts(): Promise<any[]> {
  const sessions = await db.select().from(huntSessions).orderBy(desc(huntSessions.startedAt)).limit(200);
  if (sessions.length === 0) return [];

  const campaignIds = Array.from(new Set(sessions.map(s => s.campaignId)));
  const targetIds = Array.from(new Set(sessions.map(s => s.targetId)));
  const campaignRows = campaignIds.length
    ? await db.select().from(campaigns).where(inArray(campaigns.id, campaignIds))
    : [];
  const targetRows = targetIds.length
    ? await db.select().from(targets).where(inArray(targets.id, targetIds))
    : [];
  const campaignMap = new Map(campaignRows.map(c => [c.id, c]));
  const targetMap = new Map(targetRows.map(t => [t.id, t]));

  // Map a hunt_session status onto the lifecycle the client renders.
  const statusFor = (s: typeof sessions[number], camp: any): string => {
    if (s.status === "running" && camp?.status === "running") return "active";
    if (s.status === "completed" || camp?.status === "completed") return "completed";
    if (s.status === "stopped" || camp?.status === "stopped") return "stopped";
    return s.status;
  };

  return sessions.map(s => {
    const camp = campaignMap.get(s.campaignId);
    const tgt = targetMap.get(s.targetId);
    const hyps = Array.isArray(s.hypotheses) ? (s.hypotheses as any[]) : [];
    return {
      id: s.sessionUuid,
      target: tgt?.url || camp?.name || "unknown",
      goal: camp?.goal || "",
      status: statusFor(s, camp),
      currentStep: hyps.length,
      findings: [] as any[],
      startedAt: s.startedAt,
      completedAt: s.completedAt,
    };
  });
}

router.get("/hunts", async (_req: Request, res: Response) => {
  try {
    const hunts = await shapeHunts();
    return res.json({ success: true, hunts });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.post("/hunts", async (req: Request, res: Response) => {
  try {
    const { target, goal, scope } = req.body as {
      target?: string; goal?: string; scope?: { inScope?: string[]; outOfScope?: string[] };
    };
    if (!target || typeof target !== "string") {
      return res.status(400).json({ success: false, error: "target required" });
    }

    // Normalise the target into a URL the rest of the pipeline can consume.
    const targetUrl = /^https?:\/\//i.test(target) ? target : `https://${target}`;

    // Find-or-create a local-lab program for these ad-hoc hunts so FK constraints
    // are satisfied (mirrors POST /api/hunt/start's programId === -1 path).
    let [program] = await db.select().from(programs).where(eq(programs.platform, "local")).limit(1);
    if (!program) {
      [program] = await db.insert(programs).values({
        name: "Custom / Local Lab",
        platform: "local",
        scope: (scope?.inScope && scope.inScope.length ? scope.inScope : ["*"]),
        outOfScope: scope?.outOfScope || [],
      }).returning();
    }

    const [campaign] = await db.insert(campaigns).values({
      programId: program.id,
      name: `Hunt: ${targetUrl}`,
      goal: goal || `Hunt for vulnerabilities on ${targetUrl}`,
      status: "running",
      huntMode: "backward",
      startedAt: new Date(),
    }).returning();

    const [tgt] = await db.insert(targets).values({
      programId: program.id,
      url: targetUrl,
      type: "web",
      status: "scanning",
    }).returning();

    const sessionUuid = `bh-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const [session] = await db.insert(huntSessions).values({
      campaignId: campaign.id,
      targetId: tgt.id,
      sessionUuid,
      status: "running",
      phase: "observe",
    }).returning();

    await appendAudit({
      id: `aud-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      action: "hunt.start",
      details: { sessionUuid, target: targetUrl, goal },
      timestamp: new Date().toISOString(),
    });

    return res.status(201).json({
      success: true,
      hunt: {
        id: sessionUuid,
        target: targetUrl,
        goal: campaign.goal,
        status: "active",
        currentStep: 0,
        findings: [],
        startedAt: session.startedAt,
      },
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.post("/hunts/:id/stop", async (req: Request, res: Response) => {
  try {
    const [session] = await db.select().from(huntSessions)
      .where(eq(huntSessions.sessionUuid, req.params.id)).limit(1);
    if (!session) return res.status(404).json({ success: false, error: "Hunt not found" });

    await db.update(huntSessions)
      .set({ status: "stopped", completedAt: new Date() })
      .where(eq(huntSessions.sessionUuid, req.params.id));
    await db.update(campaigns)
      .set({ status: "stopped", completedAt: new Date() })
      .where(eq(campaigns.id, session.campaignId));

    return res.json({ success: true, id: req.params.id, status: "stopped" });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ── PoC Lab extensions (PoCLab.tsx) ─────────────────────────────────────────────
// Persist every run to the `poc` workspace store so history + detail lookups work.
async function runPoc(body: any): Promise<any> {
  const { findingId, target, payload, vulnerability_type, programId: rawProgramId } = body || {};
  let finding: any = null;
  if (findingId && !Number.isNaN(parseInt(findingId))) {
    const [row] = await db.select().from(findings).where(eq(findings.id, parseInt(findingId))).limit(1);
    finding = row || null;
  }
  // Prefer the finding's own program (real provenance) over a client-supplied
  // value when a findingId was given; otherwise fall back to whatever the
  // caller passed (still subject to ScopeGuard's fail-closed policy).
  const programId = finding?.programId ?? rawProgramId;

  let executed = false;
  let success = false;
  let output: string;
  if (process.env.REAL_TOOLS && target) {
    // Best-effort live probe: fetch the target with the payload appended and look
    // for reflection (real signal, not a hardcoded verdict).
    try {
      const u = new URL(String(target));
      if (payload) u.searchParams.set("poc", String(payload));
      const resp = await scopedHttp.get(u.toString(), {}, programId);
      const text = String(resp.data ?? "");
      executed = true;
      success = payload ? text.includes(String(payload)) : resp.status < 400;
      output = `HTTP ${resp.status} — ${text.length} bytes${success ? " — payload reflected in response" : ""}`;
    } catch (err: any) {
      executed = true;
      success = false;
      output = err instanceof OutOfScopeError ? `Blocked: ${err.reason}` : `Probe error: ${err.message}`;
    }
  } else {
    output = finding ? `PoC harness for ${finding.vulnType} (set REAL_TOOLS to execute)` : "PoC harness ready (set REAL_TOOLS to execute)";
  }

  const id = `poc-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  const result = {
    id,
    vulnerability_type: vulnerability_type || finding?.vulnType || "unknown",
    target: target || finding?.affectedUrl || "unknown",
    payload: payload || finding?.exploitPayload || "",
    success,
    executed,
    output,
    evidence: finding ? `Linked finding #${finding.id}: ${finding.title}` : undefined,
    timestamp: new Date().toISOString(),
  };
  await wsWrite("poc", id, result);
  return result;
}

router.post("/poc/test", async (req: Request, res: Response) => {
  try {
    const result = await runPoc(req.body);
    return res.json({ success: true, result });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

router.get("/poc/results/:id", async (req: Request, res: Response) => {
  const result = await wsFind("poc", req.params.id);
  if (!result) return res.status(404).json({ success: false, error: "Result not found" });
  return res.json({ success: true, result });
});

// ── Draft Reports (DraftReports.tsx) ────────────────────────────────────────────
// File-backed `reports` store, mirroring the other workspace stores.
router.get("/reports", async (_req: Request, res: Response) => {
  const reports = await wsReadAll("reports");
  reports.sort((a: any, b: any) =>
    String(b.updatedAt || b.createdAt || "").localeCompare(String(a.updatedAt || a.createdAt || "")));
  return res.json({ reports });
});

router.post("/reports", async (req: Request, res: Response) => {
  const body = req.body || {};
  // Client may send its own client-generated id; sanitize to a safe store key.
  const rawId = typeof body.id === "string" ? body.id.replace(/[^A-Za-z0-9_-]/g, "") : "";
  const id = rawId || `report_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  const entry = {
    id,
    title: body.title || "Untitled Report",
    severity: body.severity || "medium",
    status: body.status || "draft",
    content: body.content || "",
    huntId: body.huntId,
    savedOnce: true,
    createdAt: body.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await wsWrite("reports", id, entry);
  return res.status(201).json(entry);
});

router.put("/reports/:id", async (req: Request, res: Response) => {
  const existing = await wsFind("reports", req.params.id);
  const body = req.body || {};
  const merged = {
    ...(existing || {}),
    ...body,
    id: req.params.id,
    savedOnce: true,
    createdAt: existing?.createdAt || body.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await wsWrite("reports", req.params.id, merged);
  return res.json(merged);
});

router.get("/reports/:id/export", async (req: Request, res: Response) => {
  const report = await wsFind("reports", req.params.id);
  if (!report) return res.status(404).json({ error: "Report not found" });
  const format = String(req.query.format || "markdown").toLowerCase();

  let exported: string;
  if (format === "json") {
    exported = JSON.stringify(report, null, 2);
  } else if (format === "html") {
    const esc = (s: string) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    exported = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${esc(report.title)}</title></head>` +
      `<body><h1>${esc(report.title)}</h1>` +
      `<p><strong>Severity:</strong> ${esc(report.severity)} | <strong>Status:</strong> ${esc(report.status)}</p>` +
      `<pre>${esc(report.content)}</pre></body></html>`;
  } else {
    // markdown (default)
    exported = `# ${report.title}\n\n` +
      `**Severity:** ${report.severity}\n\n` +
      `**Status:** ${report.status}\n\n` +
      `${report.content || ""}\n`;
  }
  return res.json({ exported, format });
});

// ── Browser extensions (BrowserView.tsx) ────────────────────────────────────────
// Back DOM/links/forms with a real HTTP fetch + parse (same gating + technique as
// the existing /browser/navigate). Screenshot uses Playwright when REAL_TOOLS is set.
function validateHttpUrl(raw: any): URL | null {
  try {
    const u = new URL(String(raw));
    return ["http:", "https:"].includes(u.protocol) ? u : null;
  } catch { return null; }
}

async function fetchPageSource(u: URL, programId?: number): Promise<{ status: number; html: string }> {
  const resp = await scopedHttp.get(u.toString(), {}, programId);
  const html = String(resp.data ?? "");
  return { status: resp.status, html };
}

router.post("/browser/dom", async (req: Request, res: Response) => {
  const u = validateHttpUrl(req.body?.url);
  if (!u) return res.status(400).json({ error: "Invalid url — must be an http(s) URL" });
  if (!process.env.REAL_TOOLS) {
    return res.json({ url: u.toString(), source: "", mock: true });
  }
  try {
    const { status, html } = await fetchPageSource(u, req.body?.programId);
    return res.json({ url: u.toString(), statusCode: status, source: html, content: html });
  } catch (err: any) {
    return res.status(502).json({ error: err.message });
  }
});

router.post("/browser/links", async (req: Request, res: Response) => {
  const u = validateHttpUrl(req.body?.url);
  if (!u) return res.status(400).json({ error: "Invalid url — must be an http(s) URL" });
  if (!process.env.REAL_TOOLS) {
    return res.json({ url: u.toString(), links: [], mock: true });
  }
  try {
    const { html } = await fetchPageSource(u, req.body?.programId);
    const links = new Set<string>();
    const re = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      try { links.add(new URL(m[1], u.toString()).toString()); }
      catch { links.add(m[1]); }
    }
    return res.json({ url: u.toString(), links: Array.from(links) });
  } catch (err: any) {
    return res.status(502).json({ error: err.message });
  }
});

router.post("/browser/forms", async (req: Request, res: Response) => {
  const u = validateHttpUrl(req.body?.url);
  if (!u) return res.status(400).json({ error: "Invalid url — must be an http(s) URL" });
  if (!process.env.REAL_TOOLS) {
    return res.json({ url: u.toString(), forms: [], mock: true });
  }
  try {
    const { html } = await fetchPageSource(u, req.body?.programId);
    const forms: any[] = [];
    const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    const attr = (s: string, name: string) => {
      const a = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, "i").exec(s);
      return a ? a[1] : undefined;
    };
    let fm: RegExpExecArray | null;
    while ((fm = formRe.exec(html)) !== null) {
      const formAttrs = fm[1];
      const inner = fm[2];
      const inputs: any[] = [];
      const inputRe = /<(input|select|textarea)\b([^>]*)>/gi;
      let im: RegExpExecArray | null;
      while ((im = inputRe.exec(inner)) !== null) {
        inputs.push({
          tag: im[1].toLowerCase(),
          name: attr(im[2], "name"),
          type: attr(im[2], "type") || (im[1].toLowerCase() === "input" ? "text" : im[1].toLowerCase()),
        });
      }
      const action = attr(formAttrs, "action");
      forms.push({
        action: action ? (() => { try { return new URL(action, u.toString()).toString(); } catch { return action; } })() : u.toString(),
        method: (attr(formAttrs, "method") || "GET").toUpperCase(),
        inputs,
      });
    }
    return res.json({ url: u.toString(), forms });
  } catch (err: any) {
    return res.status(502).json({ error: err.message });
  }
});

router.post("/browser/screenshot", async (req: Request, res: Response) => {
  const u = validateHttpUrl(req.body?.url);
  if (!u) return res.status(400).json({ error: "Invalid url — must be an http(s) URL" });
  const programId = req.body?.programId;
  if (!process.env.REAL_TOOLS) {
    return res.json({ url: u.toString(), screenshot: null, mock: true });
  }
  try {
    const { chromium } = require("playwright") as typeof import("playwright");
    const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    try {
      const page = await browser.newPage();
      // Browser-native egress chokepoint — this is a manual UI endpoint taking
      // an arbitrary caller-supplied URL, same shape as /browser/navigate and
      // the PoC-lab prober fixed in the prior (Node-HTTP) handoff. Missing or
      // invalid programId fails closed inside ScopeGuard itself.
      await installScopeRoute(page, programId);
      await page.goto(u.toString(), { waitUntil: "domcontentloaded", timeout: 20000 });
      const buf = await page.screenshot({ type: "png" });
      return res.json({ url: u.toString(), screenshot: `data:image/png;base64,${buf.toString("base64")}` });
    } finally {
      await browser.close();
    }
  } catch (err: any) {
    return res.status(502).json({ error: err.message });
  }
});

// ── Scope Manager (ScopeManager.tsx) ────────────────────────────────────────────
// Reshape DB programs into the structure the Program Manager UI renders.
function shapeProgramForScopeUI(p: any) {
  const inScope = (p.scope as string[]) || [];
  const outOfScope = (p.outOfScope as string[]) || [];
  const meta = (p.metadata as Record<string, any>) || {};
  return {
    id: String(p.id),
    name: p.name,
    platform: p.platform,
    stealthProfile: meta.stealthProfile || "balanced",
    noveltyFloor: typeof meta.noveltyFloor === "number" ? meta.noveltyFloor : 0.5,
    maxScanRate: typeof meta.maxScanRate === "number" ? meta.maxScanRate : 10,
    scope: { inScope, outOfScope, restrictions: meta.restrictions || [] },
    status: p.active ? "active" : "inactive",
    domainCount: inScope.length,
  };
}

// Scope-guard telemetry. Counts are kept inside ScopeGuard.isInScope() — the single
// chokepoint every caller (hunt-phase probes AND manual UI validation) passes
// through — so hunt-phase blocks are tallied, not just manual validations. The
// counter is additive telemetry only and does not affect enforcement.
router.get("/scope-guard/stats", (_req: Request, res: Response) => {
  return res.json({ stats: ScopeGuard.getInstance().getStats() });
});

router.get("/scope-guard/audit", async (req: Request, res: Response) => {
  const limit = Math.min(parseInt(String(req.query.limit || "10")) || 10, 200);
  const log = await readAudit();
  const entries = log
    .filter((e: any) => e.action === "scope.block" || e.action === "scope.validate")
    .slice(-limit)
    .reverse()
    .map((e: any) => ({
      timestamp: e.timestamp,
      target: e.details?.target || "",
      action: e.details?.allowed ? "allowed" : "blocked",
      reason: e.details?.reason || "",
    }));
  return res.json(entries);
});

router.post("/programs/import", async (req: Request, res: Response) => {
  try {
    const { handle, platform, stealthProfile, noveltyFloor, maxScanRate, scope, outOfScope } = req.body || {};
    if (!handle || typeof handle !== "string") {
      return res.status(400).json({ error: "handle required" });
    }
    const validPlatforms = ["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "custom", "other"];
    const plat = validPlatforms.includes(platform) ? platform : "other";

    // Accept pasted scope as an array or newline/comma-separated text.
    const toList = (v: any): string[] => {
      if (Array.isArray(v)) return v.map(String).map(s => s.trim()).filter(Boolean);
      if (typeof v === "string") return v.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
      return [];
    };

    const scopeList = toList(scope);
    const outList = toList(outOfScope);

    // Path-level scope is now enforced by ScopeGuard (host+path matching), so both
    // in-scope and out-of-scope path-bearing entries are stored verbatim. A path
    // prefix like "localhost:5000/api/Addresss" restricts the hunt to that subtree.

    const [program] = await db.insert(programs).values({
      name: handle,
      platform: plat,
      programHandle: handle,
      scope: scopeList,
      outOfScope: outList,
      metadata: {
        stealthProfile: stealthProfile || "balanced",
        noveltyFloor: typeof noveltyFloor === "number" ? noveltyFloor : 0.5,
        maxScanRate: typeof maxScanRate === "number" ? maxScanRate : 10,
      },
    }).returning();

    return res.status(201).json({
      message: `Imported ${handle}`,
      program: shapeProgramForScopeUI(program),
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/programs/validate-target", async (req: Request, res: Response) => {
  try {
    const { target, programId } = req.body || {};
    if (!target || typeof target !== "string") {
      return res.status(400).json({ error: "target required" });
    }
    const targetUrl = /^https?:\/\//i.test(target) ? target : `https://${target}`;

    // Resolve a program to validate against: explicit id, else first active program.
    let pid = programId ? parseInt(String(programId)) : NaN;
    if (Number.isNaN(pid)) {
      const [active] = await db.select().from(programs)
        .where(eq(programs.active, true)).orderBy(desc(programs.roiScore)).limit(1);
      pid = active?.id ?? NaN;
    }
    if (Number.isNaN(pid)) {
      return res.json({ allowed: false, reason: "No program available to validate against — import a program first." });
    }

    // isInScope() tallies allow/block telemetry internally now.
    const result = await ScopeGuard.getInstance().isInScope(targetUrl, pid);

    await appendAudit({
      id: `aud-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      action: result.allowed ? "scope.validate" : "scope.block",
      details: { target: targetUrl, allowed: result.allowed, reason: result.reason, programId: pid },
      timestamp: new Date().toISOString(),
    });

    return res.json({ allowed: result.allowed, valid: result.allowed, reason: result.reason });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.post("/programs/:id/update", async (req: Request, res: Response) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: "Invalid program id" });
    const [existing] = await db.select().from(programs).where(eq(programs.id, id)).limit(1);
    if (!existing) return res.status(404).json({ error: "Program not found" });

    const body = req.body || {};
    const updateData: any = { updatedAt: new Date() };
    if (body.name !== undefined) updateData.name = body.name;
    if (Array.isArray(body.scope)) updateData.scope = body.scope;
    if (Array.isArray(body.outOfScope)) updateData.outOfScope = body.outOfScope;

    // stealthProfile / noveltyFloor / maxScanRate live in metadata.
    const meta = { ...((existing.metadata as Record<string, any>) || {}) };
    if (body.stealthProfile !== undefined) meta.stealthProfile = body.stealthProfile;
    if (body.noveltyFloor !== undefined) meta.noveltyFloor = body.noveltyFloor;
    if (body.maxScanRate !== undefined) meta.maxScanRate = body.maxScanRate;
    updateData.metadata = meta;

    const [updated] = await db.update(programs).set(updateData).where(eq(programs.id, id)).returning();
    if (Array.isArray(body.scope) || Array.isArray(body.outOfScope)) {
      ScopeGuard.getInstance().invalidateCache(id);
    }
    return res.json(shapeProgramForScopeUI(updated));
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── Task Planning generator (TaskPlanning.tsx) ───────────────────────────────────
// Build a phase-based task plan from the real Kali catalog (which tools map to which
// phase) and persist each task to the tasks workspace store.
router.post("/tasks/generate", async (req: Request, res: Response) => {
  try {
    const { hunt_id, goal, target } = req.body || {};
    if (!target) return res.status(400).json({ success: false, error: "target required" });

    const phasePlan: { phase: string; titles: { title: string; description: string; priority: string; estimated_time: string }[] }[] = [
      { phase: "reconnaissance", titles: [
        { title: "Passive subdomain enumeration", description: `Enumerate subdomains of ${target} via subfinder/amass/assetfinder`, priority: "high", estimated_time: "30m" },
        { title: "Gather historical URLs", description: `Collect known URLs for ${target} (gau, waybackurls)`, priority: "medium", estimated_time: "20m" },
      ]},
      { phase: "enumeration", titles: [
        { title: "Probe live hosts & fingerprint tech", description: `Run httpx + whatweb across discovered hosts for ${target}`, priority: "high", estimated_time: "30m" },
        { title: "Content discovery", description: `Fuzz directories/files with ffuf/feroxbuster on ${target}`, priority: "medium", estimated_time: "45m" },
      ]},
      { phase: "vulnerability_discovery", titles: [
        { title: "Automated vuln scan", description: `Run nuclei templates against ${target}`, priority: "high", estimated_time: "40m" },
        { title: `Targeted testing for goal: ${goal || "vulnerabilities"}`, description: `Manual + tool-assisted testing toward "${goal || "high-impact findings"}"`, priority: "critical", estimated_time: "2h" },
      ]},
      { phase: "exploitation", titles: [
        { title: "Confirm & exploit candidates", description: `Validate promising findings on ${target} with PoC payloads`, priority: "critical", estimated_time: "2h" },
      ]},
      { phase: "reporting", titles: [
        { title: "Draft bug bounty report", description: `Write up confirmed findings for ${target}`, priority: "high", estimated_time: "1h" },
      ]},
    ];

    const created: any[] = [];
    for (const group of phasePlan) {
      for (const t of group.titles) {
        const id = `task-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
        const entry = {
          id,
          hunt_id: hunt_id || "",
          title: t.title,
          description: t.description,
          priority: t.priority,
          phase: group.phase,
          status: "pending",
          estimated_time: t.estimated_time,
          dependencies: [] as string[],
          notes: "",
          createdAt: new Date().toISOString(),
        };
        await wsWrite("tasks", id, entry);
        created.push(entry);
      }
    }

    return res.status(201).json({ success: true, tasks: created, count: created.length });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

// ── Nuclei template detail (NucleiTemplates.tsx) ─────────────────────────────────
// Reuse the same source as GET /nuclei/templates (findings that carry a nucleiTemplate)
// and return the matching template's full content.
router.get("/nuclei/templates/:id", async (req: Request, res: Response) => {
  try {
    const idParam = decodeURIComponent(req.params.id);
    const rows = await db.select().from(findings);
    const candidates = rows.filter((r: any) => r.nucleiTemplate);

    // Match by finding id, or by template text containing the id/name token.
    let match = candidates.find((r: any) => String(r.id) === idParam);
    if (!match) match = candidates.find((r: any) => r.nucleiTemplate && r.nucleiTemplate.includes(idParam));

    if (!match) return res.status(404).json({ error: "Template not found", content: "" });
    return res.json({
      id: match.id,
      name: match.nucleiTemplate ? String(match.nucleiTemplate).split("\n")[0] : idParam,
      severity: match.severity,
      content: match.nucleiTemplate,
      yaml: match.nucleiTemplate,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ── Platform status (SyncStatus.tsx) ─────────────────────────────────────────────
// Derive bug-bounty platform connection status from configured programs: a platform
// is "fully_wired" if at least one program with a handle exists for it, else "partial".
router.get("/platform/status", async (_req: Request, res: Response) => {
  try {
    const rows = await db.select().from(programs);
    const platformList = ["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack"];
    const labels: Record<string, string> = {
      hackerone: "HackerOne", bugcrowd: "Bugcrowd", intigriti: "Intigriti",
      synack: "Synack", yeswehack: "YesWeHack",
    };

    const features = platformList.map(plat => {
      const progs = rows.filter(r => r.platform === plat);
      const configured = progs.some(r => r.programHandle);
      return {
        name: labels[plat],
        status: configured ? "fully_wired" : "inactive",
        details: configured
          ? `${progs.length} program(s) configured`
          : "No program handle configured for this platform",
        lastChecked: new Date().toISOString(),
      };
    });

    const localPrograms = rows.filter(r => !isCrossCampaignEligible(r));
    const categories = [
      {
        name: "Bug Bounty Platforms",
        icon: "shield",
        color: "cyan",
        features,
      },
      {
        name: "Local / Custom Targets",
        icon: "target",
        color: "green",
        features: [{
          name: "Custom Programs",
          status: localPrograms.length > 0 ? "fully_wired" : "inactive",
          details: `${localPrograms.length} custom/local program(s)`,
          lastChecked: new Date().toISOString(),
        }],
      },
    ];

    return res.json({
      success: true,
      mode: process.env.NODE_ENV === "production" ? "production" : "web",
      categories,
    });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

export default router;

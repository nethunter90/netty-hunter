import { Router, Request, Response } from "express";
import { execFileSync, execFile } from "child_process";
import { promisify } from "util";
import { db } from "../db";
import { customTools } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";
import { dispatchTool, ToolOutOfScopeError } from "../lib/net/dispatch-tool";
import { resolveCustomTargetProgram } from "../lib/hunter/custom-target-program";

const router = Router();
const execFileAsync = promisify(execFile);

function getBinaryAvailability(binary: string): { available: boolean; path?: string; version?: string } {
  try {
    const path = execFileSync("which", [binary], { encoding: "utf8" }).trim();
    if (!path) return { available: false };
    let version: string | undefined;
    try {
      const raw = execFileSync(binary, ["--version"], { encoding: "utf8", timeout: 3000 });
      version = raw.split("\n")[0]?.trim();
    } catch { /* version unavailable */ }
    return { available: true, path, version };
  } catch {
    return { available: false };
  }
}

// GET /api/tools — returns Kali catalog with install status + DB custom tools
router.get("/", async (_req: Request, res: Response) => {
  try {
    const { KALI_CATALOG } = await import("../lib/hunter/kali-catalog");
    const catalog = KALI_CATALOG.map(entry => ({
      ...entry,
      ...getBinaryAvailability(entry.binary),
    }));
    const custom = await db.select().from(customTools).orderBy(customTools.createdAt);
    const enrichedCustom = custom.map(t => ({
      ...t,
      ...getBinaryAvailability(t.requiredBinary),
    }));
    return res.json({ catalog, custom: enrichedCustom });
  } catch (err) {
    logger.error("Failed to list tools", { err: String(err) });
    return res.status(500).json({ error: "Failed to list tools" });
  }
});

// POST /api/tools — create a new custom tool
router.post("/", async (req: Request, res: Response) => {
  const { displayName, name, description, commandTemplate, requiredBinary,
          category, vulnClasses, rateLimit, riskLevel, stealthRating, parserType } = req.body;

  if (!displayName || !commandTemplate || !requiredBinary) {
    return res.status(400).json({ error: "displayName, commandTemplate, and requiredBinary are required" });
  }

  // Auto-derive name from displayName if not provided
  const toolName = (name || displayName.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "")) as string;

  // Basic command template safety check — no shell metacharacters outside {url}
  const templateWithoutUrl = commandTemplate.replace(/\{url\}/g, "");
  if (/[;&|`$><\\]/.test(templateWithoutUrl)) {
    return res.status(400).json({ error: "Command template contains unsafe shell metacharacters" });
  }

  try {
    const [tool] = await db.insert(customTools).values({
      name: toolName,
      displayName,
      description: description || "",
      commandTemplate,
      requiredBinary,
      category: category || "scanning",
      vulnClasses: vulnClasses || [],
      rateLimit: rateLimit ?? 30,
      riskLevel: riskLevel || "medium",
      stealthRating: stealthRating ?? 5,
      parserType: parserType || "lines",
      enabled: true,
    }).returning();

    return res.status(201).json({ tool: { ...tool, ...getBinaryAvailability(tool.requiredBinary) } });
  } catch (err: unknown) {
    const msg = String(err);
    if (msg.includes("unique")) return res.status(409).json({ error: `Tool name '${toolName}' already exists` });
    logger.error("Failed to create custom tool", { err: msg });
    return res.status(500).json({ error: "Failed to create tool" });
  }
});

// PUT /api/tools/:id — update a custom tool
router.put("/:id", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid id" });

  const { displayName, description, commandTemplate, requiredBinary,
          category, vulnClasses, rateLimit, riskLevel, stealthRating, parserType, enabled } = req.body;

  if (commandTemplate) {
    const templateWithoutUrl = commandTemplate.replace(/\{url\}/g, "");
    if (/[;&|`$><\\]/.test(templateWithoutUrl)) {
      return res.status(400).json({ error: "Command template contains unsafe shell metacharacters" });
    }
  }

  try {
    const updates: Partial<typeof customTools.$inferInsert> = { updatedAt: new Date() };
    if (displayName !== undefined) updates.displayName = displayName;
    if (description !== undefined) updates.description = description;
    if (commandTemplate !== undefined) updates.commandTemplate = commandTemplate;
    if (requiredBinary !== undefined) updates.requiredBinary = requiredBinary;
    if (category !== undefined) updates.category = category;
    if (vulnClasses !== undefined) updates.vulnClasses = vulnClasses;
    if (rateLimit !== undefined) updates.rateLimit = rateLimit;
    if (riskLevel !== undefined) updates.riskLevel = riskLevel;
    if (stealthRating !== undefined) updates.stealthRating = stealthRating;
    if (parserType !== undefined) updates.parserType = parserType;
    if (enabled !== undefined) updates.enabled = enabled;

    const [tool] = await db.update(customTools).set(updates).where(eq(customTools.id, id)).returning();
    if (!tool) return res.status(404).json({ error: "Tool not found" });
    return res.json({ tool: { ...tool, ...getBinaryAvailability(tool.requiredBinary) } });
  } catch (err) {
    logger.error("Failed to update custom tool", { err: String(err) });
    return res.status(500).json({ error: "Failed to update tool" });
  }
});

// DELETE /api/tools/:id — delete a custom tool
router.delete("/:id", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid id" });

  try {
    const [deleted] = await db.delete(customTools).where(eq(customTools.id, id)).returning();
    if (!deleted) return res.status(404).json({ error: "Tool not found" });
    return res.json({ success: true });
  } catch (err) {
    logger.error("Failed to delete custom tool", { err: String(err) });
    return res.status(500).json({ error: "Failed to delete tool" });
  }
});

// POST /api/tools/:id/test — test-fire a tool against a URL
router.post("/:id/test", async (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: "Invalid id" });

  const { url, programId: bodyProgramId } = req.body;
  if (!url || typeof url !== "string") return res.status(400).json({ error: "url is required" });

  // Basic well-formedness check stays here (fast 400 before any DB/scope
  // work); the REAL scope decision — including the private-IP/loopback
  // rejection this used to do with its own regex blocklist — now lives
  // inside dispatchTool()'s ScopeGuard.isInScope() check below, which is the
  // same guard every other target-facing dispatch in this codebase uses
  // (one guard, not a second hand-rolled one that can drift).
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Only http/https URLs are allowed" });
    }
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    const [tool] = await db.select().from(customTools).where(eq(customTools.id, id));
    if (!tool) return res.status(404).json({ error: "Tool not found" });

    // 2026-07-22: tokenize the template BEFORE substituting {url} (matching
    // HunterEngine.buildCommandFromTemplate's convention dispatchTool
    // mirrors) — the previous version substituted the raw url into the
    // template STRING first and split on whitespace afterward, so a url
    // containing a space (e.g. "http://x.com/ --output=/etc/passwd") could
    // inject an extra argv entry. Tokenizing first keeps the substituted URL
    // confined to a single argument no matter what it contains.
    const templateTokens = tool.commandTemplate.split(/\s+/).filter(Boolean);
    const bin = templateTokens[0];
    const args = templateTokens.slice(1);

    const programId = bodyProgramId ?? await resolveCustomTargetProgram(url);
    const { stdout, stderr } = await dispatchTool({
      tool: bin, target: url, args, programId, timeoutMs: 30000,
    }).catch(e => {
      if (e instanceof ToolOutOfScopeError) throw e;
      return { stdout: e.stdout || "", stderr: e.stderr || String(e) };
    });

    return res.json({ stdout: stdout.slice(0, 8000), stderr: stderr.slice(0, 2000) });
  } catch (err) {
    if (err instanceof ToolOutOfScopeError) {
      return res.status(403).json({ error: `Out of scope: ${err.reason}` });
    }
    logger.error("Tool test-fire failed", { id, err: String(err) });
    return res.status(500).json({ error: "Tool test-fire failed", detail: String(err) });
  }
});

export default router;

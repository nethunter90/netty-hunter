import { Router, Request, Response } from "express";
import { execSync, execFile } from "child_process";
import { promisify } from "util";
import { db } from "../db";
import { customTools } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";

const router = Router();
const execFileAsync = promisify(execFile);

function getBinaryAvailability(binary: string): { available: boolean; path?: string; version?: string } {
  try {
    const path = execSync(`which ${binary} 2>/dev/null`, { encoding: "utf8" }).trim();
    if (!path) return { available: false };
    let version: string | undefined;
    try {
      version = execSync(`${binary} --version 2>&1 | head -1`, { encoding: "utf8", timeout: 3000 }).trim();
    } catch { /* version unavailable */ }
    return { available: true, path, version };
  } catch {
    return { available: false };
  }
}

// GET /api/tools — list all custom tools with binary availability
router.get("/", async (_req: Request, res: Response) => {
  try {
    const tools = await db.select().from(customTools).orderBy(customTools.createdAt);
    const enriched = tools.map(t => ({
      ...t,
      ...getBinaryAvailability(t.requiredBinary),
    }));
    return res.json({ tools: enriched });
  } catch (err) {
    logger.error("Failed to list custom tools", { err: String(err) });
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

  const { url } = req.body;
  if (!url || typeof url !== "string") return res.status(400).json({ error: "url is required" });

  // Scope guard — reject private IPs and non-http(s) URLs
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({ error: "Only http/https URLs are allowed" });
    }
    const hostname = parsed.hostname;
    if (/^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|localhost$|::1$)/.test(hostname)) {
      return res.status(400).json({ error: "Private/loopback URLs are not allowed for test-fire" });
    }
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    const [tool] = await db.select().from(customTools).where(eq(customTools.id, id));
    if (!tool) return res.status(404).json({ error: "Tool not found" });

    const parts = tool.commandTemplate.replace("{url}", url).split(/\s+/).filter(Boolean);
    const bin = parts[0];
    const args = parts.slice(1);

    const { stdout, stderr } = await execFileAsync(bin, args, { timeout: 30000 }).catch(e => ({
      stdout: e.stdout || "",
      stderr: e.stderr || String(e),
    }));

    return res.json({ stdout: stdout.slice(0, 8000), stderr: stderr.slice(0, 2000) });
  } catch (err) {
    logger.error("Tool test-fire failed", { id, err: String(err) });
    return res.status(500).json({ error: "Tool test-fire failed", detail: String(err) });
  }
});

export default router;

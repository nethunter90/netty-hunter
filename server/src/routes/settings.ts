import { Router, Request, Response } from "express";
import { db } from "../db";
import { reinforcementStore } from "../db/schema";
import { like } from "drizzle-orm";

const router = Router();

const SETTINGS_DOMAIN = "settings";
const ALLOWED_KEYS = new Set([
  "HACKERONE_USERNAME", "HACKERONE_TOKEN",
  "BUGCROWD_TOKEN", "INTIGRITI_TOKEN", "YESWEHACK_TOKEN",
  "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL", "NOTIFY_WEBHOOK_URL",
  "NVD_API_KEY", "OOB_HOST", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
]);

// GET /settings — return all saved settings (values masked for secrets)
router.get("/", async (_req: Request, res: Response) => {
  const rows = await db.select().from(reinforcementStore)
    .where(like(reinforcementStore.domain, SETTINGS_DOMAIN));
  const result: Record<string, string> = {};
  for (const row of rows) {
    if (ALLOWED_KEYS.has(row.key)) {
      result[row.key] = row.value != null ? String(row.value) : "";
    }
  }
  return res.json(result);
});

// POST /settings — upsert all provided key/value pairs and inject into process.env
router.post("/", async (req: Request, res: Response) => {
  const body = req.body as Record<string, string>;
  for (const [key, value] of Object.entries(body)) {
    if (!ALLOWED_KEYS.has(key)) continue;
    if (!value) continue;

    await db.insert(reinforcementStore).values({
      domain: SETTINGS_DOMAIN,
      key,
      value,
    }).onConflictDoUpdate({
      target: [reinforcementStore.domain, reinforcementStore.key],
      set: { value },
    });

    // Inject into running process so services pick it up without restart
    process.env[key] = value;
  }
  return res.json({ ok: true });
});

export default router;

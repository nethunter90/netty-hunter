import { Router, Request, Response } from "express";
import axios from "axios";
import { db } from "../db";
import { reinforcementStore } from "../db/schema";
import { like } from "drizzle-orm";
import { runtimeConfig, RUNTIME_CONFIG_ALLOWED_KEYS } from "../lib/runtime-config";

const router = Router();

const SETTINGS_DOMAIN = "settings";
const ALLOWED_KEYS = RUNTIME_CONFIG_ALLOWED_KEYS;

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

    // Apply through RuntimeConfig (validates key, sanitizes value, audits the write)
    runtimeConfig.set(key, value);
  }
  return res.json({ ok: true });
});

// ── Local LLM Auto-Detector ───────────────────────────────────────────────────

interface LocalRuntime {
  name: string;
  label: string;
  url: string;
  models: string[];
}

const LOCAL_RUNTIMES = [
  { name: "ollama",    label: "Ollama",     url: "http://localhost:11434", type: "ollama" as const },
  { name: "lm_studio", label: "LM Studio",  url: "http://localhost:1234",  type: "openai" as const },
  { name: "jan",       label: "Jan",        url: "http://localhost:1337",  type: "openai" as const },
  { name: "localai",   label: "LocalAI",    url: "http://localhost:8080",  type: "openai" as const },
  { name: "vllm",      label: "vLLM",       url: "http://localhost:8000",  type: "openai" as const },
];

async function probeRuntime(runtime: typeof LOCAL_RUNTIMES[number]): Promise<LocalRuntime | null> {
  try {
    if (runtime.type === "ollama") {
      const resp = await axios.get(`${runtime.url}/api/tags`, { timeout: 2000 });
      const models: string[] = (resp.data?.models ?? []).map((m: { name: string }) => m.name);
      return { name: runtime.name, label: runtime.label, url: runtime.url, models };
    } else {
      const resp = await axios.get(`${runtime.url}/v1/models`, { timeout: 2000 });
      const models: string[] = (resp.data?.data ?? []).map((m: { id: string }) => m.id);
      return { name: runtime.name, label: runtime.label, url: runtime.url, models };
    }
  } catch {
    return null;
  }
}

// GET /settings/local-models — probe all local LLM runtimes concurrently
router.get("/local-models", async (_req: Request, res: Response) => {
  const results = await Promise.allSettled(LOCAL_RUNTIMES.map(probeRuntime));
  const runtimes: LocalRuntime[] = results
    .map(r => (r.status === "fulfilled" ? r.value : null))
    .filter((r): r is LocalRuntime => r !== null && r.models.length > 0);

  return res.json({
    runtimes,
    active: {
      url: runtimeConfig.get("OLLAMA_BASE_URL") || process.env.OLLAMA_BASE_URL || "http://localhost:11434",
      model: runtimeConfig.get("OLLAMA_DEFAULT_MODEL") || process.env.OLLAMA_DEFAULT_MODEL || "llama3.2",
    },
  });
});

export default router;

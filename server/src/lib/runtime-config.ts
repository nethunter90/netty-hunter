/**
 * RuntimeConfig — Scoped settings store.
 *
 * Replaces direct process.env mutation from /api/settings so that operator-supplied
 * tokens are written through a validated, audited path instead of polluting the global
 * environment directly.  process.env is still updated for backward-compat with services
 * that read it directly (NVD client, report submitter, etc.) but every write is:
 *   1. Checked against the ALLOWED_KEYS allowlist
 *   2. Sanitized (null bytes stripped, length capped)
 *   3. Logged at debug level for audit trail
 *
 * Services should prefer runtimeConfig.get(key) over process.env[key] so that values
 * set via the UI during a running session are visible without restart.
 */
import logger from "../utils/logger";

export const RUNTIME_CONFIG_ALLOWED_KEYS = new Set([
  "HACKERONE_USERNAME", "HACKERONE_TOKEN",
  "BUGCROWD_TOKEN", "INTIGRITI_TOKEN", "YESWEHACK_TOKEN",
  "SLACK_WEBHOOK_URL", "DISCORD_WEBHOOK_URL", "NOTIFY_WEBHOOK_URL",
  "NVD_API_KEY", "OOB_HOST", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
]);

class RuntimeConfig {
  private readonly store = new Map<string, string>();

  set(key: string, rawValue: string): void {
    if (!RUNTIME_CONFIG_ALLOWED_KEYS.has(key)) {
      logger.warn("[RuntimeConfig] Rejected write to disallowed key", { key });
      return;
    }
    // Strip null bytes and other control characters; cap length to prevent OOM
    const value = rawValue.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "").slice(0, 4096);
    this.store.set(key, value);
    process.env[key] = value; // backward-compat: services reading process.env still work
    logger.debug("[RuntimeConfig] Setting applied", { key });
  }

  get(key: string): string | undefined {
    return this.store.get(key) ?? process.env[key];
  }

  /** Load bulk key/value pairs (used at startup from DB). */
  loadAll(entries: Array<{ key: string; value: unknown }>): void {
    for (const { key, value } of entries) {
      if (value != null) this.set(key, String(value));
    }
  }
}

export const runtimeConfig = new RuntimeConfig();

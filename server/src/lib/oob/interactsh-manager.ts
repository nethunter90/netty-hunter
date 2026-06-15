/**
 * InteractshManager — OOB callback layer backed by interactsh-client.
 *
 * interactsh-client (by ProjectDiscovery) is a Kali-native binary that
 * connects to interactsh.com and gives you a unique public domain like
 * abc123.oast.pro. Any HTTP/DNS/SMTP request to a subdomain of that domain
 * is recorded and streamed back to us — even from real internet targets that
 * obviously can't reach localhost:3001.
 *
 * Singleton: starts once when the first hunt needs it, stays running.
 * Falls back to the local callback server if interactsh-client is not installed.
 *
 * Beacon IDs use a "n"+12-hex format (13 chars) — short enough for a DNS label,
 * starts with a letter so all DNS validators accept it.
 */
import { spawn, ChildProcess } from "child_process";
import { execSync } from "child_process";
import logger from "../../utils/logger";

export interface OOBHit {
  beaconId: string;
  protocol: string;
  fromIp: string;
  at: Date;
  raw?: string;
}

class InteractshManager {
  private proc: ChildProcess | null = null;
  private domain: string | null = null;
  private starting: Promise<string | null> | null = null;
  private hits = new Map<string, OOBHit>();
  private waiters = new Map<string, (hit: OOBHit) => void>();
  private _available: boolean | null = null;

  isAvailable(): boolean {
    if (this._available !== null) return this._available;
    try {
      const p = execSync("which interactsh-client 2>/dev/null", { encoding: "utf8", timeout: 2000 }).trim();
      this._available = p.length > 0;
    } catch {
      this._available = false;
    }
    if (!this._available) {
      logger.info("[Interactsh] interactsh-client not found — blind OOB uses local callback server");
    }
    return this._available;
  }

  /** Start the client and return the assigned domain. Returns null if unavailable. */
  async start(): Promise<string | null> {
    if (!this.isAvailable()) return null;
    if (this.domain) return this.domain;
    if (this.starting) return this.starting;

    this.starting = new Promise<string | null>((resolve) => {
      logger.info("[Interactsh] Starting interactsh-client…");

      this.proc = spawn("interactsh-client", ["-json", "-v"], {
        stdio: ["ignore", "pipe", "pipe"],
      });

      let resolved = false;
      const timeout = setTimeout(() => {
        if (!resolved) {
          logger.warn("[Interactsh] Domain assignment timed out — falling back to local callbacks");
          resolved = true;
          resolve(null);
        }
      }, 30_000);

      const parseLine = (line: string) => {
        // Domain assignment — appears in both JSON and plain-text output
        const domainMatch = line.match(/Listing on\s+([\w.-]+\.[a-z]{2,})/i);
        if (domainMatch && !resolved) {
          this.domain = domainMatch[1];
          resolved = true;
          clearTimeout(timeout);
          this.starting = null;
          logger.info("[Interactsh] OOB domain ready", { domain: this.domain });
          resolve(this.domain);
          return;
        }

        // Hit event — JSON line with unique-id field
        try {
          const data = JSON.parse(line) as Record<string, string>;

          // Some builds emit {"domain":"..."} as the first JSON line
          if (data.domain && !resolved) {
            this.domain = data.domain;
            resolved = true;
            clearTimeout(timeout);
            this.starting = null;
            logger.info("[Interactsh] OOB domain ready (JSON)", { domain: this.domain });
            resolve(this.domain);
            return;
          }

          const uid = data["unique-id"] || data.uniqueId;
          if (!uid) return;

          const hit: OOBHit = {
            beaconId: uid,
            protocol: data.protocol || "http",
            fromIp: data["remote-address"] || data.remoteAddress || "",
            at: new Date(),
            raw: line,
          };
          this.hits.set(uid, hit);
          logger.info("[Interactsh] OOB hit received", { beaconId: uid, protocol: hit.protocol, from: hit.fromIp });

          const waiter = this.waiters.get(uid);
          if (waiter) {
            waiter(hit);
            this.waiters.delete(uid);
          }
        } catch { /* not JSON */ }
      };

      const bufferLines = (stream: NodeJS.ReadableStream) => {
        let buf = "";
        stream.on("data", (chunk: Buffer) => {
          buf += chunk.toString();
          const lines = buf.split("\n");
          buf = lines.pop() ?? "";
          lines.forEach(l => l.trim() && parseLine(l.trim()));
        });
      };

      if (this.proc.stdout) bufferLines(this.proc.stdout);
      if (this.proc.stderr) bufferLines(this.proc.stderr);

      this.proc.on("error", (err) => {
        logger.warn("[Interactsh] Process error", { err: String(err) });
        if (!resolved) { resolved = true; clearTimeout(timeout); resolve(null); }
        this.reset();
      });

      this.proc.on("exit", (code) => {
        logger.info("[Interactsh] Process exited", { code });
        if (!resolved) { resolved = true; clearTimeout(timeout); resolve(null); }
        this.reset();
      });
    });

    return this.starting;
  }

  /**
   * Generate a beacon for OOB probing.
   * Returns null if interactsh isn't running — caller should fall back to
   * the local callbackServer.
   */
  generateBeacon(): { beaconId: string; callbackUrl: string } | null {
    if (!this.domain) return null;
    // DNS-safe: starts with letter, 13 chars total — fits in a DNS label
    const beaconId = "n" + Math.random().toString(16).slice(2, 14).padEnd(12, "0");
    const callbackUrl = `http://${beaconId}.${this.domain}`;
    logger.debug("[Interactsh] Beacon generated", { beaconId, callbackUrl });
    return { beaconId, callbackUrl };
  }

  /** Wait up to timeoutMs for a hit on beaconId. Returns the hit or null. */
  async waitForHit(beaconId: string, timeoutMs = 15_000): Promise<OOBHit | null> {
    const existing = this.hits.get(beaconId);
    if (existing) return existing;

    return new Promise<OOBHit | null>(resolve => {
      const timer = setTimeout(() => {
        this.waiters.delete(beaconId);
        resolve(null);
      }, timeoutMs);

      this.waiters.set(beaconId, hit => {
        clearTimeout(timer);
        resolve(hit);
      });
    });
  }

  getDomain(): string | null {
    return this.domain;
  }

  private reset(): void {
    this.proc = null;
    this.domain = null;
    this.starting = null;
  }

  stop(): void {
    this.proc?.kill("SIGTERM");
    this.reset();
    this.hits.clear();
    this.waiters.clear();
  }
}

export const interactshManager = new InteractshManager();

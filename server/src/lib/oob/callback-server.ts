import { v4 as uuidv4 } from "uuid";
import logger from "../../utils/logger";

export interface BeaconRecord {
  createdAt: number;
  received: boolean;
  receivedAt?: number;
  requestIp?: string;
  requestBody?: string;
  // Command output exfiltrated via the callback query string (e.g. ?u=$(whoami)
  // → { u: "root" }). Present when the injected payload folded command output
  // into the beacon URL.
  exfil?: Record<string, string>;
}

class CallbackServer {
  private beacons = new Map<string, BeaconRecord>();
  private serverHost = process.env.OOB_HOST || `http://localhost:${process.env.PORT || "3001"}`;
  // Hard cap so a burst can't OOM the process before the 10-min pruner runs.
  private static readonly MAX_BEACONS = 50_000;

  generateBeacon(): { beaconId: string; callbackUrl: string } {
    // FIFO-evict the oldest entry (insertion-ordered Map) when at capacity.
    if (this.beacons.size >= CallbackServer.MAX_BEACONS) {
      const oldest = this.beacons.keys().next().value;
      if (oldest !== undefined) this.beacons.delete(oldest);
    }
    const beaconId = uuidv4();
    this.beacons.set(beaconId, { createdAt: Date.now(), received: false });
    logger.debug("[OOB] Beacon generated", { beaconId });
    return { beaconId, callbackUrl: `${this.serverHost}/api/callback/${beaconId}` };
  }

  recordHit(beaconId: string, ip: string, body: string, query?: Record<string, unknown>): void {
    const rec = this.beacons.get(beaconId);
    if (rec) {
      rec.received = true;
      rec.receivedAt = Date.now();
      rec.requestIp = ip;
      rec.requestBody = body;
      if (query && Object.keys(query).length > 0) {
        const exfil: Record<string, string> = {};
        for (const [k, v] of Object.entries(query)) exfil[k] = String(v);
        rec.exfil = exfil;
      }
      logger.info("[OOB] Callback received", { beaconId, ip, exfil: rec.exfil });
    }
  }

  /** Resolves the beacon record once a hit lands (so callers can read `exfil`),
   *  or null on timeout. */
  async waitForHit(beaconId: string, timeoutMs: number): Promise<BeaconRecord | null> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const rec = this.beacons.get(beaconId);
      if (rec?.received) return rec;
      await new Promise(r => setTimeout(r, 500));
    }
    return null;
  }

  cleanup(beaconId: string): void {
    this.beacons.delete(beaconId);
  }

  // Housekeep stale beacons older than 10 minutes
  pruneStale(): void {
    const cutoff = Date.now() - 10 * 60 * 1000;
    for (const [id, rec] of this.beacons) {
      if (rec.createdAt < cutoff) this.beacons.delete(id);
    }
  }
}

export const callbackServer = new CallbackServer();

// Prune every 10 minutes
setInterval(() => callbackServer.pruneStale(), 10 * 60 * 1000);

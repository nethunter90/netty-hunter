import { v4 as uuidv4 } from "uuid";
import logger from "../../utils/logger";

interface BeaconRecord {
  createdAt: number;
  received: boolean;
  receivedAt?: number;
  requestIp?: string;
  requestBody?: string;
}

class CallbackServer {
  private beacons = new Map<string, BeaconRecord>();
  private serverHost = process.env.OOB_HOST || `http://localhost:${process.env.PORT || "3001"}`;

  generateBeacon(): { beaconId: string; callbackUrl: string } {
    const beaconId = uuidv4();
    this.beacons.set(beaconId, { createdAt: Date.now(), received: false });
    logger.debug("[OOB] Beacon generated", { beaconId });
    return { beaconId, callbackUrl: `${this.serverHost}/api/callback/${beaconId}` };
  }

  recordHit(beaconId: string, ip: string, body: string): void {
    const rec = this.beacons.get(beaconId);
    if (rec) {
      rec.received = true;
      rec.receivedAt = Date.now();
      rec.requestIp = ip;
      rec.requestBody = body;
      logger.info("[OOB] Callback received", { beaconId, ip });
    }
  }

  async waitForHit(beaconId: string, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const rec = this.beacons.get(beaconId);
      if (rec?.received) return true;
      await new Promise(r => setTimeout(r, 500));
    }
    return false;
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

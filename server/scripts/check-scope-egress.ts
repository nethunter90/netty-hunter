/**
 * CI import-guard for the scope-containment chokepoint.
 *
 * Every outbound request to a hunted target must go through scopedHttp
 * (server/src/lib/net/scoped-http.ts), which enforces ScopeGuard before
 * dispatch — including on every redirect hop. A raw HTTP client used
 * anywhere else in the target-facing code silently reintroduces the bypass
 * this project spent real effort closing (see the scope-containment handoff).
 *
 * Covers every client shape actually found or plausible in this codebase —
 * not just axios, which was the first (and easiest) one to miss a client
 * entirely for:
 *   - axios: `.get/.post/.put/.delete/.patch/.request/.head(`, bare `axios({...})`,
 *     dynamic `import("axios")` (missed once already — VerifierAgent.ts used it).
 *   - fetch: global `fetch(` (found unguarded and fixed in routes/bounty.ts —
 *     three manual endpoints with zero scope check before this handoff).
 *   - got / undici / node-fetch: static or dynamic import.
 *   - raw Node http/https: `.request(`/`.get(` on an imported `http`/`https`
 *     module (websocket-probe.ts's Upgrade handshake needs this — no axios
 *     equivalent exists for an HTTP Upgrade).
 *   - ws: a dedicated WebSocket client library, if one is ever introduced.
 *
 * This script is NOT a general-purpose lint rule: it knows about a small,
 * explicit allowlist of files that legitimately talk to something other
 * than the hunted target (a local tool's control API, a bug-bounty
 * platform, a webhook, local Ollama, inbound server setup) — or that
 * implement their OWN scope check inline because no axios-based wrapper
 * applies (an HTTP Upgrade handshake can't go through an axios client).
 * Anything not on that list using any of the above forms fails the build.
 *
 * Run: npx tsx scripts/check-scope-egress.ts
 * Wired as a `pretest` hook so `npm test` always runs it first.
 */
import { readFileSync, readdirSync, statSync } from "fs";
import { join, relative } from "path";

const SRC_ROOT = join(__dirname, "..", "src");

// Files allowed to use a raw HTTP client directly. Adding to this list is a
// deliberate, reviewable decision — each entry states WHY it's safe.
const ALLOWLIST: Record<string, string> = {
  "lib/net/scoped-http.ts":
    "the chokepoint itself — the only place axios is dispatched directly",
  "lib/services/notification-service.ts":
    "Slack/Discord/generic webhooks — never the hunted target",
  "lib/intelligence/writeup-scraper.ts":
    "third-party writeup scraping (public disclosure sites), not the target",
  "lib/intelligence/report-submitter.ts":
    "bug-bounty platform submission API, not the target",
  "lib/tools/zap-scanner.ts":
    "local ZAP daemon control API (127.0.0.1) — ZAP itself makes the target " +
    "request, out of this process's HTTP client entirely; ZAP's own scope " +
    "enforcement is a separate, tracked concern",
  "intelligence/JsonPromptLoader.ts":
    "local Ollama embeddings API, not the target",
  "routes/settings.ts":
    "local Ollama /v1/models health check, not the target",
  "lib/recon/recon-runner.ts":
    "fetchCrtSh/fetchWaybackInteresting hit crt.sh/web.archive.org (third-party " +
    "OSINT); its one target-facing call (subdomain HEAD check) already routes " +
    "through scopedHttp",
  "lib/tools/websocket-probe.ts":
    "raw Node http/https Upgrade handshake — no axios equivalent exists for " +
    "an HTTP Upgrade, so checkWsUpgrade() calls ScopeGuard.isInScope() inline " +
    "itself (see the function) instead of routing through scopedHttp",
  "lib/intelligence/hunt-lab-runner.ts":
    "waitForTarget() polls a fixed, pre-registered lab-profile URL (Juice " +
    "Shop/DVWA/etc. from the lab-profile catalog, never attacker-controlled " +
    "input) purely to gate hunt START; the actual hunt it kicks off goes " +
    "through the normal scoped path via huntOrchestrator",
  "lib/orchestration/layer6-ai-bridge.ts":
    "local Ollama /api/generate and /api/tags, not the target",
  "lib/intelligence/public-disclosure-detector.ts":
    "public bug-bounty disclosure sites (HackerOne/etc. reports), not the target",
  "lib/intelligence/nvd-client.ts":
    "NVD (National Vulnerability Database) API, not the target",
  "lib/intelligence/external-apis.ts":
    "threat-intel APIs (VirusTotal/AbuseIPDB), not the target",
  "index.ts":
    "createServer() is the INBOUND Express/Socket.IO server, not an outbound client",
  "lib/verification/playwright-health.ts":
    "checkPlaywrightHealth() takes zero parameters, has exactly one call site " +
    "(index.ts, called with no arguments at startup), and navigates to the literal " +
    "constant \"about:blank\" — no request/DB/AI input reaches this navigation target, " +
    "so there is no scope to enforce",
};

const EXCLUDED_DIRS = new Set(["__tests__", "fixtures", "workspace", "node_modules"]);

// axios: method calls, bare callable form, dynamic import, require
const AXIOS_PATTERN =
  /axios\.(get|post|put|delete|patch|request|head)\(|\baxios\(\{|import\(\s*["']axios["']\s*\)|require\(\s*["']axios["']\s*\)/;
const AXIOS_IMPORT_PATTERN = /^\s*import\s+axios\b.*from\s+["']axios["']/m;

// fetch: the global fetch() function — but NOT inside a string/template
// literal (HunterEngine.ts embeds `fetch(...)` as JS text injected into a
// target page for an XSS payload, which is payload content, not our own
// outbound request; excluded by requiring fetch( to not be inside quotes on
// the same line — a deliberately narrow heuristic, see the false-positive
// check below).
const FETCH_PATTERN = /(?<!["'`].*)\bfetch\s*\(/;

// got / undici / node-fetch: static or dynamic import
const OTHER_CLIENT_IMPORT_PATTERN =
  /from\s+["'](got|undici|node-fetch|ws)["']|import\(\s*["'](got|undici|node-fetch|ws)["']\s*\)|require\(\s*["'](got|undici|node-fetch|ws)["']\s*\)/;

// raw Node http/https: imported AND actually dispatching a request via
// .request(/.get( — importing http/https alone (e.g. for createServer, or
// for a type like IncomingMessage) is not by itself an egress call.
const HTTP_MODULE_IMPORT_PATTERN =
  /^\s*import\s+(\w+)\s*(?:,\s*\{[^}]*\})?\s*from\s+["'](http|https)["']/m;
const HTTP_DISPATCH_PATTERN = /\.(request|get)\s*\(/;

function walk(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (EXCLUDED_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walk(full, files);
    } else if (entry.endsWith(".ts") && !entry.endsWith(".d.ts")) {
      files.push(full);
    }
  }
  return files;
}

function checkFetch(content: string): boolean {
  // Line-by-line, skipping comments and any line explicitly marked with the
  // suppression convention below — a whole-file regex can't reliably tell
  // real code from a comment or a string literal containing "fetch(" (e.g.
  // HunterEngine.ts embeds `onerror="fetch(...)"` as XSS PAYLOAD CONTENT
  // injected into the target page, not a call this process makes itself;
  // that line carries a `// scope-egress-ignore: <reason>` comment instead
  // of relying on a quote-counting heuristic, which proved unreliable).
  const lines = content.split("\n");
  let suppressNext = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.includes("scope-egress-ignore")) {
      suppressNext = true;
      continue;
    }
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    if (!/(?<!\.)\bfetch\s*\(/.test(line)) { suppressNext = false; continue; }
    if (suppressNext) { suppressNext = false; continue; }
    return true;
  }
  return false;
}

function checkHttpModule(content: string): boolean {
  if (!HTTP_MODULE_IMPORT_PATTERN.test(content)) return false;
  const m = content.match(HTTP_MODULE_IMPORT_PATTERN);
  if (!m) return false;
  const alias = m[1]; // the imported binding, e.g. `http` or `https`
  const aliasCallPattern = new RegExp(`\\b${alias}\\.(request|get)\\s*\\(`);
  return aliasCallPattern.test(content);
}

// Browser-native egress chokepoint (installScopeRoute, see scoped-browser-route.ts).
// Covers every way a Playwright context/page gets created — not just the two forms
// this project happened to use first. `chromium.launchPersistentContext()` in
// particular creates a context with NO separate `newContext()` call, so a guard
// that only looked for `newContext`/`newPage` would miss it entirely; enumerated
// and included here on that basis even though nothing in this codebase currently
// calls it.
const PLAYWRIGHT_IMPORT_PATTERN = /from\s+["']playwright(?:-core)?["']/;
const PLAYWRIGHT_CONTEXT_PATTERN =
  /\b(?:chromium|firefox|webkit)\.launch(?:PersistentContext)?\s*\(|\.newContext\s*\(|\.newPage\s*\(/;
const INSTALL_SCOPE_ROUTE_PATTERN = /\binstallScopeRoute\s*\(/;

function checkPlaywrightContextUnguarded(content: string): boolean {
  if (!PLAYWRIGHT_IMPORT_PATTERN.test(content)) return false;
  if (!PLAYWRIGHT_CONTEXT_PATTERN.test(content)) return false;
  return !INSTALL_SCOPE_ROUTE_PATTERN.test(content);
}

function main(): void {
  const violations: Array<{ file: string; reason: string }> = [];

  for (const absPath of walk(SRC_ROOT)) {
    const relPath = relative(SRC_ROOT, absPath).replace(/\\/g, "/");
    if (relPath in ALLOWLIST) continue;

    const content = readFileSync(absPath, "utf-8");

    const hasAxiosImport = AXIOS_IMPORT_PATTERN.test(content);
    const hasAxiosCall = AXIOS_PATTERN.test(content);
    const hasFetch = checkFetch(content);
    const hasOtherClientImport = OTHER_CLIENT_IMPORT_PATTERN.test(content);
    const hasHttpModuleDispatch = checkHttpModule(content);

    if (hasAxiosImport || hasAxiosCall) {
      violations.push({ file: relPath, reason: "imports/calls axios directly — use scopedHttp" });
    }
    if (hasFetch) {
      violations.push({ file: relPath, reason: "calls global fetch() directly — use scopedHttp" });
    }
    if (hasOtherClientImport) {
      violations.push({ file: relPath, reason: "imports got/undici/node-fetch/ws directly — use scopedHttp (or ScopeGuard inline if no axios-based wrapper applies)" });
    }
    if (hasHttpModuleDispatch) {
      violations.push({ file: relPath, reason: "dispatches a request via raw http/https .request()/.get() — use scopedHttp, or call ScopeGuard.isInScope() inline if no axios-based wrapper applies (see websocket-probe.ts)" });
    }

    if (checkPlaywrightContextUnguarded(content)) {
      violations.push({ file: relPath, reason: "creates a Playwright context/page (chromium.launch/launchPersistentContext/newContext/newPage) with no installScopeRoute() call anywhere in the file — see scoped-browser-route.ts" });
    }
  }

  if (violations.length > 0) {
    console.error("\n[check-scope-egress] FAILED — raw HTTP client usage found outside the scoped-http allowlist:\n");
    for (const v of violations) {
      console.error(`  src/${v.file}\n    ${v.reason}`);
    }
    console.error(
      "\nEvery target-facing request must go through scopedHttp (server/src/lib/net/scoped-http.ts), " +
      "or call ScopeGuard.isInScope() inline when no axios-based wrapper applies (e.g. an HTTP Upgrade " +
      "handshake), so scope containment stays structural, not a convention. If this file genuinely never " +
      "talks to the hunted target, add it to the ALLOWLIST in scripts/check-scope-egress.ts with a " +
      "one-line justification — do not silently ignore this.\n"
    );
    process.exit(1);
  }

  console.log(`[check-scope-egress] OK — no raw HTTP client usage outside the allowlist (${Object.keys(ALLOWLIST).length} files allowlisted).`);
}

main();

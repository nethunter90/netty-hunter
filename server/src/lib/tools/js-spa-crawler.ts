/**
 * JS/SPA Crawler — extracts hidden API endpoints from network requests
 * and JS bundle content using Playwright (headless Chromium) with a
 * regex-based axios fallback when Playwright is unavailable.
 *
 * Visual Tagging: injects a lightweight DOM/XHR/cookie observer into every
 * crawled page via addInitScript. Events are serialised as compact text tags
 * (e.g. [DIALOG:alert:"XSS"] [XHR:POST:/api:401] [+div:class=error:"SQL"])
 * and returned alongside endpoints so the model can reason about them
 * without ever seeing a pixel.
 */
import axios from "axios";
import logger from "../../utils/logger";

// ---------------------------------------------------------------------------
// Public interfaces
// ---------------------------------------------------------------------------

export interface DiscoveredEndpoint {
  url: string;
  method: string;
  source: "network" | "js_parse" | "dom";
  apiPath: string;
  hasParams: boolean;
  contentType?: string;
}

export interface SPACrawlResult {
  endpointsFound: DiscoveredEndpoint[];
  jsFilesScanned: number;
  visualTags: string[];          // compact security-event tags from the browser observer
  hypotheses: Array<{
    vulnClass: string;
    reasoning: string;
    targetUrl: string;
    reasoning2?: string;
    confidence: number;
    priority: number;
  }>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function extractPath(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    return u.pathname + (u.search || "");
  } catch {
    return rawUrl;
  }
}

function isAssetPath(path: string): boolean {
  return /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)/i.test(path);
}

function deduplicateEndpoints(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const seen = new Set<string>();
  return endpoints.filter(ep => {
    const key = `${ep.method}:${ep.apiPath}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function resolveScriptUrl(src: string, pageUrl: string): string | null {
  if (!src || src.startsWith("data:") || src.startsWith("blob:")) return null;
  try {
    return new URL(src, pageUrl).toString();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

const JS_API_PATTERNS: Array<{ regex: RegExp; groupIndex: number }> = [
  { regex: /['"`](\/api\/[^'"`\s]+)['"`]/g,                                groupIndex: 1 },
  { regex: /fetch\(['"`]([^'"`\s]+)['"`]/g,                                groupIndex: 1 },
  { regex: /axios\.(?:get|post|put|delete|patch)\(['"`]([^'"`\s]+)['"`]/g, groupIndex: 1 },
  { regex: /url:\s*['"`]([^'"`\s]+)['"`]/g,                                groupIndex: 1 },
];

function extractPathsFromJs(source: string): string[] {
  const found: string[] = [];
  for (const { regex, groupIndex } of JS_API_PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      const raw = m[groupIndex];
      if (raw && raw.length > 1 && raw.length < 300) found.push(raw);
    }
  }
  return found;
}

function jsPathsToEndpoints(paths: string[], pageUrl: string): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  for (const raw of paths) {
    if (isAssetPath(raw)) continue;
    const resolved = resolveScriptUrl(raw, pageUrl);
    const url = resolved ?? raw;
    const apiPath = extractPath(url);
    endpoints.push({ url, method: "GET", source: "js_parse", apiPath, hasParams: apiPath.includes("?") || apiPath.includes("{") });
  }
  return endpoints;
}

// ---------------------------------------------------------------------------
// Visual Observer — injected into the browser via addInitScript
// Runs entirely inside the page JS context; no Node.js APIs available.
// Produces compact security-event tags stored in window.__sentinelTags[].
// ---------------------------------------------------------------------------

const VISUAL_OBSERVER_SCRIPT = `
(function () {
  if (window.__sentinelActive) return;
  window.__sentinelActive = true;
  window.__sentinelTags = [];
  var MAX_TAGS = 400;

  function push(tag) {
    if (window.__sentinelTags.length < MAX_TAGS) window.__sentinelTags.push(tag);
  }

  // Serialize a DOM element to a compact tag (runs inside browser)
  function ser(el) {
    if (!el || el.nodeType !== 1) return null;
    var t = el.tagName.toLowerCase();
    if (t === 'script' || t === 'style' || t === 'link') return null;
    var parts = [t];
    var id = el.id; if (id) parts.push('id=' + id.slice(0, 20));
    var cls = el.className; if (cls && typeof cls === 'string') parts.push('class=' + cls.split(' ')[0].slice(0, 20));
    var type = el.getAttribute('type'); if (type) parts.push('type=' + type);
    var name = el.getAttribute('name'); if (name) parts.push('name=' + name.slice(0, 20));
    var hidden = el.getAttribute('hidden');
    if (hidden !== null || type === 'hidden') parts.push('hidden');
    // For inputs: note if value looks static (CSRF token heuristic)
    if (t === 'input' && (type === 'hidden') && el.value && el.value.length > 4) {
      parts.push('value=' + el.value.slice(0, 16));
    }
    var txt = (el.innerText || el.textContent || '').trim().slice(0, 50);
    if (txt && !['input','select','textarea'].includes(t)) parts.push('"' + txt + '"');
    return '[' + parts.join(':') + ']';
  }

  // Snapshot initial cookies
  function snapCookies() {
    var cookies = document.cookie;
    if (!cookies) return;
    cookies.split(';').forEach(function(c) {
      var name = c.trim().split('=')[0];
      // We can't read httponly/secure flags from JS — flag their absence as a signal
      push('[COOKIE:' + name.trim().slice(0, 30) + ':js_readable]');
    });
  }
  try { snapCookies(); } catch(e) {}

  // Snapshot initial forms
  function snapForms() {
    try {
      var forms = document.querySelectorAll('form');
      forms.forEach(function(form) {
        var action = form.getAttribute('action') || '';
        var method = (form.getAttribute('method') || 'GET').toUpperCase();
        push('[FORM:' + method + ':' + action.slice(0, 40) + ']');
        form.querySelectorAll('input,select,textarea').forEach(function(el) {
          var s = ser(el); if (s) push(s);
        });
      });
    } catch(e) {}
  }
  // Run after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', snapForms);
  } else {
    snapForms();
  }

  // MutationObserver — watch for new/removed elements
  try {
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(m) {
        m.addedNodes.forEach(function(n) {
          var s = ser(n); if (s) push('[+' + s.slice(1));
        });
        m.removedNodes.forEach(function(n) {
          var s = ser(n); if (s) push('[-' + s.slice(1));
        });
        // Character data changes (error text swapping in)
        if (m.type === 'characterData' && m.target.nodeValue) {
          var val = m.target.nodeValue.trim().slice(0, 60);
          if (val) push('[TEXT_CHANGE:"' + val + '"]');
        }
      });
    });
    observer.observe(document.documentElement, {
      childList: true, subtree: true, characterData: true
    });
  } catch(e) {}

  // XHR interceptor
  try {
    var _open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      this._sm = method; this._su = url;
      this.addEventListener('load', function() {
        var ct = (this.getResponseHeader('content-type') || '').split(';')[0].trim();
        push('[XHR:' + this._sm + ':' + (this._su + '').slice(0, 60) + ':' + this.status + ':' + ct.slice(0,20) + ']');
      });
      this.addEventListener('error', function() {
        push('[XHR_ERR:' + this._sm + ':' + (this._su + '').slice(0, 60) + ']');
      });
      _open.apply(this, arguments);
    };
  } catch(e) {}

  // Fetch interceptor
  try {
    var _fetch = window.fetch;
    window.fetch = function() {
      var args = arguments;
      var url = (typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '');
      var method = (args[1] && args[1].method) || 'GET';
      return _fetch.apply(this, args).then(function(r) {
        var ct = (r.headers.get('content-type') || '').split(';')[0].trim();
        push('[FETCH:' + method + ':' + url.slice(0, 60) + ':' + r.status + ':' + ct.slice(0,20) + ']');
        return r;
      }, function(err) {
        push('[FETCH_ERR:' + method + ':' + url.slice(0, 60) + ']');
        throw err;
      });
    };
  } catch(e) {}

  // Console error capture
  try {
    var _cerr = console.error;
    console.error = function() {
      var msg = Array.prototype.slice.call(arguments).join(' ').slice(0, 80);
      push('[CONSOLE:error:"' + msg + '"]');
      _cerr.apply(console, arguments);
    };
  } catch(e) {}

  // Unhandled JS errors
  window.addEventListener('error', function(ev) {
    push('[JS_ERR:"' + (ev.message || '').slice(0, 60) + ':' + (ev.filename || '').split('/').pop() + ':' + ev.lineno + '"]');
  });

  // Unhandled promise rejections
  window.addEventListener('unhandledrejection', function(ev) {
    push('[PROMISE_ERR:"' + String(ev.reason || '').slice(0, 60) + '"]');
  });
})();
`;

// ---------------------------------------------------------------------------
// Visual tag → hypothesis mapping
// ---------------------------------------------------------------------------

interface VisualHypothesis {
  vulnClass: string;
  reasoning: string;
  confidence: number;
  priority: number;
}

// SQL error signatures that appear in DOM mutations
const SQL_PATTERNS = [
  /sql\s*syntax/i, /syntax.*near/i, /ORA-\d{5}/i, /mysql_fetch/i,
  /pg_query/i, /unterminated\s+string/i, /unclosed\s+quotation/i,
];

const ERROR_DISCLOSURE_PATTERNS = [
  /stack\s*trace/i, /at\s+[\w.]+\([\w/:.]+\)/,  // stack frames
  /exception\s+in/i, /undefined\s+variable/i,
  /cannot\s+read\s+propert/i,
];

function visualTagsToHypotheses(tags: string[], targetUrl: string): VisualHypothesis[] {
  const hypotheses: VisualHypothesis[] = [];
  const joined = tags.join(" ");

  // XSS — alert/confirm fired (JS actually executed)
  const dialogAlert = tags.find(t => t.startsWith("[DIALOG:alert"));
  if (dialogAlert) {
    hypotheses.push({
      vulnClass: "xss",
      reasoning: `JavaScript alert() fired during crawl — script execution confirmed. Tag: ${dialogAlert}`,
      confidence: 0.92,
      priority: 9,
    });
  }

  // SQL injection — error text appeared in DOM
  const mutationTags = tags.filter(t => t.startsWith("[+") || t.startsWith("[TEXT_CHANGE"));
  for (const tag of mutationTags) {
    if (SQL_PATTERNS.some(p => p.test(tag))) {
      hypotheses.push({
        vulnClass: "sqli",
        reasoning: `SQL error signature surfaced in DOM during crawl. Tag: ${tag}`,
        confidence: 0.75,
        priority: 8,
      });
      break;
    }
  }

  // Error/stack disclosure
  for (const tag of mutationTags) {
    if (ERROR_DISCLOSURE_PATTERNS.some(p => p.test(tag))) {
      hypotheses.push({
        vulnClass: "info_disclosure",
        reasoning: `Stack trace or verbose error appeared in DOM. Tag: ${tag}`,
        confidence: 0.65,
        priority: 6,
      });
      break;
    }
  }

  // Session cookie readable from JS (missing HttpOnly)
  const sessionCookie = tags.find(t => t.includes(":js_readable") && /sess|token|auth|jwt/i.test(t));
  if (sessionCookie) {
    hypotheses.push({
      vulnClass: "xss",
      reasoning: `Session/auth cookie accessible via JS (HttpOnly not set). Tag: ${sessionCookie}`,
      confidence: 0.55,
      priority: 6,
    });
  }

  // Static CSRF token in hidden field
  const csrfTag = tags.find(t => /CSRF|_token|authenticity/i.test(t) && t.includes("value="));
  if (csrfTag) {
    hypotheses.push({
      vulnClass: "csrf",
      reasoning: `Hidden CSRF field with static-looking value observed. Tag: ${csrfTag}`,
      confidence: 0.55,
      priority: 5,
    });
  }

  // API returning 401/403 with JSON — worth probing auth
  const authErrors = tags.filter(t => (t.includes(":401:") || t.includes(":403:")) && t.includes("application/json"));
  if (authErrors.length > 0) {
    hypotheses.push({
      vulnClass: "broken_auth",
      reasoning: `${authErrors.length} JSON endpoint(s) returned 401/403 during crawl — auth bypass surface. Tags: ${authErrors.slice(0, 3).join(" ")}`,
      confidence: 0.50,
      priority: 6,
    });
  }

  // Server errors during crawl
  const serverErrors = tags.filter(t => /:5\d\d:/.test(t));
  if (serverErrors.length >= 2) {
    hypotheses.push({
      vulnClass: "info_disclosure",
      reasoning: `${serverErrors.length} 5xx responses during crawl — potential error handling / stack trace leakage. Tags: ${serverErrors.slice(0, 2).join(" ")}`,
      confidence: 0.45,
      priority: 5,
    });
  }

  // CORS error in console
  if (/Access-Control|CORS/i.test(joined)) {
    hypotheses.push({
      vulnClass: "cors",
      reasoning: `CORS policy violation logged to console during crawl. Raw: ${tags.find(t => /Access-Control|CORS/i.test(t))}`,
      confidence: 0.60,
      priority: 6,
    });
  }

  return hypotheses;
}

// ---------------------------------------------------------------------------
// Hypothesis generation (endpoint-based)
// ---------------------------------------------------------------------------

function generateHypotheses(
  endpoints: DiscoveredEndpoint[],
  targetUrl: string,
  visualHyps: VisualHypothesis[] = []
): SPACrawlResult["hypotheses"] {
  const hypotheses: SPACrawlResult["hypotheses"] = [...visualHyps.map(h => ({ ...h, targetUrl }))];

  const sensitiveEndpoints = endpoints.filter(ep =>
    /\/(admin|internal|debug|private)(\/|$)/i.test(ep.apiPath)
  );
  if (sensitiveEndpoints.length > 0) {
    const sample = sensitiveEndpoints.slice(0, 3).map(e => e.apiPath).join(", ");
    hypotheses.push({
      vulnClass: "misconfig",
      targetUrl,
      reasoning: `SPA crawler found ${sensitiveEndpoints.length} endpoint(s) with sensitive path segments (admin/internal/debug/private): ${sample}. These paths may be exposed without proper access controls.`,
      confidence: 0.7,
      priority: 8,
    });
  }

  const versionedEndpoints = endpoints.filter(ep => /\/api\/v\d+\//i.test(ep.apiPath));
  if (versionedEndpoints.length > 0) {
    const versions = [...new Set(
      versionedEndpoints.map(e => { const m = e.apiPath.match(/\/api\/(v\d+)\//i); return m ? m[1] : ""; }).filter(Boolean)
    )];
    hypotheses.push({
      vulnClass: "idor",
      targetUrl,
      reasoning: `SPA crawler discovered ${versionedEndpoints.length} versioned API endpoint(s) (${versions.join(", ")}). Older API versions may lack access control fixes — test for IDOR by enumerating object IDs across versions.`,
      confidence: 0.55,
      priority: 6,
    });
  }

  if (endpoints.length > 0) {
    hypotheses.push({
      vulnClass: "hidden_endpoints",
      targetUrl,
      reasoning: `SPA crawl surfaced ${endpoints.length} endpoint(s) not visible in a static scan. Hidden endpoints often bypass WAF rules or lack the same hardening as public-facing routes.`,
      confidence: 0.6,
      priority: 7,
    });
  }

  return hypotheses;
}

// ---------------------------------------------------------------------------
// Playwright crawl
// ---------------------------------------------------------------------------

async function playwrightCrawl(
  targetUrl: string,
  authHeaders: Record<string, string>
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number; visualTags: string[] }> {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { chromium } = require("playwright") as typeof import("playwright");

  const endpoints: DiscoveredEndpoint[] = [];
  let jsFilesScanned = 0;
  const dialogTags: string[] = [];

  const crawlWork = async () => {
    const browser = await chromium.launch({ headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    try {
      const context = await browser.newContext({ extraHTTPHeaders: authHeaders });
      const page = await context.newPage();
      await page.setExtraHTTPHeaders(authHeaders);

      // ── Inject visual observer before any page script runs ──────────────
      await page.addInitScript(VISUAL_OBSERVER_SCRIPT);

      // ── Playwright-native dialog handler (alert/confirm/prompt) ─────────
      // Captures the message, auto-dismisses to unblock the crawl
      page.on("dialog", async (dialog) => {
        const tag = `[DIALOG:${dialog.type()}:"${dialog.message().slice(0, 80)}"]`;
        dialogTags.push(tag);
        logger.debug("[JSSPACrawler] Dialog intercepted", { tag });
        await dialog.dismiss().catch(() => {});
      });

      // ── Network request interception ────────────────────────────────────
      page.on("request", (req) => {
        const url = req.url();
        const method = req.method().toUpperCase();
        const resourceType = req.resourceType();
        const headers = req.headers();
        const contentType = headers["content-type"] ?? headers["accept"] ?? undefined;

        const isApiCall =
          url.includes("/api/") ||
          ["POST", "PUT", "DELETE", "PATCH"].includes(method) ||
          (contentType?.includes("application/json") ?? false);

        if (isApiCall || resourceType === "script") {
          const apiPath = extractPath(url);
          if (!isAssetPath(apiPath) || isApiCall) {
            endpoints.push({ url, method, source: "network", apiPath, hasParams: apiPath.includes("?"), contentType });
          }
        }
      });

      // ── Navigate ─────────────────────────────────────────────────────────
      try {
        await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 15000 });
      } catch {
        try {
          await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 10000 });
        } catch { /* best-effort */ }
      }

      // Brief settle so MutationObserver events flush
      await page.waitForTimeout(800).catch(() => {});

      // ── DOM link/form extraction ──────────────────────────────────────────
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const domLinks = await page.$$eval("a[href], form[action]", (els: any[]) =>
          els.map((el: any) => ({ href: el.href || el.action || "", method: el.tagName === "FORM" ? (el.method || "GET").toUpperCase() : "GET" }))
        );
        for (const { href, method } of domLinks) {
          if (!href) continue;
          const apiPath = extractPath(href);
          if (apiPath && !isAssetPath(apiPath)) {
            endpoints.push({ url: href, method, source: "dom", apiPath, hasParams: apiPath.includes("?") });
          }
        }
      } catch (domErr) {
        logger.debug("[JSSPACrawler] DOM extraction failed", { err: String(domErr) });
      }

      // ── Collect visual tags from observer ────────────────────────────────
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const observerTags: string[] = await page.evaluate(() => (globalThis as any).__sentinelTags || []).catch(() => []);

      // ── Fetch & parse script files ────────────────────────────────────────
      try {
        const scriptSrcs = await page.$$eval("script[src]", (els: Element[]) =>
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          els.map(el => (el as any).src as string).filter(Boolean)
        );
        const externalPattern = /^https?:\/\/(?:cdn\.|www\.|static\.|unpkg\.|cdnjs\.|ajax\.googleapis)/i;
        const candidateScripts = scriptSrcs
          .filter(src => !externalPattern.test(src) && !src.includes("node_modules"))
          .slice(0, 10);

        await Promise.allSettled(candidateScripts.map(async (src) => {
          const resolved = resolveScriptUrl(src, targetUrl);
          if (!resolved) return;
          try {
            const resp = await axios.get(resolved, {
              headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...authHeaders },
              timeout: 8000, validateStatus: s => s < 400, responseType: "text", maxRedirects: 2,
            });
            if (typeof resp.data === "string" && resp.data.length < 5_000_000) {
              jsFilesScanned++;
              endpoints.push(...jsPathsToEndpoints(extractPathsFromJs(resp.data), targetUrl));
            }
          } catch { /* non-fatal */ }
        }));
      } catch (scriptErr) {
        logger.debug("[JSSPACrawler] Script extraction failed", { err: String(scriptErr) });
      }

      await context.close();

      // Merge dialog tags (from Playwright handler) with in-page observer tags
      const allTags = [...dialogTags, ...observerTags];
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (crawlWork as any).__tags = allTags;
    } finally {
      await browser.close();
    }
  };

  await Promise.race([
    crawlWork(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("Playwright crawl timed out after 30s")), 30_000)
    ),
  ]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const visualTags: string[] = (crawlWork as any).__tags ?? dialogTags;
  return { endpoints, jsFilesScanned, visualTags };
}

// ---------------------------------------------------------------------------
// Regex fallback crawl
// ---------------------------------------------------------------------------

async function regexFallbackCrawl(
  targetUrl: string,
  authHeaders: Record<string, string>
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number; visualTags: string[] }> {
  const endpoints: DiscoveredEndpoint[] = [];
  let jsFilesScanned = 0;

  let html = "";
  try {
    const resp = await axios.get(targetUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...authHeaders },
      timeout: 10000, validateStatus: s => s < 500, responseType: "text", maxRedirects: 3,
    });
    html = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
  } catch (fetchErr) {
    logger.debug("[JSSPACrawler] Fallback: failed to fetch target page", { err: String(fetchErr) });
    return { endpoints, jsFilesScanned, visualTags: [] };
  }

  const scriptSrcPattern = /<script[^>]+src=['"]([^'"]+)['"]/gi;
  const scriptSrcs: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = scriptSrcPattern.exec(html)) !== null) {
    const src = m[1];
    if (src && !src.includes("node_modules")) scriptSrcs.push(src);
  }

  const externalPattern = /^https?:\/\/(?:cdn\.|www\.|static\.|unpkg\.|cdnjs\.|ajax\.googleapis)/i;
  const candidates = scriptSrcs.filter(src => !externalPattern.test(src)).slice(0, 5);

  await Promise.allSettled(candidates.map(async (src) => {
    const resolved = resolveScriptUrl(src, targetUrl);
    if (!resolved) return;
    try {
      const resp = await axios.get(resolved, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...authHeaders },
        timeout: 8000, validateStatus: s => s < 400, responseType: "text", maxRedirects: 2,
      });
      if (typeof resp.data === "string" && resp.data.length < 5_000_000) {
        jsFilesScanned++;
        endpoints.push(...jsPathsToEndpoints(extractPathsFromJs(resp.data), targetUrl));
      }
    } catch { /* non-fatal */ }
  }));

  const inlinePaths = extractPathsFromJs(html);
  endpoints.push(...jsPathsToEndpoints(inlinePaths, targetUrl));

  return { endpoints, jsFilesScanned, visualTags: [] };
}

// ---------------------------------------------------------------------------
// Deep multi-page BFS crawl
// ---------------------------------------------------------------------------

export interface DeepCrawlResult extends SPACrawlResult {
  pagesVisited: number;
  siteMap: Array<{ url: string; depth: number; linksFound: number }>;
  formsFound: Array<{ url: string; method: string; action: string; fields: string[] }>;
}

async function crawlSinglePage(
  url: string,
  authHeaders: Record<string, string>
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number; visualTags: string[] }> {
  let playwrightAvailable = false;
  try { require.resolve("playwright"); playwrightAvailable = true; } catch { /* */ }

  if (playwrightAvailable) {
    try { return await playwrightCrawl(url, authHeaders); } catch { /* fall through */ }
  }
  return regexFallbackCrawl(url, authHeaders);
}

function normalizeForDedup(urlStr: string): string {
  try { const u = new URL(urlStr); return `${u.origin}${u.pathname}`.replace(/\/$/, ""); } catch { return urlStr; }
}

function isSameOriginNav(href: string, origin: string): boolean {
  try { const u = new URL(href); return u.origin === origin && !isAssetPath(u.pathname); } catch { return false; }
}

export async function deepCrawl(
  targetUrl: string,
  options: { maxDepth?: number; maxPages?: number; authHeaders?: Record<string, string> } = {}
): Promise<DeepCrawlResult> {
  const maxDepth = options.maxDepth ?? 2;
  const maxPages = options.maxPages ?? 20;
  const authHeaders = options.authHeaders ?? {};

  let origin: string;
  try { origin = new URL(targetUrl).origin; }
  catch { return { endpointsFound: [], jsFilesScanned: 0, visualTags: [], hypotheses: [], pagesVisited: 0, siteMap: [], formsFound: [] }; }

  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: targetUrl, depth: 0 }];
  const allEndpoints: DiscoveredEndpoint[] = [];
  const allVisualTags: string[] = [];
  let totalJsScanned = 0;
  const siteMap: DeepCrawlResult["siteMap"] = [];
  const formsFound: DeepCrawlResult["formsFound"] = [];
  const deadline = Date.now() + Math.min(maxPages * 15_000, 120_000);

  while (queue.length > 0 && visited.size < maxPages && Date.now() < deadline) {
    const entry = queue.shift();
    if (!entry) break;
    const { url, depth } = entry;
    const norm = normalizeForDedup(url);
    if (visited.has(norm)) continue;
    visited.add(norm);

    logger.debug("[DeepCrawl] Crawling page", { url, depth });

    try {
      const result = await crawlSinglePage(url, authHeaders);
      allEndpoints.push(...result.endpoints);
      totalJsScanned += result.jsFilesScanned;
      allVisualTags.push(...result.visualTags);

      const navLinks = result.endpoints
        .filter(e => e.source === "dom" && e.method === "GET")
        .map(e => e.url)
        .filter(href => isSameOriginNav(href, origin));

      siteMap.push({ url, depth, linksFound: navLinks.length });

      if (depth < maxDepth) {
        for (const link of navLinks) {
          const normLink = normalizeForDedup(link);
          if (!visited.has(normLink)) queue.push({ url: link, depth: depth + 1 });
        }
      }
    } catch (err) {
      logger.debug("[DeepCrawl] Page crawl failed", { url, err: String(err) });
    }
  }

  const endpointsFound = deduplicateEndpoints(allEndpoints);
  const uniqueTags = [...new Set(allVisualTags)];
  const visualHyps = visualTagsToHypotheses(uniqueTags, targetUrl);
  const hypotheses = generateHypotheses(endpointsFound, targetUrl, visualHyps);

  logger.info("[DeepCrawl] Complete", {
    targetUrl, pagesVisited: visited.size,
    endpointsFound: endpointsFound.length,
    jsFilesScanned: totalJsScanned,
    visualTags: uniqueTags.length,
    visualHypotheses: visualHyps.length,
  });

  return { endpointsFound, jsFilesScanned: totalJsScanned, visualTags: uniqueTags, hypotheses, pagesVisited: visited.size, siteMap, formsFound };
}

// ---------------------------------------------------------------------------
// Main crawler class
// ---------------------------------------------------------------------------

class JSSPACrawler {
  async crawl(targetUrl: string, authHeaders?: Record<string, string>): Promise<SPACrawlResult> {
    const headers = authHeaders ?? {};
    const emptyResult: SPACrawlResult = { endpointsFound: [], jsFilesScanned: 0, visualTags: [], hypotheses: [] };

    let endpoints: DiscoveredEndpoint[] = [];
    let jsFilesScanned = 0;
    let visualTags: string[] = [];
    let usedPlaywright = false;

    let playwrightAvailable = false;
    try { require.resolve("playwright"); playwrightAvailable = true; } catch { playwrightAvailable = false; }

    if (playwrightAvailable) {
      try {
        const result = await playwrightCrawl(targetUrl, headers);
        endpoints = result.endpoints;
        jsFilesScanned = result.jsFilesScanned;
        visualTags = result.visualTags;
        usedPlaywright = true;
        logger.info("[JSSPACrawler] Playwright crawl complete", { targetUrl, endpointsRaw: endpoints.length, jsFilesScanned, visualTags: visualTags.length });
      } catch (pwErr) {
        logger.warn("[JSSPACrawler] Playwright crawl failed, falling back to regex", { targetUrl, err: String(pwErr) });
      }
    }

    if (!usedPlaywright) {
      try {
        const result = await regexFallbackCrawl(targetUrl, headers);
        endpoints = result.endpoints;
        jsFilesScanned = result.jsFilesScanned;
        visualTags = result.visualTags;
        logger.info("[JSSPACrawler] Regex fallback crawl complete", { targetUrl, endpointsRaw: endpoints.length });
      } catch (fallbackErr) {
        logger.error("[JSSPACrawler] Both Playwright and regex fallback failed", { targetUrl, err: String(fallbackErr) });
        return emptyResult;
      }
    }

    const endpointsFound = deduplicateEndpoints(endpoints);
    const uniqueTags = [...new Set(visualTags)];
    const visualHyps = visualTagsToHypotheses(uniqueTags, targetUrl);
    const hypotheses = generateHypotheses(endpointsFound, targetUrl, visualHyps);

    logger.info("[JSSPACrawler] Crawl summary", { targetUrl, endpointsFound: endpointsFound.length, jsFilesScanned, visualTags: uniqueTags.length, hypotheses: hypotheses.length });
    return { endpointsFound, jsFilesScanned, visualTags: uniqueTags, hypotheses };
  }
}

export const jsSPACrawler = new JSSPACrawler();

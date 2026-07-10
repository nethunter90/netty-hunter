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
// Type-only import — erased at compile time, so this doesn't force a runtime
// dependency on playwright for callers using the regex-fallback path (the
// rest of the file already lazy-requires playwright conditionally).
import type { Page } from "playwright";

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

// SPA client-side route paths — a SEPARATE signal from JS_API_PATTERNS above.
// Modern SPAs (React Router, wouter, Vue Router) navigate between "pages" via
// history.pushState triggered by onClick handlers, not real <a href> elements
// pointing at other URLs — the DOM-anchor page-discovery below (isSameOriginNav)
// finds real anchors, but on this class of app the queue it feeds is usually
// starved (pagesVisited stays 1 regardless of maxDepth) because there ARE no
// anchor tags for in-app navigation. Router configs are still bundled as
// string literals though (`path: "/wifi"`, `{path:"/settings",...}`), so this
// mines the SAME already-fetched JS source for those instead, and deepCrawl
// below queues them as direct page.goto(origin + route) navigations — most
// SPA routers support deep-linking even with no <a> pointing there.
const SPA_ROUTE_PATTERNS: RegExp[] = [
  /\bpath:\s*["'`](\/[a-zA-Z0-9\/_-]*)["'`]/g,           // route config objects: { path: "/wifi", ... }
  /<Route\s+[^>]*\bpath=["'`](\/[a-zA-Z0-9\/_-]*)["'`]/g, // JSX (survives in dev/unminified bundles)
  /\bcreateRoute\(["'`](\/[a-zA-Z0-9\/_-]*)["'`]/g,       // wouter / TanStack Router style helpers
];

export function extractRoutesFromJs(source: string): string[] {
  const found = new Set<string>();
  for (const regex of SPA_ROUTE_PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      const raw = m[1];
      if (!raw || raw.length < 2 || raw.length > 100) continue;
      if (raw.startsWith("/api/")) continue;        // that's an API path, not a page route
      if (raw.includes(":") || raw.includes("*")) continue; // dynamic segment — nothing concrete to navigate to
      if (isAssetPath(raw)) continue;
      found.add(raw);
    }
  }
  return Array.from(found);
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

  // Per-endpoint hypotheses so the specific discovered URL survives into
  // targetUrl instead of collapsing into one generic hypothesis pointed at
  // the base target. A single bucket hypothesis is addressable at nothing —
  // downstream probing can't test "250 endpoints," only a concrete URL.
  const alreadyCovered = new Set([...sensitiveEndpoints, ...versionedEndpoints].map(e => e.url));
  const remaining = endpoints.filter(ep => !alreadyCovered.has(ep.url));
  if (remaining.length > 0) {
    const INTERESTING = /(wifi|network|monitor|scan|capture|build|deploy|exec|shell|terminal|config|secret|token|key|user|account|upload|file|password|auth|status|health|settings|integration|backend|llm|model|connection)/i;
    const scored = remaining.map(ep => ({ ep, interesting: INTERESTING.test(ep.apiPath) }));
    scored.sort((a, b) => Number(b.interesting) - Number(a.interesting));

    const PER_ENDPOINT_CAP = 20;
    const shown = scored.slice(0, PER_ENDPOINT_CAP);
    for (const { ep, interesting } of shown) {
      hypotheses.push({
        vulnClass: "hidden_endpoints",
        targetUrl: ep.url,
        reasoning: `SPA crawler discovered this endpoint (${ep.apiPath}) via ${ep.source}, not visible in a static scan. Hidden endpoints often bypass WAF rules or lack the same hardening as public-facing routes.`,
        confidence: interesting ? 0.65 : 0.5,
        priority: interesting ? 7 : 5,
      });
    }

    const omitted = remaining.length - shown.length;
    if (omitted > 0) {
      hypotheses.push({
        vulnClass: "hidden_endpoints",
        targetUrl,
        reasoning: `SPA crawl surfaced ${omitted} additional endpoint(s) beyond the ones hypothesized individually above — not all shown due to volume, but still available for future targeting.`,
        confidence: 0.4,
        priority: 3,
      });
    }
  }

  return hypotheses;
}

// ---------------------------------------------------------------------------
// Targeted nav-click pass — interaction-gated panel discovery
// ---------------------------------------------------------------------------

// Covers three distinct real-world shapes: semantic nav/sidebar containers
// (nav/aside/.sidebar — the original, narrower version of this selector),
// PLUS generic icon-toolbar buttons (header/[class*="toolbar"]/[role="toolbar"]
// and any button carrying title/data-testid/aria-label, which in practice
// means "a labeled, intentional control" as opposed to an arbitrary anonymous
// element). The toolbar half was added after finding that a real target app's
// panel-switching buttons (setLayout('wifi'), setLayout('vm'), etc.) are
// plain icon buttons in a custom toolbar, not inside any nav/sidebar
// container at all — the original nav-only selector silently never saw them.
// Safety is NOT this selector's job — it's the label-based filter below;
// widening scope here is fine precisely because that filter is independent
// of where an element sits in the DOM.
const NAV_CLICK_SELECTOR =
  'nav a, nav button, [role="navigation"] a, [role="navigation"] button, ' +
  'aside a, aside button, .sidebar a, .sidebar button, ' +
  '[class*="nav-item"], [class*="menu-item"], [class*="sidebar"] a, [class*="sidebar"] button, ' +
  'header button, [class*="toolbar"] button, [role="toolbar"] button, ' +
  'button[title], button[data-testid], button[aria-label]';

// Text-based safety net — the ACTUAL safety mechanism, independent of where
// an element sits in the DOM. Never click anything whose label reads as an
// action rather than a destination/view. Deliberately checks the label
// pulled from innerText/title/aria-label/data-testid (see candidate
// extraction below) — icon-only buttons (lucide-react icons with no visible
// text) still carry a title like "WiFi Dashboard", and skipping unlabeled
// icon buttons entirely would silently exclude exactly the panels this pass
// exists to find.
export const DESTRUCTIVE_VERB_PATTERN =
  /\b(start|stop|scan|attack|deauth|capture|execute|run|build|deploy|send|delete|remove|kill|restart|monitor|inject|launch|fire|exploit)\b/i;

const MAX_NAV_CLICKS = 25;

/**
 * Clicks candidate navigation/toolbar elements one at a time. Two outcomes
 * are captured: (a) the URL changed (client-side routing fired) — queued as
 * a discovered route via the same `routes` set the bundle-extraction path
 * feeds; (b) the URL did NOT change (a pure client-state panel switch, e.g.
 * setLayout('wifi')) — nothing is queued here, but the click itself is left
 * to trigger whatever network requests that panel makes on mount, which the
 * existing page.on("request", ...) listener in the caller already captures
 * as new `endpoints` regardless of URL. That's how a panel like "wifi" gets
 * discovered even with zero route change: not through this function's
 * return value, but as a side effect of the click during this same page load.
 *
 * @param deadline Absolute timestamp (Date.now()-scale) this pass must stop
 *   by. 2026-07-04: this used to be an independent fixed budget (35s) LARGER
 *   than playwrightCrawl's own outer 30s hard ceiling — self-inconsistent by
 *   construction, so it could never fully run in isolation, and under real
 *   hunt-load (navigation/DOM-extraction slower due to concurrent nuclei/
 *   nikto/etc. probing the same target) it got cut off by the outer race
 *   before reaching later candidates (confirmed: an isolated run consistently
 *   found the wifi toolbar button — roughly the 9th candidate — while the
 *   same code inside a live hunt found nothing wifi-related at all). Now
 *   takes the caller's actual remaining time instead of guessing its own.
 */
async function runNavClickPass(page: Page, targetUrl: string, routes: Set<string>, deadline: number): Promise<void> {
  const candidateLabels = await page.$$eval(
    NAV_CLICK_SELECTOR,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (els: any[]) => els.map((el: any) =>
      (el.innerText || el.textContent || el.getAttribute("title") || el.getAttribute("aria-label") ||
       el.getAttribute("data-testid") || "").trim().slice(0, 60)
    )
  ).catch(() => [] as string[]);

  const safeIndexes: number[] = [];
  for (let i = 0; i < candidateLabels.length && safeIndexes.length < MAX_NAV_CLICKS; i++) {
    const label = candidateLabels[i];
    // Unlike before, an EMPTY label is no longer treated as unsafe-by-default
    // — a control this app itself tags with data-testid/title but whose
    // extraction still came up blank is still worth trying, since the
    // destructive-verb check has nothing to match against either way, and
    // most of this selector's matches now come from labeled elements anyway.
    if (DESTRUCTIVE_VERB_PATTERN.test(label)) continue;
    safeIndexes.push(i);
  }

  for (const idx of safeIndexes) {
    if (Date.now() > deadline) break;
    try {
      // Re-query fresh each iteration — navigating back below invalidates any
      // element handles captured before the reset.
      const els = await page.$$(NAV_CLICK_SELECTOR);
      const el = els[idx];
      if (!el) continue;

      const beforePath = new URL(page.url()).pathname;
      await el.click({ timeout: 3000 });
      await page.waitForTimeout(500).catch(() => {});
      const afterPath = new URL(page.url()).pathname;

      if (afterPath !== beforePath && afterPath.startsWith("/") && !isAssetPath(afterPath)) {
        routes.add(afterPath);
        logger.debug("[JSSPACrawler] Nav-click discovered a route", { label: candidateLabels[idx], path: afterPath });
      }

      // Reset to a known state before the next candidate so clicks don't compound.
      await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 8000 });
    } catch {
      // One candidate failing (detached element, click intercepted, nav
      // timeout) must not abort the rest of the pass.
    }
  }
}

// ---------------------------------------------------------------------------
// Playwright crawl
// ---------------------------------------------------------------------------

// Raised from 30s: the crawl now does more work per page than when this
// ceiling was first set (nav-click pass + scanning up to 40 script files),
// and 30s was already tight for navigation + DOM extraction alone once a
// real hunt's concurrent nuclei/nikto/etc. probing slows everything down.
const CRAWL_HARD_TIMEOUT_MS = 45_000;
// Time carved out of the shared deadline for the script-fetch step that runs
// AFTER the nav-click pass — prevents nav-click from starving it outright.
const SCRIPT_FETCH_RESERVE_MS = 12_000;

async function playwrightCrawl(
  targetUrl: string,
  authHeaders: Record<string, string>
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number; visualTags: string[]; routes: string[] }> {
  const crawlDeadline = Date.now() + CRAWL_HARD_TIMEOUT_MS;
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { chromium } = require("playwright") as typeof import("playwright");

  const endpoints: DiscoveredEndpoint[] = [];
  let jsFilesScanned = 0;
  const dialogTags: string[] = [];
  const routes = new Set<string>();

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
      // networkScriptUrls captures every ACTUAL script request the page makes
      // at runtime — critically including Vite/ESM dev-server route-level code
      // splitting (dynamic `import()` fetches), which never appear as <script
      // src> DOM elements (those are only the entry chunk(s)). The static DOM
      // query below sees maybe 1-2 files; this sees everything the browser
      // really loaded, which is where a lazily-loaded feature panel's route
      // table and API calls actually live.
      const networkScriptUrls = new Set<string>();
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
        if (resourceType === "script") networkScriptUrls.add(url);
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

      // ── Targeted nav-click pass ─────────────────────────────────────────
      // Panels that switch purely via client-side state (no <a href>, and no
      // route string literal survives bundling/minification either) are
      // invisible to every discovery method above. This clicks ONLY elements
      // that look like navigation (inside a nav/sidebar/menu container),
      // never arbitrary action buttons — explicitly excluding anything whose
      // visible text matches a destructive-action verb, since this app's own
      // feature surface includes real attack tooling (wifi deauth, build
      // agents with unrestricted shell access) that must never be triggered
      // by exploration. A click that doesn't change the URL is silently
      // skipped (no route to queue) — that's a known limitation of this pass,
      // not a failure: pure-client-state panel switches need a different,
      // heavier technique (diff the DOM/observation set per click) to catch.
      try {
        // Reserve SCRIPT_FETCH_RESERVE_MS of the shared crawl deadline for the
        // script-fetch step that runs AFTER this one (below) — without this,
        // nav-click could legitimately consume the entire remaining budget on
        // its own and starve script-fetch of any time at all, trading one
        // discovery mechanism's reliability for the other's instead of fixing
        // the actual bug (an independent budget bigger than the shared ceiling).
        const navClickDeadline = crawlDeadline - SCRIPT_FETCH_RESERVE_MS;
        await runNavClickPass(page, targetUrl, routes, navClickDeadline);
      } catch (navErr) {
        logger.debug("[JSSPACrawler] Nav-click pass failed", { err: String(navErr) });
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
        // Merge the static DOM query with everything the browser ACTUALLY
        // fetched as a script over the network (networkScriptUrls) — the DOM
        // query alone only sees the entry chunk(s); Vite/ESM dev servers load
        // most application code (including route tables and lazily-loaded
        // feature panels) via runtime `import()` that never appears as a
        // <script src> element. Higher cap than before (10→40) since a real
        // ESM dev server serves many small per-module files, not one bundle.
        const candidateScripts = Array.from(new Set([...scriptSrcs, ...networkScriptUrls]))
          .filter(src => !externalPattern.test(src) && !src.includes("node_modules"))
          .slice(0, 40);

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
              for (const r of extractRoutesFromJs(resp.data)) routes.add(r);
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
      setTimeout(() => reject(new Error(`Playwright crawl timed out after ${CRAWL_HARD_TIMEOUT_MS / 1000}s`)), CRAWL_HARD_TIMEOUT_MS)
    ),
  ]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const visualTags: string[] = (crawlWork as any).__tags ?? dialogTags;
  return { endpoints, jsFilesScanned, visualTags, routes: Array.from(routes) };
}

// ---------------------------------------------------------------------------
// Regex fallback crawl
// ---------------------------------------------------------------------------

async function regexFallbackCrawl(
  targetUrl: string,
  authHeaders: Record<string, string>
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number; visualTags: string[]; routes: string[] }> {
  const endpoints: DiscoveredEndpoint[] = [];
  let jsFilesScanned = 0;
  const routes = new Set<string>();

  let html = "";
  try {
    const resp = await axios.get(targetUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...authHeaders },
      timeout: 10000, validateStatus: s => s < 500, responseType: "text", maxRedirects: 3,
    });
    html = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
  } catch (fetchErr) {
    logger.debug("[JSSPACrawler] Fallback: failed to fetch target page", { err: String(fetchErr) });
    return { endpoints, jsFilesScanned, visualTags: [], routes: [] };
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
        for (const r of extractRoutesFromJs(resp.data)) routes.add(r);
      }
    } catch { /* non-fatal */ }
  }));

  const inlinePaths = extractPathsFromJs(html);
  endpoints.push(...jsPathsToEndpoints(inlinePaths, targetUrl));
  for (const r of extractRoutesFromJs(html)) routes.add(r);

  return { endpoints, jsFilesScanned, visualTags: [], routes: Array.from(routes) };
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
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number; visualTags: string[]; routes: string[] }> {
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

      // SPA client-side routes mined from the bundle (see extractRoutesFromJs) —
      // navigate to them directly via page.goto(origin + route). This is what
      // actually gets the crawler past pagesVisited:1 on apps that route via
      // history.pushState instead of real <a href> elements: those apps have
      // NO anchor tags for navLinks to ever find, no matter how deep maxDepth
      // goes, so without this queue the BFS starves after the landing page.
      const routeLinks = result.routes.map(r => `${origin}${r}`);

      siteMap.push({ url, depth, linksFound: navLinks.length + routeLinks.length });

      if (depth < maxDepth) {
        for (const link of [...navLinks, ...routeLinks]) {
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
    // pagesVisited staying at 1 despite maxDepth>1 means the SPA-route queue
    // (below) also found nothing to navigate to — the real signal that this
    // fix needs to work is pagesVisited > 1 on a client-side-routed app.
    siteMapEntries: siteMap.length,
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

/**
 * JS/SPA Crawler — extracts hidden API endpoints from network requests
 * and JS bundle content using Playwright (headless Chromium) with a
 * regex-based axios fallback when Playwright is unavailable.
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

/** Extract the path (+ query string) from a full URL, falling back to the raw string. */
function extractPath(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    return u.pathname + (u.search || "");
  } catch {
    // Relative URL or non-standard string — return as-is
    return rawUrl;
  }
}

/** True when the path looks like it belongs to a JS/CSS/image asset — not an API call. */
function isAssetPath(path: string): boolean {
  return /\.(js|css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(\?|$)/i.test(path);
}

/** Deduplicate endpoints by (method + apiPath). */
function deduplicateEndpoints(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const seen = new Set<string>();
  return endpoints.filter(ep => {
    const key = `${ep.method}:${ep.apiPath}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Resolve a potentially relative script src against the page origin so we can
 * fetch it later.
 */
function resolveScriptUrl(src: string, pageUrl: string): string | null {
  if (!src || src.startsWith("data:") || src.startsWith("blob:")) return null;
  try {
    return new URL(src, pageUrl).toString();
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Regex patterns used by the fallback (and by the Playwright JS-parse step)
// ---------------------------------------------------------------------------

const JS_API_PATTERNS: Array<{ regex: RegExp; groupIndex: number }> = [
  { regex: /['"`](\/api\/[^'"`\s]+)['"`]/g,                                          groupIndex: 1 },
  { regex: /fetch\(['"`]([^'"`\s]+)['"`]/g,                                          groupIndex: 1 },
  { regex: /axios\.(?:get|post|put|delete|patch)\(['"`]([^'"`\s]+)['"`]/g,           groupIndex: 1 },
  { regex: /url:\s*['"`]([^'"`\s]+)['"`]/g,                                          groupIndex: 1 },
];

/** Run all regex patterns against a JS source string and return raw matched strings. */
function extractPathsFromJs(source: string): string[] {
  const found: string[] = [];
  for (const { regex, groupIndex } of JS_API_PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(source)) !== null) {
      const raw = m[groupIndex];
      if (raw && raw.length > 1 && raw.length < 300) {
        found.push(raw);
      }
    }
  }
  return found;
}

/** Convert raw strings extracted from JS into DiscoveredEndpoint objects. */
function jsPathsToEndpoints(paths: string[], pageUrl: string): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  for (const raw of paths) {
    // Skip obvious non-API strings
    if (isAssetPath(raw)) continue;
    const resolved = resolveScriptUrl(raw, pageUrl);
    const url = resolved ?? raw;
    const apiPath = extractPath(url);
    endpoints.push({
      url,
      method: "GET",
      source: "js_parse",
      apiPath,
      hasParams: apiPath.includes("?") || apiPath.includes("{"),
    });
  }
  return endpoints;
}

// ---------------------------------------------------------------------------
// Hypothesis generation
// ---------------------------------------------------------------------------

function generateHypotheses(
  endpoints: DiscoveredEndpoint[],
  targetUrl: string
): SPACrawlResult["hypotheses"] {
  const hypotheses: SPACrawlResult["hypotheses"] = [];

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

  const versionedEndpoints = endpoints.filter(ep =>
    /\/api\/v\d+\//i.test(ep.apiPath)
  );
  if (versionedEndpoints.length > 0) {
    const versions = [...new Set(
      versionedEndpoints.map(e => {
        const m = e.apiPath.match(/\/api\/(v\d+)\//i);
        return m ? m[1] : "";
      }).filter(Boolean)
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
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number }> {
  // Dynamic import guarded by require.resolve so we don't hard-fail if
  // playwright is missing from the current node_modules.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { chromium } = require("playwright") as typeof import("playwright");

  const endpoints: DiscoveredEndpoint[] = [];
  let jsFilesScanned = 0;

  const crawlWork = async () => {
    const browser = await chromium.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    try {
      const context = await browser.newContext({
        extraHTTPHeaders: authHeaders,
      });
      const page = await context.newPage();
      await page.setExtraHTTPHeaders(authHeaders);

      // ---------- Network request interception ----------
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

        const isScript = resourceType === "script";

        if (isApiCall || isScript) {
          const apiPath = extractPath(url);
          if (!isAssetPath(apiPath) || isApiCall) {
            endpoints.push({
              url,
              method,
              source: "network",
              apiPath,
              hasParams: apiPath.includes("?"),
              contentType,
            });
          }
        }
      });

      // ---------- Navigate ----------
      try {
        await page.goto(targetUrl, { waitUntil: "networkidle", timeout: 15000 });
      } catch (navErr) {
        // networkidle can time-out on aggressive SPAs; try domcontentloaded instead
        logger.debug("[JSSPACrawler] networkidle timed out, retrying with domcontentloaded", {
          err: String(navErr),
        });
        try {
          await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: 10000 });
        } catch {
          // best-effort; continue with what we have
        }
      }

      // ---------- DOM extraction ----------
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const domLinks = await page.$$eval(
          "a[href], form[action]",
          (els: any[]) =>
            els.map((el: any) => ({
              href: el.href || el.action || "",
              method:
                el.tagName === "FORM"
                  ? (el.method || "GET").toUpperCase()
                  : "GET",
            }))
        );

        for (const { href, method } of domLinks) {
          if (!href) continue;
          const apiPath = extractPath(href);
          if (apiPath && !isAssetPath(apiPath)) {
            endpoints.push({
              url: href,
              method,
              source: "dom",
              apiPath,
              hasParams: apiPath.includes("?"),
            });
          }
        }
      } catch (domErr) {
        logger.debug("[JSSPACrawler] DOM extraction failed", { err: String(domErr) });
      }

      // ---------- Fetch & parse script files ----------
      try {
        const scriptSrcs = await page.$$eval("script[src]", (els: Element[]) =>
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          els.map(el => (el as any).src as string).filter(Boolean)
        );

        const externalPattern = /^https?:\/\/(?:cdn\.|www\.|static\.|unpkg\.|cdnjs\.|ajax\.googleapis)/i;
        const candidateScripts = scriptSrcs
          .filter(src => !externalPattern.test(src) && !src.includes("node_modules"))
          .slice(0, 10); // cap at 10 to stay fast

        await Promise.allSettled(
          candidateScripts.map(async (src) => {
            const resolved = resolveScriptUrl(src, targetUrl);
            if (!resolved) return;
            try {
              const resp = await axios.get(resolved, {
                headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...authHeaders },
                timeout: 8000,
                validateStatus: s => s < 400,
                responseType: "text",
                maxRedirects: 2,
              });
              if (typeof resp.data === "string" && resp.data.length < 5_000_000) {
                jsFilesScanned++;
                const paths = extractPathsFromJs(resp.data);
                endpoints.push(...jsPathsToEndpoints(paths, targetUrl));
              }
            } catch {
              // individual script fetch failure is non-fatal
            }
          })
        );
      } catch (scriptErr) {
        logger.debug("[JSSPACrawler] Script extraction failed", { err: String(scriptErr) });
      }

      await context.close();
    } finally {
      await browser.close();
    }
  };

  // Hard 30-second wall-clock limit for the whole Playwright session
  await Promise.race([
    crawlWork(),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error("Playwright crawl timed out after 30s")), 30_000)
    ),
  ]);

  return { endpoints, jsFilesScanned };
}

// ---------------------------------------------------------------------------
// Regex fallback crawl
// ---------------------------------------------------------------------------

async function regexFallbackCrawl(
  targetUrl: string,
  authHeaders: Record<string, string>
): Promise<{ endpoints: DiscoveredEndpoint[]; jsFilesScanned: number }> {
  const endpoints: DiscoveredEndpoint[] = [];
  let jsFilesScanned = 0;

  // 1. Fetch the target page HTML
  let html = "";
  try {
    const resp = await axios.get(targetUrl, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...authHeaders },
      timeout: 10000,
      validateStatus: s => s < 500,
      responseType: "text",
      maxRedirects: 3,
    });
    html = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
  } catch (fetchErr) {
    logger.debug("[JSSPACrawler] Fallback: failed to fetch target page", { err: String(fetchErr) });
    return { endpoints, jsFilesScanned };
  }

  // 2. Find script src attributes
  const scriptSrcPattern = /<script[^>]+src=['"]([^'"]+)['"]/gi;
  const scriptSrcs: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = scriptSrcPattern.exec(html)) !== null) {
    const src = m[1];
    if (src && !src.includes("node_modules")) {
      scriptSrcs.push(src);
    }
  }

  // 3. Fetch and parse up to 5 script files (skip CDN/external)
  const externalPattern = /^https?:\/\/(?:cdn\.|www\.|static\.|unpkg\.|cdnjs\.|ajax\.googleapis)/i;
  const candidates = scriptSrcs
    .filter(src => !externalPattern.test(src))
    .slice(0, 5);

  await Promise.allSettled(
    candidates.map(async (src) => {
      const resolved = resolveScriptUrl(src, targetUrl);
      if (!resolved) return;
      try {
        const resp = await axios.get(resolved, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...authHeaders },
          timeout: 8000,
          validateStatus: s => s < 400,
          responseType: "text",
          maxRedirects: 2,
        });
        if (typeof resp.data === "string" && resp.data.length < 5_000_000) {
          jsFilesScanned++;
          const paths = extractPathsFromJs(resp.data);
          endpoints.push(...jsPathsToEndpoints(paths, targetUrl));
        }
      } catch {
        // individual script fetch failure is non-fatal
      }
    })
  );

  // 4. Also scan the HTML itself for inline API references
  const inlinePaths = extractPathsFromJs(html);
  endpoints.push(...jsPathsToEndpoints(inlinePaths, targetUrl));

  return { endpoints, jsFilesScanned };
}

// ---------------------------------------------------------------------------
// Main crawler class
// ---------------------------------------------------------------------------

class JSSPACrawler {
  async crawl(
    targetUrl: string,
    authHeaders?: Record<string, string>
  ): Promise<SPACrawlResult> {
    const headers = authHeaders ?? {};
    const emptyResult: SPACrawlResult = {
      endpointsFound: [],
      jsFilesScanned: 0,
      hypotheses: [],
    };

    let endpoints: DiscoveredEndpoint[] = [];
    let jsFilesScanned = 0;
    let usedPlaywright = false;

    // --- Try Playwright first ---
    let playwrightAvailable = false;
    try {
      require.resolve("playwright");
      playwrightAvailable = true;
    } catch {
      playwrightAvailable = false;
    }

    if (playwrightAvailable) {
      try {
        const result = await playwrightCrawl(targetUrl, headers);
        endpoints = result.endpoints;
        jsFilesScanned = result.jsFilesScanned;
        usedPlaywright = true;
        logger.info("[JSSPACrawler] Playwright crawl complete", {
          targetUrl,
          endpointsRaw: endpoints.length,
          jsFilesScanned,
        });
      } catch (pwErr) {
        logger.warn("[JSSPACrawler] Playwright crawl failed, falling back to regex", {
          targetUrl,
          err: String(pwErr),
        });
      }
    }

    // --- Regex fallback if Playwright was unavailable or failed ---
    if (!usedPlaywright) {
      try {
        const result = await regexFallbackCrawl(targetUrl, headers);
        endpoints = result.endpoints;
        jsFilesScanned = result.jsFilesScanned;
        logger.info("[JSSPACrawler] Regex fallback crawl complete", {
          targetUrl,
          endpointsRaw: endpoints.length,
          jsFilesScanned,
        });
      } catch (fallbackErr) {
        logger.error("[JSSPACrawler] Both Playwright and regex fallback failed", {
          targetUrl,
          err: String(fallbackErr),
        });
        return emptyResult;
      }
    }

    // --- Deduplicate and build hypotheses ---
    const endpointsFound = deduplicateEndpoints(endpoints);
    const hypotheses = generateHypotheses(endpointsFound, targetUrl);

    logger.info("[JSSPACrawler] Crawl summary", {
      targetUrl,
      endpointsFound: endpointsFound.length,
      jsFilesScanned,
      hypotheses: hypotheses.length,
    });

    return { endpointsFound, jsFilesScanned, hypotheses };
  }
}

export const jsSPACrawler = new JSSPACrawler();

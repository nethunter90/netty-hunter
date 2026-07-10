/**
 * CSRF-aware HTTP request helper.
 *
 * Double-submit-cookie CSRF schemes (server checks cookie value === header value,
 * with no server-side session lookup) can be defeated by anyone who can complete a
 * same-origin GET to mint a token — no authentication required. A prober that fires
 * a raw POST/PUT/PATCH/DELETE and stops at the first CSRF-shaped 403 never
 * discovers this whole class of finding. This helper detects that shape, discovers
 * a token-issuing endpoint, mints a token, and retries once with it replayed as
 * both cookie and header — before falling back to the original rejection.
 */
import axios, { AxiosRequestConfig, Method } from "axios";

const CANDIDATE_TOKEN_PATHS = [
  "/api/csrf-token", "/api/csrf_token", "/api/csrf", "/csrf-token", "/csrf",
  "/api/auth/csrf", "/api/auth/csrf-token", "/api/xsrf-token",
];

const TOKEN_BODY_FIELDS = ["csrfToken", "csrf_token", "token", "_csrf", "xsrfToken"];
const TOKEN_HEADER_NAMES = ["x-csrf-token", "csrf-token", "x-xsrf-token"];

interface CsrfContext {
  cookieName: string;
  cookieValue: string;
  headerNames: string[];
}

// origin -> discovered token context (or null once discovery has been tried and
// failed), cached so repeated calls within a hunt don't re-probe candidate paths
// on every single state-changing request.
const originCache = new Map<string, CsrfContext | null>();

function looksLikeCsrfRejection(status: number, body: unknown): boolean {
  if (status !== 403 && status !== 419) return false;
  const text = typeof body === "string" ? body : JSON.stringify(body ?? "");
  return /csrf/i.test(text);
}

function extractSetCookies(setCookieHeader: string[] | string | undefined): { name: string; value: string }[] {
  const raw = Array.isArray(setCookieHeader) ? setCookieHeader : setCookieHeader ? [setCookieHeader] : [];
  return raw
    .map((c) => {
      const pair = c.split(";")[0];
      const eq = pair.indexOf("=");
      return eq === -1 ? null : { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim() };
    })
    .filter((x): x is { name: string; value: string } => x !== null);
}

async function discoverCsrfContext(
  origin: string,
  existingHeaders?: Record<string, string>
): Promise<CsrfContext | null> {
  for (const path of CANDIDATE_TOKEN_PATHS) {
    try {
      const resp = await axios.get(origin + path, {
        timeout: 5000,
        validateStatus: () => true,
        headers: existingHeaders,
      });
      if (resp.status >= 400) continue;

      const cookies = extractSetCookies(resp.headers["set-cookie"] as string[] | string | undefined);
      const csrfCookie = cookies.find((c) => /csrf|xsrf/i.test(c.name));
      if (!csrfCookie) continue;

      let bodyToken: string | undefined;
      const data = resp.data;
      if (data && typeof data === "object") {
        for (const field of TOKEN_BODY_FIELDS) {
          const val = (data as Record<string, unknown>)[field];
          if (typeof val === "string" && val.length > 0) {
            bodyToken = val;
            break;
          }
        }
      }
      // Double-submit only requires cookie value === header value — the cookie
      // itself IS the token even when the body never echoes it back explicitly.
      const tokenValue = bodyToken || csrfCookie.value;

      return { cookieName: csrfCookie.name, cookieValue: tokenValue, headerNames: TOKEN_HEADER_NAMES };
    } catch {
      // try the next candidate path
    }
  }
  return null;
}

export interface CsrfAwareResult {
  status: number;
  data: unknown;
  headers: Record<string, unknown>;
  /** True when the initial request was CSRF-rejected and this result reflects a
   *  retry with a self-minted token — callers should treat this as a stronger
   *  signal (the endpoint is reachable with zero real authentication). */
  csrfBypassUsed: boolean;
}

/**
 * Fires the request as-is first — most targets need nothing extra, so this never
 * adds latency to requests that don't hit CSRF protection. Only when the response
 * looks like a CSRF-shaped rejection does it discover and mint a token, then retry
 * once with it replayed as both cookie and header (several common header-name
 * conventions are set simultaneously; extras are harmless and maximize the chance
 * of matching whichever one the target actually checks).
 */
export async function csrfAwareRequest(
  url: string,
  method: Method,
  body: unknown,
  headers?: Record<string, string>,
  timeout = 8000
): Promise<CsrfAwareResult> {
  const config: AxiosRequestConfig = { method, url, data: body, timeout, validateStatus: () => true, headers };
  const first = await axios.request(config);
  if (!looksLikeCsrfRejection(first.status, first.data)) {
    return { status: first.status, data: first.data, headers: first.headers as Record<string, unknown>, csrfBypassUsed: false };
  }

  const origin = new URL(url).origin;
  const extra = await getCsrfHeaders(origin, headers);
  if (Object.keys(extra).length === 0) {
    return { status: first.status, data: first.data, headers: first.headers as Record<string, unknown>, csrfBypassUsed: false };
  }

  const retry = await axios.request({ ...config, headers: { ...headers, ...extra } });
  return { status: retry.status, data: retry.data, headers: retry.headers as Record<string, unknown>, csrfBypassUsed: true };
}

/**
 * Discovers (or reuses the cached) CSRF context for an origin and returns the
 * extra Cookie/header entries a caller should merge into its own request config
 * up front. For callers that need many requests to fire with true concurrency —
 * e.g. a race-condition burst — doing discovery inline per-request (as
 * csrfAwareRequest does) would stagger the burst's timing. Call this once to warm
 * the cache before building the concurrent batch instead.
 */
export async function getCsrfHeaders(
  origin: string,
  existingHeaders?: Record<string, string>
): Promise<Record<string, string>> {
  let ctx: CsrfContext | null;
  if (originCache.has(origin)) {
    ctx = originCache.get(origin)!;
  } else {
    ctx = await discoverCsrfContext(origin, existingHeaders);
    originCache.set(origin, ctx);
  }
  if (!ctx) return {};

  const cookiePair = `${ctx.cookieName}=${ctx.cookieValue}`;
  const extra: Record<string, string> = {
    Cookie: existingHeaders?.Cookie ? `${existingHeaders.Cookie}; ${cookiePair}` : cookiePair,
  };
  for (const h of ctx.headerNames) extra[h] = ctx.cookieValue;
  return extra;
}

/** Test-only: clear the per-origin discovery cache between runs. */
export function resetCsrfCache(): void {
  originCache.clear();
}

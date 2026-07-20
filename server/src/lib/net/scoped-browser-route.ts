/**
 * Browser-native egress chokepoint — the Playwright equivalent of scopedHttp.
 *
 * scopedHttp guards every Node-side axios/fetch/http(s) call. It cannot guard
 * anything a real browser fetches on its own: page navigations and passive
 * sub-resources (script/img/xhr/fetch/websocket) that Chromium's own network
 * stack dispatches while rendering a page. That gap was proven live in the
 * prior handoff — Chrome fetched an excluded <script src> directly while the
 * app-level re-fetch was correctly blocked by scopedHttp.
 *
 * installScopeRoute() is that second chokepoint: one `route()` handler,
 * installed on the PAGE (not the context — see below), calling the exact
 * same ScopeGuard.isInScope() the HTTP chokepoint uses. Fail-closed on any
 * guard error, identical posture to scopedHttp.
 *
 * Why page-level, not context-level: Playwright's own docs (route() on
 * Page) state plainly — "Page routes take precedence over browser context
 * routes... when request matches both handlers." LogicExploitAgent's
 * offensive `intercept_request` tool installs its route via `page.route()`
 * (mid-probe, on demand). If this scope route were installed at the context
 * level, the page-level offensive route would win outright regardless of
 * registration order — this guard would simply never run for anything the
 * offensive route's pattern matches. Installing at the page level puts both
 * routes in the same precedence tier, where Playwright's documented
 * same-tier ordering applies: the LAST-registered handler runs FIRST, and
 * `route.fallback()` passes control to the next-earlier-registered handler.
 * This guard is installed immediately after `newPage()`, before any
 * navigation or tool-driven route — i.e. registered FIRST — so it always
 * runs LAST and gets the final, non-bypassable word: `abort()` or
 * `continue()`/`fulfill()`. (LogicExploitAgent's offensive handler was
 * changed from `route.continue()` to `route.fallback()` to cooperate with
 * this — see that file's `intercept_request` case.)
 *
 * Why a manual per-hop loop, not route.continue(): empirically verified
 * (see the Phase 1 test log) that `route.continue()` on a request that
 * server-redirects does NOT re-invoke this handler for the redirect target —
 * Chromium follows the Location header internally, outside the routing
 * layer, exactly the same structural gap that motivated scopedHttp's manual
 * redirect loop for the Node HTTP client. Fulfilling the raw 3xx response
 * verbatim doesn't help either — the browser then follows it as a normal
 * navigation, again without re-invoking route(). The fix: use
 * `route.fetch({ url, maxRedirects: 0 })` to fetch one hop at a time
 * ourselves, re-validating the Location target against scope BEFORE fetching
 * it, and only ever `route.fulfill()` the FINAL, non-redirect response back
 * to the browser — an intermediate 3xx is never handed back verbatim.
 *
 * Covers both navigations and sub-resources for free: a page route
 * intercepts every request that page makes, `page.goto()` included — no
 * separate mechanism needed for the AI-chosen destination vs. a passive
 * script fetch. Both go through the same per-hop loop.
 */
import type { BrowserContext, Page, Route } from "playwright";
import { ScopeGuard } from "../../middleware/scopeGuard";
import logger from "../../utils/logger";

const guard = ScopeGuard.getInstance();
const MAX_HOPS = 20; // matches Playwright's own route.fetch() default maxRedirects

async function isAllowed(url: string, programId: number | null | undefined): Promise<{ allowed: boolean; reason: string }> {
  try {
    return await guard.isInScope(url, programId);
  } catch (err) {
    logger.error("[scoped-browser-route] guard threw — failing closed", { url, programId, err: String(err) });
    return { allowed: false, reason: "guard threw — failing closed" };
  }
}

/**
 * Installs the scope-checking route. Pass the PAGE, not the context —
 * see the module docstring for why context-level would silently lose to a
 * page-level offensive route regardless of registration order. Accepts
 * BrowserContext too (typed) for callers that genuinely have no page-level
 * route anywhere in their lifecycle, but every current call site uses Page.
 */
export async function installScopeRoute(
  target: Page | BrowserContext,
  programId: number | null | undefined,
): Promise<void> {
  await target.route("**/*", async (route: Route) => {
    let currentUrl = route.request().url();

    for (let hop = 0; hop < MAX_HOPS; hop++) {
      const { allowed, reason } = await isAllowed(currentUrl, programId);
      if (!allowed) {
        logger.warn("[scoped-browser-route] Blocked out-of-scope browser request", { url: currentUrl, programId, reason, hop });
        await route.abort("blockedbyclient");
        return;
      }

      let resp;
      try {
        // hop 0 uses the routed request's own method/headers/postData; later
        // hops are always the redirect target, fetched as a plain GET the same
        // way a browser follows a 3xx (Location is authoritative for the URL,
        // and route.fetch() with an explicit `url` override fetches exactly
        // that URL instead of the original request).
        resp = await route.fetch(hop === 0 ? { maxRedirects: 0 } : { url: currentUrl, maxRedirects: 0 });
      } catch (err) {
        logger.warn("[scoped-browser-route] fetch failed mid-chain — aborting", { url: currentUrl, err: String(err) });
        await route.abort("failed");
        return;
      }

      const status = resp.status();
      if (status >= 300 && status < 400) {
        const location = resp.headers()["location"];
        if (!location) {
          await route.fulfill({ response: resp });
          return;
        }
        currentUrl = new URL(location, currentUrl).toString();
        continue; // next iteration re-validates BEFORE fetching this new hop
      }

      await route.fulfill({ response: resp });
      return;
    }

    // Redirect chain longer than MAX_HOPS — fail closed rather than loop forever.
    logger.warn("[scoped-browser-route] redirect chain exceeded max hops — aborting", { url: currentUrl, programId });
    await route.abort("blockedbyclient");
  });
}

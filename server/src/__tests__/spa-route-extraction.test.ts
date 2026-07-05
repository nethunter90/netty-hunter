/**
 * SPA route-extraction tests (2026-07-03, crawl-depth fix).
 *
 * Root cause: deepCrawl's page-discovery only followed real <a href> DOM
 * elements, so on a client-side-routed SPA (React Router/wouter — navigation
 * via history.pushState, not real anchors) pagesVisited stayed 1 regardless
 * of maxDepth, and entire feature panels (a wifi/attack panel, a build/
 * desktop-agent panel) were never visited — confirmed against two
 * independent, differently-planted vulnerability sets in the same app,
 * neither of which was ever discovered across four completed hunt runs.
 *
 * extractRoutesFromJs mines the SAME already-fetched JS bundle text (deepCrawl
 * already regex-scans it for /api/... paths) for client-side ROUTE path
 * literals instead, so deepCrawl can queue them as direct page.goto()
 * navigations — a second, SPA-aware discovery signal alongside the existing
 * (correct, but SPA-blind) anchor-tag one.
 */
import { describe, it, expect } from "vitest";
import { extractRoutesFromJs, DESTRUCTIVE_VERB_PATTERN } from "../lib/tools/js-spa-crawler";

describe("extractRoutesFromJs", () => {
  it("extracts routes from a React-Router-style bundled route config object", () => {
    const bundle = `const routes=[{path:"/wifi",element:e(WifiPanel)},{path:"/mission-control/build",element:e(BuildPanel)}];`;
    const routes = extractRoutesFromJs(bundle);
    expect(routes).toContain("/wifi");
    expect(routes).toContain("/mission-control/build");
  });

  it("extracts routes from unminified JSX <Route path=...> (survives in dev bundles)", () => {
    const bundle = `function App(){return <Route path="/settings" element={<Settings />} />}`;
    const routes = extractRoutesFromJs(bundle);
    expect(routes).toContain("/settings");
  });

  it("extracts routes from a wouter/TanStack-style createRoute() helper", () => {
    const bundle = `createRoute("/team")`;
    const routes = extractRoutesFromJs(bundle);
    expect(routes).toContain("/team");
  });

  it("excludes API paths — those are a separate signal (extractPathsFromJs), not page routes", () => {
    const bundle = `const routes=[{path:"/api/env",element:e(EnvHandler)}];`;
    const routes = extractRoutesFromJs(bundle);
    expect(routes).not.toContain("/api/env");
  });

  it("excludes dynamic-segment routes — nothing concrete to navigate to", () => {
    const bundle = `const routes=[{path:"/user/:id",element:e(UserPage)},{path:"/files/*",element:e(FileBrowser)}];`;
    const routes = extractRoutesFromJs(bundle);
    expect(routes.some(r => r.includes(":"))).toBe(false);
    expect(routes.some(r => r.includes("*"))).toBe(false);
  });

  it("dedupes repeated route declarations across multiple bundle chunks", () => {
    const bundle = `path:"/wifi" ... path:"/wifi" ... path:"/wifi"`;
    const routes = extractRoutesFromJs(bundle);
    expect(routes.filter(r => r === "/wifi").length).toBe(1);
  });

  it("returns nothing from a bundle with no route-shaped strings", () => {
    const bundle = `function add(a,b){return a+b} const x = "hello world";`;
    expect(extractRoutesFromJs(bundle)).toEqual([]);
  });
});

describe("DESTRUCTIVE_VERB_PATTERN (nav-click safety filter)", () => {
  it("flags labels naming real attack/build actions this app can actually perform", () => {
    // These are exactly the shape of controls sentprime's own answer key
    // describes: a wifi deauth trigger and an autonomous build agent with
    // unrestricted shell access. The nav-click pass must never auto-click these.
    const dangerous = [
      "Start Capture", "Stop Monitor Mode", "Send Deauth", "Attack Target",
      "Execute Build", "Deploy Agent", "Delete Campaign", "Run Scan",
    ];
    for (const label of dangerous) {
      expect(DESTRUCTIVE_VERB_PATTERN.test(label)).toBe(true);
    }
  });

  it("does not flag ordinary navigation labels", () => {
    const safe = ["Dashboard", "Settings", "Team Members", "Wifi", "Mission Control", "Reports"];
    for (const label of safe) {
      expect(DESTRUCTIVE_VERB_PATTERN.test(label)).toBe(false);
    }
  });

  it("does not flag the real icon-toolbar title attributes this fix was built for", () => {
    // Real labels from Kali-Web-IDE's KaliIDE.tsx toolbar — panel-switching
    // buttons (setLayout('wifi'), setLayout('msf'), etc.) are safe to click;
    // the destructive action is a SECOND click inside the panel they open
    // (e.g. "Start Capture"), never reached by this single-level pass.
    const realToolbarTitles = ["WiFi Dashboard", "Payload Encoder", "Metasploit Console", "Reverse Shell Generator"];
    for (const label of realToolbarTitles) {
      expect(DESTRUCTIVE_VERB_PATTERN.test(label)).toBe(false);
    }
  });
});

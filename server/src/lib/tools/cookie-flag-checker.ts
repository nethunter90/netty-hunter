/**
 * Cookie flag checker — probes common login/auth endpoints and inspects
 * Set-Cookie headers for missing security flags (HttpOnly, Secure, SameSite).
 */
import axios from "axios";
import logger from "../../utils/logger";

interface CookieIssue {
  cookieName: string;
  url: string;
  missingFlags: string[];   // e.g. ["HttpOnly", "Secure", "SameSite"]
  isSessionCookie: boolean; // name contains "session", "token", "auth", "jwt", "sid"
  severity: "high" | "medium" | "low";
  detail: string;
}

interface CookieCheckResult {
  cookiesFound: number;
  issues: CookieIssue[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

const SESSION_COOKIE_KEYWORDS = ["session", "token", "auth", "jwt", "sid", "csrf", "connect.sid"];

function isSessionCookieName(name: string): boolean {
  const lower = name.toLowerCase();
  return SESSION_COOKIE_KEYWORDS.some(kw => lower.includes(kw));
}

function parseCookieFlags(cookieStr: string): {
  name: string;
  hasHttpOnly: boolean;
  hasSecure: boolean;
  hasSameSite: boolean;
} {
  const parts = cookieStr.split(";").map(p => p.trim());
  // The first part is name=value
  const nameValue = parts[0] ?? "";
  const name = nameValue.split("=")[0].trim();

  const flags = parts.slice(1).map(p => p.toLowerCase());

  const hasHttpOnly = flags.some(f => f === "httponly");
  const hasSecure = flags.some(f => f === "secure");
  const hasSameSite = flags.some(f => f.startsWith("samesite"));

  return { name, hasHttpOnly, hasSecure, hasSameSite };
}

function determineSeverity(
  isSession: boolean,
  missingFlags: string[]
): "high" | "medium" | "low" {
  if (isSession && (missingFlags.includes("HttpOnly") || missingFlags.includes("Secure"))) {
    return "high";
  }
  if (missingFlags.includes("SameSite")) {
    return "medium";
  }
  return "low";
}

function buildDetail(
  name: string,
  isSession: boolean,
  missingFlags: string[]
): string {
  const parts: string[] = [];
  if (isSession && missingFlags.includes("HttpOnly")) {
    parts.push("session cookie missing HttpOnly — XSS could steal session");
  }
  if (isSession && missingFlags.includes("Secure")) {
    parts.push("session cookie missing Secure — session may be sent over HTTP");
  }
  if (missingFlags.includes("SameSite")) {
    parts.push("cookie missing SameSite — potential CSRF vector");
  }
  if (!isSession && missingFlags.includes("HttpOnly")) {
    parts.push("non-session cookie missing HttpOnly");
  }
  return parts.length > 0
    ? parts.join("; ")
    : `Cookie "${name}" missing flags: ${missingFlags.join(", ")}`;
}

class CookieFlagChecker {
  async check(
    targetUrl: string,
    authHeaders?: Record<string, string>
  ): Promise<CookieCheckResult> {
    const base = this.extractBase(targetUrl);

    const probes: Array<{ url: string; method: "GET" | "POST"; data?: unknown }> = [
      { url: targetUrl,          method: "GET" },
      { url: `${base}/login`,    method: "POST", data: {} },
      { url: `${base}/api/login`, method: "POST", data: {} },
      { url: `${base}/signin`,   method: "GET" },
    ];

    // Collect raw Set-Cookie strings keyed by source URL
    const collected: Array<{ url: string; cookieStr: string }> = [];

    const responses = await Promise.allSettled(
      probes.map(probe =>
        axios.request({
          method: probe.method,
          url: probe.url,
          data: probe.data,
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)",
            ...(authHeaders ?? {}),
          },
          timeout: 5000,
          validateStatus: () => true,
          maxRedirects: 0,
        }).then(resp => ({ url: probe.url, resp }))
         .catch(() => null)
      )
    );

    for (const settled of responses) {
      if (settled.status !== "fulfilled" || !settled.value) continue;
      const { url, resp } = settled.value;
      const setCookieHeader = resp.headers["set-cookie"];
      if (!setCookieHeader) continue;
      const cookies = Array.isArray(setCookieHeader)
        ? setCookieHeader
        : [setCookieHeader as string];
      for (const cookieStr of cookies) {
        collected.push({ url, cookieStr });
      }
    }

    // Deduplicate by cookie name — first occurrence wins
    const seen = new Set<string>();
    const issues: CookieIssue[] = [];

    for (const { url, cookieStr } of collected) {
      const { name, hasHttpOnly, hasSecure, hasSameSite } = parseCookieFlags(cookieStr);
      if (!name || seen.has(name)) continue;
      seen.add(name);

      const missingFlags: string[] = [];
      if (!hasHttpOnly) missingFlags.push("HttpOnly");
      if (!hasSecure)   missingFlags.push("Secure");
      if (!hasSameSite) missingFlags.push("SameSite");

      if (missingFlags.length === 0) continue; // no issues

      const isSession = isSessionCookieName(name);
      const severity = determineSeverity(isSession, missingFlags);
      const detail = buildDetail(name, isSession, missingFlags);

      issues.push({ cookieName: name, url, missingFlags, isSessionCookie: isSession, severity, detail });
    }

    const hypotheses = this.buildHypotheses(issues);

    if (issues.length > 0) {
      logger.warn("[CookieFlagChecker] Cookie security issues found", {
        base,
        count: issues.length,
        high: issues.filter(i => i.severity === "high").length,
      });
    }

    return {
      cookiesFound: seen.size,
      issues,
      hypotheses,
    };
  }

  private buildHypotheses(
    issues: CookieIssue[]
  ): Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }> {
    const hyps: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }> = [];
    const added = new Set<string>();

    for (const issue of issues) {
      if (issue.isSessionCookie && issue.missingFlags.includes("HttpOnly") && !added.has("xss")) {
        added.add("xss");
        hyps.push({
          vulnClass: "xss",
          reasoning: "Session cookie missing HttpOnly flag — XSS could steal session",
          confidence: 0.6,
          priority: 6,
          endpoint: issue.url,
        });
      }
      if (issue.isSessionCookie && issue.missingFlags.includes("Secure") && !added.has("info_disclosure")) {
        added.add("info_disclosure");
        hyps.push({
          vulnClass: "info_disclosure",
          reasoning: "Session cookie missing Secure flag — session may be transmitted over unencrypted HTTP",
          confidence: 0.65,
          priority: 6,
          endpoint: issue.url,
        });
      }
      if (issue.missingFlags.includes("SameSite") && !added.has("csrf")) {
        added.add("csrf");
        hyps.push({
          vulnClass: "csrf",
          reasoning: "Cookie missing SameSite attribute — cross-site request forgery may be possible",
          confidence: 0.55,
          priority: 5,
          endpoint: issue.url,
        });
      }
    }

    return hyps;
  }

  private extractBase(url: string): string {
    try {
      const u = new URL(url);
      return `${u.protocol}//${u.host}`;
    } catch {
      return url;
    }
  }
}

export const cookieFlagChecker = new CookieFlagChecker();

import { scopedHttp } from "../net/scoped-http";
import logger from "../../utils/logger";

interface CRLFVuln {
  url: string;
  payload: string;
  injectedHeader: string;
  reflected: boolean;
  severity: "high" | "medium";
  detail: string;
}

interface CRLFProbeResult {
  vulns: CRLFVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: CRLFVuln }>;
}

const CRLF_PAYLOADS = [
  "%0d%0aX-Injected:+crlf-netty",
  "%0aX-Injected:+crlf-netty",
  "%0d%0a%20X-Injected:+crlf-netty",
  "%E5%98%8D%E5%98%8AX-Injected:+crlf-netty",
  "%23%0dX-Injected:+crlf-netty",
];

// Exported so PostExploitAgent's crlf_injection probesFor() case can prove
// against the exact marker this prober injects, instead of a duplicated guess.
export const MARKER_HEADER = "X-Injected";
export const MARKER_VALUE = "crlf-netty";

/**
 * The single shared predicate for "is this a real, impact-proven CRLF /
 * response-splitting vulnerability" — enforced identically here AND in
 * PostExploitAgent's crlf_injection probesFor() case. Before 2026-07-21 the
 * two accepted body-reflected 
 as sufficient (crlf_probe at "medium"
 * severity, probesFor() unconditionally), while VerifierAgent's layer4_ai
 * correctly required an actual NEW line in the raw response HEADERS — three
 * different bars for the same claim. Body reflection alone is NOT this
 * predicate; a real header sink (a new header line landing in the response)
 * is. Confirmed against logic-lab (2026-07-21): its reflection endpoint is
 * body-only by design (server.js's own comment: "real header-splitting is
 * blocked by Node's http module rejecting raw CR/LF in header values") — the
 * predicate correctly returns false for it, which is why #9 was reclassified
 * rather than "fixed" to pass.
 *
 * `headers` must be the REAL response headers (case-insensitive keys, as
 * axios/scopedHttp already normalizes them) — never a captured/summarized
 * text blob standing in for them.
 */
export function isCrlfImpactProven(headers: Record<string, unknown> | undefined | null): boolean {
  if (!headers) return false;
  return headers[MARKER_HEADER.toLowerCase()] !== undefined;
}

class CRLFProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>, programId?: number): Promise<CRLFProbeResult> {
    const vulns: CRLFVuln[] = [];

    for (const payload of CRLF_PAYLOADS) {
      const testUrls: Array<{ url: string; description: string }> = [
        {
          url: `${targetUrl}?x=${payload}`,
          description: "query param x",
        },
        {
          url: `${targetUrl}?next=${payload}&redirect=${payload}&url=${payload}&return=${payload}`,
          description: "redirect params",
        },
      ];

      for (const { url } of testUrls) {
        try {
          const response = await scopedHttp.get(url, {
            timeout: 5000,
            validateStatus: () => true,
            maxRedirects: 0,
            headers: authHeaders ?? {},
          }, programId);

          const headerReflected = isCrlfImpactProven(response.headers as Record<string, unknown>);
          const bodyReflected =
            typeof response.data === "string" &&
            response.data.includes(MARKER_VALUE);

          if (headerReflected || bodyReflected) {
            // severity/detail still distinguish the two shapes for logging —
            // what changed 2026-07-21 is that only headerReflected (the real
            // predicate) is allowed to become a crlf_injection HYPOTHESIS
            // below. Body-only detections are still recorded here (not
            // deleted — the reflection itself is a real, useful signal) but
            // downgraded to "reflected_input" when turned into a hypothesis.
            const severity: "high" | "medium" = headerReflected ? "high" : "medium";
            const detail = headerReflected
              ? `Injected header "${MARKER_HEADER}" was reflected in the response headers, indicating HTTP response splitting.`
              : `Marker value "${MARKER_VALUE}" was reflected in the response body only (no new header line) — unsanitized reflection, NOT proven header injection/response-splitting.`;

            vulns.push({
              url,
              payload,
              injectedHeader: MARKER_HEADER,
              reflected: true,
              severity,
              detail,
            });

            logger.warn(
              `[crlf-probe] ${severity.toUpperCase()} – ${headerReflected ? "CRLF injection" : "reflected input (no header sink)"} detected at ${url}`
            );
          }
        } catch (err) {
          logger.debug(`[crlf-probe] Error testing ${url}: ${(err as Error).message}`);
        }
      }
    }

    const hypotheses = vulns.map((vuln) => {
      const headerReflected =
        vuln.severity === "high";
      return {
        // Only a real header-sink hit is allowed to claim crlf_injection —
        // body-only reflection is a genuinely different, lesser claim
        // (unsanitized reflection / HTML-log-injection-adjacent), not a
        // downgraded-confidence version of the same claim. See
        // isCrlfImpactProven() above for why this split exists.
        vulnClass: headerReflected ? "crlf_injection" : "reflected_input",
        reasoning: vuln.detail,
        confidence: headerReflected ? 0.8 : 0.35,
        priority: 7,
        endpoint: vuln.url,
        // Full detection detail — HunterEngine attaches this to the
        // hypothesis's evidence so the PROBE phase can recognize this was
        // already actively confirmed here (the injected header/marker
        // genuinely reflected back) and skip re-dispatching it to curl_probe
        // (whose declared vulnClasses don't even include crlf_injection — a
        // structurally gate-blocked no-op) or crlfuzz (a generic-parser
        // catalog tool that only sees "found = nonempty output," not this
        // specific confirmed reflection).
        raw: vuln,
      };
    });

    return { vulns, hypotheses };
  }
}

export const crlfProber = new CRLFProber();

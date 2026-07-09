import axios from "axios";
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
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

const CRLF_PAYLOADS = [
  "%0d%0aX-Injected:+crlf-netty",
  "%0aX-Injected:+crlf-netty",
  "%0d%0a%20X-Injected:+crlf-netty",
  "%E5%98%8D%E5%98%8AX-Injected:+crlf-netty",
  "%23%0dX-Injected:+crlf-netty",
];

const MARKER_HEADER = "X-Injected";
const MARKER_VALUE = "crlf-netty";

class CRLFProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<CRLFProbeResult> {
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
          const response = await axios.get(url, {
            timeout: 5000,
            validateStatus: () => true,
            maxRedirects: 0,
            headers: authHeaders ?? {},
          });

          const headerReflected =
            response.headers[MARKER_HEADER.toLowerCase()] !== undefined;
          const bodyReflected =
            typeof response.data === "string" &&
            response.data.includes(MARKER_VALUE);

          if (headerReflected || bodyReflected) {
            const severity: "high" | "medium" = headerReflected ? "high" : "medium";
            const detail = headerReflected
              ? `Injected header "${MARKER_HEADER}" was reflected in the response headers, indicating HTTP response splitting.`
              : `Marker value "${MARKER_VALUE}" was reflected in the response body, suggesting partial CRLF injection.`;

            vulns.push({
              url,
              payload,
              injectedHeader: MARKER_HEADER,
              reflected: true,
              severity,
              detail,
            });

            logger.warn(
              `[crlf-probe] ${severity.toUpperCase()} – CRLF injection detected at ${url}`
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
        vulnClass: "crlf_injection",
        reasoning: vuln.detail,
        confidence: headerReflected ? 0.8 : 0.55,
        priority: 7,
        endpoint: vuln.url,
      };
    });

    return { vulns, hypotheses };
  }
}

export const crlfProber = new CRLFProber();

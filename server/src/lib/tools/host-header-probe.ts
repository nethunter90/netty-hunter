import axios from "axios";
import logger from "../../utils/logger";

interface HostHeaderVuln {
  url: string;
  technique: "password_reset_poison" | "cache_poison" | "routing_bypass" | "host_reflection";
  injectedHost: string;
  reflected: boolean;
  severity: "high" | "medium";
  detail: string;
}

interface HostHeaderProbeResult {
  vulns: HostHeaderVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

class HostHeaderProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<HostHeaderProbeResult> {
    const marker = `hhi-${Date.now()}`;
    const vulns: HostHeaderVuln[] = [];

    // Establish baseline for routing bypass comparison
    let baselineStatus = 0;
    let baselineBodyLength = 0;
    try {
      const baseline = await axios.request({
        method: "GET",
        url: targetUrl,
        timeout: 6000,
        validateStatus: () => true,
        maxRedirects: 0,
        headers: { ...authHeaders },
      });
      baselineStatus = baseline.status;
      const baselineBody = typeof baseline.data === "string" ? baseline.data : JSON.stringify(baseline.data);
      baselineBodyLength = baselineBody.length;
    } catch (err) {
      logger.debug(`[host-header-probe] Baseline request error: ${err}`);
    }

    const tests: Array<() => Promise<HostHeaderVuln | null>> = [];

    // Test 1: Host reflection
    tests.push(async () => {
      try {
        const resp = await axios.request({
          method: "GET",
          url: targetUrl,
          timeout: 6000,
          validateStatus: () => true,
          maxRedirects: 0,
          headers: {
            ...authHeaders,
            Host: `${marker}.evil.com`,
          },
        });
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const locationHeader = resp.headers["location"] || "";
        const reflected = body.includes(marker) || locationHeader.includes(marker);
        if (reflected) {
          logger.debug(`[host-header-probe] Host reflection detected at ${targetUrl}`);
          return {
            url: targetUrl,
            technique: "host_reflection",
            injectedHost: `${marker}.evil.com`,
            reflected: true,
            severity: "high",
            detail: `Host header value '${marker}.evil.com' was reflected in the response, indicating potential host header injection vulnerability.`,
          };
        }
      } catch (err) {
        logger.debug(`[host-header-probe] Host reflection test error: ${err}`);
      }
      return null;
    });

    // Test 2: Password reset poisoning
    tests.push(async () => {
      const parsedUrl = new URL(targetUrl);
      const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
      const resetPaths = [
        "/forgot-password",
        "/reset-password",
        "/account/forgot",
        "/users/password",
      ];

      for (const path of resetPaths) {
        try {
          const resetUrl = `${baseUrl}${path}`;
          const resp = await axios.request({
            method: "POST",
            url: resetUrl,
            timeout: 6000,
            validateStatus: () => true,
            maxRedirects: 0,
            headers: {
              ...authHeaders,
              Host: `${marker}.evil.com`,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            data: "email=test@example.com",
          });
          const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
          const isSuccessStatus = resp.status === 200 || resp.status === 302;
          const reflected = body.includes(marker);
          if (isSuccessStatus && reflected) {
            logger.debug(`[host-header-probe] Password reset poisoning detected at ${resetUrl}`);
            return {
              url: resetUrl,
              technique: "password_reset_poison",
              injectedHost: `${marker}.evil.com`,
              reflected: true,
              severity: "high",
              detail: `Password reset endpoint '${path}' reflected injected Host '${marker}.evil.com' in response, indicating password reset poisoning vulnerability.`,
            };
          }
        } catch (err) {
          logger.debug(`[host-header-probe] Password reset poison test error for ${path}: ${err}`);
        }
      }
      return null;
    });

    // Test 3: Cache poison via X-Forwarded-Host
    tests.push(async () => {
      try {
        const resp = await axios.request({
          method: "GET",
          url: targetUrl,
          timeout: 6000,
          validateStatus: () => true,
          maxRedirects: 0,
          headers: {
            ...authHeaders,
            "X-Forwarded-Host": `${marker}.evil.com`,
          },
        });
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const reflected = body.includes(marker);
        if (reflected) {
          logger.debug(`[host-header-probe] Cache poisoning via X-Forwarded-Host detected at ${targetUrl}`);
          return {
            url: targetUrl,
            technique: "cache_poison",
            injectedHost: `${marker}.evil.com`,
            reflected: true,
            severity: "medium",
            detail: `X-Forwarded-Host value '${marker}.evil.com' was reflected in the response body, indicating potential web cache poisoning vulnerability.`,
          };
        }
      } catch (err) {
        logger.debug(`[host-header-probe] Cache poison test error: ${err}`);
      }
      return null;
    });

    // Test 4: Routing bypass via Host override
    tests.push(async () => {
      try {
        const resp = await axios.request({
          method: "GET",
          url: targetUrl,
          timeout: 6000,
          validateStatus: () => true,
          maxRedirects: 0,
          headers: {
            ...authHeaders,
            Host: "localhost",
            "X-Forwarded-For": "127.0.0.1",
          },
        });
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        const bodyLength = body.length;
        const statusDiffers = baselineStatus !== 0 && resp.status !== baselineStatus;
        const bodyLengthDiffers = baselineBodyLength !== 0 && Math.abs(bodyLength - baselineBodyLength) > 50;
        if (statusDiffers || bodyLengthDiffers) {
          logger.debug(`[host-header-probe] Routing bypass detected at ${targetUrl}`);
          return {
            url: targetUrl,
            technique: "routing_bypass",
            injectedHost: "localhost",
            reflected: false,
            severity: "medium",
            detail: `Host override to 'localhost' with X-Forwarded-For: 127.0.0.1 produced a different response (status: ${baselineStatus} → ${resp.status}, body length: ${baselineBodyLength} → ${bodyLength}), indicating potential routing bypass vulnerability.`,
          };
        }
      } catch (err) {
        logger.debug(`[host-header-probe] Routing bypass test error: ${err}`);
      }
      return null;
    });

    const results = await Promise.allSettled(tests.map((fn) => fn()));

    for (const result of results) {
      if (result.status === "fulfilled" && result.value !== null) {
        vulns.push(result.value);
      }
    }

    const hypotheses = vulns.map((vuln) => ({
      vulnClass: "host_header_injection",
      reasoning: vuln.detail,
      confidence: vuln.severity === "high" ? 0.75 : 0.6,
      priority: vuln.severity === "high" ? 8 : 6,
      endpoint: vuln.url,
    }));

    return { vulns, hypotheses };
  }
}

export const hostHeaderProber = new HostHeaderProber();

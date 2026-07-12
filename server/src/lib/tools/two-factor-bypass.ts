import axios from "axios";
import logger from "../../utils/logger";

interface TwoFAVuln {
  technique: "response_manipulation" | "step_skip" | "code_reuse" | "backup_code_brute" | "null_code";
  endpoint: string;
  severity: "critical" | "high";
  detail: string;
}

interface TwoFAResult {
  vulns: TwoFAVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: TwoFAVuln }>;
}

const TWOFA_ENDPOINTS = [
  "/api/2fa/verify",
  "/api/mfa/verify",
  "/api/otp/verify",
  "/verify-otp",
  "/api/auth/2fa",
  "/login/2fa",
];

const PROTECTED_RESOURCES = ["/api/me", "/api/dashboard"];

function isAccepted(status: number, data: unknown, headers?: Record<string, string>): boolean {
  if (status !== 200 && status !== 204) return false;

  // A 200/204 with an explicit error body is a rejection, not a bypass
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    // Explicit failure indicators
    if (obj["success"] === false) return false;
    if (obj["authenticated"] === false) return false;
    if (typeof obj["error"] === "string" && obj["error"].length > 0) return false;
    if (typeof obj["message"] === "string") {
      const msg = obj["message"].toLowerCase();
      if (/invalid|incorrect|expired|denied|failed|wrong|unauthorized/.test(msg)) return false;
    }
    // Explicit success indicators
    if (obj["success"] === true) return true;
    if (obj["authenticated"] === true) return true;
    if (obj["token"] || obj["accessToken"] || obj["access_token"] || obj["sessionToken"]) return true;
  }

  // Session cookie set = accepted (redirect to authenticated area)
  const setCookie = headers?.["set-cookie"] ?? "";
  if (/session|auth|jwt|token/i.test(setCookie)) return true;

  // HTML body (SPA fallback) is never a 2FA acceptance
  if (typeof data === "string" && data.trimStart().startsWith("<")) return false;

  // No clear signal — treat as not accepted (conservative)
  return false;
}

function hasUserData(data: unknown): boolean {
  if (!data || typeof data !== "object") return false;
  const obj = data as Record<string, unknown>;
  const userFields = ["id", "user", "username", "email", "name", "userId", "user_id", "profile"];
  return userFields.some((field) => field in obj);
}

function toHypothesis(
  vuln: TwoFAVuln
): { vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: TwoFAVuln } {
  return {
    vulnClass: "auth_bypass",
    reasoning: `2FA bypass via ${vuln.technique} — authentication second factor can be circumvented`,
    confidence: vuln.severity === "critical" ? 0.8 : 0.7,
    priority: vuln.severity === "critical" ? 10 : 8,
    // The specific endpoint this bypass was actually confirmed against —
    // previously discarded, forcing re-verification to guess at the root URL.
    endpoint: vuln.endpoint,
    // Full detection detail — HunterEngine attaches this to the hypothesis's
    // evidence so the PROBE phase can recognize this hypothesis was already
    // actively confirmed here (a real 2FA endpoint that accepted a null/empty/
    // reused/backup code, or a protected resource reachable without
    // completing 2FA) and skip re-dispatching it to nuclei's generic
    // "default-login,auth-bypass" templates, which test for known CVEs and
    // default credentials — not this specific 2FA-flow logic flaw.
    raw: vuln,
  };
}

class TwoFactorBypassProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<TwoFAResult> {
    const vulns: TwoFAVuln[] = [];
    const baseUrl = targetUrl.replace(/\/$/, "");
    const headers = { "Content-Type": "application/json", ...(authHeaders ?? {}) };
    const axiosOpts = { timeout: 5000, validateStatus: () => true };

    // Detect active 2FA endpoints — require a JSON response to exclude SPA HTML fallbacks
    // and 405 (method not allowed) to exclude routes that don't handle POST.
    const activeEndpoints: string[] = [];
    for (const ep of TWOFA_ENDPOINTS) {
      try {
        const res = await axios.post(`${baseUrl}${ep}`, {}, { ...axiosOpts, headers });
        // 404 → route doesn't exist
        // 405 → route exists but doesn't accept POST (not a 2FA handler)
        if (res.status === 404 || res.status === 405) continue;
        // SPA fallbacks return text/html — a real API endpoint returns JSON
        const ct = String(res.headers["content-type"] ?? "");
        if (!ct.includes("application/json")) {
          logger.debug(`[2FA] Skipping ${ep} — non-JSON response (${ct.split(";")[0]}), likely SPA fallback`);
          continue;
        }
        activeEndpoints.push(ep);
        logger.debug(`[2FA] Detected endpoint: ${ep} (status ${res.status})`);
      } catch (err) {
        logger.debug(`[2FA] Error probing ${ep}: ${err}`);
      }
    }

    for (const ep of activeEndpoints) {
      const url = `${baseUrl}${ep}`;

      // 1. Null code
      try {
        const res = await axios.post(
          url,
          { code: null, otp: null, token: null },
          { ...axiosOpts, headers }
        );
        if (isAccepted(res.status, res.data, res.headers as Record<string, string>)) {
          const vuln: TwoFAVuln = {
            technique: "null_code",
            // Full URL, not the bare path — HunterEngine's seed site uses this
            // as the hypothesis's targetUrl, and a truthy relative path always
            // won its `hyp.endpoint || this.state.targetUrl` fallback.
            endpoint: url,
            severity: "critical",
            detail: `Endpoint ${ep} accepted null code/otp/token (status ${res.status})`,
          };
          vulns.push(vuln);
          logger.warn(`[2FA] null_code vuln at ${ep}`);
        }
      } catch (err) {
        logger.debug(`[2FA] null_code test error at ${ep}: ${err}`);
      }

      // 2. Empty string code
      try {
        const res = await axios.post(
          url,
          { code: "", otp: "" },
          { ...axiosOpts, headers }
        );
        if (isAccepted(res.status, res.data, res.headers as Record<string, string>)) {
          const vuln: TwoFAVuln = {
            technique: "response_manipulation",
            endpoint: url,
            severity: "critical",
            detail: `Endpoint ${ep} accepted empty string code/otp (status ${res.status})`,
          };
          vulns.push(vuln);
          logger.warn(`[2FA] response_manipulation (empty string) vuln at ${ep}`);
        }
      } catch (err) {
        logger.debug(`[2FA] empty string test error at ${ep}: ${err}`);
      }

      // 3. Step skip — access protected resources without completing 2FA
      for (const resource of PROTECTED_RESOURCES) {
        try {
          const resGet = await axios.get(`${baseUrl}${resource}`, { ...axiosOpts, headers });
          if (resGet.status === 200 && hasUserData(resGet.data)) {
            const vuln: TwoFAVuln = {
              technique: "step_skip",
              endpoint: `${baseUrl}${resource}`,
              severity: "critical",
              detail: `Protected resource ${resource} accessible without completing 2FA (status ${resGet.status})`,
            };
            vulns.push(vuln);
            logger.warn(`[2FA] step_skip vuln — ${resource} accessible without 2FA`);
            break;
          }
        } catch (err) {
          logger.debug(`[2FA] step_skip GET ${resource} error: ${err}`);
        }
        try {
          const resPost = await axios.post(
            `${baseUrl}${resource}`,
            {},
            { ...axiosOpts, headers }
          );
          if (resPost.status === 200 && hasUserData(resPost.data)) {
            const vuln: TwoFAVuln = {
              technique: "step_skip",
              endpoint: `${baseUrl}${resource}`,
              severity: "critical",
              detail: `Protected resource ${resource} accessible via POST without completing 2FA (status ${resPost.status})`,
            };
            vulns.push(vuln);
            logger.warn(`[2FA] step_skip (POST) vuln — ${resource} accessible without 2FA`);
            break;
          }
        } catch (err) {
          logger.debug(`[2FA] step_skip POST ${resource} error: ${err}`);
        }
      }

      // 4. Code reuse — submit same code twice
      try {
        const code = "123456";
        await axios.post(url, { code }, { ...axiosOpts, headers });
        const res2 = await axios.post(url, { code }, { ...axiosOpts, headers });
        if (isAccepted(res2.status, res2.data, res2.headers as Record<string, string>)) {
          const vuln: TwoFAVuln = {
            technique: "code_reuse",
            endpoint: url,
            severity: "high",
            detail: `Endpoint ${ep} accepted the same OTP code on second submission (status ${res2.status})`,
          };
          vulns.push(vuln);
          logger.warn(`[2FA] code_reuse vuln at ${ep}`);
        }
      } catch (err) {
        logger.debug(`[2FA] code_reuse test error at ${ep}: ${err}`);
      }

      // 5. Backup code brute
      const backupCodes = ["00000000", "12345678", "11111111"];
      for (const backup_code of backupCodes) {
        try {
          const res = await axios.post(url, { backup_code }, { ...axiosOpts, headers });
          if (isAccepted(res.status, res.data, res.headers as Record<string, string>)) {
            const vuln: TwoFAVuln = {
              technique: "backup_code_brute",
              endpoint: url,
              severity: "high",
              detail: `Endpoint ${ep} accepted backup code "${backup_code}" (status ${res.status})`,
            };
            vulns.push(vuln);
            logger.warn(`[2FA] backup_code_brute vuln at ${ep} with code ${backup_code}`);
            break;
          }
        } catch (err) {
          logger.debug(`[2FA] backup_code_brute test error at ${ep} code ${backup_code}: ${err}`);
        }
      }
    }

    const hypotheses = vulns.map((v) => toHypothesis(v));

    return { vulns, hypotheses };
  }
}

export const twoFactorBypassProber = new TwoFactorBypassProber();

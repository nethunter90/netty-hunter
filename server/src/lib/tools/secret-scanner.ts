/**
 * Secret scanner — scans HTTP response bodies for leaked credentials,
 * API keys, tokens, and cloud credentials embedded in HTML/JS/JSON.
 */
import axios from "axios";
import logger from "../../utils/logger";

export interface SecretMatch {
  type: string;
  value: string;   // redacted after first 8 chars
  pattern: string;
  url: string;
  context: string; // 40-char surrounding snippet
}

export interface SecretScanResult {
  matches: SecretMatch[];
  urlsScanned: number;
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

const SECRET_PATTERNS: Array<{ name: string; regex: RegExp; redactFrom: number }> = [
  // AWS
  { name: "aws_access_key",    regex: /AKIA[0-9A-Z]{16}/g,                            redactFrom: 8 },
  { name: "aws_secret_key",    regex: /(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, redactFrom: 8 },
  { name: "aws_mfa_serial",    regex: /arn:aws:iam::\d{12}:mfa\//g,                   redactFrom: 20 },
  // GCP
  { name: "gcp_service_key",   regex: /"type"\s*:\s*"service_account"/g,              redactFrom: 20 },
  // Generic tokens
  { name: "bearer_token",      regex: /Bearer\s+[A-Za-z0-9\-_\.]{20,}/gi,            redactFrom: 14 },
  { name: "basic_auth_header", regex: /Authorization:\s*Basic\s+[A-Za-z0-9+\/=]{20,}/gi, redactFrom: 28 },
  // API keys by common variable names
  { name: "api_key_var",       regex: /(?:api[_-]?key|apikey|api_secret|client_secret)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{16,}['"]?/gi, redactFrom: 12 },
  // JWT
  { name: "jwt_token",         regex: /eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g, redactFrom: 10 },
  // GitHub PAT
  { name: "github_pat",        regex: /ghp_[A-Za-z0-9]{36}/g,                        redactFrom: 8 },
  { name: "github_oauth",      regex: /gho_[A-Za-z0-9]{36}/g,                        redactFrom: 8 },
  // Stripe
  { name: "stripe_secret",     regex: /sk_live_[A-Za-z0-9]{24,}/g,                   redactFrom: 10 },
  { name: "stripe_publishable", regex: /pk_live_[A-Za-z0-9]{24,}/g,                  redactFrom: 10 },
  // Slack
  { name: "slack_token",       regex: /xox[baprs]-[A-Za-z0-9\-]{16,}/g,             redactFrom: 12 },
  // Twilio
  { name: "twilio_account",    regex: /AC[a-z0-9]{32}/g,                             redactFrom: 8 },
  // Private keys
  { name: "private_key_pem",   regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,   redactFrom: 30 },
  // Password in URL
  { name: "password_in_url",   regex: /(?:password|passwd|pwd)=[^&\s"']{6,}/gi,      redactFrom: 12 },
  // DB connection strings
  { name: "db_connection",     regex: /(?:mysql|postgres|mongodb|redis):\/\/[^:]+:[^@]+@[^\s"']+/gi, redactFrom: 16 },
  // Sendgrid
  { name: "sendgrid_key",      regex: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, redactFrom: 8 },
  // Generic secret patterns
  { name: "generic_secret",    regex: /(?:secret|token|password|passwd|auth_key)\s*[:=]\s*['"]?[A-Za-z0-9+\/=\-_\.!@#$%^&*]{16,64}['"]?/gi, redactFrom: 10 },
];

// Paths likely to contain JS/JSON with secrets
const SCAN_PATHS = [
  "/", "/index.html", "/app.js", "/bundle.js", "/main.js",
  "/static/js/main.chunk.js", "/static/js/bundle.js",
  "/.env", "/.env.local", "/.env.production",
  "/config.js", "/config.json", "/settings.json",
  "/api/config", "/api/settings", "/api/env",
  "/robots.txt", "/.git/config",
  "/wp-config.php", "/wp-content/debug.log",
  "/phpinfo.php", "/server-status",
];

class SecretScanner {
  async scan(baseUrl: string, authHeaders: Record<string, string> = {}): Promise<SecretScanResult> {
    const base = this.extractBase(baseUrl);
    const matches: SecretMatch[] = [];
    let urlsScanned = 0;

    const results = await Promise.allSettled(
      SCAN_PATHS.map(path => this.fetchAndScan(`${base}${path}`, authHeaders))
    );

    for (const result of results) {
      if (result.status === "fulfilled" && result.value) {
        urlsScanned++;
        matches.push(...result.value);
      }
    }

    // Deduplicate by type+value prefix
    const seen = new Set<string>();
    const unique = matches.filter(m => {
      const key = `${m.type}:${m.value.slice(0, 12)}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const hypotheses = unique.length > 0 ? [{
      vulnClass: "info_disclosure",
      reasoning: `Secret scanning found ${unique.length} potential credential leak(s) in ${base}: ${unique.map(m => m.type).join(", ")}`,
      confidence: Math.min(0.9, 0.5 + unique.length * 0.1),
      priority: unique.some(m => m.type.includes("aws") || m.type === "private_key_pem") ? 10 : 8,
      // Representative anchor — the first secret's actual URL, not the bare
      // base — since re-verification needs a real page to fetch.
      endpoint: unique[0].url,
    }] : [];

    if (unique.length > 0) {
      logger.warn("[SecretScanner] Potential secrets found", {
        base,
        count: unique.length,
        types: [...new Set(unique.map(m => m.type))],
      });
    }

    return { matches: unique, urlsScanned, hypotheses };
  }

  private async fetchAndScan(url: string, headers: Record<string, string>): Promise<SecretMatch[] | null> {
    try {
      const resp = await axios.get(url, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)", ...headers },
        timeout: 5000,
        validateStatus: s => s < 500,
        responseType: "text",
        maxRedirects: 2,
      });

      if (resp.status !== 200) return null;
      const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
      if (body.length > 2_000_000) return null; // skip huge files

      return this.scanBody(body, url);
    } catch {
      return null;
    }
  }

  /** Public: reused by error-disclosure-prober.ts to run the same credential/
   *  secret regex set against deliberately-provoked error response bodies,
   *  which fetchAndScan() never sees (it excludes non-200 responses). */
  scanBody(body: string, url: string): SecretMatch[] {
    const matches: SecretMatch[] = [];

    for (const { name, regex, redactFrom } of SECRET_PATTERNS) {
      regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(body)) !== null) {
        const raw = match[0];
        const redacted = raw.length > redactFrom
          ? raw.slice(0, redactFrom) + "…[REDACTED]"
          : raw.slice(0, redactFrom) + "…";
        const ctxStart = Math.max(0, match.index - 20);
        const ctxEnd = Math.min(body.length, match.index + raw.length + 20);
        matches.push({
          type: name,
          value: redacted,
          pattern: name,
          url,
          context: body.slice(ctxStart, ctxEnd).replace(/\n/g, " ").trim(),
        });
        if (matches.length > 50) break; // cap per URL
      }
      if (matches.length > 50) break;
    }

    return matches;
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

export const secretScanner = new SecretScanner();

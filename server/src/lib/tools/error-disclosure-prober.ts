/**
 * Error-disclosure prober — deliberately provokes exceptions with malformed
 * input and inspects the error response for leaked secrets, stack traces, or
 * internal file paths.
 *
 * secret-scanner.ts only ever fetches a fixed list of static paths and
 * explicitly excludes non-200 responses (fetchAndScan: `validateStatus: s =>
 * s < 500`, then `if (resp.status !== 200) return null`) — an app that echoes
 * raw error.message back to the client on failure (a common pattern: routes
 * doing little more than `catch (e) { res.status(400).json({ error:
 * e.message }) }`) is invisible to that scan entirely, no matter how many
 * secrets or paths leak through it. Proven live 2026-07-10 against a real
 * target: hardcoded default creds leaked in an error message, and raw
 * error.message returned to the client across ~6 routes, leaking internal
 * filesystem paths.
 */
import axios from "axios";
import logger from "../../utils/logger";
import { secretScanner } from "./secret-scanner";
import { payloadMutator } from "./payload-mutator";

export interface DisclosureFinding {
  url: string;
  technique: string;
  status: number;
  secretsFound: string[];
  pathsLeaked: string[];
  detail: string;
}

export interface ErrorDisclosureResult {
  attempted: number;
  findings: DisclosureFinding[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string }>;
}

// Node/Express-flavored stack-trace and internal-path signatures — distinct
// from secret-scanner's credential patterns, this catches the "raw
// error.message returned to client" class even when no actual credential is
// embedded in the leaked text.
const DISCLOSURE_PATTERNS: Array<{ name: string; regex: RegExp }> = [
  { name: "stack_trace_frame",     regex: /at\s+(?:Object\.|async )?\S+\s*\([^)]*:\d+:\d+\)/ },
  { name: "source_line_ref",       regex: /\.(?:ts|js):\d+:\d+/ },
  { name: "node_modules_path",     regex: /node_modules\/[^\s"'<>]+/ },
  { name: "unix_absolute_path",    regex: /\/(?:home|usr|var|etc|opt|root)\/[^\s"'<>]{3,}/ },
  { name: "windows_absolute_path", regex: /[A-Z]:\\[^\s"'<>]{3,}/ },
  { name: "node_error_class",      regex: /\b(?:TypeError|ReferenceError|SyntaxError|RangeError):\s+\S/ },
  { name: "system_errno",          regex: /\b(?:ENOENT|ECONNREFUSED|EACCES|ETIMEDOUT|ECONNRESET)\b/ },
  { name: "db_driver_error",       regex: /\b(?:PostgresError|MongoError|SequelizeError|SqliteError|MySqlError|pg_query|SQLSTATE)\b/i },
];

function scanForDisclosure(body: string): string[] {
  const hits: string[] = [];
  for (const { name, regex } of DISCLOSURE_PATTERNS) {
    if (regex.test(body)) hits.push(name);
  }
  return hits;
}

class ErrorDisclosureProber {
  async probe(targetUrl: string, authHeaders: Record<string, string> = {}): Promise<ErrorDisclosureResult> {
    const findings: DisclosureFinding[] = [];
    let attempted = 0;

    const params = payloadMutator.findInjectableParams(targetUrl);
    const attempts: Array<{ technique: string; url: string; method: "GET" | "POST"; body?: string }> = [];

    // 1. Non-numeric value in place of what looks like a numeric id/param —
    //    a naive `parseInt(req.query.id)` or a DB driver rejecting a bad type
    //    is a classic unhandled-exception trigger.
    for (const p of params.slice(0, 5)) {
      attempts.push({ technique: `non_numeric:${p}`, url: payloadMutator.injectPayload(targetUrl, p, "not_a_number_zzz"), method: "GET" });
    }

    // 2. Null-byte injection — trips path/string handling in some frameworks.
    for (const p of params.slice(0, 3)) {
      attempts.push({ technique: `null_byte:${p}`, url: payloadMutator.injectPayload(targetUrl, p, "test%00.json"), method: "GET" });
    }

    // 3. Oversized value — some parsers/validators throw on length rather
    //    than truncating or rejecting cleanly.
    if (params.length > 0) {
      attempts.push({ technique: `oversized:${params[0]}`, url: payloadMutator.injectPayload(targetUrl, params[0], "A".repeat(10_000)), method: "GET" });
    }

    // 4. Malformed JSON body on a POST — a bare unhandled JSON.parse() throw
    //    (before any express.json() error middleware catches it) is one of
    //    the most common sources of a raw stack trace reaching the client.
    attempts.push({ technique: "malformed_json_body", url: targetUrl, method: "POST", body: '{"unterminated": "json' });

    for (const attempt of attempts) {
      attempted++;
      try {
        const resp = await axios.request({
          url: attempt.url,
          method: attempt.method,
          data: attempt.body,
          headers: { ...authHeaders, "Content-Type": "application/json" },
          timeout: 6000,
          validateStatus: () => true,
        });

        // Deliberately does NOT require status >= 400 — some apps return 200
        // with the error embedded in the JSON body instead of a real error
        // status. Scanning is driven by content shape, not status code.
        const body = typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
        if (!body || body.length < 5) continue;

        const secretMatches = secretScanner.scanBody(body, attempt.url);
        const pathsLeaked = scanForDisclosure(body);

        if (secretMatches.length > 0 || pathsLeaked.length > 0) {
          findings.push({
            url: attempt.url,
            technique: attempt.technique,
            status: resp.status,
            secretsFound: secretMatches.map(m => m.type),
            pathsLeaked,
            detail: secretMatches.length > 0
              ? `Error response leaked credential-shaped content [${secretMatches.map(m => m.type).join(", ")}] via ${attempt.technique}`
              : `Error response leaked internal path/stack-trace content [${pathsLeaked.join(", ")}] via ${attempt.technique}`,
          });
        }
      } catch (err) {
        logger.debug(`[ErrorDisclosureProber] Attempt failed (non-critical): ${attempt.technique}: ${(err as Error).message}`);
      }
    }

    const hypotheses = findings.map(f => ({
      vulnClass: "info_disclosure",
      reasoning: f.detail,
      confidence: f.secretsFound.length > 0 ? 0.85 : 0.65,
      priority: f.secretsFound.length > 0 ? 9 : 6,
      endpoint: f.url,
    }));

    if (findings.length > 0) {
      logger.info(`[ErrorDisclosureProber] ${findings.length} error-triggered disclosure(s) found at ${targetUrl}`);
    }

    return { attempted, findings, hypotheses };
  }
}

export const errorDisclosureProber = new ErrorDisclosureProber();
export default ErrorDisclosureProber;

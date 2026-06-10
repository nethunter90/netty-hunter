import winston from "winston";

const { combine, timestamp, colorize, printf, json } = winston.format;

// ─── Secret Redaction ─────────────────────────────────────────────────────────
// Patterns that must never appear in log output — API keys, session secrets,
// auth tokens. Applied to the full serialized meta string before output.
const SECRET_PATTERNS: Array<[RegExp, string]> = [
  // Anthropic API key (sk-ant-...)
  [/sk-ant-api[0-9A-Za-z_-]{20,}/g, "[ANTHROPIC_KEY_REDACTED]"],
  // Bearer tokens / JWT (three base64url segments)
  [/Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g, "Bearer [JWT_REDACTED]"],
  // Standalone JWTs in values
  [/\b[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\b/g, "[JWT_REDACTED]"],
  // Generic API keys: key/token/secret fields with long alphanumeric values
  [/("(?:api_?key|api_?token|access_?token|secret|password|authorization)"\s*:\s*)"[^"]{12,}"/gi,
    '$1"[REDACTED]"'],
  // NVD API key pattern
  [/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g, "[UUID_KEY_REDACTED]"],
];

function redactSecrets(value: unknown): unknown {
  if (typeof value === "string") {
    let s = value;
    for (const [pattern, replacement] of SECRET_PATTERNS) {
      s = s.replace(pattern, replacement);
    }
    return s;
  }
  if (typeof value === "object" && value !== null) {
    if (Array.isArray(value)) return value.map(redactSecrets);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // Redact known-sensitive key names entirely
      if (/secret|password|api.?key|api.?token|authorization|bearer/i.test(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = redactSecrets(v);
      }
    }
    return out;
  }
  return value;
}

const redactFormat = winston.format((info) => {
  // Redact the message string itself
  if (typeof info.message === "string") {
    let m = info.message;
    for (const [p, r] of SECRET_PATTERNS) m = m.replace(p, r);
    info.message = m;
  }
  // Redact all meta fields
  for (const key of Object.keys(info)) {
    if (key === "level" || key === "timestamp" || key === "message") continue;
    (info as Record<string, unknown>)[key] = redactSecrets((info as Record<string, unknown>)[key]);
  }
  return info;
});

// ─── Formats ──────────────────────────────────────────────────────────────────
const devFormat = printf(({ level, message, timestamp, ...meta }) => {
  const metaStr = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : "";
  return `${timestamp} [${level}] ${message}${metaStr}`;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: combine(
    timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
    redactFormat(),
    process.env.NODE_ENV === "production" ? json() : combine(colorize(), devFormat)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: "logs/error.log",
      level: "error",
      maxsize: 10 * 1024 * 1024,
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: "logs/combined.log",
      maxsize: 50 * 1024 * 1024,
      maxFiles: 10,
    }),
  ],
});

export default logger;

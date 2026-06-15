/**
 * Nuclei JSONL output parser.
 * Converts raw nuclei -json output into structured findings with severity,
 * CVE/CWE metadata, matched evidence, and confidence scores.
 */

export interface NucleiMatch {
  templateId: string;
  templateName: string;
  severity: "info" | "low" | "medium" | "high" | "critical" | "unknown";
  cvss: number | null;
  cveId: string | null;
  cweId: string | null;
  matcherName: string;
  extractedValues: string[];
  host: string;
  matchedAt: string;
  description: string;
  tags: string[];
  reference: string[];
  rawLine: string;
}

export interface NucleiParseResult {
  found: boolean;
  count: number;
  matches: NucleiMatch[];
  highestSeverity: NucleiMatch["severity"];
  confidence: number;
  flagValues: string[];
  rawOutput: string;
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 1.0,
  high: 0.85,
  medium: 0.7,
  low: 0.5,
  info: 0.3,
  unknown: 0.4,
};

const FLAG_RE = /flag\{[^}]+\}|\b[0-9a-f]{32}\b/gi;

export function parseNucleiOutput(raw: string): NucleiParseResult {
  const matches: NucleiMatch[] = [];
  const flagValues: string[] = [];

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      // Nuclei plain-text line — check for flags anyway
      const flagsInLine = trimmed.match(FLAG_RE);
      if (flagsInLine) flagValues.push(...flagsInLine);
      continue;
    }

    const info = (obj["info"] as Record<string, unknown>) || {};
    const severity = ((info["severity"] as string) || "unknown").toLowerCase() as NucleiMatch["severity"];
    const classification = (info["classification"] as Record<string, unknown>) || {};

    const cveIds = classification["cve-id"] as string[] | string | undefined;
    const cveId = Array.isArray(cveIds) ? cveIds[0] ?? null : (cveIds ?? null);

    const cweIds = classification["cwe-id"] as string[] | string | undefined;
    const cweId = Array.isArray(cweIds) ? cweIds[0] ?? null : (cweIds ?? null);

    const cvssScore = (classification["cvss-score"] as number) ?? null;

    const extracted = (obj["extracted-results"] as string[]) || [];
    const matcherName = (obj["matcher-name"] as string) || "";
    const host = (obj["host"] as string) || (obj["url"] as string) || "";
    const matchedAt = (obj["matched-at"] as string) || host;

    // Pull flag values from extracted results and matched-at
    for (const val of [...extracted, matchedAt, JSON.stringify(obj)]) {
      const found = String(val).match(FLAG_RE);
      if (found) flagValues.push(...found);
    }

    matches.push({
      templateId: (obj["template-id"] as string) || (obj["templateID"] as string) || "",
      templateName: (info["name"] as string) || "",
      severity,
      cvss: cvssScore,
      cveId,
      cweId,
      matcherName,
      extractedValues: extracted,
      host,
      matchedAt,
      description: (info["description"] as string) || "",
      tags: (info["tags"] as string[]) || [],
      reference: (info["reference"] as string[]) || [],
      rawLine: trimmed,
    });
  }

  const highestSeverity = matches.reduce<NucleiMatch["severity"]>((best, m) => {
    return (SEVERITY_WEIGHT[m.severity] ?? 0) > (SEVERITY_WEIGHT[best] ?? 0) ? m.severity : best;
  }, "unknown");

  const confidence = matches.length > 0
    ? Math.min(0.95, (SEVERITY_WEIGHT[highestSeverity] ?? 0.4) + (matches.length > 1 ? 0.1 : 0))
    : 0;

  return {
    found: matches.length > 0,
    count: matches.length,
    matches,
    highestSeverity,
    confidence,
    flagValues: [...new Set(flagValues)],
    rawOutput: raw.slice(0, 1200),
  };
}

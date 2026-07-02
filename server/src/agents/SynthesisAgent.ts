/**
 * SynthesisAgent — Cross-finding exploit chain synthesis.
 * After each hunt update, synthesizes confirmed findings into
 * chained hypotheses that automated single-vuln probes miss.
 */
import { ClaudeClient } from "../lib/claude-client";
import logger from "../utils/logger";

interface ConfirmedFinding {
  hypothesis: { id: string; vulnClass: string; targetUrl: string; reasoning: string };
  severity: string;
  exploitPayload: string;
}

export interface ChainedHypothesis {
  id: string;
  vulnClass: string;
  targetUrl: string;
  reasoning: string;
  confidence: number;
  priority: number;
  evidence: unknown[];
  status: "pending";
  createdAt: number;
  chainedFrom: string[];
}

export class SynthesisAgent {
  async synthesize(
    sessionId: string,
    confirmedFindings: ConfirmedFinding[],
    discoveredUrls: string[],
    testedVulnClasses: string[],
  ): Promise<ChainedHypothesis[]> {
    if (confirmedFindings.length < 1) return [];
    if (!ClaudeClient.isAvailable()) return [];

    const prompt = `You are analyzing confirmed vulnerability findings to identify exploit chains.

CONFIRMED FINDINGS:
${confirmedFindings.map((f, i) => `${i + 1}. ${f.hypothesis.vulnClass.toUpperCase()} at ${f.hypothesis.targetUrl} (${f.severity}) — ${f.hypothesis.reasoning.slice(0, 200)}`).join("\n")}

ALREADY TESTED: ${testedVulnClasses.join(", ")}

KNOWN URLS (sample): ${discoveredUrls.slice(0, 20).join(", ")}

CLASSIFICATION RULE: Path traversal payloads (../../) targeting files or directories are ALWAYS labeled \`lfi\` or \`path_traversal\` — NEVER \`sqli\`. This applies even when the target is a .sqlite file, database file, or database directory. \`sqli\` requires actual SQL injection into a database query, not reading a file via path traversal.

Identify exploit chains by combining these findings. Common patterns:
- XSS + CORS → exfiltrate authenticated data
- IDOR + info_disclosure → enumerate and extract all user records
- open_redirect + XSS → phishing + cookie theft
- auth_bypass + IDOR → full account takeover
- SSRF + internal → cloud metadata credential theft
- CSRF + auth_bypass → persistent account compromise
- SQLi + info_disclosure → credential dump
- lfi + info_disclosure → read source code, config files, or environment secrets via path traversal
- path_traversal + lfi → escalate from directory listing to arbitrary file read

For each chain worth pursuing, generate a chained hypothesis. Return JSON array:
[{
  "vulnClass": "string",
  "targetUrl": "string (most relevant endpoint from the finding URLs)",
  "reasoning": "string (specific chain logic — exactly how the two vulnerabilities combine)",
  "confidence": number (0.0-1.0),
  "priority": number (1-10),
  "chainedFrom": ["findingId1", "findingId2"]
}]

Return [] if no meaningful chains exist. Only include chains with confidence > 0.6.`;

    try {
      const response = await ClaudeClient.reason(sessionId, prompt);
      const match = response.match(/\[[\s\S]*\]/);
      if (!match) return [];

      const raw = JSON.parse(match[0]) as Array<{
        vulnClass: string;
        targetUrl: string;
        reasoning: string;
        confidence: number;
        priority: number;
        chainedFrom: string[];
      }>;

      return raw
        .filter(c => c.confidence > 0.6 && c.vulnClass && c.targetUrl)
        .map(c => ({
          id: `chain-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
          vulnClass: c.vulnClass,
          targetUrl: c.targetUrl,
          reasoning: c.reasoning,
          confidence: c.confidence,
          priority: c.priority ?? 7,
          evidence: [],
          status: "pending" as const,
          createdAt: Date.now(),
          chainedFrom: c.chainedFrom ?? [],
        }));
    } catch (err) {
      logger.debug("[SynthesisAgent] Chain synthesis failed (non-fatal)", { err: String(err) });
      return [];
    }
  }
}

export const synthesisAgent = new SynthesisAgent();

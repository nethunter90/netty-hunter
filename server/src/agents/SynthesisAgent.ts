/**
 * SynthesisAgent — cross-finding correlation pass.
 *
 * Runs after each update() phase to find attack chains that combine
 * two or more confirmed findings for higher-impact exploitation.
 * Operates on the same ClaudeClient conversation thread as the hunt
 * so it has full context of everything discovered so far.
 */
import { ClaudeClient } from "../lib/claude-client";
import logger from "../utils/logger";
import { v4 as uuidv4 } from "uuid";

// Minimal local types to avoid circular import with HunterEngine
interface ConfirmedFinding {
  hypothesis: {
    id: string;
    vulnClass: string;
    targetUrl: string;
    reasoning: string;
    confidence: number;
  };
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
  chainedFrom: string[];
  evidence: never[];
  status: "pending";
  createdAt: number;
  modelSource: "claude";
}

export class SynthesisAgent {
  async synthesize(
    sessionId: string,
    confirmedFindings: ConfirmedFinding[],
    discoveredUrls: string[],
    testedVulnClasses: string[],
  ): Promise<ChainedHypothesis[]> {
    if (confirmedFindings.length < 1) return [];

    const findingSummary = confirmedFindings.map(f => ({
      id: f.hypothesis.id,
      vulnClass: f.hypothesis.vulnClass,
      url: f.hypothesis.targetUrl,
      severity: f.severity,
      reasoning: f.hypothesis.reasoning.slice(0, 300),
    }));

    const prompt = `Cross-finding synthesis pass.

Confirmed findings so far:
${JSON.stringify(findingSummary, null, 2)}

Discovered endpoints (${discoveredUrls.length} total, showing first 30):
${discoveredUrls.slice(0, 30).join('\n')}

Already tested vulnerability classes: ${[...new Set(testedVulnClasses)].join(', ')}

Your task: identify attack CHAINS — combinations of 2 or more confirmed findings that together enable higher-impact exploitation than any individual finding alone.

Chain patterns to look for:
- XSS + CORS misconfiguration = cross-origin account takeover
- IDOR (ID enumeration) + info_disclosure (email/PII leak) = targeted attack at scale
- Open redirect + XSS = phishing with payload delivery
- Auth_bypass + IDOR = horizontal privilege escalation to any account
- SSRF + info_disclosure (internal IPs/services) = targeted internal service probing
- CSRF + auth_bypass = forced privileged action without user interaction
- SQLi (blind/error) + info_disclosure (table names/schema) = accelerated data extraction

For each chain you identify:
- targetUrl: the endpoint where the chain EXECUTES (the final impact step)
- reasoning: the full sequence — "Step 1: Use [finding A] to obtain X. Step 2: Use X with [finding B] to achieve Y."
- chainedFrom: array of finding IDs being combined
- confidence: higher than either individual finding if the chain is clearly executable
- priority: 8-10 — chains are high value

Return a JSON array (max 3 chains). Same schema as hypothesis generation plus chainedFrom:
[{
  "vulnClass": "auth_bypass",
  "targetUrl": "https://...",
  "reasoning": "...",
  "confidence": 0.8,
  "priority": 9,
  "chainedFrom": ["finding-id-1", "finding-id-2"]
}]

If no meaningful chains exist, return [].`;

    try {
      const response = await ClaudeClient.reason(sessionId, prompt);
      const raw = response.match(/\[[\s\S]*\]/)?.[0]?.slice(0, 32768) ?? "[]";
      const parsed = JSON.parse(raw) as Record<string, unknown>[];

      return parsed.slice(0, 3).map(h => ({
        id: uuidv4(),
        vulnClass: String(h.vulnClass ?? "info_disclosure"),
        targetUrl: String(h.targetUrl ?? ""),
        reasoning: String(h.reasoning ?? ""),
        confidence: Math.min(1, Math.max(0, Number(h.confidence) || 0.6)),
        priority: Math.min(10, Math.max(1, Number(h.priority) || 8)),
        chainedFrom: Array.isArray(h.chainedFrom) ? (h.chainedFrom as string[]) : [],
        evidence: [] as never[],
        status: "pending" as const,
        createdAt: Date.now(),
        modelSource: "claude" as const,
      }));
    } catch (err) {
      logger.warn("[SynthesisAgent] Chain synthesis failed", { err: String(err) });
      return [];
    }
  }
}

export const synthesisAgent = new SynthesisAgent();

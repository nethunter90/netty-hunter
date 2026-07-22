/**
 * Draft Report Generator
 * Auto-generates submission-ready bug bounty reports from verified findings.
 */
import { ModelRouter } from "./ModelRouter";
import logger from "../utils/logger";
import type { VerificationResult } from "../agents/VerifierAgent";
import type { SolverResult } from "../agents/SolverPool";

export interface BugBountyReport {
  title: string;
  severity: string;
  cvssScore: number;
  cvssVector: string;
  summary: string;
  vulnerability: string;
  impact: string;
  stepsToReproduce: string[];
  proofOfConcept: string;
  evidence: string[];
  affectedAssets: string[];
  remediation: string;
  references: string[];
  timeline: string;
  reportMarkdown: string;
  videoPath?: string;
}

const SEVERITY_TO_CVSS: Record<string, { score: number; vector: string }> = {
  critical: { score: 9.8, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  high: { score: 7.5, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" },
  medium: { score: 5.4, vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" },
  low: { score: 3.1, vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N" },
  info: { score: 0.0, vector: "N/A" },
};

const VULN_DESCRIPTIONS: Record<string, { name: string; description: string; remediation: string; refs: string[] }> = {
  xss: {
    name: "Cross-Site Scripting (XSS)",
    description: "The application reflects user-supplied input in the HTML response without proper encoding/sanitization, allowing an attacker to inject and execute malicious JavaScript in a victim's browser.",
    remediation: "1. Apply context-aware output encoding for all user-controlled data.\n2. Implement a strict Content-Security-Policy (CSP) header.\n3. Use a framework-level XSS protection mechanism (e.g., React's JSX auto-escaping).\n4. Validate and sanitize input on the server side using an allowlist approach.",
    refs: ["https://owasp.org/www-community/attacks/xss/", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/79.html"],
  },
  sqli: {
    name: "SQL Injection",
    description: "The application constructs SQL queries using unsanitized user input, enabling an attacker to manipulate database queries. This can lead to authentication bypass, data exfiltration, data modification, or in some cases, Remote Code Execution.",
    remediation: "1. Use parameterized queries (prepared statements) with bound parameters.\n2. Use an ORM that handles query construction safely.\n3. Apply the principle of least privilege to database accounts.\n4. Implement input validation and allowlist filtering.\n5. Deploy a WAF as a defense-in-depth measure.",
    refs: ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/89.html"],
  },
  ssrf: {
    name: "Server-Side Request Forgery (SSRF)",
    description: "The application makes HTTP requests to URLs controlled by an attacker, allowing interaction with internal network services, cloud metadata APIs, and potentially leading to credential theft or RCE.",
    remediation: "1. Use an allowlist of permitted URLs/domains for server-side requests.\n2. Block requests to private IP ranges (RFC 1918) and cloud metadata endpoints.\n3. Resolve DNS to IP before validating against an allowlist.\n4. Disable unnecessary URL schemes (file://, gopher://, dict://).\n5. Use a dedicated egress proxy for outbound requests.",
    refs: ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/918.html"],
  },
  idor: {
    name: "Insecure Direct Object Reference (IDOR)",
    description: "The application exposes internal object references (e.g., sequential IDs) without proper access control checks, allowing an attacker to access or modify data belonging to other users.",
    remediation: "1. Implement server-side access control checks for every object access.\n2. Use indirect object references (e.g., GUIDs instead of sequential IDs).\n3. Verify that the authenticated user is authorized to access the requested resource.\n4. Implement comprehensive audit logging for resource access.",
    refs: ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References", "https://cwe.mitre.org/data/definitions/639.html"],
  },
  open_redirect: {
    name: "Open Redirect",
    description: "The application accepts an unvalidated URL parameter and redirects users to external domains. This can be used for phishing attacks and bypassing URL-based security controls.",
    remediation: "1. Avoid using user-controlled input in redirect URLs.\n2. If redirects are needed, use an allowlist of permitted redirect destinations.\n3. Validate that the redirect target is a relative URL or belongs to your domain.\n4. Display a warning interstitial page before redirecting to external URLs.",
    refs: ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/601.html"],
  },
  lfi: {
    name: "Local File Inclusion / Path Traversal",
    description: "The application passes a user-controlled path parameter into a filesystem operation (file read or directory listing) without canonicalizing or validating it, allowing an attacker to supply `../` traversal sequences that escape the intended base directory and reach arbitrary locations on the filesystem.",
    remediation: "1. Canonicalize the resolved path (e.g. `path.resolve`/`realpath`) and verify it stays within the intended base directory before use.\n2. Reject any input containing `..` traversal sequences rather than attempting to strip them.\n3. Use an allowlist of permitted files/directories instead of accepting an arbitrary user-supplied path.\n4. Avoid passing user input directly to filesystem APIs (`fs.readdir`, `fs.readFile`, etc.) — map it to a fixed, pre-validated set of identifiers instead.",
    refs: ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/22.html"],
  },
  rce: {
    name: "Remote Command Execution",
    description: "The application passes user-controlled input into a shell command or command-execution sink without sanitization, allowing an attacker to inject additional commands that the server executes.",
    remediation: "1. Never pass user input to a shell (`exec`, `system`, backticks) — use a language-level API that doesn't invoke a shell (e.g. `execFile`/`spawn` with an argument array, not a concatenated string).\n2. If shell invocation is unavoidable, use strict allowlisting of permitted characters and reject anything containing shell metacharacters (`;`, `|`, `` ` ``, `$()`, `&`).\n3. Run the process under the minimum privilege required (dedicated low-privilege service account, not root/Administrator).\n4. Apply OS-level sandboxing (containers, seccomp, AppArmor) to limit blast radius if injection occurs.",
    refs: ["https://owasp.org/www-community/attacks/Command_Injection", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/78.html"],
  },
  info_disclosure: {
    name: "Information Disclosure",
    description: "The application exposes internal configuration, environment, or diagnostic data to unauthenticated or unauthorized requests without an access control check, allowing an attacker to learn details about the underlying system, stack, or configuration that should not be publicly reachable.",
    remediation: "1. Require authentication/authorization on any endpoint that returns configuration, environment, or diagnostic data.\n2. Remove or disable debug/diagnostic endpoints in production builds entirely rather than relying on obscurity.\n3. Audit what the endpoint actually returns and strip anything not required by legitimate clients (secrets, internal hostnames, stack traces, dependency versions).\n4. Apply the principle of least information — return only what the calling client needs, never a full environment/config dump.",
    refs: ["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/", "https://cwe.mitre.org/data/definitions/200.html"],
  },
};

/**
 * Per-vulnClass honesty policy (handoff Task 2c, generalized for Task 3):
 * shared scaffolding for "cite what was actually proven, never inflate the
 * claim" — the SHAPE is generic, but each policy's content is class-specific
 * because the overclaim risk and evidence shape genuinely differ (rce's proof
 * is a structured oracle marker + optional privilege; info_disclosure's proof
 * is a raw response body whose actual field names must be cited, not assumed).
 * A class with no policy entry falls back to the pre-existing generic
 * (non-inflating, but non-specific) wording — adding a class here is "write
 * one policy object," not "touch the shared pipeline."
 */
interface HonestyPolicy {
  /** Phrases that claim more than this class's proof method can establish. Stripped case-insensitively from AI and fallback text alike. */
  overclaimPhrases: string[];
  /** Verbose, LLM-facing instruction block citing the real proof facts. Null when no recognizable evidence for this class is present. */
  promptNote: (verification: VerificationResult, rawEvidence?: string) => string | null;
  /** Short, human-facing bullet(s) for the report's Evidence section. Empty array when nothing recognized. */
  evidenceLines: (verification: VerificationResult, rawEvidence?: string) => string[];
  /** Honest narrative used when AI generation fails (or omits impact) — must never say more than promptNote allows. */
  fallbackImpact: (finding: SolverResult, verification: VerificationResult, rawEvidence?: string) => string;
}

function stripOverclaims(vulnClass: string, text: string): string {
  const policy = HONESTY_POLICIES[vulnClass];
  if (!policy) return text;
  let cleaned = text;
  for (const phrase of policy.overclaimPhrases) {
    const re = new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    if (re.test(cleaned)) {
      logger.warn("ReportGenerator: stripped an over-claim phrase from generated report text", { vulnClass, phrase });
      cleaned = cleaned.replace(re, "the proven capability only");
    }
  }
  return cleaned;
}

// Extracts the proven privilege level from an `id`-style output if present in
// the oracle's evidence — e.g. "uid=33(www-data) gid=33(www-data)". Returns
// null when no such output is present, so callers never fabricate a privilege
// claim the oracle didn't actually demonstrate.
function extractProvenPrivilege(evidenceText: string): string | null {
  const match = evidenceText.match(/uid=\d+\([^)]*\)\s*gid=\d+\([^)]*\)[^\n]*/i) ?? evidenceText.match(/uid=\d+.*gid=\d+/i);
  return match ? match[0] : null;
}

// Field names that make a disclosure genuinely sensitive vs. merely
// diagnostic (NODE_ENV, PORT, uptime, etc.) — used to decide whether the
// honest report may call out "credential-shaped data" or must stick to
// neutral "configuration/environment data" language.
// No \b before the keyword — field names commonly prefix these with `_`
// (e.g. "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY"), and \b never matches between
// two word characters (underscore counts as one), so an anchored version
// silently misses the most common real-world naming convention.
const SENSITIVE_KEY_PATTERN = /(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key|auth)/i;

// Extracts KEY=VALUE / "key": "value" shaped tokens from a raw response body
// so the report can cite the ACTUAL field names observed rather than assuming
// what an env-dump endpoint returns. Deliberately conservative — returns keys
// only, never values, so a real secret value is never echoed into the report.
function extractDisclosedFieldNames(body: string): string[] {
  const keys = new Set<string>();
  for (const m of body.matchAll(/^([A-Z][A-Z0-9_]{2,})\s*=/gm)) keys.add(m[1]);
  for (const m of body.matchAll(/"([A-Za-z][A-Za-z0-9_]{2,})"\s*:/g)) keys.add(m[1]);
  return Array.from(keys).slice(0, 30);
}

const HONESTY_POLICIES: Partial<Record<string, HonestyPolicy>> = {
  rce: {
    overclaimPhrases: [
      "full compromise", "full server compromise", "complete compromise",
      "root access", "full rce", "system takeover", "total control",
      "compromise the entire", "compromise the server",
    ],
    promptNote: (verification, rawEvidence) => {
      const l2Snippet = verification.layer2_reprobe.responseSnippet ?? "";
      const nonceMatch = l2Snippet.match(/Command execution confirmed via nonce echo \(param="([^"]+)", payload="([^"]+)"\): ([\s\S]*)/);
      if (nonceMatch) {
        const [, param, payload, executedOutput] = nonceMatch;
        const privilege = extractProvenPrivilege(executedOutput);
        return (
          `PROVEN FACTS (cite these exactly, do not embellish):\n` +
          `- Proof method: nonce-echo command-injection oracle.\n` +
          `- Injectable parameter: \`${param}\`\n` +
          `- Payload: \`${payload}\`\n` +
          `- Executed output (nonce returned in command stdout, not reflected as literal input): ${executedOutput.slice(0, 300)}\n` +
          (privilege
            ? `- Proven privilege level (from \`id\` output): \`${privilege}\`\n`
            : `- No privilege-revealing output (e.g. \`id\`) was captured — do NOT state a privilege level.\n`) +
          `State ONLY "confirmed command execution"${privilege ? " with the privilege level above" : ""}. ` +
          `NEVER say "full compromise", "full server compromise", "root access", or "full RCE" — ` +
          `an execution oracle proves execution, not reach, persistence, or lateral movement.`
        );
      }
      // OOB callback path (method 1) — HunterEngine marks this in the probe
      // output as "OOB callback received — rce confirmed"; that's the only
      // fact available at report time for this path (no listener timestamp is
      // threaded through the current data model, so this doesn't fabricate one).
      const oobHit = /OOB callback received[^.]*rce confirmed/i.test(rawEvidence ?? "");
      if (oobHit) {
        return (
          `PROVEN FACTS (cite these exactly, do not embellish):\n` +
          `- Proof method: out-of-band (OOB) callback. The target made an outbound interaction to an ` +
          `attacker-controlled listener in response to the injected payload.\n` +
          `- No command output or privilege-revealing data was captured by this method — do NOT state a ` +
          `privilege level.\n` +
          `State ONLY "confirmed command execution via OOB callback; the target initiated an outbound interaction ` +
          `to an attacker-controlled listener". NEVER say "full compromise", "full server compromise", "root access", ` +
          `or "full RCE" — an OOB ping proves execution, not reach, persistence, or lateral movement.`
        );
      }
      return null;
    },
    evidenceLines: (verification) => {
      if (verification.adaptation) return [];
      const l2Snippet = verification.layer2_reprobe.responseSnippet ?? "";
      if (!l2Snippet.startsWith("Command execution confirmed via nonce echo")) return [];
      const lines = [l2Snippet.slice(0, 500)];
      const privilege = extractProvenPrivilege(l2Snippet);
      if (privilege) lines.push(`Proven privilege level (from \`id\` output): \`${privilege}\``);
      return lines;
    },
    fallbackImpact: (finding, verification, rawEvidence) => {
      const note = HONESTY_POLICIES.rce!.promptNote(verification, rawEvidence);
      if (!note) {
        return `Command execution was reported at ${finding.endpoint}, but no oracle evidence (nonce-echo or OOB) was available to cite — verify manually before submission.`;
      }
      const privilegeLine = note.includes("do NOT state a privilege level") ? "" : ` Proven privilege level is noted in the evidence section.`;
      return `Confirmed command execution at ${finding.endpoint}.${privilegeLine} This proves the target executes attacker-supplied commands; it does not by itself establish further reach, persistence, or data access beyond what was directly observed.`;
    },
  },

  info_disclosure: {
    overclaimPhrases: [
      "all environment secrets", "full database access", "complete database access",
      "full database dump", "entire user database", "access to all user accounts",
      "full system compromise", "all credentials exposed", "complete system access",
    ],
    promptNote: (verification, rawEvidence) => {
      const body = rawEvidence ?? verification.layer2_reprobe.responseSnippet ?? "";
      const fields = extractDisclosedFieldNames(body);
      if (fields.length === 0) return null;
      const sensitiveFields = fields.filter(f => SENSITIVE_KEY_PATTERN.test(f));
      return (
        `PROVEN FACTS (cite these exactly, do not embellish):\n` +
        `- Proof method: unauthenticated/unauthorized request returned the response body captured above.\n` +
        `- Field names actually observed in the response: ${fields.map(f => `\`${f}\``).join(", ")}\n` +
        (sensitiveFields.length > 0
          ? `- Among these, the following are credential/secret-SHAPED field names (cite the NAME only — do not restate the value even if you can see it): ${sensitiveFields.map(f => `\`${f}\``).join(", ")}\n`
          : `- None of the observed field names look like credentials/secrets — describe this as configuration/diagnostic data exposure, not a credential leak.\n`) +
        `Cite ONLY the field names listed above as what was disclosed. Do NOT claim "database access", "all user data", or "full system compromise" — ` +
        `this proof method demonstrates disclosure of exactly these fields from exactly this endpoint, nothing more.`
      );
    },
    evidenceLines: (verification, rawEvidence) => {
      const body = rawEvidence ?? verification.layer2_reprobe.responseSnippet ?? "";
      const fields = extractDisclosedFieldNames(body);
      if (fields.length === 0) return [];
      const sensitiveFields = fields.filter(f => SENSITIVE_KEY_PATTERN.test(f));
      const lines = [`Disclosed field names observed in response: ${fields.join(", ")}`];
      if (sensitiveFields.length > 0) lines.push(`Credential/secret-shaped field names present: ${sensitiveFields.join(", ")}`);
      return lines;
    },
    fallbackImpact: (finding, verification, rawEvidence) => {
      const body = rawEvidence ?? verification.layer2_reprobe.responseSnippet ?? "";
      const fields = extractDisclosedFieldNames(body);
      if (fields.length === 0) {
        return `Unauthenticated access to ${finding.endpoint} returned response data — verify the specific fields disclosed manually before submission.`;
      }
      const sensitiveFields = fields.filter(f => SENSITIVE_KEY_PATTERN.test(f));
      const sensitiveNote = sensitiveFields.length > 0
        ? ` This includes credential/secret-shaped fields (${sensitiveFields.join(", ")}), which materially raises severity.`
        : ` These are configuration/diagnostic values, not credentials.`;
      return `Unauthenticated access to ${finding.endpoint} discloses the following fields without access control: ${fields.join(", ")}.${sensitiveNote} This does not by itself demonstrate database access, other users' data, or broader system compromise.`;
    },
  },
};

export class DraftReportGenerator {
  private modelRouter = ModelRouter.getInstance();

  async generate(
    finding: SolverResult,
    verification: VerificationResult,
    metadata: {
      severity: string;
      programName: string;
      targetUrl: string;
      huntDate: string;
      rawEvidence?: string;
      videoPath?: string;
      // 2026-07-22 (budget chokepoint fix): required so generateAIContent()'s
      // LLM call has a real budget key instead of ModelRouter's old shared
      // "default" fallback (a cross-hunt/cross-caller budget-counter collision
      // risk — see ModelRouter.generate()'s fail-closed check on this exact gap).
      sessionId: string;
      /**
       * 2026-07-22 (budget chokepoint Phase 3 must-have #2): false when the
       * finding's impact demonstration was cut short by the LLM dollar cap
       * (PostExploitAgent's ImpactAssessment.evidenceComplete). A truncated
       * demonstration must not read as a fully-proven, submission-ready
       * report — this flips the timeline status and adds a caveat line
       * instead of silently presenting thin evidence as complete.
       */
      evidenceComplete?: boolean;
    }
  ): Promise<BugBountyReport> {
    // Veto-path invariant (handoff 2c.3): a non-confirmed finding must produce
    // NO report at all, regardless of vulnClass — never a low-confidence one,
    // never a "possible" note. This is enforced HERE, structurally, rather
    // than trusting every caller to filter correctly upstream (callers today
    // do filter correctly — CampaignOrchestrator's Layer5→Layer6 split and
    // ReportGeneratorStore's `verificationStatus === 'confirmed'` filter — but
    // a future caller that forgets to filter would otherwise silently leak a
    // refused finding into a submittable report).
    if (verification.finalVerdict !== "confirmed") {
      throw new Error(
        `DraftReportGenerator.generate() refused: finding ${finding.taskId} has finalVerdict=` +
        `"${verification.finalVerdict}", not "confirmed" — reports are only generated for confirmed findings.`
      );
    }

    const vulnInfo = VULN_DESCRIPTIONS[finding.vulnClass] || {
      name: finding.vulnClass.toUpperCase(),
      description: `A ${finding.vulnClass} vulnerability was identified.`,
      remediation: "Apply appropriate security controls.",
      refs: [],
    };

    const cvssData = SEVERITY_TO_CVSS[metadata.severity] || SEVERITY_TO_CVSS.medium;

    // AI-enhanced impact, summary, and steps generation
    const aiEnhanced = await this.generateAIContent(finding, verification, metadata, vulnInfo);

    // Use AI-generated steps when raw HTTP evidence is available — they reference actual captured requests
    const stepsToReproduce = aiEnhanced.steps ?? this.buildReproductionSteps(finding, verification, metadata.rawEvidence);
    const evidence = this.buildEvidence(finding, verification, metadata.rawEvidence);
    if (metadata.evidenceComplete === false) {
      evidence.push(
        "CAVEAT: Impact demonstration was cut short by the hunt's LLM budget cap before all " +
        "planned proof steps ran. The vulnerability class itself is confirmed above, but the " +
        "impact evidence below is partial — verify manually before relying on it for severity/scope."
      );
    }

    const report: BugBountyReport = {
      title: `[${metadata.severity.toUpperCase()}] ${vulnInfo.name} in ${finding.endpoint}`,
      severity: metadata.severity,
      cvssScore: cvssData.score,
      cvssVector: cvssData.vector,
      summary: aiEnhanced.summary,
      vulnerability: vulnInfo.description,
      impact: aiEnhanced.impact,
      stepsToReproduce,
      proofOfConcept: this.buildPoC(finding, verification, metadata.rawEvidence, metadata.videoPath),
      evidence,
      affectedAssets: [finding.endpoint],
      remediation: vulnInfo.remediation,
      references: vulnInfo.refs,
      timeline: `**Discovered**: ${metadata.huntDate}\n**Verified**: ${new Date().toISOString().split("T")[0]}\n**Status**: ${metadata.evidenceComplete === false ? "Impact evidence incomplete (budget-truncated) — review before submission" : "Ready for submission"}`,
      reportMarkdown: "",
      videoPath: metadata.videoPath,
    };

    report.reportMarkdown = this.renderMarkdown(report, metadata.programName);

    logger.info("Report generated", {
      vulnClass: finding.vulnClass,
      severity: metadata.severity,
      endpoint: finding.endpoint,
    });

    return report;
  }

  private async generateAIContent(
    finding: SolverResult,
    verification: VerificationResult,
    metadata: { programName: string; targetUrl: string; rawEvidence?: string; videoPath?: string; sessionId: string },
    vulnInfo: { name: string; description: string }
  ): Promise<{ summary: string; impact: string; steps?: string[] }> {
    const hasRawHttp = !!metadata.rawEvidence;
    const rawSection = hasRawHttp
      ? `\n\nRAW HTTP EVIDENCE (captured during exploitation):\n\`\`\`\n${metadata.rawEvidence!.slice(0, 2500)}\n\`\`\``
      : "";

    const stepsInstruction = hasRawHttp
      ? `3. "steps": Array of exact, copy-paste reproduction steps derived from the raw HTTP evidence above. Each step should be a complete instruction a triager can follow — e.g. "Send POST /api/basket/add with body: {\\"ProductId\\":1,\\"quantity\\":-100}" or "Observe the 200 OK response containing another user's data". Reference specific endpoint paths, headers, and body values from the captured requests.`
      : `3. "steps": Array of specific reproduction steps for this vulnerability class. Be concrete — include the endpoint path, parameter names, and a realistic payload.`;

    // When a payload-adaptation retry is what actually confirmed this finding,
    // the ORIGINAL hypothesis (e.g. "reads /etc/passwd contents") is what was
    // hypothesized, not what was proven — only the adapted payload/response is
    // real evidence. Make that explicit so the model doesn't default to
    // describing the (unproven, more dramatic) original hypothesis.
    const adaptationNote = verification.adaptation
      ? `\n\nIMPORTANT — this finding was confirmed via an ADAPTED payload, not the original\n` +
        `one. The original payload FAILED verification (do not describe it as working or\n` +
        `cite it as the proof). The adapted payload "${verification.adaptation.adaptedPayload}"\n` +
        `is what actually succeeded, returning: ${verification.adaptation.responseSnippet.slice(0, 500)}\n` +
        `Describe ONLY what this adapted response demonstrates (e.g. a directory listing\n` +
        `proves path traversal / arbitrary directory read — it does NOT by itself prove file\n` +
        `content disclosure unless the response actually contains file contents).`
      : "";

    // Class-specific honesty constraint (handoff Task 2c, generalized Task 3):
    // cite the ACTUAL proof facts and forbid over-claiming beyond what that
    // class's proof method can establish. No-op for classes with no policy.
    const policy = HONESTY_POLICIES[finding.vulnClass];
    const honestyNote = policy
      ? (() => {
          const note = policy.promptNote(verification, metadata.rawEvidence);
          return note ? `\n\nIMPORTANT — HONESTY CONSTRAINT:\n${note}` : "";
        })()
      : "";

    const prompt = `Write professional bug bounty report content for the following confirmed vulnerability:

Vulnerability: ${vulnInfo.name}
Endpoint: ${finding.endpoint}
Target: ${metadata.targetUrl}
Program: ${metadata.programName}
Payload: ${finding.payload || "N/A"}
Verification confidence: ${Math.round(verification.finalConfidence * 100)}%
Browser alerts triggered: ${verification.layer3_playwright.consoleAlerts.join(", ") || "none"}${rawSection}${adaptationNote}${honestyNote}

Generate:
1. "summary": 2-3 sentence executive summary. Professional, factual, specific. If raw HTTP is provided, reference the actual endpoint and method observed. NEVER describe a stronger result than the evidence shows (e.g. if the evidence is a directory listing, say "directory listing" — do not say "file contents were read" unless the response body actually contains file contents).
2. "impact": A focused paragraph on the business/security impact — what an attacker gains, what data is exposed, what invariants are broken. Ground this in what was actually demonstrated; further escalation potential may be noted as a possibility but must be clearly distinguished from what was proven.
${stepsInstruction}

Return ONLY valid JSON (no markdown fences): { "summary": "...", "impact": "...", "steps": ["step1", "step2", ...] }`;

    try {
      const response = await this.modelRouter.generate(prompt, "analyze", { sessionId: metadata.sessionId });
      const match = response.match(/\{[\s\S]+\}/);
      const parsed = JSON.parse(match?.[0] || "{}");
      const summary = parsed.summary || `A ${vulnInfo.name} vulnerability was discovered and verified at ${finding.endpoint}.`;
      const impact = parsed.impact || (policy
        ? policy.fallbackImpact(finding, verification, metadata.rawEvidence)
        : `This vulnerability poses a significant security risk to ${metadata.programName} and its users.`);
      return {
        // Final safety net regardless of source (AI or fallback string) — a
        // policy-governed class must never carry an over-claim phrase, even
        // if the model ignored the prompt instruction.
        summary: policy ? stripOverclaims(finding.vulnClass, summary) : summary,
        impact: policy ? stripOverclaims(finding.vulnClass, impact) : impact,
        steps: Array.isArray(parsed.steps) && parsed.steps.length > 0 ? parsed.steps as string[] : undefined,
      };
    } catch (err) {
      logger.warn("ReportGenerator: AI content generation failed — using template fallback", {
        err: String(err),
        vulnClass: finding.vulnClass,
        endpoint: finding.endpoint,
      });
      return {
        summary: `A ${vulnInfo.name} vulnerability was discovered and verified at ${finding.endpoint} with ${Math.round(verification.finalConfidence * 100)}% confidence.`,
        impact: policy
          ? policy.fallbackImpact(finding, verification, metadata.rawEvidence)
          : `Successful exploitation of this vulnerability could allow an attacker to compromise user data and system integrity.`,
      };
    }
  }

  private buildReproductionSteps(finding: SolverResult, verification: VerificationResult, rawEvidence?: string): string[] {
    const steps = [
      `Navigate to the affected endpoint: \`${finding.endpoint}\``,
      `Intercept the request using a proxy (e.g., Burp Suite)`,
    ];

    if (finding.payload) {
      steps.push(`Inject the following payload: \`${finding.payload}\``);
    }

    if (rawEvidence) {
      // Extract the first request line for a specific reproduction step
      const firstReqLine = rawEvidence.split("\n").find(l => /^(GET|POST|PUT|DELETE|PATCH|HEAD)\s/.test(l));
      if (firstReqLine) {
        steps.push(`Send the following request: \`${firstReqLine}\``);
      }
    } else if (finding.request) {
      steps.push(`Send the modified request: \`${finding.request}\``);
    }

    steps.push(`Observe the response for evidence of the vulnerability`);

    if (verification.layer3_playwright.consoleAlerts.length > 0) {
      steps.push(`Observe browser dialog/alert: "${verification.layer3_playwright.consoleAlerts[0]}"`);
    }

    return steps;
  }

  private buildPoC(finding: SolverResult, verification: VerificationResult, rawEvidence?: string, videoPath?: string): string {
    let poc = `**Tool Used**: ${finding.toolsUsed.join(", ") || "automated probe"}\n\n`;

    if (rawEvidence) {
      poc += `**Raw HTTP Evidence**:\n\`\`\`http\n${rawEvidence.slice(0, 3000)}\n\`\`\`\n\n`;
    } else {
      poc += `**Request**:\n\`\`\`\n${finding.request || "N/A"}\n\`\`\`\n\n`;
      poc += `**Response**:\n\`\`\`\n${finding.response?.slice(0, 500) || "N/A"}\n\`\`\`\n\n`;
    }

    if (videoPath) {
      poc += `**Video PoC**: Recorded exploitation session — \`${videoPath}\`\n\n`;
    }
    // verification.layer3_playwright/consoleAlerts always describe the ORIGINAL
    // probe. When adaptation confirmed the finding, that screenshot/alert belongs
    // to the FAILED payload (e.g. a 400 error page) — citing it here as PoC would
    // misrepresent it as proof of the adapted result, so it's suppressed. The
    // adapted request/response is already shown above via rawEvidence.
    if (!verification.adaptation) {
      if (verification.layer3_playwright.screenshot) {
        poc += `**Screenshot**: [Attached – base64 encoded screenshot available]\n\n`;
      }
      if (verification.layer3_playwright.consoleAlerts.length > 0) {
        poc += `**Browser Alerts**: ${verification.layer3_playwright.consoleAlerts.join(", ")}\n`;
      }
    } else {
      poc += `**Note**: Confirmed via an adapted payload after the original payload failed for a mechanical reason (see Evidence section). The request/response above is the adapted proof; screenshot, if archived, is at \`evidence/<finding-id>/adapted_screenshot.png\`.\n`;
    }

    return poc;
  }

  private buildEvidence(finding: SolverResult, verification: VerificationResult, rawEvidence?: string): string[] {
    const evidence = [
      `Verification Confidence: ${Math.round(verification.finalConfidence * 100)}%`,
      `Payload: ${finding.payload || "N/A"}`,
    ];

    if (verification.adaptation) {
      // Layer 2/3/4 below describe the ORIGINAL payload, which failed for a
      // mechanical/endpoint-shape reason — the finding was actually confirmed
      // by the adapted payload/response shown in the Proof of Concept section.
      // Surface that explicitly so "NOT CONFIRMED" here doesn't read as
      // contradicting the confirmed verdict.
      evidence.push(
        `Confirmed via payload adaptation (rule: ${verification.adaptation.rule}) — the original payload below failed, ` +
        `the adapted payload \`${verification.adaptation.adaptedPayload}\` succeeded (HTTP ${verification.adaptation.statusCode}); see Proof of Concept.`
      );
    } else {
      evidence.push(`HTTP Response Status: ${verification.layer2_reprobe.statusCode}`);
    }

    evidence.push(
      `Layer 2 (HTTP Reprobe)${verification.adaptation ? " [original payload]" : ""}: ${verification.layer2_reprobe.confirmed ? "CONFIRMED" : "NOT CONFIRMED"}`,
      `Layer 3 (Browser Replay)${verification.adaptation ? " [original payload]" : ""}: ${verification.layer3_playwright.confirmed ? "CONFIRMED" : "NOT CONFIRMED"}`,
      `Layer 4 (AI Analysis)${verification.adaptation ? " [original payload]" : ""}: ${verification.layer4_ai.confirmed ? "CONFIRMED" : "NOT CONFIRMED"} - ${verification.layer4_ai.reasoning}`,
    );

    if (finding.toolsUsed.includes("sqlmap")) {
      evidence.push("sqlmap: Automated SQL injection tool confirmed vulnerability");
    }

    // Class-specific evidence citation (e.g. rce's proven param/payload/
    // privilege, info_disclosure's actual disclosed field names) — this is
    // what makes the finding submittable per handoff 2c/Task 3, rather than
    // leaving the Evidence section generic.
    const policy = HONESTY_POLICIES[finding.vulnClass];
    if (policy) {
      evidence.push(...policy.evidenceLines(verification, rawEvidence));
    }

    return evidence;
  }

  private renderMarkdown(report: BugBountyReport, programName: string): string {
    const videoSection = report.videoPath
      ? `\n## Video Proof of Concept\n**Recording**: \`${report.videoPath}\`\n> Submit this video file alongside the report for platforms requiring video PoC (Synack, Intigriti P1/P2).\n`
      : "";

    return `# ${report.title}

## Summary
${report.summary}

## Severity
**Severity**: ${report.severity.toUpperCase()}
**CVSS Score**: ${report.cvssScore} (${report.cvssScore >= 9 ? "Critical" : report.cvssScore >= 7 ? "High" : report.cvssScore >= 4 ? "Medium" : "Low"})
**CVSS Vector**: \`${report.cvssVector}\`

## Vulnerability Description
${report.vulnerability}

## Impact
${report.impact}

## Affected Asset(s)
${report.affectedAssets.map(a => `- \`${a}\``).join("\n")}

## Steps to Reproduce
${report.stepsToReproduce.map((s, i) => `${i + 1}. ${s}`).join("\n")}

## Proof of Concept
${report.proofOfConcept}${videoSection}
## Evidence
${report.evidence.map(e => `- ${e}`).join("\n")}

## Remediation
${report.remediation}

## References
${report.references.map(r => `- ${r}`).join("\n")}

## Timeline
${report.timeline}

---
*Report generated by Netty Hunter (Sentinel Primordial) – automated bug bounty intelligence platform*
*Program: ${programName}*
`;
  }
}

export default DraftReportGenerator;

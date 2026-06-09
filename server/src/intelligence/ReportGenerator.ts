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
    }
  ): Promise<BugBountyReport> {
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
    const evidence = this.buildEvidence(finding, verification);

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
      timeline: `**Discovered**: ${metadata.huntDate}\n**Verified**: ${new Date().toISOString().split("T")[0]}\n**Status**: Ready for submission`,
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
    metadata: { programName: string; targetUrl: string; rawEvidence?: string; videoPath?: string },
    vulnInfo: { name: string; description: string }
  ): Promise<{ summary: string; impact: string; steps?: string[] }> {
    const hasRawHttp = !!metadata.rawEvidence;
    const rawSection = hasRawHttp
      ? `\n\nRAW HTTP EVIDENCE (captured during exploitation):\n\`\`\`\n${metadata.rawEvidence!.slice(0, 2500)}\n\`\`\``
      : "";

    const stepsInstruction = hasRawHttp
      ? `3. "steps": Array of exact, copy-paste reproduction steps derived from the raw HTTP evidence above. Each step should be a complete instruction a triager can follow — e.g. "Send POST /api/basket/add with body: {\\"ProductId\\":1,\\"quantity\\":-100}" or "Observe the 200 OK response containing another user's data". Reference specific endpoint paths, headers, and body values from the captured requests.`
      : `3. "steps": Array of specific reproduction steps for this vulnerability class. Be concrete — include the endpoint path, parameter names, and a realistic payload.`;

    const prompt = `Write professional bug bounty report content for the following confirmed vulnerability:

Vulnerability: ${vulnInfo.name}
Endpoint: ${finding.endpoint}
Target: ${metadata.targetUrl}
Program: ${metadata.programName}
Payload: ${finding.payload || "N/A"}
Verification confidence: ${Math.round(verification.finalConfidence * 100)}%
Browser alerts triggered: ${verification.layer3_playwright.consoleAlerts.join(", ") || "none"}${rawSection}

Generate:
1. "summary": 2-3 sentence executive summary. Professional, factual, specific. If raw HTTP is provided, reference the actual endpoint and method observed.
2. "impact": A focused paragraph on the business/security impact — what an attacker gains, what data is exposed, what invariants are broken.
${stepsInstruction}

Return ONLY valid JSON (no markdown fences): { "summary": "...", "impact": "...", "steps": ["step1", "step2", ...] }`;

    try {
      const response = await this.modelRouter.generate(prompt, "analyze");
      const match = response.match(/\{[\s\S]+\}/);
      const parsed = JSON.parse(match?.[0] || "{}");
      return {
        summary: parsed.summary || `A ${vulnInfo.name} vulnerability was discovered and verified at ${finding.endpoint}.`,
        impact: parsed.impact || `This vulnerability poses a significant security risk to ${metadata.programName} and its users.`,
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
        impact: `Successful exploitation of this vulnerability could allow an attacker to compromise user data and system integrity.`,
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
    if (verification.layer3_playwright.screenshot) {
      poc += `**Screenshot**: [Attached – base64 encoded screenshot available]\n\n`;
    }
    if (verification.layer3_playwright.consoleAlerts.length > 0) {
      poc += `**Browser Alerts**: ${verification.layer3_playwright.consoleAlerts.join(", ")}\n`;
    }

    return poc;
  }

  private buildEvidence(finding: SolverResult, verification: VerificationResult): string[] {
    const evidence = [
      `HTTP Response Status: ${verification.layer2_reprobe.statusCode}`,
      `Verification Confidence: ${Math.round(verification.finalConfidence * 100)}%`,
      `Payload: ${finding.payload || "N/A"}`,
      `Layer 2 (HTTP Reprobe): ${verification.layer2_reprobe.confirmed ? "CONFIRMED" : "NOT CONFIRMED"}`,
      `Layer 3 (Browser Replay): ${verification.layer3_playwright.confirmed ? "CONFIRMED" : "NOT CONFIRMED"}`,
      `Layer 4 (AI Analysis): ${verification.layer4_ai.confirmed ? "CONFIRMED" : "NOT CONFIRMED"} - ${verification.layer4_ai.reasoning}`,
    ];

    if (finding.toolsUsed.includes("sqlmap")) {
      evidence.push("sqlmap: Automated SQL injection tool confirmed vulnerability");
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

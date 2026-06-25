import { Router, Request, Response } from "express";
import logger from "../utils/logger";

// Report export router.
//
//  POST /export – formats a finding into a platform-specific submission document.
//                 Body:  { finding, options: { format, includeRemediation } }
//                 Reply: { success: true, data: <markdown string> }
//                 (see DraftReports.tsx exportPlatform ~216).

const router = Router();

type Platform = "hackerone" | "bugcrowd" | "intigriti";

interface ExportFinding {
  id?: string;
  title?: string;
  type?: string;
  severity?: string;
  description?: string;
  stepsToReproduce?: string[];
  impact?: string;
  affectedEndpoint?: string;
  exploitPayload?: string;
  poc?: string;
  cvssScore?: number;
  cvssVector?: string;
}

const REMEDIATION_BY_TYPE: Record<string, string> = {
  xss: "Apply context-aware output encoding for all user-controlled data and enforce a strict Content-Security-Policy.",
  sqli: "Use parameterized queries / prepared statements and apply least-privilege to database accounts.",
  ssrf: "Validate and allowlist outbound request destinations; block private IP ranges and cloud metadata endpoints.",
  idor: "Enforce server-side authorization checks on every object access and use non-sequential identifiers.",
  open_redirect: "Allowlist redirect destinations and avoid using user-controlled input in redirect targets.",
};

function steps(finding: ExportFinding): string {
  const list = finding.stepsToReproduce && finding.stepsToReproduce.length > 0
    ? finding.stepsToReproduce
    : ["See the description above for reproduction details."];
  return list.map((s, i) => `${i + 1}. ${s.replace(/^[-\d.\s]+/, "")}`).join("\n");
}

function remediation(finding: ExportFinding): string {
  return REMEDIATION_BY_TYPE[(finding.type || "").toLowerCase()]
    || "Apply appropriate security controls to mitigate the described vulnerability.";
}

// Severity precision: append CVSS when the finding carries it. Absent → "" so the
// bare severity word (current behaviour) is preserved exactly. Never fabricated.
function cvssSuffix(f: ExportFinding): string {
  if (typeof f.cvssScore === "number" && f.cvssVector) return ` (CVSS ${f.cvssScore} — ${f.cvssVector})`;
  if (typeof f.cvssScore === "number") return ` (CVSS ${f.cvssScore})`;
  return "";
}

// Proof-of-Concept block — the concrete payload/request a triager needs to
// reproduce. Renders only when present; absent → "" so output is byte-identical
// to today for findings without a payload (the discriminating-negative case).
function pocBlock(f: ExportFinding, heading: string): string {
  const poc = (f.exploitPayload ?? f.poc ?? "").trim();
  if (!poc) return "";
  return `\n## ${heading}\n\`\`\`\n${poc}\n\`\`\`\n`;
}

// Each platform has slightly different section conventions. These produce
// submission-ready markdown tailored to each program's expectations.
function formatHackerOne(f: ExportFinding, includeRemediation: boolean): string {
  return `## Summary
${f.description || f.title || "Vulnerability report."}

## Vulnerability Type
${f.type || "N/A"}

## Severity
${(f.severity || "medium").toUpperCase()}${cvssSuffix(f)}

## Affected Endpoint / Asset
${f.affectedEndpoint || "N/A"}

## Steps To Reproduce
${steps(f)}
${pocBlock(f, "Proof of Concept")}
## Impact
${f.impact || "See description."}
${includeRemediation ? `\n## Remediation\n${remediation(f)}\n` : ""}`;
}

function formatBugcrowd(f: ExportFinding, includeRemediation: boolean): string {
  return `# ${f.title || "Vulnerability Submission"}

**VRT Category:** ${f.type || "N/A"}
**Severity:** ${(f.severity || "medium").toUpperCase()}${cvssSuffix(f)}
**Affected URL:** ${f.affectedEndpoint || "N/A"}

## Description
${f.description || "N/A"}

## Proof of Concept / Steps
${steps(f)}
${pocBlock(f, "Payload")}
## Business Impact
${f.impact || "See description."}
${includeRemediation ? `\n## Suggested Remediation\n${remediation(f)}\n` : ""}`;
}

function formatIntigriti(f: ExportFinding, includeRemediation: boolean): string {
  return `# ${f.title || "Submission"}

**Type:** ${f.type || "N/A"}
**Severity (CVSS band):** ${(f.severity || "medium").toUpperCase()}${cvssSuffix(f)}
**Endpoint:** ${f.affectedEndpoint || "N/A"}

## What is the issue?
${f.description || "N/A"}

## Steps to reproduce
${steps(f)}
${pocBlock(f, "Proof of Concept")}
## Impact
${f.impact || "See description."}
${includeRemediation ? `\n## Recommended fix\n${remediation(f)}\n` : ""}`;
}

const FORMATTERS: Record<Platform, (f: ExportFinding, r: boolean) => string> = {
  hackerone: formatHackerOne,
  bugcrowd: formatBugcrowd,
  intigriti: formatIntigriti,
};

// Exported for unit testing the format directly (no HTTP). The route below is
// the only production caller.
export { FORMATTERS };
export type { ExportFinding };

// ── POST /export ──────────────────────────────────────────────────────────────
router.post("/export", (req: Request, res: Response) => {
  try {
    const { finding, options } = req.body as {
      finding?: ExportFinding;
      options?: { format?: string; includeRemediation?: boolean };
    };

    if (!finding) {
      return res.status(400).json({ success: false, error: "finding is required" });
    }

    const format = (options?.format || "hackerone").toLowerCase() as Platform;
    const formatter = FORMATTERS[format];
    if (!formatter) {
      return res.status(400).json({
        success: false,
        error: `Unsupported format: ${format}. Supported: hackerone, bugcrowd, intigriti.`,
      });
    }

    const data = formatter(finding, options?.includeRemediation !== false);
    return res.json({ success: true, data, format });
  } catch (err: any) {
    logger.error("report-export:/export failed", { err: err.message });
    return res.status(500).json({ success: false, error: err.message });
  }
});

export default router;

import { Router, Request, Response } from "express";
import { db } from "../db";
import { findings } from "../db/schema";
import { eq } from "drizzle-orm";
import logger from "../utils/logger";

// Report export router.
//
//  POST /export – gate-checked, DB-authoritative platform export.
//                 Body:  { findingId: number, options: { format, includeRemediation } }
//                 Reply: { success: true, data: <markdown string> }
//
//  Gate: only findings with verificationStatus === "confirmed" can export.
//  All other states (pending, rejected, inconclusive, deduplicated) return 403.
//  No findingId or no matching DB row returns 400.
//
//  Data-plumbing: exploitPayload and cvssScore are populated from the DB row,
//  not from caller-supplied inline JSON. No fabrication when absent.

const router = Router();

type Platform = "hackerone" | "bugcrowd" | "intigriti";

export interface ExportFinding {
  findingId?: number;
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

// ── Gate ─────────────────────────────────────────────────────────────────────

type FindingRow = typeof findings.$inferSelect;

export type GateResult =
  | { allowed: false; httpStatus: 400 | 403; error: string }
  | { allowed: true; row: FindingRow };

/**
 * Gate check — exported for direct unit testing (no HTTP, no DB mock needed).
 * Enforces: only verificationStatus === "confirmed" permits export.
 * All other states fail closed. No row → 400. Wrong status → 403 with actual status.
 */
export function gateCheck(row: FindingRow | null | undefined, findingId: number): GateResult {
  if (!row) {
    return { allowed: false, httpStatus: 400, error: `no finding for id ${findingId}` };
  }
  if (row.verificationStatus !== "confirmed") {
    return {
      allowed: false,
      httpStatus: 403,
      error: `cannot export: finding status is '${row.verificationStatus}'`,
    };
  }
  return { allowed: true, row };
}

// ── Formatters ────────────────────────────────────────────────────────────────

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

function cvssSuffix(f: ExportFinding): string {
  if (typeof f.cvssScore === "number" && f.cvssVector) return ` (CVSS ${f.cvssScore} — ${f.cvssVector})`;
  if (typeof f.cvssScore === "number") return ` (CVSS ${f.cvssScore})`;
  return "";
}

function pocBlock(f: ExportFinding, heading: string): string {
  const poc = (f.exploitPayload ?? f.poc ?? "").trim();
  if (!poc) return "";
  return `\n## ${heading}\n\`\`\`\n${poc}\n\`\`\`\n`;
}

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

export { FORMATTERS };

// ── POST /export ──────────────────────────────────────────────────────────────

router.post("/export", async (req: Request, res: Response) => {
  try {
    const { findingId, options } = req.body as {
      findingId?: unknown;
      options?: { format?: string; includeRemediation?: boolean };
    };

    if (typeof findingId !== "number" || !Number.isInteger(findingId)) {
      return res.status(400).json({ success: false, error: "findingId (integer) is required" });
    }

    const rows = await db.select().from(findings).where(eq(findings.id, findingId)).limit(1);
    const gate = gateCheck(rows[0], findingId);
    if (!gate.allowed) {
      return res.status(gate.httpStatus).json({ success: false, error: gate.error });
    }
    const { row } = gate;

    const format = (options?.format || "hackerone").toLowerCase() as Platform;
    const formatter = FORMATTERS[format];
    if (!formatter) {
      return res.status(400).json({
        success: false,
        error: `Unsupported format: ${format}. Supported: hackerone, bugcrowd, intigriti.`,
      });
    }

    // Build ExportFinding from DB row — no inline caller data, no fabrication.
    // Fields absent on the row (null) are omitted so the formatter's existing
    // absent-field behaviour is preserved byte-identical to the prior output.
    const finding: ExportFinding = {
      findingId,
      title: row.title,
      type: row.vulnType,
      severity: row.severity,
      description: row.description,
      impact: row.impact ?? undefined,
      affectedEndpoint: row.affectedUrl ?? undefined,
      exploitPayload: row.exploitPayload ?? undefined,
      cvssScore: row.cvssScore ?? undefined,
    };

    const data = formatter(finding, options?.includeRemediation !== false);
    return res.json({ success: true, data, format });
  } catch (err: any) {
    logger.error("report-export:/export failed", { err: err.message });
    return res.status(500).json({ success: false, error: err.message });
  }
});

export default router;

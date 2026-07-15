/**
 * Report Submitter — actual API submission to bug bounty platforms.
 * Complements the existing formatter/optimizer in bounty-intelligence/index.ts
 * by adding real HTTP POST calls to each platform's submission API.
 */
import axios from "axios";
import logger from "../../utils/logger";
import { runtimeConfig } from '../runtime-config';

export interface SubmissionPayload {
  title: string;
  vulnType: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  description: string;
  reproductionSteps: string;
  impact: string;
  remediation?: string;
  cvssScore?: number;
  cweId?: number;
  cveId?: string;
  targetUrl: string;
  exploitPayload?: string;
  evidence?: string;
  programHandle: string;
  platform: "hackerone" | "bugcrowd" | "intigriti" | "yeswehack";
}

export interface SubmissionResult {
  success: boolean;
  reportId?: string;
  reportUrl?: string;
  platform: string;
  error?: string;
  draftOnly?: boolean;
}

const SEVERITY_TO_H1_RATING: Record<string, string> = {
  critical: "critical", high: "high", medium: "medium", low: "low", informational: "informational",
};

const SEVERITY_TO_BUGCROWD_PRIORITY: Record<string, number> = {
  critical: 1, high: 2, medium: 3, low: 4, informational: 5,
};

class ReportSubmitter {
  async submit(payload: SubmissionPayload): Promise<SubmissionResult> {
    if (!runtimeConfig.isPlatformEnabled(payload.platform)) {
      logger.warn("[ReportSubmitter] Platform disconnected — submission skipped", { platform: payload.platform });
      return { success: false, platform: payload.platform, draftOnly: true, error: `${payload.platform} is disconnected` };
    }

    switch (payload.platform) {
      case "hackerone":  return this.submitHackerOne(payload);
      case "bugcrowd":   return this.submitBugcrowd(payload);
      case "intigriti":  return this.submitIntigriti(payload);
      case "yeswehack":  return this.submitYesWeHack(payload);
      default:
        return { success: false, platform: payload.platform, error: "Unknown platform" };
    }
  }

  private async submitHackerOne(payload: SubmissionPayload): Promise<SubmissionResult> {
    const username = runtimeConfig.get("HACKERONE_USERNAME") || process.env.HACKERONE_USERNAME;
    const token = runtimeConfig.get("HACKERONE_TOKEN") || process.env.HACKERONE_API_TOKEN;
    if (!username || !token) {
      logger.warn("[ReportSubmitter] HackerOne credentials missing — report saved as draft only");
      return { success: false, platform: "hackerone", draftOnly: true, error: "Missing HACKERONE_USERNAME or HACKERONE_API_TOKEN" };
    }

    const body = this.buildH1Body(payload);

    try {
      const resp = await axios.post(
        "https://api.hackerone.com/v1/reports",
        {
          data: {
            type: "report",
            attributes: {
              title: payload.title,
              vulnerability_information: body,
              impact: payload.impact,
              weakness_id: payload.cweId ? await this.resolveH1WeaknessId(payload.cweId, username, token) : undefined,
              structured_scope_id: null,
              severity_rating: SEVERITY_TO_H1_RATING[payload.severity] || "medium",
            },
            relationships: {
              program: { data: { type: "program", id: payload.programHandle } },
            },
          },
        },
        {
          auth: { username, password: token },
          headers: { "Content-Type": "application/json", Accept: "application/json" },
          timeout: 30000,
          validateStatus: () => true,
        }
      );

      if (resp.status === 201) {
        const d = resp.data as Record<string, unknown>;
        const reportId = String((d?.data as Record<string, unknown>)?.id ?? "");
        const reportUrl = `https://hackerone.com/reports/${reportId}`;
        logger.info("[ReportSubmitter] HackerOne report submitted", { reportId, reportUrl });
        return { success: true, platform: "hackerone", reportId, reportUrl };
      }

      const errMsg = JSON.stringify((resp.data as Record<string, unknown>)?.errors ?? resp.statusText);
      logger.warn("[ReportSubmitter] HackerOne submission failed", { status: resp.status, error: errMsg });
      return { success: false, platform: "hackerone", error: errMsg };
    } catch (err) {
      logger.error("[ReportSubmitter] HackerOne network error", { err: String(err) });
      return { success: false, platform: "hackerone", error: String(err) };
    }
  }

  private async submitBugcrowd(payload: SubmissionPayload): Promise<SubmissionResult> {
    const token = process.env.BUGCROWD_API_TOKEN;
    if (!token) {
      return { success: false, platform: "bugcrowd", draftOnly: true, error: "Missing BUGCROWD_API_TOKEN" };
    }

    const body = this.buildMarkdownBody(payload);
    const priority = SEVERITY_TO_BUGCROWD_PRIORITY[payload.severity] ?? 3;

    try {
      const resp = await axios.post(
        `https://api.bugcrowd.com/submissions`,
        {
          data: {
            type: "submission",
            attributes: {
              title: payload.title,
              description: body,
              severity: priority,
              vrt_id: this.bugcrowdVRT(payload.vulnType),
              extra_info: `Target: ${payload.targetUrl}\nPayload: ${payload.exploitPayload ?? "N/A"}`,
            },
            relationships: {
              target_group: { data: { type: "target_group", id: payload.programHandle } },
            },
          },
        },
        {
          headers: {
            Authorization: `Token ${token}`,
            "Content-Type": "application/vnd.bugcrowd.v4+json",
            Accept: "application/vnd.bugcrowd.v4+json",
          },
          timeout: 30000,
          validateStatus: () => true,
        }
      );

      if (resp.status === 201 || resp.status === 200) {
        const d = resp.data as Record<string, unknown>;
        const sub = (d?.data as Record<string, unknown>);
        const reportId = String(sub?.id ?? "");
        logger.info("[ReportSubmitter] Bugcrowd submission created", { reportId });
        return { success: true, platform: "bugcrowd", reportId };
      }

      return { success: false, platform: "bugcrowd", error: JSON.stringify((resp.data as Record<string, unknown>)?.errors ?? resp.statusText) };
    } catch (err) {
      return { success: false, platform: "bugcrowd", error: String(err) };
    }
  }

  private async submitIntigriti(payload: SubmissionPayload): Promise<SubmissionResult> {
    const token = process.env.INTIGRITI_API_TOKEN;
    if (!token) {
      return { success: false, platform: "intigriti", draftOnly: true, error: "Missing INTIGRITI_API_TOKEN" };
    }

    const body = this.buildMarkdownBody(payload);

    try {
      const resp = await axios.post(
        `https://api.intigriti.com/core/public/programs/${payload.programHandle}/vulnerabilities`,
        {
          title: payload.title,
          description: body,
          severity: { vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, value: payload.cvssScore ?? 5.0 },
          type: { cweId: payload.cweId ? `CWE-${payload.cweId}` : "CWE-200" },
          endpoint: payload.targetUrl,
          proofOfConcept: payload.exploitPayload ?? payload.evidence ?? "See description",
          impact: payload.impact,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          timeout: 30000,
          validateStatus: () => true,
        }
      );

      if (resp.status === 200 || resp.status === 201) {
        const reportId = String((resp.data as Record<string, unknown>)?.id ?? "");
        logger.info("[ReportSubmitter] Intigriti vulnerability submitted", { reportId });
        return { success: true, platform: "intigriti", reportId };
      }

      return { success: false, platform: "intigriti", error: JSON.stringify(resp.data) };
    } catch (err) {
      return { success: false, platform: "intigriti", error: String(err) };
    }
  }

  private async submitYesWeHack(payload: SubmissionPayload): Promise<SubmissionResult> {
    const token = process.env.YESWEHACK_API_TOKEN;
    if (!token) {
      return { success: false, platform: "yeswehack", draftOnly: true, error: "Missing YESWEHACK_API_TOKEN" };
    }

    try {
      const resp = await axios.post(
        `https://api.yeswehack.com/programs/${payload.programHandle}/reports`,
        {
          title: payload.title,
          scope: payload.targetUrl,
          vulnerability_type: { id: this.ywvType(payload.vulnType) },
          cvss: payload.cvssScore ?? 5.0,
          description_html: this.buildHtmlBody(payload),
          poc_html: payload.exploitPayload ?? payload.evidence ?? "See description",
          impact_html: payload.impact,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          timeout: 30000,
          validateStatus: () => true,
        }
      );

      if (resp.status === 201 || resp.status === 200) {
        const reportId = String((resp.data as Record<string, unknown>)?.id ?? "");
        return { success: true, platform: "yeswehack", reportId };
      }

      return { success: false, platform: "yeswehack", error: JSON.stringify(resp.data) };
    } catch (err) {
      return { success: false, platform: "yeswehack", error: String(err) };
    }
  }

  private async resolveH1WeaknessId(cweId: number, username: string, token: string): Promise<number | undefined> {
    // Common CWE → H1 weakness ID mapping (avoids an API lookup on every submission)
    const CWE_TO_H1: Record<number, number> = {
      79: 86, 89: 67, 22: 17, 78: 58, 918: 840, 639: 359,
      287: 1, 352: 352, 611: 165, 601: 601, 200: 204, 16: 1389,
    };
    return CWE_TO_H1[cweId];
  }

  private buildH1Body(p: SubmissionPayload): string {
    return `## Summary\n${p.description}\n\n## Steps to Reproduce\n${p.reproductionSteps}\n\n## Supporting Material\n**Target:** ${p.targetUrl}\n**Payload:** \`${p.exploitPayload ?? "N/A"}\`\n\n## Impact\n${p.impact}\n\n## Recommended Fix\n${p.remediation ?? "Apply input validation and output encoding."}`;
  }

  private buildMarkdownBody(p: SubmissionPayload): string {
    return `## Description\n${p.description}\n\n## Steps to Reproduce\n${p.reproductionSteps}\n\n**Target URL:** ${p.targetUrl}\n**Payload:** \`${p.exploitPayload ?? "N/A"}\`\n\n## Impact\n${p.impact}\n\n## Remediation\n${p.remediation ?? "Apply input validation."}`;
  }

  private buildHtmlBody(p: SubmissionPayload): string {
    return `<h2>Description</h2><p>${p.description}</p><h2>Steps</h2><p>${p.reproductionSteps.replace(/\n/g, "<br>")}</p><h2>Target</h2><p>${p.targetUrl}</p>`;
  }

  private bugcrowdVRT(vulnType: string): string {
    const map: Record<string, string> = {
      xss: "cross_site_scripting_xss.reflected", sqli: "sql_injection",
      ssrf: "server_side_request_forgery_ssrf", lfi: "local_file_inclusion_lfi",
      rce: "remote_code_execution", idor: "broken_object_level_authorization",
      auth_bypass: "broken_authentication", csrf: "cross_site_request_forgery_csrf",
      xxe: "xml_external_entity_injection_xxe", cors: "sensitive_data_exposure.insecure_cors",
      open_redirect: "open_redirect", info_disclosure: "sensitive_data_exposure",
      misconfig: "security_misconfiguration",
    };
    return map[vulnType] ?? "other";
  }

  private ywvType(vulnType: string): number {
    const map: Record<string, number> = {
      xss: 1, sqli: 2, ssrf: 3, lfi: 4, rce: 5, idor: 6,
      auth_bypass: 7, csrf: 8, xxe: 9, cors: 10, misconfig: 11,
    };
    return map[vulnType] ?? 99;
  }
}

export const reportSubmitter = new ReportSubmitter();

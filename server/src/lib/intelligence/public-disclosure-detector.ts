/**
 * Public Disclosure Detector
 * Checks whether a confirmed finding has already been publicly disclosed
 * by another hunter on the same bug bounty program.
 *
 * Uses platform APIs (HackerOne, Bugcrowd, Intigriti) when tokens are
 * available. Fails open — if no token or API error, returns 'skipped'
 * so the finding is never blocked by an unavailable check.
 */
import logger from '../../utils/logger';
import { runtimeConfig } from '../runtime-config';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface PublicReport {
  id: string;
  title: string;
  vulnCategory: string;    // normalized to our vulnClass names
  severity: string;
  disclosedAt: string;
  url: string;
  affectedDomain?: string;
}

export type DisclosureStatus =
  | 'clear'
  | 'likely_duplicate'
  | 'confirmed_duplicate'
  | 'skipped';

export interface DisclosureCheckResult {
  status: DisclosureStatus;
  matchedReport?: PublicReport;
  reason?: string;
}

interface FindingContext {
  vulnClass: string;
  targetUrl: string;
}

interface ProgramContext {
  platform?: string | null;
  programHandle?: string | null;
}

// ── Vulnerability keyword mappings ─────────────────────────────────────────────

const VULN_MAP: Record<string, string[]> = {
  xss:          ['cross-site scripting', 'xss', 'html injection', 'script injection'],
  sqli:         ['sql injection', 'sqli', 'database injection', 'sql'],
  ssrf:         ['server-side request forgery', 'ssrf'],
  idor:         ['insecure direct object', 'idor', 'broken object level', 'bola'],
  rce:          ['remote code execution', 'rce', 'command injection', 'code execution'],
  xxe:          ['xml external entity', 'xxe', 'xml injection'],
  lfi:          ['local file inclusion', 'lfi', 'path traversal', 'directory traversal'],
  auth_bypass:  ['authentication bypass', 'broken auth', 'login bypass', 'account takeover'],
  open_redirect:['open redirect', 'unvalidated redirect'],
  csrf:         ['cross-site request forgery', 'csrf'],
  cors:         ['cors', 'cross-origin'],
  subdomain_takeover: ['subdomain takeover', 'dangling dns'],
  info_disclosure: ['information disclosure', 'sensitive data', 'data leak', 'pii'],
  misconfig:    ['misconfiguration', 'security misconfiguration'],
  exposed_admin:['exposed admin', 'admin panel', 'unauthenticated admin'],
};

// ── Main class ─────────────────────────────────────────────────────────────────

export class PublicDisclosureDetector {
  // Per-run cache: "platform:handle" → reports
  private cache = new Map<string, PublicReport[]>();

  clearCache() {
    this.cache.clear();
  }

  async check(
    finding: FindingContext,
    program: ProgramContext | null | undefined
  ): Promise<DisclosureCheckResult> {
    if (!program?.platform || !program?.programHandle) {
      return { status: 'skipped', reason: 'no platform/handle on program' };
    }

    const cacheKey = `${program.platform}:${program.programHandle}`;

    if (!this.cache.has(cacheKey)) {
      const reports = await this.fetchReports(program.platform, program.programHandle);
      this.cache.set(cacheKey, reports);
    }

    const reports = this.cache.get(cacheKey)!;

    if (reports.length === 0) {
      return { status: 'skipped', reason: 'no public reports available (token missing or API unavailable)' };
    }

    return this.matchScore(finding, reports);
  }

  private matchScore(finding: FindingContext, reports: PublicReport[]): DisclosureCheckResult {
    let targetDomain = '';
    try { targetDomain = new URL(finding.targetUrl).hostname; } catch { /* ignore */ }

    const keywords = VULN_MAP[finding.vulnClass] ?? [finding.vulnClass.toLowerCase()];

    for (const report of reports) {
      const categoryLower = report.vulnCategory.toLowerCase();
      const vulnMatch = keywords.some(kw => categoryLower.includes(kw));

      if (!vulnMatch) continue;

      // Check domain match
      const domainMatch = report.affectedDomain
        ? targetDomain && (
          report.affectedDomain.includes(targetDomain) ||
          targetDomain.includes(report.affectedDomain)
        )
        : false;

      if (vulnMatch && domainMatch) {
        return {
          status: 'confirmed_duplicate',
          matchedReport: report,
          reason: `${finding.vulnClass} already disclosed on same domain (${report.affectedDomain})`,
        };
      }

      if (vulnMatch) {
        return {
          status: 'likely_duplicate',
          matchedReport: report,
          reason: `${finding.vulnClass} type previously disclosed on this program`,
        };
      }
    }

    return { status: 'clear' };
  }

  private async fetchReports(platform: string, handle: string): Promise<PublicReport[]> {
    switch (platform.toLowerCase()) {
      case 'hackerone': return this.fetchHackerOne(handle);
      case 'bugcrowd':  return this.fetchBugcrowd(handle);
      case 'intigriti': return this.fetchIntigriti(handle);
      default:          return [];
    }
  }

  // ── HackerOne ─────────────────────────────────────────────────────────────

  private async fetchHackerOne(handle: string): Promise<PublicReport[]> {
    const username = runtimeConfig.get("HACKERONE_USERNAME") || process.env.HACKERONE_USERNAME;
    const token = runtimeConfig.get("HACKERONE_TOKEN") || process.env.HACKERONE_API_TOKEN;
    if (!username || !token) return [];

    try {
      const creds = Buffer.from(`${username}:${token}`).toString('base64');
      const resp = await fetch(
        `https://api.hackerone.com/v1/programs/${encodeURIComponent(handle)}/reports?filter[state][]=disclosed&page[size]=100`,
        {
          headers: {
            Authorization: `Basic ${creds}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(8000),
        }
      );

      if (!resp.ok) {
        logger.warn('[PublicDisclosureDetector] HackerOne API error', { status: resp.status, handle });
        return [];
      }

      const json = await resp.json() as { data?: any[] };
      return (json.data ?? []).map((r: any) => {
        const attrs = r.attributes ?? {};
        const weaknessName: string =
          r.relationships?.weakness?.data?.attributes?.name ?? '';
        return {
          id: String(r.id ?? ''),
          title: String(attrs.title ?? ''),
          vulnCategory: weaknessName.toLowerCase(),
          severity: String(attrs.severity_rating ?? 'medium'),
          disclosedAt: String(attrs.disclosed_at ?? ''),
          url: `https://hackerone.com/reports/${r.id}`,
          affectedDomain: this.extractDomain(String(attrs.vulnerability_information ?? '')),
        };
      });
    } catch (err: any) {
      logger.warn('[PublicDisclosureDetector] HackerOne fetch failed', { err: err.message });
      return [];
    }
  }

  // ── Bugcrowd ──────────────────────────────────────────────────────────────

  private async fetchBugcrowd(handle: string): Promise<PublicReport[]> {
    const token = process.env.BUGCROWD_API_TOKEN;
    if (!token) return [];

    try {
      const resp = await fetch(
        `https://api.bugcrowd.com/programs/${encodeURIComponent(handle)}/submissions?q[accepted]=true&page[size]=100`,
        {
          headers: {
            Authorization: `Token token=${token}`,
            Accept: 'application/vnd.bugcrowd+json; version=1',
          },
          signal: AbortSignal.timeout(8000),
        }
      );

      if (!resp.ok) {
        logger.warn('[PublicDisclosureDetector] Bugcrowd API error', { status: resp.status, handle });
        return [];
      }

      const json = await resp.json() as { submissions?: any[] };
      return (json.submissions ?? []).map((s: any) => ({
        id: String(s.reference ?? s.id ?? ''),
        title: String(s.title ?? ''),
        vulnCategory: String(s.vrt_label ?? s.vulnerability_type ?? '').toLowerCase(),
        severity: String(s.priority ?? 'medium'),
        disclosedAt: String(s.submitted_at ?? ''),
        url: `https://bugcrowd.com/submissions/${s.reference ?? s.id}`,
        affectedDomain: this.extractDomain(String(s.description ?? '')),
      }));
    } catch (err: any) {
      logger.warn('[PublicDisclosureDetector] Bugcrowd fetch failed', { err: err.message });
      return [];
    }
  }

  // ── Intigriti ────────────────────────────────────────────────────────────

  private async fetchIntigriti(handle: string): Promise<PublicReport[]> {
    const token = process.env.INTIGRITI_API_TOKEN;
    if (!token) return [];

    try {
      const resp = await fetch(
        `https://api.intigriti.com/core/researcher/submission?programId=${encodeURIComponent(handle)}&status=closed&limit=100`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(8000),
        }
      );

      if (!resp.ok) {
        logger.warn('[PublicDisclosureDetector] Intigriti API error', { status: resp.status, handle });
        return [];
      }

      const json = await resp.json() as { records?: any[] };
      return (json.records ?? []).map((r: any) => ({
        id: String(r.id ?? ''),
        title: String(r.title ?? ''),
        vulnCategory: String(r.type?.value ?? r.type ?? '').toLowerCase(),
        severity: String(r.severity?.value ?? 'medium'),
        disclosedAt: String(r.closedAt ?? ''),
        url: `https://app.intigriti.com/researcher/submissions/${r.id}`,
        affectedDomain: this.extractDomain(String(r.endpoint ?? '')),
      }));
    } catch (err: any) {
      logger.warn('[PublicDisclosureDetector] Intigriti fetch failed', { err: err.message });
      return [];
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  private extractDomain(text: string): string | undefined {
    const match = text.match(/https?:\/\/([^/\s"']+)/);
    if (!match) return undefined;
    try { return new URL(match[0]).hostname; } catch { return undefined; }
  }
}

export const publicDisclosureDetector = new PublicDisclosureDetector();

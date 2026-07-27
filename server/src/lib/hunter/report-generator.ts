/**
 * ReportGenerator — lib/hunter singleton
 *
 * Session-aware wrapper that generates structured bug bounty reports
 * from confirmed findings.
 */
import { v4 as uuidv4 } from 'uuid';
import type { Finding, Severity } from './types';
import { offensiveGraphDB } from '../intelligence/offensive-graph-db';
import { mdInlineCode, safeCodeFence } from '../report/markdown-escape';

export interface BugReport {
  id:         string;
  sessionId?: string;
  findingId:  string;
  title:      string;
  severity:   Severity;
  platform:   string;
  vulnClass:  string;
  markdown:   string;
  wordCount:  number;
  createdAt:  number;
}

export interface ReportStats {
  total:    number;
  bySeverity: Record<Severity, number>;
  byPlatform: Record<string, number>;
}

const SEVERITY_TITLE: Record<Severity, string> = {
  critical: '[Critical]',
  high:     '[High]',
  medium:   '[Medium]',
  low:      '[Low]',
  info:     '[Info]',
};

const VULN_DESCRIPTIONS: Record<string, string> = {
  xss:                'Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users.',
  sqli:               'SQL Injection allows attackers to interfere with database queries, potentially extracting or modifying data.',
  ssrf:               'Server-Side Request Forgery tricks the server into making requests to internal or external resources.',
  rce:                'Remote Code Execution allows attackers to run arbitrary commands on the server.',
  idor:               'Insecure Direct Object Reference exposes internal objects without authorization checks.',
  lfi:                'Local File Inclusion allows attackers to read arbitrary files from the server filesystem.',
  xxe:                'XML External Entity injection can be used to exfiltrate files or perform SSRF attacks.',
  csrf:               'Cross-Site Request Forgery tricks authenticated users into performing unintended actions.',
  cors:               'CORS misconfiguration allows unauthorized origins to read sensitive cross-origin responses.',
  auth_bypass:        'Authentication bypass allows attackers to access protected resources without valid credentials.',
  open_redirect:      'Open Redirect can be used for phishing by redirecting users to attacker-controlled pages.',
  info_disclosure:    'Sensitive information is exposed that could aid further attacks.',
  misconfig:          'Security misconfiguration leaves the application in an insecure state.',
  subdomain_takeover: 'Unclaimed subdomain can be claimed by an attacker to serve malicious content.',
  rate_limit_bypass:  'Missing or bypassable rate limiting enables brute force and enumeration attacks.',
  business_logic:     'Business logic flaw allows unintended application behavior that violates security assumptions.',
  security_headers:   'Missing or weak security headers leave the application exposed to common browser attacks.',
  exposed_admin:      'Administrative panel exposed without adequate access controls.',
  rfi:                'Remote File Inclusion allows attackers to include remote malicious files for execution.',
};

class ReportGeneratorStore {
  private reports: Map<string /* sessionId */, BugReport[]> = new Map();
  private allReports: Map<string /* reportId */, BugReport> = new Map();

  private ensureSession(sessionId: string): BugReport[] {
    if (!this.reports.has(sessionId)) this.reports.set(sessionId, []);
    return this.reports.get(sessionId)!;
  }

  async generateReport(finding: Finding, platform: string, huntId?: string): Promise<BugReport> {
    const description = VULN_DESCRIPTIONS[finding.vulnClass] ?? `${finding.vulnClass} vulnerability found.`;
    // Title carries finding.endpoint (target-controlled) but is also stored
    // verbatim as BugReport.title outside the markdown — escaping it there
    // would corrupt that field, so only the markdown H1 below is escaped.
    const title = `${SEVERITY_TITLE[finding.severity]} ${finding.vulnClass.toUpperCase()} at ${finding.endpoint}`;

    const chainSection = huntId ? await this.buildExploitChainSection(huntId, finding) : '';

    const markdown = `# ${SEVERITY_TITLE[finding.severity]} ${finding.vulnClass.toUpperCase()} at ${mdInlineCode(finding.endpoint)}

## Summary
${description}

A ${finding.severity} severity ${finding.vulnClass} vulnerability was identified at:
${mdInlineCode(finding.endpoint)}

## Steps to Reproduce
1. Navigate to ${mdInlineCode(finding.endpoint)}
2. Send the following payload: ${mdInlineCode(finding.payload || 'See evidence below')}
3. Observe the vulnerability response

## Impact
${this.buildImpact(finding)}
${chainSection}
## Evidence
${safeCodeFence(JSON.stringify(finding.evidence, null, 2).slice(0, 500))}

## Remediation
${this.buildRemediation(finding.vulnClass)}

**Confidence:** ${Math.round(finding.confidence * 100)}%
**Verification:** ${finding.verificationStatus}
**Reported via:** ${platform}
`;

    const report: BugReport = {
      id:        uuidv4(),
      sessionId: finding.sessionId,
      findingId: finding.id,
      title,
      severity:  finding.severity,
      platform,
      vulnClass: finding.vulnClass,
      markdown,
      wordCount: markdown.split(/\s+/).length,
      createdAt: Date.now(),
    };

    const sessionReports = this.ensureSession(finding.sessionId);
    sessionReports.push(report);
    this.allReports.set(report.id, report);
    return report;
  }

  async generateBatchReports(findings: Finding[], platform: string, huntId?: string): Promise<BugReport[]> {
    const confirmed = findings.filter(f => f.verificationStatus === 'confirmed');
    return Promise.all(confirmed.map(f => this.generateReport(f, platform, huntId)));
  }

  private async buildExploitChainSection(huntId: string, finding: Finding): Promise<string> {
    try {
      const vulnNode = offensiveGraphDB.findNode(huntId, 'vulnerability', finding.vulnClass);
      if (!vulnNode) return '';

      // BFS along chains_to edges up to depth 4
      const huntEdges = offensiveGraphDB.getHuntEdges(huntId);
      const chainEdges = huntEdges.filter(e => e.relationship === 'chains_to');
      if (chainEdges.length === 0) return '';

      const edgesBySource = new Map<string, typeof chainEdges>();
      for (const e of chainEdges) {
        if (!edgesBySource.has(e.sourceId)) edgesBySource.set(e.sourceId, []);
        edgesBySource.get(e.sourceId)!.push(e);
      }

      interface ChainStep { label: string; nodeType: string; reasoning: string }
      const steps: ChainStep[] = [{ label: finding.vulnClass, nodeType: 'vulnerability', reasoning: 'Initial foothold' }];
      let currentId = vulnNode.id;
      const visited = new Set<string>([currentId]);

      for (let depth = 0; depth < 4; depth++) {
        const nexts = edgesBySource.get(currentId);
        if (!nexts || nexts.length === 0) break;
        const next = nexts[0];
        if (visited.has(next.targetId)) break;
        visited.add(next.targetId);
        const targetNode = offensiveGraphDB.getNode(next.targetId);
        if (!targetNode) break;
        steps.push({
          label:     targetNode.label,
          nodeType:  targetNode.nodeType,
          reasoning: (next.properties?.reasoning as string) || '',
        });
        currentId = next.targetId;
      }

      if (steps.length < 2) return '';

      const stepLines = steps.map((step, i) => {
        const arrow = i < steps.length - 1 ? '\n   ↓ *chains to*' : '';
        return `${i + 1}. **\`${step.label}\`** *(${step.nodeType})*${step.reasoning ? ' — ' + step.reasoning : ''}${arrow}`;
      }).join('\n');

      return `\n## Exploit Chain\n\nThis vulnerability is the entry point to a **${steps.length}-hop attack chain** identified during the hunt:\n\n${stepLines}\n\n> Triage note: steps 2+ represent implied next-hop surfaces based on graph-mapped pivot relationships. Verify independently before escalating.\n`;
    } catch {
      return '';
    }
  }

  getReports(sessionId: string): BugReport[] {
    return this.reports.get(sessionId) ?? [];
  }

  getReport(sessionId: string, reportId: string): BugReport | null {
    const report = this.allReports.get(reportId);
    if (!report || report.sessionId !== sessionId) return null;
    return report;
  }

  getStats(sessionId: string): ReportStats {
    const reports = this.getReports(sessionId);
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byPlatform: Record<string, number> = {};

    for (const r of reports) {
      bySeverity[r.severity]             = (bySeverity[r.severity] || 0) + 1;
      byPlatform[r.platform]             = (byPlatform[r.platform] || 0) + 1;
    }

    return { total: reports.length, bySeverity, byPlatform };
  }

  private buildImpact(finding: Finding): string {
    const impacts: Record<string, string> = {
      rce:      'Full server compromise, data exfiltration, lateral movement',
      sqli:     'Database exfiltration, authentication bypass, data manipulation',
      ssrf:     'Access to internal services, cloud metadata theft, potential RCE',
      xss:      'Session hijacking, credential theft, malware distribution',
      idor:     'Unauthorized access to other users\' data, privacy violation',
      auth_bypass: 'Unauthorized access to privileged functionality',
    };
    return impacts[finding.vulnClass] ?? `${finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)} security impact`;
  }

  private buildRemediation(vulnClass: string): string {
    const remediations: Record<string, string> = {
      xss:      'Implement strict Content Security Policy, sanitize all user inputs, use context-aware output encoding',
      sqli:     'Use parameterized queries/prepared statements, implement input validation, apply least-privilege DB accounts',
      ssrf:     'Validate and whitelist allowed URLs, disable unnecessary URL schemes, implement network segmentation',
      rce:      'Avoid executing user-controlled input, use sandboxing, implement allowlists for command arguments',
      idor:     'Implement proper authorization checks, use indirect references, validate object ownership on every request',
      lfi:      'Validate file paths, use allowlists, avoid user-controlled paths in file operations',
      auth_bypass: 'Review authentication logic, implement proper session management, use multi-factor authentication',
      cors:     'Configure CORS allowlist to specific trusted origins, avoid wildcard origins with credentials',
    };
    return remediations[vulnClass] ?? 'Review security controls and implement defense-in-depth measures';
  }
}

export const reportGenerator = new ReportGeneratorStore();

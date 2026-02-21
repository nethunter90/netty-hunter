/**
 * NucleiTemplateGenerator — lib/hunter singleton
 *
 * Session-aware nuclei YAML template store.
 */
import { v4 as uuidv4 } from 'uuid';
import type { Finding } from './types';

export interface NucleiTemplate {
  id:        string;
  sessionId: string;
  findingId: string;
  vulnClass: string;
  name:      string;
  yaml:      string;
  severity:  string;
  tags:      string[];
  createdAt: number;
}

export interface TemplateStats {
  total:      number;
  bySeverity: Record<string, number>;
}

class NucleiTemplateGeneratorStore {
  private templates:    Map<string /* sessionId */, NucleiTemplate[]> = new Map();
  private allTemplates: Map<string /* id */, NucleiTemplate>          = new Map();

  private ensure(sessionId: string): NucleiTemplate[] {
    if (!this.templates.has(sessionId)) this.templates.set(sessionId, []);
    return this.templates.get(sessionId)!;
  }

  generateFromFinding(finding: Finding): NucleiTemplate {
    const name = `${finding.vulnClass}-${finding.endpoint.replace(/[^a-z0-9]/gi, '-').slice(0, 40)}-${Date.now()}`;
    const yaml  = this.buildYAML(finding, name);

    const tmpl: NucleiTemplate = {
      id:        uuidv4(),
      sessionId: finding.sessionId,
      findingId: finding.id,
      vulnClass: finding.vulnClass,
      name,
      yaml,
      severity:  finding.severity,
      tags:      [finding.vulnClass, 'custom', `session-${finding.sessionId.slice(0, 8)}`],
      createdAt: Date.now(),
    };

    this.ensure(finding.sessionId).push(tmpl);
    this.allTemplates.set(tmpl.id, tmpl);
    return tmpl;
  }

  getTemplates(sessionId: string): NucleiTemplate[] {
    return this.templates.get(sessionId) ?? [];
  }

  getTemplate(sessionId: string, templateId: string): NucleiTemplate | null {
    const tmpl = this.allTemplates.get(templateId);
    if (!tmpl || tmpl.sessionId !== sessionId) return null;
    return tmpl;
  }

  getStats(sessionId: string): TemplateStats {
    const tmpls = this.getTemplates(sessionId);
    const bySeverity: Record<string, number> = {};
    for (const t of tmpls) bySeverity[t.severity] = (bySeverity[t.severity] || 0) + 1;
    return { total: tmpls.length, bySeverity };
  }

  getAllTemplateYAMLs(sessionId: string): string | null {
    const tmpls = this.getTemplates(sessionId);
    if (tmpls.length === 0) return null;
    return tmpls.map(t => t.yaml).join('\n---\n');
  }

  private buildYAML(finding: Finding, name: string): string {
    const endpoint = finding.endpoint.replace(/'/g, "''");
    const payload  = (finding.payload || '').replace(/'/g, "''");

    return `id: ${name}

info:
  name: ${finding.vulnClass.toUpperCase()} at ${finding.endpoint.slice(0, 60)}
  author: netty-hunter
  severity: ${finding.severity}
  tags: ${[finding.vulnClass, 'custom'].join(',')}
  description: Auto-generated template for ${finding.vulnClass} vulnerability

requests:
  - method: GET
    path:
      - '{{BaseURL}}${this.pathOf(finding.endpoint)}'
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
${payload ? `      - type: word
        words:
          - '${payload.slice(0, 50)}'
        part: body` : ''}
`;
  }

  private pathOf(endpoint: string): string {
    try { return new URL(endpoint).pathname; }
    catch { return endpoint.startsWith('/') ? endpoint : `/${endpoint}`; }
  }
}

export const nucleiTemplateGenerator = new NucleiTemplateGeneratorStore();

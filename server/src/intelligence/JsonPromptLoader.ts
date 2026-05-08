/**
 * JSON Prompt Loader
 * Singleton that reads all *.json files from server/data/prompts/ at startup.
 * Provides structured domain knowledge for injection into AI reasoning prompts.
 * Handles multiple file schemas: api_auth_chains, attack_paths, bounty_patterns.
 */
import * as fs from 'fs';
import * as path from 'path';
import logger from '../utils/logger';

export interface JsonPrompt {
  id: number;
  category: string;
  scenario: string;
  prompt: string;
  expected_answer: string;
  evaluation_criteria: string;
  // api_auth_chains fields
  prompt_id?: string;
  complexity?: string;
  auth_domain?: string;
  reasoning_focus?: string;
  // attack_paths / bounty_patterns fields
  objective?: string;
  reasoning_requirement?: string;
}

export class JsonPromptLoader {
  private static instance: JsonPromptLoader;
  private prompts: JsonPrompt[] = [];
  private loaded = false;

  private constructor() {}

  static getInstance(): JsonPromptLoader {
    if (!JsonPromptLoader.instance) {
      JsonPromptLoader.instance = new JsonPromptLoader();
      JsonPromptLoader.instance.load();
    }
    return JsonPromptLoader.instance;
  }

  load(): void {
    if (this.loaded) return;

    const dataDir = path.resolve(__dirname, '../../../data/prompts');
    if (!fs.existsSync(dataDir)) {
      logger.warn('[JsonPromptLoader] data/prompts directory not found', { dataDir });
      this.loaded = true;
      return;
    }

    const files = fs.readdirSync(dataDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const raw = fs.readFileSync(path.join(dataDir, file), 'utf-8');
        const entries = JSON.parse(raw) as JsonPrompt[];
        if (Array.isArray(entries)) {
          this.prompts.push(...entries);
        }
      } catch (err) {
        logger.warn('[JsonPromptLoader] Failed to load prompt file', { file, err });
      }
    }

    this.loaded = true;
    logger.info('[JsonPromptLoader] Loaded prompts', { count: this.prompts.length, files: files.length });
  }

  getByDomain(auth_domain: string): JsonPrompt[] {
    return this.prompts.filter(p => p.auth_domain === auth_domain);
  }

  getByCategory(category: string): JsonPrompt[] {
    return this.prompts.filter(p => p.category === category);
  }

  getByComplexity(level: string): JsonPrompt[] {
    return this.prompts.filter(p => p.complexity === level);
  }

  getAll(): JsonPrompt[] {
    return this.prompts;
  }

  /**
   * Returns a formatted context block for injection into AI prompts.
   * Combines domain-matched entries (api_auth_chains) with keyword-matched entries
   * (attack_paths, bounty_patterns) for the given vuln class.
   */
  getContextBlock(vulnClass: string, maxEntries = 3): string {
    const sections: JsonPrompt[] = [];

    // 1. Auth domain entries (api_auth_chains)
    const domains = this.vulnClassToDomains(vulnClass);
    for (const domain of domains) {
      const domainPrompts = this.getByDomain(domain)
        .sort((a, b) => {
          const order = ['L1', 'L2', 'L3', 'L4', 'L5'];
          return order.indexOf(a.complexity ?? 'L3') - order.indexOf(b.complexity ?? 'L3');
        });
      sections.push(...domainPrompts);
      if (sections.length >= maxEntries) break;
    }

    // 2. Keyword-matched entries from attack_paths / bounty_patterns
    if (sections.length < maxEntries) {
      const keywords = this.vulnClassToKeywords(vulnClass);
      const kwLower = keywords.map(k => k.toLowerCase());
      const matched = this.prompts.filter(p =>
        p.category !== 'api_auth_chains' &&
        !sections.includes(p) &&
        kwLower.some(k =>
          p.scenario.toLowerCase().includes(k) ||
          (p.objective ?? '').toLowerCase().includes(k) ||
          p.prompt.toLowerCase().includes(k)
        )
      );
      sections.push(...matched);
    }

    const selected = sections.slice(0, maxEntries);
    if (selected.length === 0) return '';

    const lines: string[] = [];
    let lastGroup = '';

    for (const p of selected) {
      const group = p.auth_domain ?? p.category;
      if (group !== lastGroup) {
        const header = p.auth_domain
          ? `Auth Domain Knowledge: ${p.auth_domain}`
          : `Attack Pattern Knowledge: ${p.category.replace(/_/g, ' ')}`;
        lines.push(`\n=== ${header} ===`);
        lastGroup = group;
      }

      const tag = p.prompt_id ? `[${p.prompt_id} ${p.complexity}]` : `[#${p.id}]`;
      const focus = p.reasoning_focus ?? p.reasoning_requirement ?? p.objective ?? '';
      const answerExcerpt = p.expected_answer.slice(0, 200).replace(/\n/g, ' ');

      lines.push(`${tag} ${p.scenario}`);
      if (focus) lines.push(`  Focus: ${focus}`);
      lines.push(`  Answer excerpt: ${answerExcerpt}...`);
    }

    return lines.join('\n');
  }

  private vulnClassToDomains(vulnClass: string): string[] {
    const map: Record<string, string[]> = {
      auth_bypass:      ['JWT', 'OAuth2', 'SAML', 'OIDC', 'Session Management', 'SSO', 'MFA/2FA'],
      jwt_weakness:     ['JWT'],
      cors:             ['CORS'],
      csrf:             ['Session Management', 'CORS'],
      xss:              ['Session Management'],
      sqli:             ['LDAP/AD'],
      ssrf:             ['mTLS', 'Certificate Auth'],
      idor:             ['GraphQL Auth'],
      info_disclosure:  ['API Keys', 'Certificate Auth'],
      weak_credentials: ['API Keys', 'MFA/2FA'],
      oauth:            ['OAuth2', 'OIDC', 'Token Refresh/Rotation'],
      saml:             ['SAML', 'SSO'],
      token:            ['JWT', 'Token Refresh/Rotation'],
      websocket:        ['WebSocket Auth'],
      misconfig:        ['API Keys', 'CORS'],
      open_redirect:    ['OAuth2', 'SAML'],
    };
    return map[vulnClass] ?? [];
  }

  private vulnClassToKeywords(vulnClass: string): string[] {
    const map: Record<string, string[]> = {
      sqli:             ['sql', 'injection', 'database', 'mysql', 'mssql'],
      xss:              ['xss', 'cross-site scripting', 'javascript', 'script injection'],
      ssrf:             ['ssrf', 'server-side request', 'internal ip', 'metadata'],
      idor:             ['idor', 'direct object', 'sequential id', 'predictable'],
      rce:              ['rce', 'remote code', 'command injection', 'code execution'],
      lfi:              ['lfi', 'file inclusion', 'path traversal', 'directory traversal'],
      auth_bypass:      ['authentication bypass', 'privilege escalation', 'admin access'],
      info_disclosure:  ['information disclosure', 'stack trace', 'error message', 'debug'],
      misconfig:        ['misconfiguration', 'default credentials', 'open redirect'],
      cors:             ['cors', 'cross-origin'],
      csrf:             ['csrf', 'cross-site request forgery', 'state parameter'],
      weak_credentials: ['weak password', 'brute force', 'credential', 'spray'],
    };
    return map[vulnClass] ?? [vulnClass.replace(/_/g, ' ')];
  }
}

export const jsonPromptLoader = JsonPromptLoader.getInstance();

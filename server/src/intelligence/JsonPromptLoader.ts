/**
 * JSON Prompt Loader
 * Singleton that reads all *.json files from server/data/prompts/ at startup.
 * Provides structured domain knowledge for injection into AI reasoning prompts.
 */
import * as fs from 'fs';
import * as path from 'path';
import logger from '../utils/logger';

export interface JsonPrompt {
  id: number;
  prompt_id: string;
  complexity: string;
  auth_domain: string;
  scenario: string;
  prompt: string;
  reasoning_focus: string;
  expected_answer: string;
  evaluation_criteria: string;
  category: string;
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
   * Maps the vuln class to relevant auth domains and picks up to maxEntries
   * prompts, preferring L1-L2 (concrete, attack-focused examples).
   */
  getContextBlock(vulnClass: string, maxEntries = 3): string {
    const domains = this.vulnClassToDomains(vulnClass);
    if (domains.length === 0) return '';

    const candidates: JsonPrompt[] = [];
    for (const domain of domains) {
      const domainPrompts = this.getByDomain(domain);
      // Prefer lower complexity (more concrete) for context injection
      const sorted = domainPrompts.sort((a, b) => {
        const levelOrder = ['L1', 'L2', 'L3', 'L4', 'L5'];
        return levelOrder.indexOf(a.complexity) - levelOrder.indexOf(b.complexity);
      });
      candidates.push(...sorted);
      if (candidates.length >= maxEntries) break;
    }

    const selected = candidates.slice(0, maxEntries);
    if (selected.length === 0) return '';

    const lines: string[] = [];
    let lastDomain = '';

    for (const p of selected) {
      if (p.auth_domain !== lastDomain) {
        lines.push(`\n=== Auth Domain Knowledge: ${p.auth_domain} ===`);
        lastDomain = p.auth_domain;
      }
      const answerExcerpt = p.expected_answer.slice(0, 200).replace(/\n/g, ' ');
      lines.push(`[${p.prompt_id} ${p.complexity}] ${p.scenario}`);
      lines.push(`  Focus: ${p.reasoning_focus}`);
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
}

export const jsonPromptLoader = JsonPromptLoader.getInstance();

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
  id: number | string;
  category?: string;
  scenario?: string;
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
  // business-logic (T5) fields
  domain?: string;
  // cloud-security (T4) fields
  cloud_domain?: string;
  // chain_scenarios fields
  chain_steps?: string;
  impact_level?: string;
  // defensive_awareness fields
  signal_observed?: string;
  level?: string;
  // engagement-signals (T6) fields
  signal_type?: string;
  // kali_tool_interpretation (T2) fields
  tool?: string;
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
    return this.prompts.filter(p => p.auth_domain === auth_domain || p.domain === auth_domain || p.cloud_domain === auth_domain);
  }

  getByCloudDomain(cloud_domain: string): JsonPrompt[] {
    return this.prompts.filter(p => p.cloud_domain === cloud_domain);
  }

  getByCategory(category: string): JsonPrompt[] {
    return this.prompts.filter(p => p.category === category);
  }

  getByBusinessDomain(domain: string): JsonPrompt[] {
    return this.prompts.filter(p => p.domain === domain);
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

    // 2. Cloud-security domain entries (T4 — cloud-security.json)
    if (sections.length < maxEntries) {
      const cloudDomains = this.vulnClassToCloudDomains(vulnClass);
      for (const cd of cloudDomains) {
        const cdPrompts = this.getByCloudDomain(cd)
          .filter(p => !sections.includes(p))
          .sort((a, b) => {
            const order = ['L1', 'L2', 'L3', 'L4', 'L5'];
            return order.indexOf(a.complexity ?? 'L3') - order.indexOf(b.complexity ?? 'L3');
          });
        sections.push(...cdPrompts);
        if (sections.length >= maxEntries) break;
      }
    }

    // 3. Business-logic domain entries (T5 — business-logic.json)
    if (sections.length < maxEntries) {
      const bizDomains = this.vulnClassToBusinessDomains(vulnClass);
      for (const bd of bizDomains) {
        const bdPrompts = this.getByBusinessDomain(bd)
          .filter(p => !sections.includes(p))
          .sort((a, b) => {
            const order = ['L1', 'L2', 'L3', 'L4', 'L5'];
            return order.indexOf(a.complexity ?? 'L3') - order.indexOf(b.complexity ?? 'L3');
          });
        sections.push(...bdPrompts);
        if (sections.length >= maxEntries) break;
      }
    }

    // 3. Keyword-matched entries from attack_paths / bounty_patterns
    if (sections.length < maxEntries) {
      const keywords = this.vulnClassToKeywords(vulnClass);
      const kwLower = keywords.map(k => k.toLowerCase());
      const matched = this.prompts.filter(p =>
        p.category !== 'api_auth_chains' &&
        !p.domain &&
        !p.cloud_domain &&
        !sections.includes(p) &&
        (p.category !== undefined || p.signal_type !== undefined) &&
        kwLower.some(k =>
          (p.scenario ?? '').toLowerCase().includes(k) ||
          (p.objective ?? '').toLowerCase().includes(k) ||
          (p.chain_steps ?? '').toLowerCase().includes(k) ||
          (p.signal_type ?? '').toLowerCase().includes(k) ||
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
      const group = p.auth_domain ?? p.cloud_domain ?? p.domain ?? p.signal_type ?? p.category ?? 'general';
      if (group !== lastGroup) {
        let header: string;
        if (p.auth_domain) {
          header = `Auth Domain Knowledge: ${p.auth_domain}`;
        } else if (p.cloud_domain) {
          header = `Cloud Security Knowledge: ${p.cloud_domain}`;
        } else if (p.domain) {
          header = `Business Logic Knowledge: ${p.domain}`;
        } else if (p.signal_type) {
          header = `Engagement Signal: ${p.signal_type}`;
        } else if (p.category === 'chain_scenarios') {
          header = `Attack Chain Scenario`;
        } else {
          header = `Attack Pattern Knowledge: ${(p.category ?? 'general').replace(/_/g, ' ')}`;
        }
        lines.push(`\n=== ${header} ===`);
        lastGroup = group;
      }

      const idStr = typeof p.id === 'string' ? p.id : `#${p.id}`;
      const tag = p.prompt_id
        ? `[${p.prompt_id} ${p.complexity}]`
        : p.complexity
          ? `[${idStr} ${p.complexity}]`
          : `[${idStr}]`;
      const focus = p.reasoning_focus ?? p.reasoning_requirement ?? p.objective ?? '';
      const answerExcerpt = p.expected_answer.slice(0, 200).replace(/\n/g, ' ');

      lines.push(`${tag} ${p.scenario ?? p.prompt.slice(0, 150)}`);
      if (p.chain_steps) lines.push(`  Chain: ${p.chain_steps}`);
      if (p.signal_observed) lines.push(`  Signal: ${p.signal_observed}`);
      if (p.impact_level) lines.push(`  Impact: ${p.impact_level}`);
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

  private vulnClassToCloudDomains(vulnClass: string): string[] {
    const map: Record<string, string[]> = {
      ssrf:             ['AWS EC2', 'AWS S3', 'GCP Compute', 'Azure', 'Kubernetes + Cloud'],
      iam_escalation:   ['AWS IAM', 'AWS IAM + STS', 'AWS IAM Permission Boundaries', 'GCP IAM', 'Azure AD', 'Azure RBAC'],
      info_disclosure:  ['AWS CloudTrail', 'AWS CloudWatch', 'AWS Lambda', 'AWS SSM', 'Infrastructure-as-Code', 'Container Registry'],
      credential:       ['AWS Secrets Manager', 'AWS SSM', 'Azure Key Vault', 'GCP IAM', 'CI/CD'],
      privilege_esc:    ['AWS IAM', 'GCP IAM', 'Azure AD', 'Kubernetes', 'AWS Organizations', 'AWS Org'],
      misconfig:        ['AWS S3', 'GCP Storage', 'Azure Storage', 'Kubernetes', 'Service Mesh'],
      container_escape: ['Container', 'Container Kubernetes', 'Kubernetes', 'Kubernetes Platform', 'Docker'],
      cloud_pivot:      ['AWS Multi-Account', 'Multi-Cloud', 'Kubernetes + Cloud', 'Federated Identity', 'Identity Federation'],
      auth_bypass:      ['Identity Provider', 'Azure AD', 'AWS STS + OIDC', 'Identity Federation', 'Federated Identity'],
      supply_chain:     ['CI/CD', 'Infrastructure-as-Code', 'Container Registry', 'AWS ECR'],
      data_exposure:    ['AWS RDS', 'AWS S3', 'GCP Storage', 'Azure Storage', 'Multi-Tenant Cloud Storage', 'Multi-Tenant SaaS'],
      network:          ['AWS API Gateway', 'CDN + Origin', 'Multi-Cloud DNS', 'Global Load Balancer'],
      serverless:       ['AWS Lambda', 'Serverless', 'Serverless Architecture', 'GCP Cloud Run', 'Azure Functions'],
      event_injection:  ['AWS EventBridge', 'AWS SQS', 'AWS SQS + Lambda', 'AWS S3 + Lambda', 'Azure Service Bus', 'Webhooks'],
      monitoring:       ['AWS CloudTrail', 'AWS Organizations', 'AWS Org'],
    };
    return map[vulnClass] ?? [];
  }

  private vulnClassToBusinessDomains(vulnClass: string): string[] {
    const map: Record<string, string[]> = {
      business_logic:   ['Rewards', 'Coupons', 'Subscription', 'Refunds', 'Marketplace', 'Cart', 'Referrals', 'Gift Cards', 'Pricing', 'Promotions', 'Cashback', 'Affiliate'],
      race_condition:   ['Fintech', 'Fintech Core', 'Marketplace', 'E-commerce', 'Flash Sales', 'Payments', 'Escrow'],
      idor:             ['Marketplace', 'E-commerce', 'Subscription SaaS', 'Enterprise SaaS', 'Marketplace SaaS'],
      payment_fraud:    ['Fintech', 'Fintech Core', 'Fintech Platform', 'Fintech API', 'Payments', 'Cryptocurrency', 'Lending', 'Escrow', 'Payroll'],
      promo_abuse:      ['Coupons', 'Promotions', 'Referrals', 'Gift Cards', 'Cashback', 'Affiliate', 'Flash Sales'],
      logic_flaw:       ['Subscription', 'Tax', 'Shipping', 'Digital Goods', 'Auctions', 'Travel', 'Gaming', 'Insurance', 'Token Economy'],
      info_disclosure:  ['Fintech Reporting', 'Invoicing', 'Global Platform', 'Enterprise SaaS'],
      auth_bypass:      ['Token Economy', 'Token Lifecycle', 'Microservices'],
      sqli:             ['E-commerce', 'Marketplace', 'Enterprise SaaS'],
      ssrf:             ['Microservices', 'Global Platform'],
      travel:           ['Travel', 'Travel Platform'],
      gaming:           ['Gaming', 'Token Economy', 'Token Lifecycle'],
      lending:          ['Lending', 'Fintech Core', 'Fintech Platform'],
      crypto:           ['Cryptocurrency', 'Token Economy', 'Token Lifecycle'],
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

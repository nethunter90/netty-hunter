/**
 * JSON Prompt Loader
 * Singleton that reads all *.json files from server/data/prompts/ at startup.
 * Provides structured domain knowledge for injection into AI reasoning prompts.
 * Handles multiple file schemas: api_auth_chains, attack_paths, bounty_patterns.
 *
 * Semantic retrieval: on first call to getContextBlockAsync(), pre-computes
 * embeddings via Ollama (nomic-embed-text) and caches them to disk.
 * Falls back to keyword filtering if Ollama is unavailable.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import axios from 'axios';
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
  // tool-chain-reasoning (T9) fields
  tools_involved?: string[];
  // access-level-scenarios (T7) fields
  access_level?: string;
  // vulnerability-severity-reasoning (T8) fields
  vulnerability_type?: string;
  // engagement-decision-reasoning (T10) fields
  engagement_context?: string;
}

interface EmbeddingCache {
  hash: string;
  model: string;
  entries: { key: string; embedding: number[] }[];
}

export class JsonPromptLoader {
  private static instance: JsonPromptLoader;
  private prompts: JsonPrompt[] = [];
  private loaded = false;

  // Semantic retrieval state
  private embeddings: Map<string, number[]> = new Map();
  private embeddingsReady = false;
  private embeddingInitPromise: Promise<void> | null = null;
  private readonly ollamaBase: string;
  private readonly embedModel: string;
  private readonly cacheFile: string;

  private constructor() {
    this.ollamaBase = process.env.OLLAMA_BASE_URL || 'http://localhost:11434';
    this.embedModel = process.env.EMBED_MODEL || 'nomic-embed-text';
    this.cacheFile = path.resolve(__dirname, '../../../data/prompt-embeddings-cache.json');
  }

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

  // ─── Semantic retrieval ───────────────────────────────────────────────────────

  /**
   * Pre-computes embeddings for all loaded prompts. Caches to disk; only
   * re-embeds when the prompt files change. Safe to call multiple times.
   */
  async initEmbeddings(): Promise<void> {
    if (this.embeddingsReady) return;
    if (this.embeddingInitPromise) return this.embeddingInitPromise;

    this.embeddingInitPromise = this._doInitEmbeddings().catch(err => {
      logger.warn('[JsonPromptLoader] Embedding init failed, falling back to keyword search', { err: String(err) });
      this.embeddingInitPromise = null;
    });
    return this.embeddingInitPromise;
  }

  private async _doInitEmbeddings(): Promise<void> {
    const hash = this.computePromptsHash();
    const cached = this.loadEmbeddingCache(hash);

    if (cached) {
      for (const e of cached.entries) {
        this.embeddings.set(e.key, e.embedding);
      }
      this.embeddingsReady = true;
      logger.info('[JsonPromptLoader] Loaded embeddings from cache', { count: this.embeddings.size });
      return;
    }

    logger.info('[JsonPromptLoader] Computing embeddings for all prompts (first run — please wait)', {
      count: this.prompts.length, model: this.embedModel,
    });

    const entries: { key: string; embedding: number[] }[] = [];
    const chunkSize = 8;

    for (let i = 0; i < this.prompts.length; i += chunkSize) {
      const chunk = this.prompts.slice(i, i + chunkSize);
      const results = await Promise.all(chunk.map(async p => {
        const key = this.entryKey(p);
        const text = this.buildEntryText(p);
        const embedding = await this.embedText(text);
        return { key, embedding };
      }));
      for (const r of results) {
        this.embeddings.set(r.key, r.embedding);
        entries.push(r);
      }

      if ((i / chunkSize) % 20 === 0 && i > 0) {
        logger.info('[JsonPromptLoader] Embedding progress', { done: i, total: this.prompts.length });
      }
    }

    this.saveEmbeddingCache({ hash, model: this.embedModel, entries });
    this.embeddingsReady = true;
    logger.info('[JsonPromptLoader] Embeddings ready', { count: this.embeddings.size });
  }

  /**
   * Semantic context retrieval. Embeds the query text and returns the
   * most relevant prompt examples. Falls back to keyword search if embeddings
   * are not yet ready.
   */
  async getContextBlockAsync(queryText: string, maxEntries = 7): Promise<string> {
    if (!this.embeddingsReady) {
      // Kick off init in background, return keyword result for now
      void this.initEmbeddings();
      const vulnHint = this.extractVulnHint(queryText);
      return this.getContextBlock(vulnHint, maxEntries);
    }

    let queryEmbedding: number[];
    try {
      queryEmbedding = await this.embedText(queryText);
    } catch {
      const vulnHint = this.extractVulnHint(queryText);
      return this.getContextBlock(vulnHint, maxEntries);
    }

    // Score every prompt by cosine similarity
    const scored: { prompt: JsonPrompt; score: number }[] = [];
    for (const p of this.prompts) {
      const key = this.entryKey(p);
      const emb = this.embeddings.get(key);
      if (!emb) continue;
      const score = this.cosineSimilarity(queryEmbedding, emb);
      scored.push({ prompt: p, score });
    }

    scored.sort((a, b) => b.score - a.score);
    const selected = scored.slice(0, maxEntries).map(s => s.prompt);

    return this.renderContextBlock(selected);
  }

  private buildEntryText(p: JsonPrompt): string {
    const parts: string[] = [];
    if (p.scenario)          parts.push(`Scenario: ${p.scenario}`);
    if (p.objective)         parts.push(`Objective: ${p.objective}`);
    if (p.reasoning_focus)   parts.push(`Focus: ${p.reasoning_focus}`);
    if (p.auth_domain)       parts.push(`Auth domain: ${p.auth_domain}`);
    if (p.cloud_domain)      parts.push(`Cloud domain: ${p.cloud_domain}`);
    if (p.domain)            parts.push(`Business domain: ${p.domain}`);
    if (p.vulnerability_type) parts.push(`Vulnerability: ${p.vulnerability_type}`);
    if (p.engagement_context) parts.push(`Context: ${p.engagement_context}`);
    if (p.signal_type)       parts.push(`Signal: ${p.signal_type}`);
    if (p.chain_steps)       parts.push(`Chain: ${p.chain_steps}`);
    if (p.tools_involved)    parts.push(`Tools: ${p.tools_involved.join(', ')}`);
    if (p.access_level)      parts.push(`Access: ${p.access_level}`);
    parts.push(`Prompt: ${p.prompt.slice(0, 300)}`);
    parts.push(`Answer: ${p.expected_answer.slice(0, 300)}`);
    return parts.join('. ');
  }

  private entryKey(p: JsonPrompt): string {
    return String(p.id) + ':' + (p.category ?? '') + ':' + (p.auth_domain ?? p.domain ?? p.cloud_domain ?? '');
  }

  private async embedText(text: string): Promise<number[]> {
    const resp = await axios.post(
      `${this.ollamaBase}/api/embeddings`,
      { model: this.embedModel, prompt: text },
      { timeout: 15000 }
    );
    return resp.data.embedding as number[];
  }

  private cosineSimilarity(a: number[], b: number[]): number {
    let dot = 0, normA = 0, normB = 0;
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      dot   += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dot / denom;
  }

  private computePromptsHash(): string {
    const dataDir = path.resolve(__dirname, '../../../data/prompts');
    const files = fs.readdirSync(dataDir).filter(f => f.endsWith('.json')).sort();
    const hash = crypto.createHash('sha256');
    for (const f of files) {
      hash.update(fs.readFileSync(path.join(dataDir, f)));
    }
    return hash.digest('hex');
  }

  private loadEmbeddingCache(hash: string): EmbeddingCache | null {
    try {
      if (!fs.existsSync(this.cacheFile)) return null;
      const cache = JSON.parse(fs.readFileSync(this.cacheFile, 'utf-8')) as EmbeddingCache;
      if (cache.hash !== hash || cache.model !== this.embedModel) return null;
      return cache;
    } catch {
      return null;
    }
  }

  private saveEmbeddingCache(cache: EmbeddingCache): void {
    try {
      fs.writeFileSync(this.cacheFile, JSON.stringify(cache), 'utf-8');
    } catch (err) {
      logger.warn('[JsonPromptLoader] Failed to save embedding cache', { err });
    }
  }

  private extractVulnHint(queryText: string): string {
    const classes = ['sqli', 'xss', 'ssrf', 'idor', 'rce', 'lfi', 'auth_bypass',
                     'info_disclosure', 'misconfig', 'cors', 'csrf', 'jwt', 'oauth'];
    const lower = queryText.toLowerCase();
    return classes.find(c => lower.includes(c)) ?? 'info_disclosure';
  }

  // ─── Structured retrieval (sync fallback) ────────────────────────────────────

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
   * Sync keyword/domain fallback — used when embeddings aren't ready and as a
   * direct call for callers that don't need semantic precision.
   */
  getContextBlock(vulnClass: string, maxEntries = 3): string {
    const sections: JsonPrompt[] = [];

    // 1. Auth domain entries
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

    // 2. Cloud-security domain entries
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

    // 3. Business-logic domain entries
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

    // 4. Keyword fallback
    if (sections.length < maxEntries) {
      const keywords = this.vulnClassToKeywords(vulnClass);
      const kwLower = keywords.map(k => k.toLowerCase());
      const matched = this.prompts.filter(p =>
        p.category !== 'api_auth_chains' &&
        !p.domain &&
        !p.cloud_domain &&
        !sections.includes(p) &&
        (p.category !== undefined || p.signal_type !== undefined || p.tools_involved !== undefined || p.access_level !== undefined || p.vulnerability_type !== undefined || p.engagement_context !== undefined) &&
        kwLower.some(k =>
          (p.scenario ?? '').toLowerCase().includes(k) ||
          (p.objective ?? '').toLowerCase().includes(k) ||
          (p.chain_steps ?? '').toLowerCase().includes(k) ||
          (p.signal_type ?? '').toLowerCase().includes(k) ||
          (p.vulnerability_type ?? '').toLowerCase().includes(k) ||
          (p.engagement_context ?? '').toLowerCase().includes(k) ||
          p.prompt.toLowerCase().includes(k)
        )
      );
      sections.push(...matched);
    }

    return this.renderContextBlock(sections.slice(0, maxEntries));
  }

  private renderContextBlock(selected: JsonPrompt[]): string {
    if (selected.length === 0) return '';

    const lines: string[] = [];
    let lastGroup = '';

    for (const p of selected) {
      const group = p.auth_domain ?? p.cloud_domain ?? p.domain ?? p.signal_type ?? p.category ?? (p.tools_involved ? p.tools_involved[0] : null) ?? p.access_level ?? p.vulnerability_type ?? p.engagement_context ?? 'general';
      if (group !== lastGroup) {
        let header: string;
        if (p.auth_domain)           header = `Auth Domain Knowledge: ${p.auth_domain}`;
        else if (p.cloud_domain)     header = `Cloud Security Knowledge: ${p.cloud_domain}`;
        else if (p.domain)           header = `Business Logic Knowledge: ${p.domain}`;
        else if (p.signal_type)      header = `Engagement Signal: ${p.signal_type}`;
        else if (p.category === 'chain_scenarios') header = `Attack Chain Scenario`;
        else if (p.tools_involved)   header = `Tool Chain Reasoning: ${p.tools_involved.slice(0, 2).join(' + ')}`;
        else if (p.access_level)     header = `Access Level Scenario: ${p.access_level}`;
        else if (p.vulnerability_type) header = `Severity Reasoning: ${p.vulnerability_type}`;
        else if (p.engagement_context) header = `Engagement Decision: ${p.engagement_context}`;
        else                         header = `Attack Pattern Knowledge: ${(p.category ?? 'general').replace(/_/g, ' ')}`;
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
      if (p.tools_involved)     lines.push(`  Tools: ${p.tools_involved.join(', ')}`);
      if (p.access_level)       lines.push(`  Access: ${p.access_level}`);
      if (p.engagement_context) lines.push(`  Context: ${p.engagement_context}`);
      if (p.chain_steps)        lines.push(`  Chain: ${p.chain_steps}`);
      if (p.signal_observed)    lines.push(`  Signal: ${p.signal_observed}`);
      if (p.impact_level)       lines.push(`  Impact: ${p.impact_level}`);
      if (focus)                lines.push(`  Focus: ${focus}`);
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

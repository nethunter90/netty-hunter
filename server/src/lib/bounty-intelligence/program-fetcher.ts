import { EventEmitter } from 'events';
import fs from 'fs/promises';
import path from 'path';
import { runtimeConfig } from '../runtime-config';
import logger from '../../utils/logger';

// === Interfaces ===

export interface ProgramConfig {
  id: string;
  name: string;
  platform: 'hackerone' | 'bugcrowd' | 'intigriti' | 'synack' | 'yeswehack' | 'custom';
  url: string;
  handle?: string;
  enabled: boolean;
  addedAt: number;
}

export interface ProgramScope {
  inScope: ScopeAsset[];
  outOfScope: ScopeAsset[];
  lastUpdated: number;
}

export interface ScopeAsset {
  type: 'url' | 'domain' | 'wildcard' | 'ios' | 'android' | 'api' | 'hardware' | 'other';
  identifier: string;
  maxSeverity?: string;
  eligible?: boolean;
  instruction?: string;
}

export interface ProgramRules {
  disclosure: string;
  safeHarbor: boolean;
  maxBounty?: number;
  minBounty?: number;
  responseTime?: string;
  rules: string[];
  exclusions: string[];
  lastUpdated: number;
  /** Real program-state fields, only ever populated from an authenticated
   *  fetch — never fabricated. Absent (not false) means "we don't know",
   *  distinct from a confirmed VDP-only program. */
  submissionState?: string;
  offersBounties?: boolean;
}

/**
 * Shape stored into the DB-backed programs table's `metadata` jsonb column
 * (previously declared but never actually used anywhere) — preserves the
 * per-asset richness (asset type, severity ceiling, bounty eligibility) that
 * a bare `scope: string[]` column structurally can't hold, without touching
 * that column's shape at all (ScopeGuard's enforcement path reads `scope`/
 * `outOfScope` as flat string arrays and must never be given anything else).
 */
export interface ProgramMetadata {
  scopeAssets?: { inScope: ScopeAsset[]; outOfScope: ScopeAsset[] };
  submissionState?: string;
  offersBounties?: boolean;
  policyDescription?: string;
  lastSyncedAt?: string;
}

export interface ProgramDocumentation {
  programId: string;
  name: string;
  platform: string;
  url: string;
  scope: ProgramScope;
  rules: ProgramRules;
  description: string;
  lastFetched: number;
  fetchHistory: FetchRecord[];
  changes: ChangeRecord[];
  /** False when scope/rules above are the synthetic fallback template
   *  (or a stale real doc kept because the latest fetch only produced
   *  fallback data) rather than genuinely fetched per-program data.
   *  Consumers (e.g. analyzeScope()) should treat false as low-confidence. */
  realDataFound: boolean;
}

export interface FetchRecord {
  timestamp: number;
  success: boolean;
  error?: string;
  changesDetected: boolean;
  realDataFound: boolean;
}

export interface ChangeRecord {
  timestamp: number;
  field: string;
  description: string;
  previousValue?: string;
  newValue?: string;
}

export interface FetcherStatus {
  totalPrograms: number;
  enabledPrograms: number;
  lastAutoFetch: number | null;
  nextAutoFetch: number | null;
  autoFetchInterval: number;
  autoFetchEnabled: boolean;
  programStatuses: ProgramFetchStatus[];
}

export interface ProgramFetchStatus {
  programId: string;
  name: string;
  platform: string;
  lastFetched: number | null;
  lastSuccess: boolean;
  changesDetected: number;
  enabled: boolean;
}

// === ProgramFetcher ===

export class ProgramFetcher extends EventEmitter {
  private storageDir: string;
  private programs: Map<string, ProgramConfig>;
  private documentation: Map<string, ProgramDocumentation>;
  private autoFetchTimer: NodeJS.Timeout | null;
  private autoFetchInterval: number;
  private autoFetchEnabled: boolean;
  private lastAutoFetch: number | null;

  constructor() {
    super();
    this.storageDir = path.join(process.cwd(), 'workspace/bounty-intelligence/programs');
    this.programs = new Map();
    this.documentation = new Map();
    this.autoFetchTimer = null;
    this.autoFetchInterval = 24 * 60 * 60 * 1000;
    this.autoFetchEnabled = false;
    this.lastAutoFetch = null;
    this.loadPrograms().catch(() => {});
  }

  // === Storage ===

  private async ensureStorageDir(): Promise<void> {
    await fs.mkdir(this.storageDir, { recursive: true });
  }

  private async loadJson<T>(filename: string, fallback: T): Promise<T> {
    try {
      const filePath = path.join(this.storageDir, filename);
      const data = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(data) as T;
    } catch {
      return fallback;
    }
  }

  private async saveJson(filename: string, data: any): Promise<void> {
    await this.ensureStorageDir();
    const filePath = path.join(this.storageDir, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  async loadPrograms(): Promise<void> {
    await this.ensureStorageDir();
    const configs = await this.loadJson<ProgramConfig[]>('programs.json', []);
    this.programs.clear();
    this.documentation.clear();

    for (const config of configs) {
      this.programs.set(config.id, config);
      const doc = await this.loadJson<ProgramDocumentation | null>(`${config.id}.json`, null);
      if (doc) {
        this.documentation.set(config.id, doc);
      }
    }
  }

  private async savePrograms(): Promise<void> {
    const configs = Array.from(this.programs.values());
    await this.saveJson('programs.json', configs);
  }

  private async saveProgramDoc(programId: string): Promise<void> {
    const doc = this.documentation.get(programId);
    if (doc) {
      await this.saveJson(`${programId}.json`, doc);
    }
  }

  // === Program Management ===

  async addProgram(config: Omit<ProgramConfig, 'id' | 'addedAt' | 'enabled'>): Promise<ProgramConfig> {
    const id = config.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .substring(0, 48);

    const program: ProgramConfig = {
      ...config,
      id,
      enabled: true,
      addedAt: Date.now(),
    };

    this.programs.set(id, program);
    await this.savePrograms();
    return program;
  }

  async removeProgram(programId: string): Promise<void> {
    this.programs.delete(programId);
    this.documentation.delete(programId);
    await this.savePrograms();
    try {
      await fs.unlink(path.join(this.storageDir, `${programId}.json`));
    } catch {}
  }

  listPrograms(): ProgramConfig[] {
    return Array.from(this.programs.values());
  }

  getProgram(programId: string): ProgramDocumentation | null {
    return this.documentation.get(programId) || null;
  }

  // === Fetch Core ===

  async fetchProgram(programId: string): Promise<{ success: boolean; changes: ChangeRecord[]; documentation: ProgramDocumentation | null }> {
    const config = this.programs.get(programId);
    if (!config) {
      return { success: false, changes: [], documentation: null };
    }

    if (config.platform !== 'custom' && !runtimeConfig.isPlatformEnabled(config.platform)) {
      const existing = this.documentation.get(programId);
      this.emit('program:error', { programId: config.id, name: config.name, error: `${config.platform} is disconnected` });
      return { success: false, changes: [], documentation: existing || null };
    }

    try {
      let fetched: { scope: ProgramScope; rules: ProgramRules; description: string; realDataFound: boolean };

      switch (config.platform) {
        case 'hackerone':
          fetched = await this.fetchHackerOne(config);
          break;
        case 'bugcrowd':
          fetched = await this.fetchBugcrowd(config);
          break;
        case 'intigriti':
          fetched = await this.fetchIntigriti(config);
          break;
        case 'synack':
          fetched = await this.fetchSynack(config);
          break;
        case 'yeswehack':
          fetched = await this.fetchYesWeHack(config);
          break;
        default:
          fetched = await this.fetchCustom(config);
          break;
      }

      const existing = this.documentation.get(programId);

      // Never let a fetch that only produced the synthetic fallback clobber
      // previously-obtained real scope — mirrors the DB-side sync-hackerone
      // fix (skip fake data rather than store it as real). Record the
      // attempt in fetchHistory as degraded and keep serving the last real doc.
      if (!fetched.realDataFound && existing?.realDataFound) {
        logger.warn('[ProgramFetcher] Fetch returned only fallback data — keeping previous real scope', { programId, name: config.name, platform: config.platform });
        const fetchRecord: FetchRecord = {
          timestamp: Date.now(),
          success: false,
          error: 'Fetch returned only synthetic fallback data; kept previous real scope',
          changesDetected: false,
          realDataFound: false,
        };
        existing.fetchHistory = [...existing.fetchHistory, fetchRecord].slice(-100);
        this.documentation.set(programId, existing);
        await this.saveProgramDoc(programId);
        this.emit('program:error', { programId: config.id, name: config.name, error: 'No real scope data found — kept previous data' });
        return { success: false, changes: [], documentation: existing };
      }

      const changes = existing ? this.detectChanges(existing, fetched) : [];
      const now = Date.now();

      const fetchRecord: FetchRecord = {
        timestamp: now,
        success: true,
        changesDetected: changes.length > 0,
        realDataFound: fetched.realDataFound,
      };

      const doc: ProgramDocumentation = {
        programId: config.id,
        name: config.name,
        platform: config.platform,
        url: config.url,
        scope: fetched.scope,
        rules: fetched.rules,
        description: fetched.description,
        lastFetched: now,
        fetchHistory: [...(existing?.fetchHistory || []), fetchRecord].slice(-100),
        changes: [...(existing?.changes || []), ...changes].slice(-500),
        realDataFound: fetched.realDataFound,
      };

      this.documentation.set(programId, doc);
      await this.saveProgramDoc(programId);

      this.emit('program:fetched', { programId: config.id, name: config.name, success: true, realDataFound: fetched.realDataFound });

      if (changes.length > 0) {
        this.emit('program:changed', { programId: config.id, name: config.name, changes });
      }

      return { success: true, changes, documentation: doc };
    } catch (err: any) {
      const existing = this.documentation.get(programId);
      const fetchRecord: FetchRecord = {
        timestamp: Date.now(),
        success: false,
        error: err.message || String(err),
        changesDetected: false,
        realDataFound: false,
      };

      if (existing) {
        existing.fetchHistory = [...existing.fetchHistory, fetchRecord].slice(-100);
        this.documentation.set(programId, existing);
        await this.saveProgramDoc(programId);
      }

      this.emit('program:error', { programId: config.id, name: config.name, error: err.message || String(err) });
      return { success: false, changes: [], documentation: existing || null };
    }
  }

  async fetchAllPrograms(): Promise<{ total: number; succeeded: number; failed: number; changesDetected: number; results: Array<{ programId: string; success: boolean; changes: number }> }> {
    const enabled = Array.from(this.programs.values())
      .filter(p => p.enabled)
      .filter(p => p.platform === 'custom' || runtimeConfig.isPlatformEnabled(p.platform));
    this.emit('autofetch:start', { count: enabled.length });

    const results: Array<{ programId: string; success: boolean; changes: number }> = [];
    let succeeded = 0;
    let failed = 0;
    let changesDetected = 0;

    for (const program of enabled) {
      const result = await this.fetchProgram(program.id);
      results.push({
        programId: program.id,
        success: result.success,
        changes: result.changes.length,
      });
      if (result.success) succeeded++;
      else failed++;
      if (result.changes.length > 0) changesDetected++;
    }

    const summary = { total: enabled.length, succeeded, failed, changesDetected, results };
    this.emit('autofetch:complete', { results: summary });
    return summary;
  }

  // === Auto Fetch ===

  startAutoFetch(intervalMs?: number): void {
    this.stopAutoFetch();
    if (intervalMs !== undefined) {
      this.autoFetchInterval = intervalMs;
    }
    this.autoFetchEnabled = true;
    this.autoFetchTimer = setInterval(async () => {
      this.lastAutoFetch = Date.now();
      await this.fetchAllPrograms();
    }, this.autoFetchInterval);
  }

  stopAutoFetch(): void {
    if (this.autoFetchTimer) {
      clearInterval(this.autoFetchTimer);
      this.autoFetchTimer = null;
    }
    this.autoFetchEnabled = false;
  }

  setAutoFetchInterval(intervalMs: number): void {
    this.autoFetchInterval = intervalMs;
    if (this.autoFetchEnabled) {
      this.startAutoFetch(intervalMs);
    }
  }

  // === Status ===

  getStatus(): FetcherStatus {
    const programs = Array.from(this.programs.values());
    const programStatuses: ProgramFetchStatus[] = programs.map(p => {
      const doc = this.documentation.get(p.id);
      const lastRecord = doc?.fetchHistory[doc.fetchHistory.length - 1];
      return {
        programId: p.id,
        name: p.name,
        platform: p.platform,
        lastFetched: doc?.lastFetched || null,
        lastSuccess: lastRecord?.success ?? false,
        changesDetected: doc?.changes.length || 0,
        enabled: p.enabled,
      };
    });

    return {
      totalPrograms: programs.length,
      enabledPrograms: programs.filter(p => p.enabled).length,
      lastAutoFetch: this.lastAutoFetch,
      nextAutoFetch: this.autoFetchEnabled && this.lastAutoFetch
        ? this.lastAutoFetch + this.autoFetchInterval
        : this.autoFetchEnabled
          ? Date.now() + this.autoFetchInterval
          : null,
      autoFetchInterval: this.autoFetchInterval,
      autoFetchEnabled: this.autoFetchEnabled,
      programStatuses,
    };
  }

  getChanges(programId?: string, since?: number): ChangeRecord[] {
    if (programId) {
      const doc = this.documentation.get(programId);
      if (!doc) return [];
      const changes = doc.changes;
      return since ? changes.filter(c => c.timestamp >= since) : changes;
    }

    const allChanges: ChangeRecord[] = [];
    for (const doc of Array.from(this.documentation.values())) {
      allChanges.push(...doc.changes);
    }
    allChanges.sort((a, b) => b.timestamp - a.timestamp);
    return since ? allChanges.filter(c => c.timestamp >= since) : allChanges;
  }

  getRecentChanges(limit = 50): ChangeRecord[] {
    return this.getChanges().slice(0, limit);
  }

  // === Change Detection ===

  private detectChanges(
    existing: ProgramDocumentation,
    fetched: { scope: ProgramScope; rules: ProgramRules; description: string }
  ): ChangeRecord[] {
    const changes: ChangeRecord[] = [];
    const now = Date.now();

    const oldInScope = new Set(existing.scope.inScope.map(a => `${a.type}:${a.identifier}`));
    const newInScope = new Set(fetched.scope.inScope.map(a => `${a.type}:${a.identifier}`));

    for (const asset of fetched.scope.inScope) {
      const key = `${asset.type}:${asset.identifier}`;
      if (!oldInScope.has(key)) {
        changes.push({
          timestamp: now,
          field: 'scope.inScope',
          description: `Added in-scope asset: ${asset.identifier} (${asset.type})`,
          newValue: key,
        });
      }
    }

    for (const asset of existing.scope.inScope) {
      const key = `${asset.type}:${asset.identifier}`;
      if (!newInScope.has(key)) {
        changes.push({
          timestamp: now,
          field: 'scope.inScope',
          description: `Removed in-scope asset: ${asset.identifier} (${asset.type})`,
          previousValue: key,
        });
      }
    }

    const oldOutScope = new Set(existing.scope.outOfScope.map(a => `${a.type}:${a.identifier}`));
    const newOutScope = new Set(fetched.scope.outOfScope.map(a => `${a.type}:${a.identifier}`));

    for (const asset of fetched.scope.outOfScope) {
      const key = `${asset.type}:${asset.identifier}`;
      if (!oldOutScope.has(key)) {
        changes.push({
          timestamp: now,
          field: 'scope.outOfScope',
          description: `Added out-of-scope asset: ${asset.identifier} (${asset.type})`,
          newValue: key,
        });
      }
    }

    for (const asset of existing.scope.outOfScope) {
      const key = `${asset.type}:${asset.identifier}`;
      if (!newOutScope.has(key)) {
        changes.push({
          timestamp: now,
          field: 'scope.outOfScope',
          description: `Removed out-of-scope asset: ${asset.identifier} (${asset.type})`,
          previousValue: key,
        });
      }
    }

    if (existing.rules.maxBounty !== fetched.rules.maxBounty) {
      changes.push({
        timestamp: now,
        field: 'rules.maxBounty',
        description: 'Maximum bounty amount changed',
        previousValue: existing.rules.maxBounty?.toString(),
        newValue: fetched.rules.maxBounty?.toString(),
      });
    }

    if (existing.rules.minBounty !== fetched.rules.minBounty) {
      changes.push({
        timestamp: now,
        field: 'rules.minBounty',
        description: 'Minimum bounty amount changed',
        previousValue: existing.rules.minBounty?.toString(),
        newValue: fetched.rules.minBounty?.toString(),
      });
    }

    if (existing.rules.safeHarbor !== fetched.rules.safeHarbor) {
      changes.push({
        timestamp: now,
        field: 'rules.safeHarbor',
        description: 'Safe harbor policy changed',
        previousValue: String(existing.rules.safeHarbor),
        newValue: String(fetched.rules.safeHarbor),
      });
    }

    if (existing.rules.disclosure !== fetched.rules.disclosure) {
      changes.push({
        timestamp: now,
        field: 'rules.disclosure',
        description: 'Disclosure policy changed',
        previousValue: existing.rules.disclosure,
        newValue: fetched.rules.disclosure,
      });
    }

    const oldRules = new Set(existing.rules.rules);
    const newRules = new Set(fetched.rules.rules);
    for (const rule of fetched.rules.rules) {
      if (!oldRules.has(rule)) {
        changes.push({ timestamp: now, field: 'rules.rules', description: `New rule added: ${rule}`, newValue: rule });
      }
    }
    for (const rule of existing.rules.rules) {
      if (!newRules.has(rule)) {
        changes.push({ timestamp: now, field: 'rules.rules', description: `Rule removed: ${rule}`, previousValue: rule });
      }
    }

    const oldExclusions = new Set(existing.rules.exclusions);
    const newExclusions = new Set(fetched.rules.exclusions);
    for (const ex of fetched.rules.exclusions) {
      if (!oldExclusions.has(ex)) {
        changes.push({ timestamp: now, field: 'rules.exclusions', description: `New exclusion added: ${ex}`, newValue: ex });
      }
    }
    for (const ex of existing.rules.exclusions) {
      if (!newExclusions.has(ex)) {
        changes.push({ timestamp: now, field: 'rules.exclusions', description: `Exclusion removed: ${ex}`, previousValue: ex });
      }
    }

    if (existing.description !== fetched.description) {
      changes.push({
        timestamp: now,
        field: 'description',
        description: 'Program description updated',
        previousValue: existing.description.substring(0, 200),
        newValue: fetched.description.substring(0, 200),
      });
    }

    return changes;
  }

  // === Platform Fetchers ===

  private extractDomain(url: string): string {
    return url.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  }

  private generateFallbackScope(domain: string): ProgramScope {
    const now = Date.now();
    return {
      inScope: [
        { type: 'domain', identifier: domain, maxSeverity: 'critical', eligible: true },
        { type: 'wildcard', identifier: `*.${domain}`, maxSeverity: 'critical', eligible: true },
        { type: 'url', identifier: `https://${domain}`, maxSeverity: 'critical', eligible: true },
        { type: 'url', identifier: `https://api.${domain}`, maxSeverity: 'critical', eligible: true },
        { type: 'url', identifier: `https://app.${domain}`, maxSeverity: 'high', eligible: true },
        { type: 'api', identifier: `https://api.${domain}/v1`, maxSeverity: 'critical', eligible: true },
        { type: 'api', identifier: `https://api.${domain}/v2`, maxSeverity: 'critical', eligible: true },
      ],
      outOfScope: [
        { type: 'domain', identifier: `blog.${domain}`, eligible: false, instruction: 'Blog is out of scope' },
        { type: 'domain', identifier: `support.${domain}`, eligible: false, instruction: 'Support portal is out of scope' },
        { type: 'domain', identifier: `status.${domain}`, eligible: false, instruction: 'Status page is out of scope' },
        { type: 'other', identifier: 'Third-party services', eligible: false, instruction: 'Do not test third-party integrations' },
      ],
      lastUpdated: now,
    };
  }

  private generateFallbackRules(domain: string, platform: string): ProgramRules {
    return {
      disclosure: 'coordinated',
      safeHarbor: true,
      maxBounty: platform === 'hackerone' ? 10000 : platform === 'bugcrowd' ? 7500 : 5000,
      minBounty: platform === 'hackerone' ? 100 : platform === 'bugcrowd' ? 150 : 50,
      responseTime: '5 business days',
      rules: [
        'Do not access or modify other users\' data',
        'Do not perform denial of service attacks',
        'Do not use automated scanners without prior approval',
        'Report vulnerabilities promptly after discovery',
        'Provide sufficient detail to reproduce the issue',
        'Do not publicly disclose without written permission',
        'Only test against accounts you own or have explicit permission to test',
      ],
      exclusions: [
        'Social engineering attacks',
        'Physical security attacks',
        'Denial of service',
        'Spam or social engineering against employees',
        'Clickjacking on pages with no sensitive actions',
        'Self-XSS that requires victim to paste code',
        'Missing best practices without demonstrable impact',
        'Rate limiting or brute force issues without impact',
      ],
      lastUpdated: Date.now(),
    };
  }

  /** Number(v) collapses to NaN for undefined/null/'' , so `Number.isFinite`
   *  (not `|| undefined`) is required to tell a genuine 0 (e.g. a real $0
   *  VDP-only bounty cap) apart from "the API didn't give us this field". */
  private numOrUndef(v: unknown): number | undefined {
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  }

  private h1AuthHeader(): string | null {
    const username = runtimeConfig.get('HACKERONE_USERNAME');
    const token = runtimeConfig.get('HACKERONE_TOKEN') || process.env.HACKERONE_API_TOKEN;
    if (!username || !token) return null;
    return 'Basic ' + Buffer.from(`${username}:${token}`).toString('base64');
  }

  /** Enumerate the programs the authenticated hacker account actually has access to. */
  async listAccessiblePrograms(): Promise<Array<{ handle: string; name: string }>> {
    if (!runtimeConfig.isPlatformEnabled('hackerone')) return [];
    const auth = this.h1AuthHeader();
    if (!auth) return [];

    const programs: Array<{ handle: string; name: string }> = [];
    let url: string | null = 'https://api.hackerone.com/v1/hackers/programs';

    while (url) {
      const response: Response = await fetch(url, {
        headers: { 'Accept': 'application/json', 'Authorization': auth },
        signal: AbortSignal.timeout(15000),
      });
      if (!response.ok) break;

      const data = await response.json() as any;
      for (const item of data.data || []) {
        const handle = item.attributes?.handle;
        if (handle) programs.push({ handle, name: item.attributes?.name || handle });
      }
      url = data.links?.next || null;
    }

    return programs;
  }

  /** Exposed (was private) so callers that need a real authenticated scope
   *  fetch without going through this class's own file-based program store
   *  (e.g. syncing straight into the DB-backed programs table) can reuse the
   *  same authenticated-first, fallback-to-public logic instead of duplicating it.
   *
   *  `realDataFound` is the load-bearing part of this contract: every failure
   *  mode (non-2xx, thrown error, or a 2xx with an empty structured_scopes
   *  relationship) used to be swallowed silently and fall through to
   *  generateFallbackScope()/generateFallbackRules() — a FIXED, identical
   *  synthetic template (same asset count, same $10k bounty) regardless of
   *  which program it was "for". Found live: syncing an account's accessible
   *  programs produced hundreds of rows that were all identical except the
   *  name, because every single fetch attempt was failing for reasons that
   *  were never logged. Callers MUST check this flag before trusting scope/
   *  rules as real — see sync-hackerone in routes/bounty.ts, which now skips
   *  inserting a program rather than storing fabricated data as if real. */
  async fetchHackerOne(config: ProgramConfig): Promise<{ scope: ProgramScope; rules: ProgramRules; description: string; realDataFound: boolean }> {
    const handle = config.handle || config.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const domain = this.extractDomain(config.url);
    const auth = this.h1AuthHeader();

    // Prefer the authenticated hacker-resources API — it returns structured
    // scope for private/invite-only programs, which the public JSON endpoint
    // below cannot see.
    if (auth) {
      try {
        const response = await fetch(`https://api.hackerone.com/v1/hackers/programs/${handle}?include=structured_scopes`, {
          headers: { 'Accept': 'application/json', 'Authorization': auth },
          signal: AbortSignal.timeout(15000),
        });

        if (response.ok) {
          const data = await response.json() as any;
          // This single-resource endpoint returns the program directly at the
          // top level ({id, type, attributes, relationships}) — unlike the
          // list endpoint above it, which wraps entries in `data: [...]`.
          // Reading `data.data?.attributes` here always came back undefined,
          // so structured_scopes looked empty for every single program even
          // though the API was returning real scope data (see
          // fetchHackerOne's doc comment for how this was found).
          const attrs = data.attributes || {};

          const inScope: ScopeAsset[] = [];
          const outOfScope: ScopeAsset[] = [];

          if (data.relationships?.structured_scopes?.data) {
            for (const scope of data.relationships.structured_scopes.data) {
              const sAttrs = scope.attributes || {};
              // Skip entries with no identifier entirely — pushing an empty
              // string let realDataFound:true be returned for a program
              // whose "scope" was actually unusable once bounty.ts's own
              // `.filter(Boolean)` on identifiers stripped these out again.
              if (!sAttrs.asset_identifier) continue;
              const asset: ScopeAsset = {
                type: this.mapHackerOneAssetType(sAttrs.asset_type),
                identifier: sAttrs.asset_identifier,
                maxSeverity: sAttrs.max_severity || undefined,
                eligible: sAttrs.eligible_for_bounty ?? true,
                instruction: sAttrs.instruction || undefined,
              };
              if (sAttrs.eligible_for_submission !== false) {
                inScope.push(asset);
              } else {
                outOfScope.push(asset);
              }
            }
          }

          if (inScope.length > 0 || outOfScope.length > 0) {
            const programScope: ProgramScope = {
              inScope,
              outOfScope,
              lastUpdated: Date.now(),
            };

            // Best-effort real bounty range — HackerOne's exact attribute
            // naming isn't pinned down against live API docs here, so this
            // tries the plausible key spellings and stays undefined (never a
            // guessed number) if none are present.
            const lowerBounty = Number(attrs.average_bounty_lower_amount ?? attrs.bounty_lower_amount);
            const upperBounty = Number(attrs.average_bounty_upper_amount ?? attrs.bounty_upper_amount);

            const rules: ProgramRules = {
              disclosure: attrs.policy || 'coordinated',
              safeHarbor: attrs.safe_harbor_enabled ?? true,
              maxBounty: Number.isFinite(upperBounty) ? upperBounty : undefined,
              minBounty: Number.isFinite(lowerBounty) ? lowerBounty : undefined,
              responseTime: attrs.response_efficiency_percentage
                ? `${attrs.response_efficiency_percentage}% within SLA`
                : undefined,
              // No fabricated boilerplate here anymore — a program we have
              // real authenticated access to but no genuine structured rules
              // list for should read as "we don't have this," not a made-up
              // generic policy that isn't actually this program's rules.
              rules: [],
              exclusions: [],
              submissionState: attrs.submission_state || attrs.state || undefined,
              offersBounties: typeof attrs.offers_bounties === 'boolean' ? attrs.offers_bounties : undefined,
              lastUpdated: Date.now(),
            };

            const description = attrs.about || attrs.description || `HackerOne program for ${config.name}`;

            return { scope: programScope, rules, description, realDataFound: true };
          }
          logger.warn('[ProgramFetcher] HackerOne authenticated fetch OK but structured_scopes was empty', { handle });
        } else {
          logger.warn('[ProgramFetcher] HackerOne authenticated fetch failed', { handle, status: response.status });
        }
      } catch (err) {
        logger.warn('[ProgramFetcher] HackerOne authenticated fetch threw', { handle, err: String(err) });
      }
    }

    try {
      const response = await fetch(`https://hackerone.com/api/v1/hackers/programs/${handle}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(15000),
      });

      if (response.ok) {
        const data = await response.json() as any;

        const inScope: ScopeAsset[] = [];
        const outOfScope: ScopeAsset[] = [];

        if (data.relationships?.structured_scopes?.data) {
          for (const scope of data.relationships.structured_scopes.data) {
            const attrs = scope.attributes || {};
            if (!attrs.asset_identifier) continue;
            const asset: ScopeAsset = {
              type: this.mapHackerOneAssetType(attrs.asset_type),
              identifier: attrs.asset_identifier,
              maxSeverity: attrs.max_severity || undefined,
              eligible: attrs.eligible_for_bounty ?? true,
              instruction: attrs.instruction || undefined,
            };
            if (attrs.eligible_for_submission !== false) {
              inScope.push(asset);
            } else {
              outOfScope.push(asset);
            }
          }
        }

        if (inScope.length > 0 || outOfScope.length > 0) {
          const programScope: ProgramScope = {
            inScope,
            outOfScope,
            lastUpdated: Date.now(),
          };

          const bountyTable = data.relationships?.bounty_table?.data?.attributes || {};
          const rules: ProgramRules = {
            disclosure: data.attributes?.policy || 'coordinated',
            safeHarbor: data.attributes?.safe_harbor_enabled ?? true,
            // Number.isFinite (via numOrUndef), not `||` — a genuine $0 bounty
            // (VDP-only program) must not collapse to "no data", matching the
            // fix applied to the authenticated branch above.
            maxBounty: this.numOrUndef(bountyTable.max_bounty),
            minBounty: this.numOrUndef(bountyTable.min_bounty),
            responseTime: data.attributes?.response_efficiency_percentage
              ? `${data.attributes.response_efficiency_percentage}% within SLA`
              : undefined,
            // Same discipline as the authenticated branch above — no
            // fabricated rules/exclusions text for a program we don't
            // actually have a genuine structured list for.
            rules: [],
            exclusions: [],
            lastUpdated: Date.now(),
          };

          const description = data.attributes?.about || data.attributes?.description || `HackerOne program for ${config.name}`;

          return { scope: programScope, rules, description, realDataFound: true };
        }
        logger.warn('[ProgramFetcher] HackerOne public fetch OK but structured_scopes was empty', { handle });
      } else {
        logger.warn('[ProgramFetcher] HackerOne public fetch failed', { handle, status: response.status });
      }
    } catch (err) {
      logger.warn('[ProgramFetcher] HackerOne public fetch threw', { handle, err: String(err) });
    }

    logger.warn('[ProgramFetcher] No real scope data found for HackerOne program — falling back to synthetic placeholder', { handle });
    return {
      scope: this.generateFallbackScope(domain),
      rules: this.generateFallbackRules(domain, 'hackerone'),
      description: `HackerOne bug bounty program for ${config.name}. Targets include ${domain} and related assets.`,
      realDataFound: false,
    };
  }

  private async fetchBugcrowd(config: ProgramConfig): Promise<{ scope: ProgramScope; rules: ProgramRules; description: string; realDataFound: boolean }> {
    const handle = config.handle || config.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const domain = this.extractDomain(config.url);

    try {
      const response = await fetch(`https://bugcrowd.com/${handle}.json`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(15000),
      });

      if (response.ok) {
        const data = await response.json() as any;

        const inScope: ScopeAsset[] = [];
        const outOfScope: ScopeAsset[] = [];

        if (data.target_groups) {
          for (const group of data.target_groups) {
            if (group.targets) {
              for (const target of group.targets) {
                const identifier = target.name || target.uri || '';
                if (!identifier) continue;
                const asset: ScopeAsset = {
                  type: this.mapBugcrowdAssetType(target.category),
                  identifier,
                  maxSeverity: target.max_severity || undefined,
                  eligible: true,
                  instruction: target.description || undefined,
                };
                if (group.in_scope !== false) {
                  inScope.push(asset);
                } else {
                  outOfScope.push(asset);
                }
              }
            }
          }
        }

        if (inScope.length > 0 || outOfScope.length > 0) {
          const programScope: ProgramScope = { inScope, outOfScope, lastUpdated: Date.now() };

          const rules: ProgramRules = {
            disclosure: data.disclosure_policy || 'coordinated',
            safeHarbor: data.safe_harbor ?? true,
            maxBounty: this.numOrUndef(data.max_payout),
            minBounty: this.numOrUndef(data.min_payout),
            responseTime: data.response_time || undefined,
            rules: [],
            exclusions: [],
            lastUpdated: Date.now(),
          };

          const description = data.description || data.brief_url || `Bugcrowd program for ${config.name}`;

          return { scope: programScope, rules, description, realDataFound: true };
        }
        logger.warn('[ProgramFetcher] Bugcrowd fetch OK but no scope targets found', { handle });
      } else {
        logger.warn('[ProgramFetcher] Bugcrowd fetch failed', { handle, status: response.status });
      }
    } catch (err) {
      logger.warn('[ProgramFetcher] Bugcrowd fetch threw', { handle, err: String(err) });
    }

    logger.warn('[ProgramFetcher] No real scope data found for Bugcrowd program — falling back to synthetic placeholder', { handle });
    return {
      scope: this.generateFallbackScope(domain),
      rules: this.generateFallbackRules(domain, 'bugcrowd'),
      description: `Bugcrowd bug bounty program for ${config.name}. Targets include ${domain} and related assets.`,
      realDataFound: false,
    };
  }

  private async fetchIntigriti(config: ProgramConfig): Promise<{ scope: ProgramScope; rules: ProgramRules; description: string; realDataFound: boolean }> {
    const handle = config.handle || config.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const domain = this.extractDomain(config.url);

    try {
      const response = await fetch(`https://app.intigriti.com/api/program/${handle}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(15000),
      });

      if (response.ok) {
        const data = await response.json() as any;

        const inScope: ScopeAsset[] = [];
        const outOfScope: ScopeAsset[] = [];

        if (data.domains) {
          for (const d of data.domains) {
            const identifier = d.endpoint || d.domain || '';
            if (!identifier) continue;
            const asset: ScopeAsset = {
              type: this.mapIntigritiAssetType(d.type),
              identifier,
              maxSeverity: d.severity || undefined,
              eligible: d.bounty_eligible ?? true,
              instruction: d.description || undefined,
            };
            if (d.in_scope !== false) {
              inScope.push(asset);
            } else {
              outOfScope.push(asset);
            }
          }
        }

        if (inScope.length > 0 || outOfScope.length > 0) {
          const programScope: ProgramScope = { inScope, outOfScope, lastUpdated: Date.now() };

          const rules: ProgramRules = {
            disclosure: data.disclosure_type || 'coordinated',
            safeHarbor: data.safe_harbor ?? true,
            maxBounty: this.numOrUndef(data.max_bounty),
            minBounty: this.numOrUndef(data.min_bounty),
            responseTime: data.sla || undefined,
            rules: [],
            exclusions: [],
            lastUpdated: Date.now(),
          };

          const description = data.description || `Intigriti program for ${config.name}`;

          return { scope: programScope, rules, description, realDataFound: true };
        }
        logger.warn('[ProgramFetcher] Intigriti fetch OK but no scope domains found', { handle });
      } else {
        logger.warn('[ProgramFetcher] Intigriti fetch failed', { handle, status: response.status });
      }
    } catch (err) {
      logger.warn('[ProgramFetcher] Intigriti fetch threw', { handle, err: String(err) });
    }

    logger.warn('[ProgramFetcher] No real scope data found for Intigriti program — falling back to synthetic placeholder', { handle });
    return {
      scope: this.generateFallbackScope(domain),
      rules: this.generateFallbackRules(domain, 'intigriti'),
      description: `Intigriti bug bounty program for ${config.name}. Targets include ${domain} and related assets.`,
      realDataFound: false,
    };
  }

  private async fetchSynack(config: ProgramConfig): Promise<{ scope: ProgramScope; rules: ProgramRules; description: string; realDataFound: boolean }> {
    const handle = config.handle || config.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const domain = this.extractDomain(config.url);

    try {
      const synackToken = process.env.SYNACK_API_TOKEN;
      if (!synackToken) {
        throw new Error('SYNACK_API_TOKEN not set');
      }

      const response = await fetch(`https://platform.synack.com/api/asset/v2/assets?listingUid[]=${handle}&active=true&scope[]=in&scope[]=discovered&perPage=500`, {
        headers: {
          'Authorization': `Bearer ${synackToken}`,
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(15000),
      });

      if (response.ok) {
        const data = await response.json() as any;

        const inScope: ScopeAsset[] = [];
        const outOfScope: ScopeAsset[] = [];

        const assets = data.assets || data.data || data || [];
        const assetList = Array.isArray(assets) ? assets : [];

        for (const asset of assetList) {
          const identifier = asset.location || asset.value || asset.name || '';
          if (!identifier) continue;
          const scopeAsset: ScopeAsset = {
            type: this.mapSynackAssetType(asset.assetType || asset.type || ''),
            identifier,
            maxSeverity: asset.maxSeverity || undefined,
            eligible: true,
            instruction: asset.notes || undefined,
          };
          if (asset.scope === 'in' || asset.scope === 'discovered') {
            inScope.push(scopeAsset);
          } else if (asset.scope === 'out') {
            outOfScope.push(scopeAsset);
          } else {
            inScope.push(scopeAsset);
          }
        }

        if (inScope.length > 0 || outOfScope.length > 0) {
          const programScope: ProgramScope = { inScope, outOfScope, lastUpdated: Date.now() };

          const targetResponse = await fetch(`https://platform.synack.com/api/targets/${handle}`, {
            headers: {
              'Authorization': `Bearer ${synackToken}`,
              'Accept': 'application/json',
            },
            signal: AbortSignal.timeout(10000),
          }).catch(() => null);

          let targetData: any = {};
          if (targetResponse?.ok) {
            targetData = await targetResponse.json().catch(() => ({}));
          }

          const rules: ProgramRules = {
            disclosure: 'coordinated',
            safeHarbor: true,
            maxBounty: this.numOrUndef(targetData.maxPayout ?? targetData.bounty_max),
            minBounty: this.numOrUndef(targetData.minPayout ?? targetData.bounty_min),
            responseTime: undefined,
            // Real, program-independent facts about how Synack testing works
            // (not fabricated per-program policy text) — every Synack
            // engagement genuinely requires LaunchPoint VPN and Red Team terms.
            rules: [
              'Synack Red Team rules apply',
              'All testing must be conducted through Synack LaunchPoint VPN',
              'Do not test outside of designated target scope',
            ],
            exclusions: [],
            lastUpdated: Date.now(),
          };

          const description = targetData.description || targetData.about || `Synack program for ${config.name}`;

          return { scope: programScope, rules, description, realDataFound: true };
        }
        logger.warn('[ProgramFetcher] Synack fetch OK but no scope assets found', { handle });
      } else {
        logger.warn('[ProgramFetcher] Synack fetch failed', { handle, status: response.status });
      }
    } catch (err) {
      logger.warn('[ProgramFetcher] Synack fetch threw', { handle, err: String(err) });
    }

    logger.warn('[ProgramFetcher] No real scope data found for Synack program — falling back to synthetic placeholder', { handle });
    return {
      scope: this.generateFallbackScope(domain),
      rules: {
        ...this.generateFallbackRules(domain, 'synack'),
        rules: [
          ...this.generateFallbackRules(domain, 'synack').rules,
          'Synack Red Team rules apply',
          'All testing must be conducted through Synack LaunchPoint VPN',
        ],
      },
      description: `Synack bug bounty program for ${config.name}. Targets include ${domain} and related assets. Note: Synack requires LaunchPoint VPN for testing.`,
      realDataFound: false,
    };
  }

  private async fetchYesWeHack(config: ProgramConfig): Promise<{ scope: ProgramScope; rules: ProgramRules; description: string; realDataFound: boolean }> {
    const handle = config.handle || config.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const domain = this.extractDomain(config.url);

    try {
      const ywhToken = process.env.YESWEHACK_API_TOKEN;
      const headers: Record<string, string> = { 'Accept': 'application/json' };
      if (ywhToken) {
        headers['X-AUTH-TOKEN'] = ywhToken;
      }

      const response = await fetch(`https://api.yeswehack.com/programs/${handle}`, {
        headers,
        signal: AbortSignal.timeout(15000),
      });

      if (response.ok) {
        const data = await response.json() as any;

        const inScope: ScopeAsset[] = [];
        const outOfScope: ScopeAsset[] = [];

        const scopes = data.scopes || data.scope || [];
        for (const s of (Array.isArray(scopes) ? scopes : [])) {
          const identifier = s.scope || s.asset || s.target || '';
          if (!identifier) continue;
          const asset: ScopeAsset = {
            type: this.mapYesWeHackAssetType(s.scope_type || s.asset_type || s.type || ''),
            identifier,
            maxSeverity: s.max_severity || undefined,
            eligible: s.bounty_eligible ?? true,
            instruction: s.instruction || s.description || undefined,
          };
          if (s.in_scope !== false && s.scope_type_prefix !== 'out') {
            inScope.push(asset);
          } else {
            outOfScope.push(asset);
          }
        }

        if (data.domains) {
          for (const d of (Array.isArray(data.domains) ? data.domains : [])) {
            const identifier = d.domain || d.endpoint || d.value || '';
            if (!identifier) continue;
            const asset: ScopeAsset = {
              type: this.mapYesWeHackAssetType(d.type || 'domain'),
              identifier,
              maxSeverity: d.severity || undefined,
              eligible: d.bounty_eligible ?? true,
              instruction: d.description || undefined,
            };
            if (d.in_scope !== false) {
              inScope.push(asset);
            } else {
              outOfScope.push(asset);
            }
          }
        }

        if (inScope.length > 0 || outOfScope.length > 0) {
          const programScope: ProgramScope = { inScope, outOfScope, lastUpdated: Date.now() };

          const rules: ProgramRules = {
            disclosure: data.disclosure_policy || data.disclosure || 'coordinated',
            safeHarbor: data.safe_harbor ?? true,
            maxBounty: this.numOrUndef(data.max_bounty ?? data.reward_max),
            minBounty: this.numOrUndef(data.min_bounty ?? data.reward_min),
            responseTime: data.response_time || data.sla || undefined,
            rules: data.rules ? (Array.isArray(data.rules) ? data.rules : [data.rules]) : [],
            exclusions: data.out_of_scope_rules ? (Array.isArray(data.out_of_scope_rules) ? data.out_of_scope_rules : [data.out_of_scope_rules]) : [],
            lastUpdated: Date.now(),
          };

          const description = data.description || data.title || `YesWeHack program for ${config.name}`;

          return { scope: programScope, rules, description, realDataFound: true };
        }
        logger.warn('[ProgramFetcher] YesWeHack authenticated fetch OK but no scope found', { handle });
      } else {
        logger.warn('[ProgramFetcher] YesWeHack authenticated fetch failed', { handle, status: response.status });
      }

      const publicResponse = await fetch(`https://yeswehack.com/programs/${handle}`, {
        headers: { 'Accept': 'text/html' },
        signal: AbortSignal.timeout(15000),
      });

      if (publicResponse.ok) {
        const html = await publicResponse.text();
        const titleMatch = html.match(/<title[^>]*>(.*?)<\/title>/i);
        const scopeMatches = html.match(/scope[^"]*":\s*"([^"]+)"/g) || [];

        const extractedScopes: ScopeAsset[] = [];
        for (const match of scopeMatches.slice(0, 20)) {
          const val = match.replace(/.*":\s*"/, '').replace(/"$/, '');
          if (val && val.includes('.')) {
            extractedScopes.push({
              type: val.startsWith('*.') ? 'wildcard' : 'domain',
              identifier: val,
              eligible: true,
            });
          }
        }

        if (extractedScopes.length > 0) {
          // Best-effort HTML scrape — inScope is genuinely scraped, but we
          // have no real signal on out-of-scope from this page, so it stays
          // empty ("we don't know") rather than the synthetic placeholder.
          return {
            scope: { inScope: extractedScopes, outOfScope: [], lastUpdated: Date.now() },
            rules: { disclosure: 'coordinated', safeHarbor: true, rules: [], exclusions: [], lastUpdated: Date.now() },
            description: titleMatch ? titleMatch[1].trim() : `YesWeHack program for ${config.name}`,
            realDataFound: true,
          };
        }
        logger.warn('[ProgramFetcher] YesWeHack public page had no extractable scope', { handle });
      } else {
        logger.warn('[ProgramFetcher] YesWeHack public fetch failed', { handle, status: publicResponse.status });
      }
    } catch (err) {
      logger.warn('[ProgramFetcher] YesWeHack fetch threw', { handle, err: String(err) });
    }

    logger.warn('[ProgramFetcher] No real scope data found for YesWeHack program — falling back to synthetic placeholder', { handle });
    return {
      scope: this.generateFallbackScope(domain),
      rules: this.generateFallbackRules(domain, 'yeswehack'),
      description: `YesWeHack bug bounty program for ${config.name}. Targets include ${domain} and related assets.`,
      realDataFound: false,
    };
  }

  private async fetchCustom(config: ProgramConfig): Promise<{ scope: ProgramScope; rules: ProgramRules; description: string; realDataFound: boolean }> {
    const domain = this.extractDomain(config.url);
    const inScope: ScopeAsset[] = [
      { type: 'url', identifier: config.url, maxSeverity: 'critical', eligible: true },
      { type: 'domain', identifier: domain, maxSeverity: 'critical', eligible: true },
    ];

    try {
      const robotsResponse = await fetch(`https://${domain}/robots.txt`, {
        signal: AbortSignal.timeout(10000),
      });
      if (robotsResponse.ok) {
        const robotsTxt = await robotsResponse.text();
        const disallowPaths = robotsTxt
          .split('\n')
          .filter(line => line.toLowerCase().startsWith('disallow:'))
          .map(line => line.replace(/^disallow:\s*/i, '').trim())
          .filter(Boolean);

        for (const p of disallowPaths.slice(0, 10)) {
          inScope.push({
            type: 'url',
            identifier: `https://${domain}${p}`,
            instruction: 'Discovered via robots.txt',
            eligible: true,
          });
        }
      }
    } catch {}

    try {
      const sitemapResponse = await fetch(`https://${domain}/sitemap.xml`, {
        signal: AbortSignal.timeout(10000),
      });
      if (sitemapResponse.ok) {
        const sitemapXml = await sitemapResponse.text();
        const urlMatches = sitemapXml.match(/<loc>(.*?)<\/loc>/g) || [];
        const urls = urlMatches
          .map(m => m.replace(/<\/?loc>/g, ''))
          .filter(u => u.includes(domain))
          .slice(0, 20);

        for (const u of urls) {
          if (!inScope.find(a => a.identifier === u)) {
            inScope.push({
              type: 'url',
              identifier: u,
              instruction: 'Discovered via sitemap.xml',
              eligible: true,
            });
          }
        }
      }
    } catch {}

    return {
      scope: {
        inScope,
        outOfScope: [
          { type: 'other', identifier: 'Third-party services', eligible: false, instruction: 'Do not test third-party integrations' },
        ],
        lastUpdated: Date.now(),
      },
      rules: this.generateFallbackRules(domain, 'custom'),
      description: `Custom bug bounty program for ${config.name} targeting ${domain}.`,
      // A custom program has no external source of truth to fall back FROM —
      // this URL/robots.txt/sitemap.xml scrape IS the real data for it, not a
      // synthetic placeholder standing in for a failed authoritative fetch.
      realDataFound: true,
    };
  }

  // === Asset Type Mapping ===

  private mapHackerOneAssetType(assetType: string): ScopeAsset['type'] {
    const mapping: Record<string, ScopeAsset['type']> = {
      URL: 'url',
      CIDR: 'domain',
      DOMAIN: 'domain',
      WILDCARD: 'wildcard',
      IOS: 'ios',
      ANDROID: 'android',
      API: 'api',
      HARDWARE: 'hardware',
      SOURCE_CODE: 'other',
      EXECUTABLE: 'other',
      OTHER: 'other',
    };
    return mapping[assetType?.toUpperCase()] || 'other';
  }

  private mapBugcrowdAssetType(category: string): ScopeAsset['type'] {
    const mapping: Record<string, ScopeAsset['type']> = {
      website: 'url',
      api: 'api',
      mobile: 'android',
      ios: 'ios',
      android: 'android',
      hardware: 'hardware',
      other: 'other',
    };
    return mapping[category?.toLowerCase()] || 'other';
  }

  private mapIntigritiAssetType(type: string): ScopeAsset['type'] {
    const mapping: Record<string, ScopeAsset['type']> = {
      url: 'url',
      domain: 'domain',
      wildcard: 'wildcard',
      ios: 'ios',
      android: 'android',
      api: 'api',
      ip: 'domain',
    };
    return mapping[type?.toLowerCase()] || 'other';
  }

  private mapSynackAssetType(assetType: string): ScopeAsset['type'] {
    const mapping: Record<string, ScopeAsset['type']> = {
      webapp: 'url',
      web: 'url',
      host: 'domain',
      cidr: 'domain',
      ip: 'domain',
      mobile: 'android',
      ios: 'ios',
      android: 'android',
      api: 'api',
      hardware: 'hardware',
      re: 'other',
    };
    return mapping[assetType?.toLowerCase()] || 'other';
  }

  private mapYesWeHackAssetType(scopeType: string): ScopeAsset['type'] {
    const mapping: Record<string, ScopeAsset['type']> = {
      'web-application': 'url',
      web: 'url',
      url: 'url',
      domain: 'domain',
      wildcard: 'wildcard',
      ip: 'domain',
      cidr: 'domain',
      api: 'api',
      'mobile-application': 'android',
      'mobile-application-android': 'android',
      'mobile-application-ios': 'ios',
      ios: 'ios',
      android: 'android',
      hardware: 'hardware',
      other: 'other',
    };
    return mapping[scopeType?.toLowerCase()] || 'other';
  }
}

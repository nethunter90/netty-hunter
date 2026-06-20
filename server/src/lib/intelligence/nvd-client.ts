/**
 * NVD Client — National Vulnerability Database (NIST NVD API 2.0)
 * Free API: 5 req/30s without key, 50 req/30s with NVD_API_KEY.
 * All methods fail open — return [] on any error or timeout.
 */
import logger from '../../utils/logger';
import { runtimeConfig } from '../runtime-config';

export interface CVERecord {
  id: string;
  description: string;
  cvssScore: number;
  cweIds: string[];
  exploitAvailable: boolean;
  publishedDate: string;
  references: string[];
}

class NVDClient {
  private get apiKey(): string | undefined { return runtimeConfig.get("NVD_API_KEY") || process.env.NVD_API_KEY; }
  private readonly cache = new Map<string, { records: CVERecord[]; fetchedAt: number }>();
  private readonly CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
  private readonly WINDOW_MS = 30_000;
  private windowStart = 0;
  private windowCount = 0;
  private queueRunning = false;
  private readonly queue: Array<() => Promise<void>> = [];

  private get maxPerWindow(): number {
    return this.apiKey ? 45 : 4;
  }

  private cacheKey(params: Record<string, string>): string {
    return Object.entries(params)
      .map(([k, v]) => `${k}:${encodeURIComponent(v.toLowerCase())}`)
      .join(';');
  }

  private async drainQueue(): Promise<void> {
    if (this.queueRunning) return;
    this.queueRunning = true;
    while (this.queue.length > 0) {
      const now = Date.now();
      if (now - this.windowStart >= this.WINDOW_MS) {
        this.windowStart = now;
        this.windowCount = 0;
      }
      if (this.windowCount >= this.maxPerWindow) {
        const wait = this.WINDOW_MS - (Date.now() - this.windowStart) + 50;
        await new Promise(r => setTimeout(r, wait));
        this.windowStart = Date.now();
        this.windowCount = 0;
      }
      const task = this.queue.shift();
      if (task) {
        this.windowCount++;
        await task();
      }
    }
    this.queueRunning = false;
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push(async () => {
        try { resolve(await fn()); }
        catch (e) { reject(e); }
      });
      this.drainQueue().catch(() => {});
    });
  }

  async lookupByKeyword(tech: string, version?: string): Promise<CVERecord[]> {
    const keyword = version ? `${tech} ${version}` : tech;
    const params = { keywordSearch: keyword };
    const key = this.cacheKey(params);

    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.fetchedAt < this.CACHE_TTL_MS) {
      return cached.records;
    }

    try {
      const records = await this.enqueue(() => this.fetchNVD(params));
      this.cache.set(key, { records, fetchedAt: Date.now() });
      return records;
    } catch (err: any) {
      const isAbort = err?.name === 'AbortError' || err?.name === 'TimeoutError';
      logger[isAbort ? 'debug' : 'warn']('[NVDClient] lookupByKeyword failed', { keyword, err: err.message });
      return [];
    }
  }

  async lookupById(cveId: string): Promise<CVERecord | null> {
    const params = { cveId };
    const key = this.cacheKey(params);

    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.fetchedAt < this.CACHE_TTL_MS) {
      return cached.records[0] ?? null;
    }

    try {
      const records = await this.enqueue(() => this.fetchNVD(params));
      this.cache.set(key, { records, fetchedAt: Date.now() });
      return records[0] ?? null;
    } catch (err: any) {
      const isAbort = err?.name === 'AbortError' || err?.name === 'TimeoutError';
      logger[isAbort ? 'debug' : 'warn']('[NVDClient] lookupById failed', { cveId, err: err.message });
      return null;
    }
  }

  async lookupByKeywordFiltered(keyword: string, options: { severity?: string; year?: string } = {}): Promise<CVERecord[]> {
    const params: Record<string, string> = { keywordSearch: keyword };
    if (options.year && options.year !== 'all') {
      params.pubStartDate = `${options.year}-01-01T00:00:00.000`;
      params.pubEndDate = `${options.year}-12-31T23:59:59.999`;
    }
    const key = this.cacheKey(params);

    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.fetchedAt < this.CACHE_TTL_MS) {
      return this.filterBySeverity(cached.records, options.severity);
    }

    try {
      const records = await this.enqueue(() => this.fetchNVD(params));
      this.cache.set(key, { records, fetchedAt: Date.now() });
      return this.filterBySeverity(records, options.severity);
    } catch (err: any) {
      const isAbort = err?.name === 'AbortError' || err?.name === 'TimeoutError';
      logger[isAbort ? 'debug' : 'warn']('[NVDClient] lookupByKeywordFiltered failed', { keyword, err: err.message });
      return [];
    }
  }

  private filterBySeverity(records: CVERecord[], severity?: string): CVERecord[] {
    if (!severity || severity === 'all') return records;
    return records.filter(r => {
      const s = cvssToSeverity(r.cvssScore);
      return s === severity;
    });
  }

  async lookupByCWE(cweId: string): Promise<CVERecord[]> {
    const params = { cweId };
    const key = this.cacheKey(params);

    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.fetchedAt < this.CACHE_TTL_MS) {
      return cached.records;
    }

    try {
      const records = await this.enqueue(() => this.fetchNVD(params));
      this.cache.set(key, { records, fetchedAt: Date.now() });
      return records;
    } catch (err: any) {
      const isAbort = err?.name === 'AbortError' || err?.name === 'TimeoutError';
      logger[isAbort ? 'debug' : 'warn']('[NVDClient] lookupByCWE failed', { cweId, err: err.message });
      return [];
    }
  }

  private async fetchNVD(params: Record<string, string>): Promise<CVERecord[]> {
    const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (this.apiKey) headers['apiKey'] = this.apiKey;

    const resp = await fetch(url.toString(), {
      headers,
      signal: AbortSignal.timeout(15000),
    });

    if (!resp.ok) {
      const level = resp.status === 503 ? 'debug' : 'warn';
      logger[level]('[NVDClient] API error', { status: resp.status, params });
      return [];
    }

    const json = await resp.json();
    return this.parseResponse(json);
  }

  private parseResponse(json: unknown): CVERecord[] {
    if (typeof json !== 'object' || json === null || !('vulnerabilities' in json)) return [];
    const vulns = (json as any).vulnerabilities;
    if (!Array.isArray(vulns)) return [];

    return vulns.slice(0, 20).map((entry: any): CVERecord | null => {
      const cve = entry?.cve;
      if (!cve) return null;

      const id = String(cve.id ?? '');
      if (!id.startsWith('CVE-')) return null;

      const description = (cve.descriptions as any[])?.find((d: any) => d.lang === 'en')?.value ?? '';

      // CVSS: try V31 → V30 → V2
      const metrics = cve.metrics ?? {};
      const cvssScore: number =
        metrics.cvssMetricV31?.[0]?.cvssData?.baseScore ??
        metrics.cvssMetricV30?.[0]?.cvssData?.baseScore ??
        metrics.cvssMetricV2?.[0]?.cvssData?.baseScore ??
        0;

      const cweIds: string[] = (cve.weaknesses as any[] ?? [])
        .flatMap((w: any) => (w.description as any[] ?? []).map((d: any) => String(d.value ?? '')))
        .filter((v: string) => v.startsWith('CWE-'));

      const references: string[] = (cve.references as any[] ?? [])
        .slice(0, 5)
        .map((r: any) => String(r.url ?? ''));

      const exploitAvailable = references.some(r =>
        /exploit-db|exploitdb|github\.com\/.*exploit|metasploit|packetstorm|poc/i.test(r)
      );

      return {
        id,
        description: String(description).slice(0, 500),
        cvssScore,
        cweIds,
        exploitAvailable,
        publishedDate: String(cve.published ?? ''),
        references,
      };
    }).filter((r): r is CVERecord => r !== null);
  }
}

export const nvdClient = new NVDClient();

export function cvssToSeverity(score: number): string {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

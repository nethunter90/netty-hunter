/**
 * ExploitChainIntelligence — lib/hunter
 *
 * In-memory singleton tracking cross-session exploit chain patterns,
 * ROI data, and WAF-aware recommendations.
 */
import { v4 as uuidv4 } from 'uuid';

export interface ChainRecord {
  chainId: string;
  sessionId?: string;
  vendor?: string;
  techStack: string[];
  sequence: string[];    // ordered list of vulnClass or technique names
  bounty: number;        // payout received; 0 if not yet paid
  succeeded: boolean;
  recordedAt: number;
}

export interface ChainPattern {
  sequence: string[];
  occurrences: number;
  avgBounty: number;
  successRate: number;
  wafVendors: string[];
  lastSeen: number;
}

export interface ChainRecommendation {
  sequence: string[];
  rationale: string;
  estimatedBounty: number;
  confidence: number;
}

export interface ChainROIEntry {
  sequence: string[];
  avgBounty: number;
  successRate: number;
  roi: number;            // avgBounty * successRate
  attempts: number;
}

export interface ChainStats {
  totalChains: number;
  successfulChains: number;
  totalBounty: number;
  avgBountyPerChain: number;
  topSequence: string[] | null;
}

// ── Singleton ─────────────────────────────────────────────────────────────────

class ExploitChainIntelligenceStore {
  private chains: Map<string, ChainRecord> = new Map();

  // ── Write ──────────────────────────────────────────────────────────────────

  recordChain(data: Partial<ChainRecord> & { sequence: string[] }): ChainRecord {
    const record: ChainRecord = {
      chainId:    uuidv4(),
      sessionId:  data.sessionId,
      vendor:     data.vendor,
      techStack:  data.techStack ?? [],
      sequence:   data.sequence,
      bounty:     data.bounty ?? 0,
      succeeded:  data.succeeded ?? false,
      recordedAt: Date.now(),
    };
    this.chains.set(record.chainId, record);
    return record;
  }

  recordOutcome(chainId: string, bounty: number): boolean {
    const chain = this.chains.get(chainId);
    if (!chain) return false;
    chain.bounty    = bounty;
    chain.succeeded = bounty > 0;
    return true;
  }

  // ── Read ───────────────────────────────────────────────────────────────────

  getChainPatterns(): ChainPattern[] {
    const patternMap = new Map<string, { records: ChainRecord[]; vendors: Set<string> }>();

    for (const c of this.chains.values()) {
      const key = c.sequence.join(' → ');
      if (!patternMap.has(key)) patternMap.set(key, { records: [], vendors: new Set() });
      const entry = patternMap.get(key)!;
      entry.records.push(c);
      if (c.vendor) entry.vendors.add(c.vendor);
    }

    return Array.from(patternMap.entries())
      .map(([key, { records, vendors }]) => {
        const successful   = records.filter(r => r.succeeded);
        const totalBounty  = records.reduce((s, r) => s + r.bounty, 0);
        return {
          sequence:     key.split(' → '),
          occurrences:  records.length,
          avgBounty:    records.length > 0 ? Math.round(totalBounty / records.length) : 0,
          successRate:  records.length > 0 ? Math.round((successful.length / records.length) * 100) / 100 : 0,
          wafVendors:   Array.from(vendors),
          lastSeen:     Math.max(...records.map(r => r.recordedAt)),
        };
      })
      .sort((a, b) => b.successRate * b.avgBounty - a.successRate * a.avgBounty);
  }

  getRecommendations(context: { techStack?: string[]; wafVendor?: string }): ChainRecommendation[] {
    const patterns = this.getChainPatterns();

    return patterns
      .filter(p => {
        if (context.wafVendor && p.wafVendors.length > 0 && !p.wafVendors.includes(context.wafVendor)) return false;
        return p.successRate > 0.2 && p.occurrences >= 2;
      })
      .slice(0, 5)
      .map(p => ({
        sequence:        p.sequence,
        rationale:       `Seen ${p.occurrences}x with ${Math.round(p.successRate * 100)}% success rate`,
        estimatedBounty: p.avgBounty,
        confidence:      Math.min(0.95, p.successRate * (1 + Math.log10(Math.max(p.occurrences, 1)) * 0.1)),
      }));
  }

  getChainsToAvoid(context: { wafVendor?: string }): ChainRecord[] {
    return Array.from(this.chains.values())
      .filter(c => {
        if (!c.succeeded) return true;
        if (context.wafVendor && c.vendor === context.wafVendor && !c.succeeded) return true;
        return false;
      })
      .slice(-20);
  }

  getChainROI(): ChainROIEntry[] {
    const patterns = this.getChainPatterns();
    return patterns
      .map(p => ({
        sequence:    p.sequence,
        avgBounty:   p.avgBounty,
        successRate: p.successRate,
        roi:         Math.round(p.avgBounty * p.successRate),
        attempts:    p.occurrences,
      }))
      .sort((a, b) => b.roi - a.roi)
      .slice(0, 20);
  }

  getStats(): ChainStats {
    const all = Array.from(this.chains.values());
    const successful = all.filter(c => c.succeeded);
    const totalBounty = all.reduce((s, c) => s + c.bounty, 0);
    const top = this.getChainPatterns()[0];
    return {
      totalChains:        all.length,
      successfulChains:   successful.length,
      totalBounty,
      avgBountyPerChain:  all.length > 0 ? Math.round(totalBounty / all.length) : 0,
      topSequence:        top?.sequence ?? null,
    };
  }
}

export const exploitChainIntelligence = new ExploitChainIntelligenceStore();

import fs from 'fs/promises';
import path from 'path';
import {
  CampaignProfile,
  TechniqueOutcome,
  FindingSummary,
  DefenseProfile,
  TechFingerprint,
  CampaignOutcome,
  HuntGoal,
} from './intelligence-types';

export interface CampaignIndexEntry {
  id: string;
  domain: string;
  industry: string;
  stackHash: string;
  wafType: string | null;
  outcome: CampaignOutcome;
  findingCount: number;
  completedAt: string;
}

export interface SimilarCampaign {
  campaignId: string;
  domain: string;
  industry: string;
  similarityScore: number;
  outcome: CampaignOutcome;
  findingCount: number;
  topTechniques: string[];
  completedAt: string;
}

export interface TechniqueRecommendation {
  technique: string;
  variant: string;
  successRate: number;
  avgTimeMinutes: number;
  sourceCampaigns: number;
  adaptations: string[];
  confidence: number;
}

export class CrossCampaignLearning {
  private storageDir: string;
  private index: CampaignIndexEntry[];

  constructor(storageDir: string) {
    this.storageDir = path.join(storageDir, 'campaigns');
    this.index = [];
    this.loadIndex().catch(() => {});
  }

  private async ensureStorageDir(): Promise<void> {
    await fs.mkdir(path.join(this.storageDir, 'profiles'), { recursive: true });
  }

  private async loadIndex(): Promise<void> {
    try {
      const data = await fs.readFile(path.join(this.storageDir, 'index.json'), 'utf-8');
      this.index = JSON.parse(data) as CampaignIndexEntry[];
    } catch {
      this.index = [];
    }
  }

  private async saveIndex(): Promise<void> {
    await this.ensureStorageDir();
    await fs.writeFile(
      path.join(this.storageDir, 'index.json'),
      JSON.stringify(this.index, null, 2),
      'utf-8'
    );
  }

  private computeStackHash(tech: TechFingerprint): string {
    const parts = [
      tech.language || '',
      tech.framework || '',
      tech.server || '',
      tech.database || '',
    ].sort();
    let hash = 0;
    const str = parts.join('|');
    for (let i = 0; i < str.length; i++) {
      const chr = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  }

  async saveCampaign(profile: CampaignProfile): Promise<void> {
    await this.ensureStorageDir();

    const profilePath = path.join(this.storageDir, 'profiles', `${profile.id}.json`);
    await fs.writeFile(profilePath, JSON.stringify(profile, null, 2), 'utf-8');

    const entry: CampaignIndexEntry = {
      id: profile.id,
      domain: profile.target.domain,
      industry: profile.target.industry,
      stackHash: this.computeStackHash(profile.target.techStack),
      wafType: profile.target.defensePosture.wafType,
      outcome: profile.outcome,
      findingCount: profile.findings.length,
      completedAt: profile.hunt.completedAt,
    };

    const existingIdx = this.index.findIndex(e => e.id === profile.id);
    if (existingIdx >= 0) {
      this.index[existingIdx] = entry;
    } else {
      this.index.push(entry);
    }

    await this.saveIndex();
  }

  async getCampaign(id: string): Promise<CampaignProfile | null> {
    try {
      const profilePath = path.join(this.storageDir, 'profiles', `${id}.json`);
      const data = await fs.readFile(profilePath, 'utf-8');
      return JSON.parse(data) as CampaignProfile;
    } catch {
      return null;
    }
  }

  listCampaigns(): CampaignIndexEntry[] {
    return [...this.index];
  }

  async deleteCampaign(id: string): Promise<boolean> {
    const existingIdx = this.index.findIndex(e => e.id === id);
    if (existingIdx < 0) {
      return false;
    }

    this.index.splice(existingIdx, 1);
    await this.saveIndex();

    try {
      await fs.unlink(path.join(this.storageDir, 'profiles', `${id}.json`));
    } catch {}

    return true;
  }

  async findSimilar(
    targetProfile: {
      domain: string;
      techStack?: TechFingerprint;
      defensePosture?: DefenseProfile;
      industry?: string;
    },
    limit?: number
  ): Promise<SimilarCampaign[]> {
    const maxResults = limit ?? 5;
    const scored: Array<{ entry: CampaignIndexEntry; profile: CampaignProfile; score: number }> = [];

    for (const entry of this.index) {
      const profile = await this.getCampaign(entry.id);
      if (!profile) continue;

      const score = this.computeSimilarity(targetProfile, profile);
      scored.push({ entry, profile, score });
    }

    scored.sort((a, b) => {
      if (Math.abs(a.score - b.score) > 0.001) return b.score - a.score;
      return new Date(b.entry.completedAt).getTime() - new Date(a.entry.completedAt).getTime();
    });

    return scored.slice(0, maxResults).map(s => {
      const techniqueCounts = new Map<string, number>();
      for (const t of s.profile.techniques) {
        if (t.result === 'success' || t.result === 'partial') {
          techniqueCounts.set(t.technique, (techniqueCounts.get(t.technique) || 0) + 1);
        }
      }
      const topTechniques = Array.from(techniqueCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([t]) => t);

      return {
        campaignId: s.entry.id,
        domain: s.entry.domain,
        industry: s.entry.industry,
        similarityScore: Math.round(s.score * 1000) / 1000,
        outcome: s.entry.outcome,
        findingCount: s.entry.findingCount,
        topTechniques,
        completedAt: s.entry.completedAt,
      };
    });
  }

  async getRecommendations(
    targetProfile: {
      domain: string;
      techStack?: TechFingerprint;
      defensePosture?: DefenseProfile;
      industry?: string;
    }
  ): Promise<TechniqueRecommendation[]> {
    const similar = await this.findSimilar(targetProfile, 10);
    const relevant = similar.filter(s => s.similarityScore >= 0.70);

    if (relevant.length === 0) {
      return [];
    }

    const techniqueMap = new Map<
      string,
      {
        variants: Map<string, { successes: number; total: number; totalTime: number }>;
        campaignIds: Set<string>;
        adaptations: Set<string>;
      }
    >();

    for (const sim of relevant) {
      const profile = await this.getCampaign(sim.campaignId);
      if (!profile) continue;

      for (const t of profile.techniques) {
        if (!techniqueMap.has(t.technique)) {
          techniqueMap.set(t.technique, {
            variants: new Map(),
            campaignIds: new Set(),
            adaptations: new Set(),
          });
        }

        const entry = techniqueMap.get(t.technique)!;
        entry.campaignIds.add(sim.campaignId);

        if (!entry.variants.has(t.variant)) {
          entry.variants.set(t.variant, { successes: 0, total: 0, totalTime: 0 });
        }

        const variantStats = entry.variants.get(t.variant)!;
        variantStats.total++;
        variantStats.totalTime += t.timeSpentMinutes;
        if (t.result === 'success' || t.result === 'partial') {
          variantStats.successes++;
        }

        if (t.result === 'blocked' && t.blockingReason) {
          entry.adaptations.add(`Bypass ${t.blockingReason}`);
        }
      }
    }

    const recommendations: TechniqueRecommendation[] = [];

    for (const [technique, data] of Array.from(techniqueMap.entries())) {
      let bestVariant = '';
      let bestRate = -1;
      let bestTime = 0;
      let bestTotal = 0;

      for (const [variant, stats] of Array.from(data.variants.entries())) {
        const rate = stats.total > 0 ? stats.successes / stats.total : 0;
        if (rate > bestRate || (rate === bestRate && stats.total > bestTotal)) {
          bestVariant = variant;
          bestRate = rate;
          bestTime = stats.total > 0 ? stats.totalTime / stats.total : 0;
          bestTotal = stats.total;
        }
      }

      const confidence = Math.min(1.0, (data.campaignIds.size / relevant.length) * bestRate);

      recommendations.push({
        technique,
        variant: bestVariant,
        successRate: Math.round(bestRate * 1000) / 1000,
        avgTimeMinutes: Math.round(bestTime * 10) / 10,
        sourceCampaigns: data.campaignIds.size,
        adaptations: Array.from(data.adaptations),
        confidence: Math.round(confidence * 1000) / 1000,
      });
    }

    recommendations.sort((a, b) => {
      const scoreA = a.successRate * a.confidence;
      const scoreB = b.successRate * b.confidence;
      return scoreB - scoreA;
    });

    return recommendations;
  }

  async getTechniqueStats(): Promise<Record<string, { total: number; successes: number; rate: number }>> {
    const stats: Record<string, { total: number; successes: number; rate: number }> = {};

    for (const entry of this.index) {
      const profile = await this.getCampaign(entry.id);
      if (!profile) continue;

      for (const t of profile.techniques) {
        if (!stats[t.technique]) {
          stats[t.technique] = { total: 0, successes: 0, rate: 0 };
        }
        stats[t.technique].total++;
        if (t.result === 'success' || t.result === 'partial') {
          stats[t.technique].successes++;
        }
      }
    }

    for (const key of Object.keys(stats)) {
      stats[key].rate = stats[key].total > 0
        ? Math.round((stats[key].successes / stats[key].total) * 1000) / 1000
        : 0;
    }

    return stats;
  }

  private computeSimilarity(
    target: {
      domain: string;
      techStack?: TechFingerprint;
      defensePosture?: DefenseProfile;
      industry?: string;
    },
    campaign: CampaignProfile
  ): number {
    let score = 0;
    const defense = target.defensePosture;
    const campDefense = campaign.target.defensePosture;

    const wafScore = this.computeWafSimilarity(defense, campDefense);
    score += 0.20 * wafScore;

    const techScore = this.computeTechStackSimilarity(target.techStack, campaign.target.techStack);
    score += 0.18 * techScore;

    const verbosityScore = this.computeVerbositySimilarity(defense, campDefense);
    score += 0.14 * verbosityScore;

    const cspScore = this.computeCspSimilarity(defense, campDefense);
    score += 0.12 * cspScore;

    const apiScore = this.computeApiStyleSimilarity(defense, campDefense);
    score += 0.10 * apiScore;

    const industryScore = this.computeIndustrySimilarity(target.industry, campaign.target.industry);
    score += 0.08 * industryScore;

    const authScore = this.computeAuthSimilarity(defense, campDefense);
    score += 0.08 * authScore;

    const rateScore = this.computeRateLimitSimilarity(defense, campDefense);
    score += 0.05 * rateScore;

    const headerScore = this.computeSecurityHeaderSimilarity(defense, campDefense);
    score += 0.05 * headerScore;

    return score;
  }

  private computeWafSimilarity(
    a?: DefenseProfile,
    b?: DefenseProfile
  ): number {
    if (!a || !b) return 0;

    let typeScore = 0;
    if (a.wafType === b.wafType) {
      typeScore = 1.0;
    } else if (a.wafType === null || b.wafType === null) {
      typeScore = 0;
    } else {
      typeScore = 0;
    }

    const strictnessLevels = ['permissive', 'moderate', 'strict'];
    const aIdx = strictnessLevels.indexOf(a.wafStrictness);
    const bIdx = strictnessLevels.indexOf(b.wafStrictness);
    let strictnessScore = 0;
    if (aIdx >= 0 && bIdx >= 0) {
      const dist = Math.abs(aIdx - bIdx);
      if (dist === 0) strictnessScore = 1.0;
      else if (dist === 1) strictnessScore = 0.5;
      else strictnessScore = 0.0;
    }

    return (typeScore + strictnessScore) / 2;
  }

  private computeTechStackSimilarity(
    a?: TechFingerprint,
    b?: TechFingerprint
  ): number {
    if (!a || !b) return 0;

    const aSet = new Set<string>();
    const bSet = new Set<string>();

    if (a.framework) aSet.add(a.framework.toLowerCase());
    if (a.language) aSet.add(a.language.toLowerCase());
    if (a.server) aSet.add(a.server.toLowerCase());

    if (b.framework) bSet.add(b.framework.toLowerCase());
    if (b.language) bSet.add(b.language.toLowerCase());
    if (b.server) bSet.add(b.server.toLowerCase());

    return this.jaccardSimilarity(aSet, bSet);
  }

  private computeVerbositySimilarity(
    a?: DefenseProfile,
    b?: DefenseProfile
  ): number {
    if (!a || !b) return 0;

    const levels = ['suppressed', 'standard', 'verbose'];
    const aIdx = levels.indexOf(a.errorVerbosity);
    const bIdx = levels.indexOf(b.errorVerbosity);

    if (aIdx < 0 || bIdx < 0) return 0;
    const dist = Math.abs(aIdx - bIdx);
    if (dist === 0) return 1.0;
    if (dist === 1) return 0.5;
    return 0.0;
  }

  private computeCspSimilarity(
    a?: DefenseProfile,
    b?: DefenseProfile
  ): number {
    if (!a || !b) return 0;
    if (!a.cspPolicy || !b.cspPolicy) return 0;

    const levels = ['none', 'basic', 'strict', 'nonce-based'];
    const aIdx = levels.indexOf(a.cspPolicy.strictness);
    const bIdx = levels.indexOf(b.cspPolicy.strictness);

    if (aIdx < 0 || bIdx < 0) return 0;
    return this.ordinalDistance(aIdx, bIdx, levels.length - 1);
  }

  private computeApiStyleSimilarity(
    a?: DefenseProfile,
    b?: DefenseProfile
  ): number {
    if (!a || !b) return 0;
    return a.apiStyle === b.apiStyle ? 1.0 : 0.0;
  }

  private computeIndustrySimilarity(a?: string, b?: string): number {
    if (!a || !b) return 0;

    if (a.toLowerCase() === b.toLowerCase()) return 1.0;

    const sectorMap: Record<string, string> = {
      fintech: 'finance',
      banking: 'finance',
      insurance: 'finance',
      cryptocurrency: 'finance',
      payments: 'finance',
      ecommerce: 'retail',
      retail: 'retail',
      marketplace: 'retail',
      healthcare: 'health',
      pharma: 'health',
      biotech: 'health',
      saas: 'technology',
      cloud: 'technology',
      software: 'technology',
      security: 'technology',
      social: 'media',
      media: 'media',
      entertainment: 'media',
      gaming: 'media',
      education: 'education',
      edtech: 'education',
      government: 'government',
      defense: 'government',
      telecom: 'telecom',
      networking: 'telecom',
    };

    const sectorA = sectorMap[a.toLowerCase()] || a.toLowerCase();
    const sectorB = sectorMap[b.toLowerCase()] || b.toLowerCase();

    if (sectorA === sectorB) return 0.5;
    return 0.0;
  }

  private computeAuthSimilarity(
    a?: DefenseProfile,
    b?: DefenseProfile
  ): number {
    if (!a || !b) return 0;

    const aSet = new Set(a.authMechanisms.map(m => m.toLowerCase()));
    const bSet = new Set(b.authMechanisms.map(m => m.toLowerCase()));

    return this.jaccardSimilarity(aSet, bSet);
  }

  private computeRateLimitSimilarity(
    a?: DefenseProfile,
    b?: DefenseProfile
  ): number {
    if (!a || !b) return 0;

    const aRL = a.rateLimiting;
    const bRL = b.rateLimiting;

    if (aRL.detected && bRL.detected) {
      if (aRL.threshold !== null && bRL.threshold !== null) {
        const maxThreshold = Math.max(aRL.threshold, bRL.threshold);
        if (maxThreshold === 0) return 1.0;
        return 1.0 - Math.abs(aRL.threshold - bRL.threshold) / maxThreshold;
      }
      return 1.0;
    }

    return aRL.detected === bRL.detected ? 1.0 : 0.0;
  }

  private computeSecurityHeaderSimilarity(
    a?: DefenseProfile,
    b?: DefenseProfile
  ): number {
    if (!a || !b) return 0;
    if (!a.securityHeaders || !b.securityHeaders) return 0;

    const aVec = [
      a.securityHeaders.hsts ? 1 : 0,
      a.securityHeaders.xFrameOptions ? 1 : 0,
      a.securityHeaders.xContentType ? 1 : 0,
      a.securityHeaders.referrerPolicy ? 1 : 0,
    ];

    const bVec = [
      b.securityHeaders.hsts ? 1 : 0,
      b.securityHeaders.xFrameOptions ? 1 : 0,
      b.securityHeaders.xContentType ? 1 : 0,
      b.securityHeaders.referrerPolicy ? 1 : 0,
    ];

    let dotProduct = 0;
    let magA = 0;
    let magB = 0;

    for (let i = 0; i < aVec.length; i++) {
      dotProduct += aVec[i] * bVec[i];
      magA += aVec[i] * aVec[i];
      magB += bVec[i] * bVec[i];
    }

    magA = Math.sqrt(magA);
    magB = Math.sqrt(magB);

    if (magA === 0 && magB === 0) return 1.0;
    if (magA === 0 || magB === 0) return 0.0;

    return dotProduct / (magA * magB);
  }

  private jaccardSimilarity(a: Set<string>, b: Set<string>): number {
    if (a.size === 0 && b.size === 0) return 1.0;

    let intersection = 0;
    Array.from(a).forEach(item => {
      if (b.has(item)) intersection++;
    });

    const union = a.size + b.size - intersection;
    if (union === 0) return 1.0;

    return intersection / union;
  }

  private ordinalDistance(a: number, b: number, maxDist: number): number {
    if (maxDist === 0) return 1.0;
    return 1.0 - Math.abs(a - b) / maxDist;
  }
}

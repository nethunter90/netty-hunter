import fs from 'fs/promises';
import path from 'path';
import { DuplicatePrediction } from './intelligence-types';

export interface HeatmapEntry {
  vulnType: string;
  targetArea: string;
  duplicateProbability: number;
  recommendation: 'avoid' | 'proceed-with-caution' | 'likely-clear' | 'high-value-target';
}

export interface DuplicateOutcome {
  programId: string;
  vulnType: string;
  targetArea: string;
  wasDuplicate: boolean;
  timestamp: string;
}

const DEFAULT_COMMONALITY: Record<string, number> = {
  'xss': 0.95,
  'sqli': 0.85,
  'csrf': 0.80,
  'idor': 0.70,
  'open-redirect': 0.75,
  'ssrf': 0.40,
  'ssti': 0.25,
  'xxe': 0.30,
  'rce': 0.15,
  'lfi': 0.50,
  'rfi': 0.35,
  'auth-bypass': 0.55,
  'cmdi': 0.20,
};

const DEFAULT_TARGET_EXPOSURE: Record<string, number> = {
  'login': 1.0,
  'signup': 0.95,
  'search': 0.85,
  'profile': 0.80,
  'api': 0.60,
  'admin': 0.40,
  'upload': 0.50,
  'payment': 0.45,
  'webhook': 0.30,
  'internal-api': 0.15,
};

export class PredictiveDuplicateAvoidance {
  private storageDir: string;

  constructor(storageDir: string) {
    this.storageDir = path.join(storageDir, 'duplicates');
  }

  private async ensureDir(): Promise<void> {
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

  private async saveJson(filename: string, data: unknown): Promise<void> {
    await this.ensureDir();
    const filePath = path.join(this.storageDir, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  private getRecommendation(probability: number): 'avoid' | 'proceed-with-caution' | 'likely-clear' | 'high-value-target' {
    if (probability > 0.80) return 'avoid';
    if (probability > 0.50) return 'proceed-with-caution';
    if (probability > 0.25) return 'likely-clear';
    return 'high-value-target';
  }

  async predictDuplicate(
    programId: string,
    vulnType: string,
    targetArea: string,
    programAge?: number,
    reportCount?: number,
    scopeChangeDays?: number
  ): Promise<DuplicatePrediction> {
    const commonalityIndex = await this.loadJson<Record<string, number>>('commonality-index.json', {});
    const programProfiles = await this.loadJson<Record<string, { programAge?: number; reportCount?: number }>>('program-profiles.json', {});

    const profile = programProfiles[programId] || {};
    const ageDays = programAge ?? profile.programAge ?? 90;
    const reports = reportCount ?? profile.reportCount ?? 50;
    const scopeDays = scopeChangeDays ?? 999;

    const ageFactor = Math.min(1 - Math.exp(-ageDays / 90), 0.95);

    const mergedCommonality = { ...DEFAULT_COMMONALITY, ...commonalityIndex };
    const vulnCommonality = mergedCommonality[vulnType.toLowerCase()] ?? 0.50;

    const targetExposure = DEFAULT_TARGET_EXPOSURE[targetArea.toLowerCase()] ?? 0.50;

    const reportVolumeFactor = Math.min(reports / 500, 1.0);

    const scopeMultiplier = scopeDays <= 30
      ? Math.max(0.3, 1 - (scopeDays / 30) * 0.7)
      : 1.0;

    const hunterActivity = Math.min(reports / 100, 1.0);

    const factors: Record<string, number> = {
      programAge: ageFactor,
      vulnCommonality,
      targetExposure,
      reportVolume: reportVolumeFactor,
      scopeFreshness: scopeMultiplier,
      hunterActivity,
    };

    const weightedSum =
      ageFactor * 0.25 +
      vulnCommonality * 0.25 +
      targetExposure * 0.20 +
      reportVolumeFactor * 0.15 +
      hunterActivity * 0.05;

    let probability = weightedSum * scopeMultiplier;
    probability = Math.max(0, Math.min(1, probability));

    const recommendation = this.getRecommendation(probability);

    const sortedFactors = Object.entries(factors)
      .sort((a, b) => b[1] - a[1]);

    const reasoningParts: string[] = [];
    for (const [name, value] of sortedFactors.slice(0, 3)) {
      if (name === 'programAge') {
        reasoningParts.push(`Program age (${ageDays} days) contributes ${(value * 100).toFixed(0)}% duplicate likelihood`);
      } else if (name === 'vulnCommonality') {
        reasoningParts.push(`${vulnType} is a commonly reported vuln type (${(value * 100).toFixed(0)}% commonality)`);
      } else if (name === 'targetExposure') {
        reasoningParts.push(`${targetArea} is a ${value >= 0.7 ? 'highly' : 'moderately'} exposed target area (${(value * 100).toFixed(0)}%)`);
      } else if (name === 'reportVolume') {
        reasoningParts.push(`Report volume (${reports} reports) indicates ${value >= 0.5 ? 'heavy' : 'moderate'} researcher activity`);
      } else if (name === 'scopeFreshness') {
        reasoningParts.push(`Scope ${scopeDays <= 30 ? `changed ${scopeDays} days ago, reducing` : 'has not changed recently, not reducing'} duplicate probability`);
      } else if (name === 'hunterActivity') {
        reasoningParts.push(`Hunter activity level: ${(value * 100).toFixed(0)}%`);
      }
    }

    const dupRecommendation = recommendation === 'avoid' ? 'avoid'
      : recommendation === 'proceed-with-caution' ? 'caution'
      : 'proceed';

    return {
      vulnType,
      targetArea,
      duplicateProbability: Math.round(probability * 1000) / 1000,
      reasoning: reasoningParts.join('. ') + '.',
      factors,
      recommendation: dupRecommendation,
    };
  }

  async getHeatmap(programId: string): Promise<HeatmapEntry[]> {
    const vulnTypes = Object.keys(DEFAULT_COMMONALITY);
    const targetAreas = Object.keys(DEFAULT_TARGET_EXPOSURE);
    const entries: HeatmapEntry[] = [];

    for (const vulnType of vulnTypes) {
      for (const targetArea of targetAreas) {
        const prediction = await this.predictDuplicate(programId, vulnType, targetArea);
        entries.push({
          vulnType,
          targetArea,
          duplicateProbability: prediction.duplicateProbability,
          recommendation: this.getRecommendation(prediction.duplicateProbability),
        });
      }
    }

    return entries;
  }

  async recordOutcome(data: DuplicateOutcome): Promise<void> {
    const history = await this.loadJson<DuplicateOutcome[]>('outcome-history.json', []);
    history.push(data);
    await this.saveJson('outcome-history.json', history);
  }

  async getCommonalityIndex(): Promise<Record<string, number>> {
    const stored = await this.loadJson<Record<string, number>>('commonality-index.json', {});
    return { ...DEFAULT_COMMONALITY, ...stored };
  }
}

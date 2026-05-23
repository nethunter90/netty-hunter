import fs from 'fs/promises';
import path from 'path';
import { TriagePrediction } from './intelligence-types';

export interface TriageDataPoint {
  programId: string;
  severity: string;
  reportQuality: number;
  submittedAt: string;
  triagedAt: string;
  actualDays: number;
}

export interface ProgramTriageAverage {
  programId: string;
  avgDays: number;
  bySeverity: Record<string, number>;
  sampleSize: number;
  lastUpdated: string;
}

export interface SubmissionTiming {
  bestDay: string;
  bestTimeUtc: string;
  estimatedTriageDays: number;
  reasoning: string;
}

const SEVERITY_BASELINES: Record<string, number> = {
  critical: 3,
  high: 7,
  medium: 14,
  low: 30,
};

const DAY_FACTORS: Record<number, number> = {
  0: 1.5,
  1: 0.8,
  2: 1.0,
  3: 1.0,
  4: 1.0,
  5: 1.2,
  6: 1.5,
};

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

export class TriagePredictor {
  private storageDir: string;

  constructor(storageDir: string) {
    this.storageDir = path.join(storageDir, 'triage');
  }

  private async ensureDir(): Promise<void> {
    await fs.mkdir(this.storageDir, { recursive: true });
  }

  private async loadJson<T>(filename: string, fallback: T): Promise<T> {
    try {
      const data = await fs.readFile(path.join(this.storageDir, filename), 'utf-8');
      return JSON.parse(data) as T;
    } catch {
      return fallback;
    }
  }

  private async saveJson(filename: string, data: unknown): Promise<void> {
    await this.ensureDir();
    await fs.writeFile(path.join(this.storageDir, filename), JSON.stringify(data, null, 2), 'utf-8');
  }

  async predictTriageTime(programId: string, severity: string, reportQuality?: number): Promise<TriagePrediction> {
    const history = await this.loadJson<TriageDataPoint[]>('triage-history.json', []);
    const programHistory = history.filter(h => h.programId === programId);

    const severityBase = SEVERITY_BASELINES[severity] ?? 14;
    const quality = reportQuality ?? 0.5;
    const qualityMultiplier = 2.0 - quality;
    const dayFactor = DAY_FACTORS[new Date().getDay()] ?? 1.0;

    const factors: Record<string, number> = {
      severityBase,
      qualityMultiplier,
      dayOfWeekFactor: dayFactor,
    };

    let estimatedDays: number;
    let confidence: number;

    if (programHistory.length >= 3) {
      const matchingSeverity = programHistory.filter(h => h.severity === severity);
      if (matchingSeverity.length >= 2) {
        estimatedDays = matchingSeverity.reduce((sum, h) => sum + h.actualDays, 0) / matchingSeverity.length;
        estimatedDays *= qualityMultiplier * dayFactor;
        confidence = Math.min(0.9, 0.5 + matchingSeverity.length * 0.05);
        factors.historicalAvg = matchingSeverity.reduce((sum, h) => sum + h.actualDays, 0) / matchingSeverity.length;
      } else {
        const avgDays = programHistory.reduce((sum, h) => sum + h.actualDays, 0) / programHistory.length;
        estimatedDays = avgDays * qualityMultiplier * dayFactor;
        confidence = Math.min(0.7, 0.3 + programHistory.length * 0.04);
        factors.historicalAvg = avgDays;
      }
    } else {
      estimatedDays = severityBase * qualityMultiplier * dayFactor;
      confidence = 0.3;
    }

    estimatedDays = Math.round(estimatedDays * 10) / 10;

    return { programId, estimatedDays, confidence, factors };
  }

  async recordTriageOutcome(data: TriageDataPoint): Promise<void> {
    const history = await this.loadJson<TriageDataPoint[]>('triage-history.json', []);
    history.push(data);
    await this.saveJson('triage-history.json', history);
    await this.recomputeAverages(history);
  }

  private async recomputeAverages(history: TriageDataPoint[]): Promise<void> {
    const grouped: Record<string, TriageDataPoint[]> = {};
    for (const h of history) {
      if (!grouped[h.programId]) grouped[h.programId] = [];
      grouped[h.programId].push(h);
    }

    const averages: Record<string, ProgramTriageAverage> = {};
    for (const [programId, points] of Object.entries(grouped)) {
      const avgDays = points.reduce((sum, p) => sum + p.actualDays, 0) / points.length;
      const bySeverity: Record<string, number> = {};
      const severityGroups: Record<string, number[]> = {};

      for (const p of points) {
        if (!severityGroups[p.severity]) severityGroups[p.severity] = [];
        severityGroups[p.severity].push(p.actualDays);
      }

      for (const [sev, days] of Object.entries(severityGroups)) {
        bySeverity[sev] = Math.round((days.reduce((s, d) => s + d, 0) / days.length) * 10) / 10;
      }

      averages[programId] = {
        programId,
        avgDays: Math.round(avgDays * 10) / 10,
        bySeverity,
        sampleSize: points.length,
        lastUpdated: new Date().toISOString(),
      };
    }

    await this.saveJson('program-averages.json', averages);
  }

  async getProgramAverages(): Promise<Record<string, ProgramTriageAverage>> {
    return this.loadJson<Record<string, ProgramTriageAverage>>('program-averages.json', {});
  }

  async getOptimalSubmissionTiming(programId: string): Promise<SubmissionTiming> {
    const history = await this.loadJson<TriageDataPoint[]>('triage-history.json', []);
    const programHistory = history.filter(h => h.programId === programId);

    if (programHistory.length >= 5) {
      const dayStats: Record<number, number[]> = {};
      for (const h of programHistory) {
        const day = new Date(h.submittedAt).getDay();
        if (!dayStats[day]) dayStats[day] = [];
        dayStats[day].push(h.actualDays);
      }

      let bestDay = 1;
      let bestAvg = Infinity;
      for (const [day, days] of Object.entries(dayStats)) {
        const avg = days.reduce((s, d) => s + d, 0) / days.length;
        if (avg < bestAvg) {
          bestAvg = avg;
          bestDay = parseInt(day);
        }
      }

      return {
        bestDay: DAY_NAMES[bestDay],
        bestTimeUtc: '09:00',
        estimatedTriageDays: Math.round(bestAvg * 10) / 10,
        reasoning: `Based on ${programHistory.length} historical data points, ${DAY_NAMES[bestDay]} submissions average ${Math.round(bestAvg * 10) / 10} days to triage.`,
      };
    }

    return {
      bestDay: 'Monday',
      bestTimeUtc: '09:00',
      estimatedTriageDays: 7,
      reasoning: 'Insufficient historical data. Monday mornings UTC recommended as triage teams typically process queues at start of work week.',
    };
  }
}

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { huntCortex, SignalType } from './hunt-cortex';
import { TOOL_FALLBACK_CHAINS } from './seed-knowledge';
import { decisionTraceLogger } from './decision-trace';

export interface VerificationRecord {
  id: string;
  findingId: string;
  huntId: string;
  target: string;
  verifiedAt: number;
  confidence: number;
  verificationMethod: string;
  dependents: string[];
  status: 'fresh' | 'aging' | 'stale' | 'reverifying';
  lastChecked: number;
}

export interface TargetProfile {
  target: string;
  changeRate: number;
  lastObservedChange: number;
  observationCount: number;
}

export interface ProcessResult {
  processed: number;
  fresh: number;
  aging: number;
  stale: number;
  reverifying: number;
  cascadeDowngrades: number;
  queuedForReverification: number;
}

const BASELINE_TTL_EXPLOITATION = 30 * 60 * 1000;
const BASELINE_TTL_RECON = 2 * 60 * 60 * 1000;
const BASELINE_TTL_DEFAULT = 60 * 60 * 1000;

export class VerificationLifecycle extends EventEmitter {
  private verifications: Map<string, VerificationRecord> = new Map();
  private targetProfiles: Map<string, TargetProfile> = new Map();
  private reverificationQueue: Map<string, VerificationRecord[]> = new Map();
  private staleTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    super();
    this.staleTimer = setInterval(() => {
      this.processStale();
    }, 60_000);
  }

  addVerification(record: Omit<VerificationRecord, 'id'> & { id?: string }): VerificationRecord {
    const verification: VerificationRecord = {
      ...record,
      id: record.id || uuidv4(),
    };
    this.verifications.set(verification.id, verification);
    this.emit('verification:added', verification);
    decisionTraceLogger.recordEvent({
      huntId: verification.huntId,
      eventType: 'verification_event',
      sourceSystem: 'verification-lifecycle',
      data: { findingId: verification.findingId, method: verification.verificationMethod, confidence: verification.confidence, status: verification.status },
      confidenceAtEvent: verification.confidence,
      reasoning: `Verification added for finding ${verification.findingId}`,
    }).catch(() => {});
    return verification;
  }

  getVerification(id: string): VerificationRecord | undefined {
    return this.verifications.get(id);
  }

  getAllForHunt(huntId: string): VerificationRecord[] {
    return Array.from(this.verifications.values()).filter(v => v.huntId === huntId);
  }

  getStats(): {
    total: number;
    fresh: number;
    aging: number;
    stale: number;
    reverifying: number;
    averageConfidence: number;
    queuedForReverification: number;
  } {
    const all = Array.from(this.verifications.values());
    const total = all.length;
    const fresh = all.filter(v => v.status === 'fresh').length;
    const aging = all.filter(v => v.status === 'aging').length;
    const stale = all.filter(v => v.status === 'stale').length;
    const reverifying = all.filter(v => v.status === 'reverifying').length;
    const averageConfidence = total > 0
      ? all.reduce((sum, v) => sum + v.confidence, 0) / total
      : 0;
    let queuedCount = 0;
    Array.from(this.reverificationQueue.values()).forEach(batch => {
      queuedCount += batch.length;
    });
    return { total, fresh, aging, stale, reverifying, averageConfidence, queuedForReverification: queuedCount };
  }

  updateTargetProfile(target: string, changed: boolean): void {
    const existing = this.targetProfiles.get(target);
    if (existing) {
      existing.observationCount++;
      if (changed) {
        const decayFactor = 0.3;
        existing.changeRate = existing.changeRate * (1 - decayFactor) + decayFactor;
        existing.lastObservedChange = Date.now();
      } else {
        const decayFactor = 0.1;
        existing.changeRate = existing.changeRate * (1 - decayFactor);
      }
      existing.changeRate = Math.min(1, Math.max(0, existing.changeRate));
    } else {
      this.targetProfiles.set(target, {
        target,
        changeRate: changed ? 0.5 : 0.1,
        lastObservedChange: changed ? Date.now() : 0,
        observationCount: 1,
      });
    }
  }

  private getBaselineTTL(verification: VerificationRecord): number {
    const method = verification.verificationMethod.toLowerCase();
    if (method.includes('exploit') || method.includes('attack') || method.includes('injection')) {
      return BASELINE_TTL_EXPLOITATION;
    }
    if (method.includes('recon') || method.includes('discovery') || method.includes('enumeration')) {
      return BASELINE_TTL_RECON;
    }
    return BASELINE_TTL_DEFAULT;
  }

  calculateStaleness(verification: VerificationRecord): number {
    const now = Date.now();
    const age = now - verification.lastChecked;
    const profile = this.targetProfiles.get(verification.target);
    const volatility = profile ? profile.changeRate : 0.5;
    const baselineTTL = this.getBaselineTTL(verification);
    const adjustedTTL = baselineTTL * (1 - volatility * 0.8);
    const staleness = age / adjustedTTL;
    return Math.min(1, Math.max(0, staleness));
  }

  processStale(): ProcessResult {
    const result: ProcessResult = {
      processed: 0,
      fresh: 0,
      aging: 0,
      stale: 0,
      reverifying: 0,
      cascadeDowngrades: 0,
      queuedForReverification: 0,
    };

    for (const verification of Array.from(this.verifications.values())) {
      if (verification.status === 'reverifying') {
        result.reverifying++;
        result.processed++;
        continue;
      }

      const staleness = this.calculateStaleness(verification);
      result.processed++;

      if (staleness < 0.3) {
        verification.status = 'fresh';
        result.fresh++;
      } else if (staleness <= 0.7) {
        verification.status = 'aging';
        verification.confidence = Math.max(0.1, verification.confidence * (1 - (staleness - 0.3) * 0.5));
        result.aging++;

        for (const depId of verification.dependents) {
          const dep = this.verifications.get(depId);
          if (dep) {
            dep.confidence = Math.max(0.1, dep.confidence * 0.95);
            result.cascadeDowngrades++;
          }
        }
      } else {
        verification.status = 'stale';
        result.stale++;

        huntCortex.broadcast({
          signalType: SignalType.VERIFICATION_DEGRADED,
          sourceSystem: 'verification',
          huntId: verification.huntId,
          payload: {
            verificationId: verification.id,
            staleness,
            dependentCount: verification.dependents.length,
            dependentFindings: verification.dependents,
          },
          confidence: verification.confidence,
        });

        verification.status = 'reverifying';
        const target = verification.target;
        if (!this.reverificationQueue.has(target)) {
          this.reverificationQueue.set(target, []);
        }
        const queue = this.reverificationQueue.get(target)!;
        if (!queue.find(v => v.id === verification.id)) {
          queue.push(verification);
          result.queuedForReverification++;
        }

        for (const depId of verification.dependents) {
          const dep = this.verifications.get(depId);
          if (dep) {
            dep.confidence = Math.max(0, dep.confidence * 0.5);
            dep.status = 'stale';
            result.cascadeDowngrades++;
          }
        }
      }
    }

    this.emit('stale:processed', result);
    return result;
  }

  getCascadeImpact(verificationId: string): string[] {
    const affected: string[] = [];
    const visited = new Set<string>();

    const traverse = (id: string) => {
      if (visited.has(id)) return;
      visited.add(id);
      const record = this.verifications.get(id);
      if (!record) return;
      for (const depId of record.dependents) {
        affected.push(depId);
        traverse(depId);
      }
    };

    traverse(verificationId);
    return affected;
  }

  getReverificationBatch(target: string): VerificationRecord[] {
    return this.reverificationQueue.get(target) || [];
  }

  clearReverificationBatch(target: string): void {
    this.reverificationQueue.delete(target);
  }

  addDependency(parentId: string, dependentId: string): void {
    const parent = this.verifications.get(parentId);
    if (parent && !parent.dependents.includes(dependentId)) {
      parent.dependents.push(dependentId);
    }
  }

  getDependents(id: string): string[] {
    const record = this.verifications.get(id);
    return record ? [...record.dependents] : [];
  }

  applyDegradationCoefficient(verification: VerificationRecord, toolUsed: string): void {
    for (const chain of TOOL_FALLBACK_CHAINS) {
      const fallback = chain.fallbacks.find(f => f.tool === toolUsed);
      if (fallback) {
        verification.confidence = verification.confidence * fallback.degradationCoefficient;
        break;
      }
    }
  }

  destroy(): void {
    if (this.staleTimer) {
      clearInterval(this.staleTimer);
      this.staleTimer = null;
    }
  }
}

export const verificationLifecycle = new VerificationLifecycle();

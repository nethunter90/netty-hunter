/**
 * ValidationGate — lib/hunter singleton
 *
 * Tracks 4-layer validation stats per session and exposes aggregate metrics.
 */
import type { Finding, ValidationStats } from './types';

class ValidationGateStore {
  private stats: Map<string, ValidationStats> = new Map();

  private ensure(sessionId: string): ValidationStats {
    if (!this.stats.has(sessionId)) {
      this.stats.set(sessionId, {
        sessionId,
        totalChecked:  0,
        confirmed:     0,
        rejected:      0,
        inconclusive:  0,
        layer3Skipped: 0,
        avgConfidence: 0,
      });
    }
    return this.stats.get(sessionId)!;
  }

  recordValidation(sessionId: string, finding: Finding, layer3Skipped: boolean): void {
    const s = this.ensure(sessionId);
    s.totalChecked += 1;
    if (finding.verificationStatus === 'confirmed')   s.confirmed    += 1;
    if (finding.verificationStatus === 'rejected')    s.rejected     += 1;
    if (finding.verificationStatus === 'inconclusive') s.inconclusive += 1;
    if (layer3Skipped) s.layer3Skipped += 1;

    // Running average confidence
    s.avgConfidence = Math.round(
      ((s.avgConfidence * (s.totalChecked - 1)) + finding.confidence) / s.totalChecked * 100
    ) / 100;
  }

  getStats(sessionId: string): ValidationStats | null {
    return this.stats.get(sessionId) ?? null;
  }

  getAllStats(): ValidationStats[] {
    return Array.from(this.stats.values());
  }
}

export const validationGate = new ValidationGateStore();

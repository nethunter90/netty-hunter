/**
 * ObservationCompressor — historical state vector for context window management.
 *
 * After COMPRESS_AFTER observations accumulate the prompt would exceed practical
 * model context limits.  This module keeps the last RECENT_WINDOW observations
 * verbatim and condenses the rest into a compact "historical state vector" string.
 *
 * The compressor is purely additive — it never discards information from the
 * model's perspective, it just recodes old data as a denser representation.
 */

import type { Observation } from '../../agents/HunterEngine';

const COMPRESS_AFTER = 20;   // start compressing once observations exceed this
const RECENT_WINDOW  = 8;    // always keep this many raw observations in prompt

interface StateVector {
  /** Compact textual summary of historical observations */
  summary: string;
  /** Most-seen tags weighted by anomaly score, descending */
  dominantSignals: string[];
  /** Observation count that went into this vector */
  compressedCount: number;
  /** Highest anomaly score seen in the compressed window */
  peakAnomaly: number;
}

class ObservationCompressor {
  /** Per-session compressed state */
  private vectors = new Map<string, StateVector>();

  /**
   * Given a session's full observation list, return:
   *   - `historicalSummary`: a compact state vector string to inject into the prompt
   *   - `recentObservations`: the RECENT_WINDOW raw observations to append verbatim
   *
   * When there are fewer than COMPRESS_AFTER observations the summary is empty
   * and all observations are returned as-is.
   */
  compress(
    sessionId: string,
    observations: Observation[],
  ): { historicalSummary: string; recentObservations: Observation[] } {
    if (observations.length <= COMPRESS_AFTER) {
      return { historicalSummary: '', recentObservations: observations };
    }

    const recentObservations = observations.slice(-RECENT_WINDOW);
    const historical = observations.slice(0, observations.length - RECENT_WINDOW);

    // Merge with any previously compressed vector for this session
    const prev = this.vectors.get(sessionId);
    const allHistorical = prev ? [...historical] : historical;

    // Tag frequency weighted by anomaly score
    const tagWeights = new Map<string, number>();
    let peakAnomaly = prev?.peakAnomaly ?? 0;

    for (const obs of allHistorical) {
      if (obs.anomalyScore > peakAnomaly) peakAnomaly = obs.anomalyScore;
      for (const tag of obs.tags) {
        tagWeights.set(tag, (tagWeights.get(tag) ?? 0) + obs.anomalyScore);
      }
    }

    const dominantSignals = [...tagWeights.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([tag]) => tag);

    // Source breakdown
    const sourceCounts = new Map<string, number>();
    for (const obs of allHistorical) {
      sourceCounts.set(obs.source, (sourceCounts.get(obs.source) ?? 0) + 1);
    }
    const sourceBreakdown = [...sourceCounts.entries()]
      .map(([src, count]) => `${src}(${count})`)
      .join(', ');

    // Average anomaly
    const avgAnomaly = allHistorical.length
      ? allHistorical.reduce((s, o) => s + o.anomalyScore, 0) / allHistorical.length
      : 0;

    const summary = [
      `Historical state vector (${allHistorical.length} observations compressed):`,
      `  Dominant signals: ${dominantSignals.join(', ') || 'none'}`,
      `  Source coverage: ${sourceBreakdown || 'none'}`,
      `  Anomaly profile: avg=${avgAnomaly.toFixed(2)} peak=${peakAnomaly.toFixed(2)}`,
      prev ? `  Previous summary: ${prev.summary.split('\n')[0]}` : '',
    ].filter(Boolean).join('\n');

    const vector: StateVector = {
      summary,
      dominantSignals,
      compressedCount: allHistorical.length,
      peakAnomaly,
    };
    this.vectors.set(sessionId, vector);

    return { historicalSummary: summary, recentObservations };
  }

  clearSession(sessionId: string): void {
    this.vectors.delete(sessionId);
  }
}

export const observationCompressor = new ObservationCompressor();

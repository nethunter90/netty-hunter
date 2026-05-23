import { EventEmitter } from 'events';
import { pool } from '../../db';
import { v4 as uuidv4 } from 'uuid';

export type TraceEventType =
  | 'planner_ranking'
  | 'tool_selection'
  | 'tool_execution'
  | 'cortex_signal'
  | 'meta_pivot'
  | 'meta_evaluation'
  | 'verification_event'
  | 'finding_confirmed'
  | 'finding_invalidated'
  | 'phase_advance'
  | 'hunt_start'
  | 'hunt_complete';

export interface TraceEvent {
  id: string;
  huntId: string;
  timestamp: number;
  eventType: TraceEventType;
  sourceSystem: string;
  data: Record<string, any>;
  reasoning?: string;
  confidenceAtEvent: number;
}

export interface HuntMetrics {
  huntId: string;
  totalEvents: number;
  duration: number;
  totalPivots: number;
  productivePivots: number;
  wastedPivots: number;
  pivotEfficiencyRatio: number;
  pathAccuracy: number;
  timeToFirstFinding: number;
  falsePositiveRate: number;
  coverageRatio: number;
  confidenceCalibration: ConfidenceCalibrationPoint[];
}

export interface ConfidenceCalibrationPoint {
  confidenceBucket: string;
  pivotCount: number;
  successCount: number;
  actualSuccessRate: number;
  avgConfidence: number;
}

export interface PivotAnalysis {
  fromStrategy: string;
  toStrategy: string;
  confidenceAtPivot: number;
  cyclesUntilNextFinding: number;
  productive: boolean;
}

export interface GroundTruth {
  expectedFindings: string[];
  plannerTopPaths: string[];
}

export class DecisionTraceLogger extends EventEmitter {
  private traceBuffer: Map<string, TraceEvent[]> = new Map();
  private initialized = false;

  constructor() {
    super();
    this.setMaxListeners(50);
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS "decision_traces" (
          "id" varchar PRIMARY KEY,
          "hunt_id" text NOT NULL,
          "event_type" text NOT NULL,
          "source_system" text NOT NULL,
          "data" jsonb NOT NULL DEFAULT '{}',
          "reasoning" text,
          "confidence_at_event" real NOT NULL DEFAULT 0,
          "created_at" timestamp DEFAULT now()
        )
      `);
      this.initialized = true;
    } catch (_err) {
      this.initialized = true;
    }
  }

  async recordEvent(event: Omit<TraceEvent, 'id' | 'timestamp'> & { id?: string; timestamp?: number }): Promise<TraceEvent> {
    await this.initialize();

    const traceEvent: TraceEvent = {
      id: event.id || uuidv4(),
      huntId: event.huntId,
      timestamp: event.timestamp || Date.now(),
      eventType: event.eventType,
      sourceSystem: event.sourceSystem,
      data: event.data,
      reasoning: event.reasoning,
      confidenceAtEvent: event.confidenceAtEvent,
    };

    if (!this.traceBuffer.has(traceEvent.huntId)) {
      this.traceBuffer.set(traceEvent.huntId, []);
    }
    this.traceBuffer.get(traceEvent.huntId)!.push(traceEvent);

    try {
      await pool.query(
        `INSERT INTO decision_traces (id, hunt_id, event_type, source_system, data, reasoning, confidence_at_event, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8 / 1000.0))`,
        [
          traceEvent.id,
          traceEvent.huntId,
          traceEvent.eventType,
          traceEvent.sourceSystem,
          JSON.stringify(traceEvent.data),
          traceEvent.reasoning || null,
          traceEvent.confidenceAtEvent,
          traceEvent.timestamp,
        ]
      );
    } catch (_err) {}

    this.emit('trace:event', traceEvent);
    return traceEvent;
  }

  getTrace(huntId: string): TraceEvent[] {
    const events = this.traceBuffer.get(huntId) || [];
    return [...events].sort((a, b) => a.timestamp - b.timestamp);
  }

  getTraceWindow(huntId: string, since: number, until: number): TraceEvent[] {
    const events = this.traceBuffer.get(huntId) || [];
    return events
      .filter(e => e.timestamp >= since && e.timestamp <= until)
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  getTraceByType(huntId: string, eventType: TraceEventType): TraceEvent[] {
    const events = this.traceBuffer.get(huntId) || [];
    return events
      .filter(e => e.eventType === eventType)
      .sort((a, b) => a.timestamp - b.timestamp);
  }

  getBufferedHuntIds(): string[] {
    return Array.from(this.traceBuffer.keys());
  }

  async getPersistedHuntIds(): Promise<string[]> {
    try {
      await this.initialize();
      const result = await pool.query(
        `SELECT hunt_id FROM decision_traces GROUP BY hunt_id ORDER BY MAX(created_at) DESC LIMIT 50`
      );
      return result.rows.map((r: any) => r.hunt_id);
    } catch (_err) {
      return [];
    }
  }

  async getAllHuntIds(): Promise<string[]> {
    const buffered = this.getBufferedHuntIds();
    const persisted = await this.getPersistedHuntIds();
    const merged = new Set([...buffered, ...persisted]);
    return Array.from(merged);
  }

  async getTraceFromDb(huntId: string): Promise<TraceEvent[]> {
    try {
      await this.initialize();
      const result = await pool.query(
        `SELECT * FROM decision_traces WHERE hunt_id = $1 ORDER BY created_at ASC`,
        [huntId]
      );
      return result.rows.map((row: any) => ({
        id: row.id,
        huntId: row.hunt_id,
        timestamp: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
        eventType: row.event_type as TraceEventType,
        sourceSystem: row.source_system,
        data: typeof row.data === 'string' ? JSON.parse(row.data) : row.data,
        reasoning: row.reasoning || undefined,
        confidenceAtEvent: row.confidence_at_event ?? 0,
      }));
    } catch (_err) {
      return [];
    }
  }

  async getTraceWithFallback(huntId: string): Promise<TraceEvent[]> {
    const buffered = this.getTrace(huntId);
    if (buffered.length > 0) {
      return buffered;
    }
    const fromDb = await this.getTraceFromDb(huntId);
    if (fromDb.length > 0) {
      this.traceBuffer.set(huntId, fromDb);
    }
    return fromDb;
  }

  clearBuffer(huntId: string): void {
    this.traceBuffer.delete(huntId);
  }
}

const CALIBRATION_BUCKETS = ['0.0-0.2', '0.2-0.4', '0.4-0.6', '0.6-0.8', '0.8-1.0'];

function getBucketIndex(confidence: number): number {
  if (confidence < 0.2) return 0;
  if (confidence < 0.4) return 1;
  if (confidence < 0.6) return 2;
  if (confidence < 0.8) return 3;
  return 4;
}

export class HuntMetricsCollector {
  private logger: DecisionTraceLogger;

  constructor(logger: DecisionTraceLogger) {
    this.logger = logger;
  }

  computeMetrics(huntId: string, groundTruth?: GroundTruth): HuntMetrics {
    const trace = this.logger.getTrace(huntId);

    const totalEvents = trace.length;
    const duration = trace.length >= 2
      ? trace[trace.length - 1].timestamp - trace[0].timestamp
      : 0;

    const pivots = trace.filter(e => e.eventType === 'meta_pivot');
    const totalPivots = pivots.length;

    const confirmed = trace.filter(e => e.eventType === 'finding_confirmed');
    const invalidated = trace.filter(e => e.eventType === 'finding_invalidated');

    let productivePivots = 0;
    let wastedPivots = 0;

    for (const pivot of pivots) {
      const pivotIdx = trace.indexOf(pivot);
      let cyclesAfter = 0;
      let foundFinding = false;

      for (let i = pivotIdx + 1; i < trace.length; i++) {
        if (trace[i].eventType === 'meta_evaluation') {
          cyclesAfter++;
        }
        if (trace[i].eventType === 'finding_confirmed') {
          foundFinding = true;
          break;
        }
        if (trace[i].eventType === 'meta_pivot') {
          break;
        }
        if (cyclesAfter >= 3 && !foundFinding) {
          break;
        }
      }

      if (foundFinding && cyclesAfter <= 3) {
        productivePivots++;
      } else if (cyclesAfter >= 3 && !foundFinding) {
        wastedPivots++;
      }
    }

    const pivotEfficiencyRatio = totalPivots > 0 ? productivePivots / totalPivots : 0;

    let pathAccuracy = 0;
    if (groundTruth && groundTruth.plannerTopPaths.length > 0 && confirmed.length > 0) {
      const confirmedTypes = confirmed.map(e => e.data.findingType || e.data.vulnerability || '').filter(Boolean);
      const topPaths = groundTruth.plannerTopPaths.slice(0, 3);
      const matchCount = topPaths.filter(p =>
        confirmedTypes.some(ct => ct.toLowerCase().includes(p.toLowerCase()) || p.toLowerCase().includes(ct.toLowerCase()))
      ).length;
      pathAccuracy = matchCount / Math.max(topPaths.length, 1);
    }

    const huntStart = trace.find(e => e.eventType === 'hunt_start');
    const firstFinding = trace.find(e => e.eventType === 'finding_confirmed');
    const timeToFirstFinding = huntStart && firstFinding
      ? firstFinding.timestamp - huntStart.timestamp
      : -1;

    const totalFindings = confirmed.length + invalidated.length;
    const falsePositiveRate = totalFindings > 0 ? invalidated.length / totalFindings : 0;

    let coverageRatio = 0;
    if (groundTruth && groundTruth.expectedFindings.length > 0) {
      const confirmedDescriptions = confirmed.map(e =>
        (e.data.findingType || e.data.vulnerability || e.data.description || '').toLowerCase()
      );
      const matched = groundTruth.expectedFindings.filter(expected =>
        confirmedDescriptions.some(cd => cd.includes(expected.toLowerCase()) || expected.toLowerCase().includes(cd))
      ).length;
      coverageRatio = matched / groundTruth.expectedFindings.length;
    }

    const confidenceCalibration = this.computeCalibrationFromTrace(trace);

    return {
      huntId,
      totalEvents,
      duration,
      totalPivots,
      productivePivots,
      wastedPivots,
      pivotEfficiencyRatio,
      pathAccuracy,
      timeToFirstFinding,
      falsePositiveRate,
      coverageRatio,
      confidenceCalibration,
    };
  }

  getPivotAnalysis(huntId: string): PivotAnalysis[] {
    const trace = this.logger.getTrace(huntId);
    const pivots = trace.filter(e => e.eventType === 'meta_pivot');
    const results: PivotAnalysis[] = [];

    for (const pivot of pivots) {
      const pivotIdx = trace.indexOf(pivot);
      const fromStrategy = pivot.data.fromStrategy || pivot.data.from || 'unknown';
      const toStrategy = pivot.data.toStrategy || pivot.data.to || 'unknown';
      const confidenceAtPivot = pivot.confidenceAtEvent;

      let cyclesUntilNextFinding = 0;
      let foundFinding = false;

      for (let i = pivotIdx + 1; i < trace.length; i++) {
        if (trace[i].eventType === 'meta_evaluation') {
          cyclesUntilNextFinding++;
        }
        if (trace[i].eventType === 'finding_confirmed') {
          foundFinding = true;
          break;
        }
        if (trace[i].eventType === 'meta_pivot') {
          break;
        }
      }

      if (!foundFinding) {
        cyclesUntilNextFinding = -1;
      }

      results.push({
        fromStrategy,
        toStrategy,
        confidenceAtPivot,
        cyclesUntilNextFinding,
        productive: foundFinding && cyclesUntilNextFinding <= 3,
      });
    }

    return results;
  }

  getConfidenceCalibration(huntIds?: string[]): ConfidenceCalibrationPoint[] {
    const ids = huntIds || this.logger.getBufferedHuntIds();
    const buckets: { confidences: number[]; successes: number }[] = CALIBRATION_BUCKETS.map(() => ({
      confidences: [],
      successes: 0,
    }));

    for (const huntId of ids) {
      const trace = this.logger.getTrace(huntId);
      const pivots = trace.filter(e => e.eventType === 'meta_pivot');

      for (const pivot of pivots) {
        const pivotIdx = trace.indexOf(pivot);
        const confidence = pivot.confidenceAtEvent;
        const bucketIdx = getBucketIndex(confidence);

        buckets[bucketIdx].confidences.push(confidence);

        let foundFinding = false;
        for (let i = pivotIdx + 1; i < trace.length; i++) {
          if (trace[i].eventType === 'finding_confirmed') {
            foundFinding = true;
            break;
          }
          if (trace[i].eventType === 'meta_pivot') {
            break;
          }
        }

        if (foundFinding) {
          buckets[bucketIdx].successes++;
        }
      }
    }

    return CALIBRATION_BUCKETS.map((bucket, idx) => {
      const data = buckets[idx];
      const pivotCount = data.confidences.length;
      const avgConfidence = pivotCount > 0
        ? data.confidences.reduce((sum, c) => sum + c, 0) / pivotCount
        : 0;

      return {
        confidenceBucket: bucket,
        pivotCount,
        successCount: data.successes,
        actualSuccessRate: pivotCount > 0 ? data.successes / pivotCount : 0,
        avgConfidence,
      };
    });
  }

  getDecisionQualityScore(huntId: string): number {
    const metrics = this.computeMetrics(huntId);

    const pivotScore = metrics.pivotEfficiencyRatio;

    const pathScore = metrics.pathAccuracy;

    const calibration = metrics.confidenceCalibration;
    let calibrationError = 0;
    let calibrationBucketsUsed = 0;
    for (const point of calibration) {
      if (point.pivotCount > 0) {
        const bucketMidpoint = parseFloat(point.confidenceBucket.split('-')[0]) + 0.1;
        calibrationError += Math.abs(point.actualSuccessRate - bucketMidpoint);
        calibrationBucketsUsed++;
      }
    }
    const avgCalibrationError = calibrationBucketsUsed > 0
      ? calibrationError / calibrationBucketsUsed
      : 0.5;
    const calibrationScore = Math.max(0, 1 - avgCalibrationError);

    const falsePositivePenalty = Math.max(0, 1 - metrics.falsePositiveRate);

    const score = (
      pivotScore * 0.3 +
      pathScore * 0.25 +
      calibrationScore * 0.25 +
      falsePositivePenalty * 0.2
    );

    return Math.min(1, Math.max(0, score));
  }

  private computeCalibrationFromTrace(trace: TraceEvent[]): ConfidenceCalibrationPoint[] {
    const buckets: { confidences: number[]; successes: number }[] = CALIBRATION_BUCKETS.map(() => ({
      confidences: [],
      successes: 0,
    }));

    const pivots = trace.filter(e => e.eventType === 'meta_pivot');

    for (const pivot of pivots) {
      const pivotIdx = trace.indexOf(pivot);
      const confidence = pivot.confidenceAtEvent;
      const bucketIdx = getBucketIndex(confidence);

      buckets[bucketIdx].confidences.push(confidence);

      let foundFinding = false;
      for (let i = pivotIdx + 1; i < trace.length; i++) {
        if (trace[i].eventType === 'finding_confirmed') {
          foundFinding = true;
          break;
        }
        if (trace[i].eventType === 'meta_pivot') {
          break;
        }
      }

      if (foundFinding) {
        buckets[bucketIdx].successes++;
      }
    }

    return CALIBRATION_BUCKETS.map((bucket, idx) => {
      const data = buckets[idx];
      const pivotCount = data.confidences.length;
      const avgConfidence = pivotCount > 0
        ? data.confidences.reduce((sum, c) => sum + c, 0) / pivotCount
        : 0;

      return {
        confidenceBucket: bucket,
        pivotCount,
        successCount: data.successes,
        actualSuccessRate: pivotCount > 0 ? data.successes / pivotCount : 0,
        avgConfidence,
      };
    });
  }
}

export const decisionTraceLogger = new DecisionTraceLogger();
export const huntMetricsCollector = new HuntMetricsCollector(decisionTraceLogger);

/**
 * Shared type definitions for the Hunter subsystem
 */

export type StealthMode = 'passive' | 'balanced' | 'aggressive';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type VerificationStatus = 'confirmed' | 'rejected' | 'inconclusive' | 'pending';
export type HypothesisStatus = 'pending' | 'testing' | 'confirmed' | 'rejected' | 'skipped';
export type SessionStatus = 'running' | 'paused' | 'stopped' | 'completed' | 'error';

export interface HunterConfig {
  target: string;
  stealthMode: StealthMode;
  requestBudget: number;
  maxIterations: number;
  enabledProbes?: string[];
  huntId?: string;
  huntGoal?: string;
  scope?: string[];
  intelligenceOverrides?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  sessionId: string;
  vulnClass: string;
  endpoint: string;
  severity: Severity;
  confidence: number;
  payload: string;
  evidence: Record<string, unknown>;
  verificationStatus: VerificationStatus;
  layer3Confirmed: boolean;
  foundAt: number;
  reportedAt?: number;
}

export interface Hypothesis {
  id: string;
  sessionId: string;
  vulnClass: string;
  endpoint: string;
  rationale: string;
  priority: number;           // 0-1, higher = test first
  confidence: number;         // prior probability estimate
  status: HypothesisStatus;
  createdAt: number;
  testedAt?: number;
}

// ── WAF Profile ──────────────────────────────────────────────────────────────

export interface WAFProfile {
  vendor: string;
  confidence: number;
  detectedSignals: string[];
  bypassRate: number;
  lastDetectedAt: number;
}

export interface BoundaryMap {
  sessionId: string;
  endpoint: string;
  parameter: string;
  category: string;
  maxPayloadLength: number;
  blockedTokens: string[];
  allowedTokens: string[];
  effectiveBypass: boolean;
  technique: string;
  mappedAt: number;
}

export interface CalibrationEvent {
  sessionId: string;
  signalType: string;
  vendor: string;
  rawSignal: string;
  inferredBehavior: string;
  accuracy: number;
  recordedAt: number;
}

export interface WAFRuleProfile {
  vendor: string;
  rulesetComplexity: 'minimal' | 'standard' | 'comprehensive' | 'hardened';
  comprehensiveCategories: string[];
  isolatedCategories: string[];
  bypassResistance: Record<string, number>;
  sharedRulePairs: [string, string][];
}

export interface WAFBehaviorModel {
  vendor: string;
  currentPhase: string;
  blockRate: number;
  avgResponseTime: number;
  adaptiveLearning: boolean;
  escalationRisk: boolean;
  temporalPatterns: string[];
}

// ── Intelligence ──────────────────────────────────────────────────────────────

export interface IntelligenceRecommendations {
  optimalTechniques: string[];
  expectedBehavior: {
    currentPhase: string;
    predictedNextPhase: string | null;
    blockRate: number;
    avgResponseTime: number;
    adaptiveLearning: boolean;
    escalationRisk: boolean;
  };
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskFactors: string[];
  suggestedPacing: {
    maxRequestsPerMinute: number;
    cooldownAfterBlock: number;
    burstAllowed: boolean;
    reasoningForPacing: string;
  };
  avoidTechniques: string[];
  avoidCategories: string[];
  exploitChains: {
    recommended: string[];
    avoid: string[];
  };
  wafProfile: {
    rulesetComplexity: string;
    comprehensiveCategories: string[];
    isolatedCategories: string[];
    bypassResistance: Record<string, number>;
    sharedRulePairs: [string, string][];
  };
}

export interface UnifiedIntelligence {
  vendor: string;
  confidence: number;
  dataQuality: 'insufficient' | 'low' | 'medium' | 'high' | 'excellent';
  recommendations: IntelligenceRecommendations;
  reasoning: string[];
  sourceSummary: Record<string, unknown>;
  synthesizedAt: number;
}

export interface VendorEvasionProfile {
  vendor: string;
  totalSessions: number;
  totalAttempts: number;
  overallSuccessRate: number;
  topTechniques: Array<{ technique: string; category: string; successRate: number; attempts: number }>;
  byCategory: Record<string, { attempts: number; successes: number; rate: number }>;
  recommendedStrategies: string[];
  lastUpdated: number;
}

export interface ExploitChainIntel {
  vendor: string;
  successfulChains: Array<{ sequence: string[]; successRate: number; avgBounty: number }>;
  failedPatterns: string[];
  recommendedSequences: string[][];
  lastUpdated: number;
}

// ── Strategy ──────────────────────────────────────────────────────────────────

export interface StrategyStep {
  id: string;
  tool: string;
  purpose: string;
  commandTemplate: string;
  status: 'pending' | 'running' | 'done' | 'skipped';
  dynamic: boolean;
  addedAt: number;
}

export interface HuntStrategy {
  sessionId: string;
  objective: string;
  currentPhase: string;
  phaseHistory: string[];
  steps: StrategyStep[];
  adaptations: Array<{ reason: string; action: string; details: string; at: number }>;
  createdAt: number;
  updatedAt: number;
}

// ── Solver Pool ───────────────────────────────────────────────────────────────

export interface SolverEntry {
  id: string;
  sessionId: string;
  endpoint: string;
  vulnClass: string;
  status: 'spawned' | 'running' | 'completed' | 'cancelled';
  result?: { findingsCount: number; vulnsFound: string[]; confidence: number };
  spawnedAt: number;
  completedAt?: number;
}

export interface SolverPoolState {
  sessionId: string;
  totalSpawned: number;
  running: number;
  completed: number;
  cancelled: number;
  solvers: SolverEntry[];
}

export interface SolverDecision {
  at: number;
  action: string;
  endpoint: string;
  vulnClass: string;
  reason: string;
}

// ── Validation Gate ───────────────────────────────────────────────────────────

export interface ValidationStats {
  sessionId: string;
  totalChecked: number;
  confirmed: number;
  rejected: number;
  inconclusive: number;
  layer3Skipped: number;
  avgConfidence: number;
}

// ── Plan Memory ───────────────────────────────────────────────────────────────

export interface PlanPhase {
  name: string;
  objective: string;
  status: 'pending' | 'active' | 'done' | 'skipped';
  outcomes: string[];
  startedAt?: number;
  completedAt?: number;
}

export interface PlanSummary {
  sessionId: string;
  currentPhase: PlanPhase | null;
  phases: PlanPhase[];
  totalPhases: number;
  completedPhases: number;
  startedAt: number;
}

// ── Agent Coordination ────────────────────────────────────────────────────────

export type AgentRole = 'coordinator' | 'hypothesis_agent' | 'probe_agent' | 'verify_agent' | 'report_agent';

export interface AgentState {
  role: AgentRole;
  status: 'idle' | 'busy' | 'blocked';
  currentTask?: string;
  taskCount: number;
  lastActiveAt: number;
}

export interface CoordinationDecision {
  at: number;
  coordinatorAction: string;
  reason: string;
  affectedAgents: AgentRole[];
  outcome?: string;
}

export interface CoordinationState {
  sessionId: string;
  agents: Record<AgentRole, AgentState>;
  decisions: CoordinationDecision[];
  phase: string;
  blockers: string[];
}

// ── Static Analysis ───────────────────────────────────────────────────────────

export interface RouteDefinition {
  method: string;
  path: string;
  file: string;
  line: number;
  parameters: string[];
  potentialVulns: string[];
}

export interface StaticAnalysisResult {
  routes: RouteDefinition[];
  hypotheses: Array<{ endpoint: string; vulnClass: string; confidence: number; rationale: string }>;
  stats: {
    filesAnalyzed: number;
    routesFound: number;
    hypothesesGenerated: number;
    durationMs: number;
  };
}

// ── Observability ─────────────────────────────────────────────────────────────

export interface LiveObservability {
  sessionId: string;
  requestsPerMinute: number;
  blockRate: number;
  avgResponseMs: number;
  activeHypotheses: number;
  confirmedFindings: number;
  remainingBudget: number;
  elapsedMs: number;
  currentActivity: string;
}

// ── Reasoning ─────────────────────────────────────────────────────────────────

export interface ReasoningSnapshot {
  sessionId: string;
  phase: string;
  currentHypothesis?: string;
  recentObservations: string[];
  planSummary: string;
  nextActions: string[];
  capturedAt: number;
}

// ── Evasion ───────────────────────────────────────────────────────────────────

export interface EvasionAttempt {
  sessionId: string;
  technique: string;
  category: string;
  succeeded: boolean;
  responseCode: number;
  responseTimeMs: number;
  attemptedAt: number;
}

export interface EvasionRanking {
  rankings: Array<{ technique: string; category: string; successRate: number; attempts: number; rank: number }>;
  byCategory: Record<string, { attempts: number; successes: number; rate: number }>;
}

export interface TemporalPhase {
  name: string;
  startedAt: number;
  endedAt?: number;
  blockRate: number;
  requestCount: number;
}

export interface TemporalAnalysis {
  phases: TemporalPhase[];
  currentPhase: string | null;
  transitionPattern: 'escalating' | 'stable' | 'de-escalating' | 'no_data';
  predictedNextPhase: string | null;
  phaseTransitions: Array<{ from: string; to: string; at: number }>;
}

export interface BlockCluster {
  category: string;
  techniques: string[];
  blockRate: number;
  size: number;
}

export interface Anomaly {
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  detectedAt: number;
}

export interface RuleCorrelationMatrix {
  correlations: Array<{ category1: string; category2: string; sharedBlockRate: number }>;
  comprehensiveCategories: string[];
  isolatedCategories: string[];
  rulesetComplexity: 'minimal' | 'standard' | 'comprehensive' | 'hardened';
  lastUpdated: number;
}

// ── Calibration ───────────────────────────────────────────────────────────────

export interface CalibrationMetrics {
  totalCalibrations: number;
  passiveAccuracy: number;
  byVendor: Record<string, { count: number; accuracy: number }>;
  bySignalType: Record<string, { count: number; accuracy: number }>;
  weightAdjustments: Array<{ signal: string; oldWeight: number; newWeight: number; at: number }>;
}

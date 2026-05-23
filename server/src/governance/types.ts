export type GovernancePillar =
  | 'Pillar 1 - Kinetic Clause'
  | 'Pillar 2 - Recursive Loop'
  | 'Pillar 3 - Ethical Boundary'
  | 'Pillar 4 - Hardware Sovereignty'
  | 'Pillar 5 - Multi-Agent Quorum'
  | 'Safety Controls'
  | 'Prompt Injection Detection'
  | 'Blue Team Oversight';

export type GovernanceVerdict = 'approved' | 'modified' | 'blocked';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface GovernanceDecision {
  id: string;
  timestamp: Date;
  agentId: string;
  agentName: string;
  action: string;
  actionType: 'filesystem' | 'command' | 'tool' | 'network' | 'ai_call' | 'vision' | 'scope_check';
  verdict: GovernanceVerdict;
  pillar: GovernancePillar;
  confidence: number;
  riskLevel: RiskLevel;
  reason: string;
  coachMessage: string;
  replay: {
    userPrompt?: string;
    agentThoughts?: string;
    toolCommand?: string;
    stdoutPreview?: string;
    systemMetrics?: Record<string, any>;
    decisionChain?: Array<{
      step: string;
      reasoning: string;
      pillar: GovernancePillar;
    }>;
  };
  quorum?: {
    votesFor: number;
    votesAgainst: number;
    total: number;
    threshold: number;
    voters: Array<{
      agentId: string;
      vote: 'for' | 'against';
      reasoning: string;
    }>;
  };
  originalAction?: string;
  modifiedAction?: string;
  modifications?: string[];
  huntId?: string;
}

export interface AuditEvent {
  id: string;
  timestamp: Date;
  category: 'command' | 'agent' | 'model_call' | 'vision' | 'scope_check' | 'governance' | 'security';
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  metadata: Record<string, any>;
  huntId?: string;
  agentId?: string;
  governanceDecisionId?: string;
}

export interface SelfAttestation {
  id: string;
  timestamp: Date;
  agentId: string;
  agentName: string;
  action: string;
  justification: string;
  confidence: number;
  context: {
    targetInfo: string;
    toolsConsidered: string[];
    alternativesRejected: Array<{
      alternative: string;
      reason: string;
    }>;
    evidenceBasis: string[];
    riskAssessment: {
      level: RiskLevel;
      factors: string[];
      mitigations: string[];
    };
    governancePillar: GovernancePillar;
  };
  replay: {
    inputState: Record<string, any>;
    decisionTree: Array<{
      step: string;
      options: string[];
      chosen: string;
      reasoning: string;
    }>;
    toolchainSnapshot: string[];
    environmentSnapshot: Record<string, any>;
  };
  sessionId: string;
  huntId?: string;
}

export interface GovernanceSnapshot {
  id: string;
  timestamp: Date;
  config: {
    realToolsMode: boolean;
    scopeEnforcement: boolean;
    autoStealth: boolean;
    pillarSensitivities: Record<GovernancePillar, number>;
    agentPermissions: Record<string, any>;
  };
  verdicts: {
    approved: number;
    modified: number;
    blocked: number;
    total: number;
  };
  pillarActivity: Record<GovernancePillar, number>;
  agentActivity: Record<string, number>;
  riskDistribution: Record<RiskLevel, number>;
}

export interface DriftAnalysis {
  timestamp: Date;
  recentPeriod: {
    start: Date;
    end: Date;
    snapshots: number;
  };
  baselinePeriod: {
    start: Date;
    end: Date;
    snapshots: number;
  };
  verdictDrift: {
    blockRateChange: number;
    modifyRateChange: number;
    approveRateChange: number;
    flagged: boolean;
  };
  pillarDrift: Array<{
    pillar: GovernancePillar;
    activityChange: number;
    flagged: boolean;
  }>;
  configChanges: Array<{
    timestamp: Date;
    change: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
  anomalies: string[];
}

export interface Scope {
  inScope: string[];
  outOfScope: string[];
  exemptions: string[];
}

export interface AgentContract {
  agentId: string;
  allowedActions: string[];
  rateLimit: number;
  allowedDomains: string[];
  restrictionLevel: 'strict' | 'moderate' | 'relaxed';
}

export interface NetworkRequest {
  id: string;
  timestamp: Date;
  agentId: string;
  url: string;
  method: string;
  status: 'allowed' | 'blocked';
  responseTime?: number;
  governanceDecisionId?: string;
  blockReason?: string;
  stealth: {
    delayApplied: number;
    jitter: number;
  };
}

export interface PathValidationResult {
  valid: boolean;
  reason?: string;
  sanitizedPath?: string;
}

export interface CommandValidationResult {
  valid: boolean;
  risk: RiskLevel;
  reason?: string;
  sanitizedCommand?: string;
}

export interface InjectionDetectionResult {
  safe: boolean;
  score: number;
  reasons: string[];
  detections: {
    keywords?: Array<{ keyword: string; weight: number }>;
    patterns?: Array<{ pattern: string; match: string }>;
    semantic?: Array<{ category: string; indicator: string }>;
    structural?: string[];
  };
}

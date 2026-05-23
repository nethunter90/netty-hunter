export type CampaignOutcome = 'success' | 'partial' | 'failure';

export type ExecutionPhase = 'recon' | 'enumeration' | 'exploitation' | 'post-exploit';

export type HuntGoal = 'find-vulns' | 'recon-only' | 'specific-vuln' | 'full-audit' | 'api-testing' | 'auth-testing' | 'injection-hunting' | 'misconfig-hunting';

export interface IntelligenceEvent {
  type: 'hunt:started' | 'hunt:completed' | 'task:executed' | 'tool:result'
       | 'finding:confirmed' | 'report:submitted' | 'report:triaged';
  timestamp: string;
  campaignId: string;
  payload: Record<string, unknown>;
}

export interface DefenseProfile {
  wafType: string | null;
  wafStrictness: 'permissive' | 'moderate' | 'strict';
  rateLimiting: {
    detected: boolean;
    threshold: number | null;
    resetWindow: number | null;
  };
  errorVerbosity: 'verbose' | 'standard' | 'suppressed';
  cspPolicy: {
    present: boolean;
    strictness: 'none' | 'basic' | 'strict' | 'nonce-based';
    reportOnly: boolean;
  };
  securityHeaders: {
    hsts: boolean;
    xFrameOptions: boolean;
    xContentType: boolean;
    referrerPolicy: string | null;
  };
  cookieFlags: {
    httpOnly: boolean;
    secure: boolean;
    sameSite: string | null;
  };
  authMechanisms: string[];
  apiStyle: 'rest' | 'graphql' | 'soap' | 'grpc' | 'mixed';
}

export interface TechFingerprint {
  language: string | null;
  framework: string | null;
  server: string | null;
  database: string | null;
  cdn: string | null;
  jsLibraries: string[];
}

export interface TechniqueOutcome {
  technique: string;
  variant: string;
  targetEndpoint: string;
  toolsUsed: string[];
  result: 'success' | 'partial' | 'blocked' | 'not-applicable';
  blockingReason?: string;
  timeSpentMinutes: number;
  confidenceScore: number;
}

export interface FindingSummary {
  id: string;
  vulnType: string;
  severity: string;
  endpoint: string;
  technique: string;
  cvssScore: number;
  title: string;
  confirmedAt: string;
}

export interface CampaignProfile {
  id: string;
  target: {
    domain: string;
    industry: string;
    techStack: TechFingerprint;
    defensePosture: DefenseProfile;
  };
  hunt: {
    goal: HuntGoal;
    startedAt: string;
    completedAt: string;
    durationMinutes: number;
    tasksExecuted: number;
    toolsUsed: string[];
  };
  techniques: TechniqueOutcome[];
  findings: FindingSummary[];
  outcome: CampaignOutcome;
}

export interface ToolExecutionRecord {
  id: string;
  campaignId: string;
  tool: string;
  phase: ExecutionPhase;
  timestamp: string;
  input: {
    params: Record<string, unknown>;
    sourceRecordId: string | null;
    consumedFields: string[];
  };
  output: {
    rawResultHash: string;
    structuredFields: Record<string, unknown>;
    findingCount: number;
    severity: string | null;
  };
  effectiveness: {
    producedActionableOutput: boolean;
    ledToFinding: boolean;
    timeToResult: number;
  };
}

export interface DataFlowEdge {
  sourceId: string;
  targetId: string;
  consumedFields: string[];
  fieldMapping: Record<string, string>;
}

export interface ToolFlowDAG {
  campaignId: string;
  nodes: ToolExecutionRecord[];
  edges: DataFlowEdge[];
  findingPaths: string[][];
}

export interface PlaybookStep {
  order: number;
  tool: string;
  phase: ExecutionPhase;
  defaultParams: Record<string, unknown>;
  inputMapping: Record<string, string>;
  requiredOutputFields: string[];
  gateCondition: string | null;
}

export interface Playbook {
  id: string;
  name: string;
  steps: PlaybookStep[];
  applicableWhen: {
    techStack: Partial<TechFingerprint>;
    defenseProfile: Partial<DefenseProfile>;
    huntGoal: HuntGoal[];
  };
  stats: {
    timesUsed: number;
    successRate: number;
    avgFindingsPerRun: number;
    avgDurationMinutes: number;
    lastUsed: string | null;
  };
}

export interface PredictionFeatureVector {
  techStack: TechFingerprint;
  defenseProfile: DefenseProfile;
  industry: string;
  huntGoal: HuntGoal;
  campaignState: {
    tasksCompleted: number;
    findingsSoFar: number;
    timeElapsedMinutes: number;
    techniquesAttempted: string[];
    blockedTechniques: string[];
  };
}

export interface ConditionalBranch {
  condition: string;
  conditionProbability: number;
  updatedProbability: number;
  updatedEvScore: number;
  suggestedAction: string;
}

export interface PredictionNode {
  technique: string;
  baseProbability: number;
  conditionalBranches: ConditionalBranch[];
  expectedTimeMinutes: number;
  expectedSeverity: string;
  expectedPayout: number;
  evScore: number;
}

export interface StrategyRecommendation {
  rankedStrategies: PredictionNode[];
  optimalPath: string[];
  totalExpectedValue: number;
  confidence: number;
  reasoning: string;
}

export interface PredictionTrainingPoint {
  id: string;
  featureVector: PredictionFeatureVector;
  technique: string;
  predictedProbability: number;
  actualOutcome: 'success' | 'partial' | 'blocked' | 'not-applicable';
  timestamp: string;
}

export interface PayoutDataPoint {
  id: string;
  programId: string;
  vulnType: string;
  severity: string;
  payout: number;
  impactFraming: string;
  pocComplexity: 'low' | 'medium' | 'high';
  escalationChain: string[];
  timeToTriage: number;
}

export interface ImpactFraming {
  vulnType: string;
  lowValueFraming: string;
  highValueFraming: string;
  payoutMultiplier: number;
  escalationChain: string[];
}

export interface DuplicatePrediction {
  vulnType: string;
  targetArea: string;
  duplicateProbability: number;
  reasoning: string;
  factors: Record<string, number>;
  recommendation: 'proceed' | 'caution' | 'avoid';
}

export interface TriagePrediction {
  programId: string;
  estimatedDays: number;
  confidence: number;
  factors: Record<string, number>;
}

export interface UnifiedRecommendation {
  technique: string;
  successProbability: number;
  duplicateProbability: number;
  expectedPayout: number;
  adjustedEV: number;
  recommendedPlaybook: string | null;
  historicalContext: string;
  conditionalUpside: ConditionalBranch[];
}

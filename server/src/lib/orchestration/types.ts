export type HuntPhase = 'recon' | 'scanning' | 'exploitation' | 'reporting' | 'completed';

export type AgentType = 'recon' | 'scanner' | 'exploit' | 'support' | 'cognitive';

export type ResourceClass = 'lightweight' | 'standard' | 'enterprise';
export type StealthLevel = 'aggressive' | 'balanced' | 'stealth' | 'ultrastealth';

export interface ConcurrencyLimits {
  maxHeavyTools: number;
  maxTotalTools: number;
  heavyTools: string[];
}

export const RESOURCE_CLASS_LIMITS: Record<ResourceClass, ConcurrencyLimits> = {
  lightweight: { maxHeavyTools: 1, maxTotalTools: 3, heavyTools: ['nikto', 'nuclei', 'sqlmap', 'hydra', 'masscan'] },
  standard: { maxHeavyTools: 2, maxTotalTools: 5, heavyTools: ['nikto', 'nuclei', 'sqlmap', 'hydra', 'masscan'] },
  enterprise: { maxHeavyTools: 4, maxTotalTools: 10, heavyTools: ['nikto', 'nuclei', 'sqlmap', 'hydra', 'masscan'] },
};

export interface Hunt {
  id: string;
  target: string;
  goal: string;
  phase: HuntPhase;
  status: 'active' | 'paused' | 'completed' | 'failed' | 'aborted';
  scope: {
    inScope: string[];
    outOfScope: string[];
  };
  startedAt: Date;
  completedAt?: Date;
  phaseStartedAt: Date;
  autoAdvance: boolean;
  phaseTimeouts: {
    recon: number;
    scanning: number;
    exploitation: number;
    reporting: number;
  };
  findings: Finding[];
  stealthMode: StealthLevel;
  resourceClass: ResourceClass;
  metadata: {
    expectedPayout?: number;
    priority?: 'low' | 'medium' | 'high' | 'critical';
    tags?: string[];
  };
}

export interface Finding {
  id: string;
  huntId: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: string[];
  cvss?: number;
  cwe?: string[];
  discoveredBy: string;
  discoveredAt: Date;
  endpoint?: string;
  payload?: string;
  status: 'unverified' | 'verified' | 'false_positive' | 'duplicate';
}

export interface Agent {
  id: string;
  type: AgentType;
  huntId: string;
  status: 'idle' | 'working' | 'waiting' | 'stopped' | 'errored';
  currentTarget?: string;
  claimedTargets: string[];
  maxConcurrent: number;
  timeout: number;
  startedAt: Date;
  lastActivity: Date;
  invocations: number;
  successCount: number;
  errorCount: number;
  metadata: Record<string, any>;
}

export interface AgentTask {
  id: string;
  agentId: string;
  type: string;
  target: string;
  tool: string;
  parameters: Record<string, any>;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt?: Date;
  completedAt?: Date;
  result?: any;
  error?: string;
}

export interface AgentEvent {
  id: string;
  type: string;
  agentId: string;
  huntId: string;
  timestamp: Date;
  data: Record<string, any>;
  processed: boolean;
  subscribers: AgentType[];
}

export interface MissionMemory {
  huntId: string;
  domains: string[];
  subdomains: string[];
  endpoints: Endpoint[];
  technologies: Technology[];
  vulnerabilities: Vulnerability[];
  credentials: Credential[];
  notes: string[];
  lastUpdated: Date;
}

export interface Endpoint {
  url: string;
  method: string;
  statusCode?: number;
  title?: string;
  contentType?: string;
  technologies?: string[];
  headers?: Record<string, string>;
  discoveredBy: string;
  discoveredAt: Date;
}

export interface Technology {
  name: string;
  version?: string;
  category: string;
  confidence: number;
}

export interface Vulnerability {
  id: string;
  type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  endpoint: string;
  description: string;
  evidence: string;
  exploitable: boolean;
}

export interface Credential {
  username: string;
  password?: string;
  hash?: string;
  source: string;
  service: string;
}

export interface ToolConfig {
  name: string;
  command: string;
  args: string[];
  timeout: number;
  outputParser: (output: string) => any;
}

export interface CognitiveTask {
  id: string;
  type: 'plan' | 'analyze' | 'research' | 'validate';
  huntId: string;
  input: Record<string, any>;
  status: 'pending' | 'running' | 'completed' | 'failed';
  result?: any;
  error?: string;
}

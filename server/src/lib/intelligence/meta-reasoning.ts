import { EventEmitter } from 'events';
import { reasoningEngine } from './reasoning-engine';
import { decisionEngine } from './decision-engine';
import { huntOrchestrator } from '../orchestration/layer1-hunt-orchestrator';
import { missionMemory } from '../orchestration/mission-memory';
import { eventBus } from '../orchestration/layer3-event-bus';
import { huntCortex, SignalType, CortexSignal } from './hunt-cortex';
import { decisionJournal } from './decision-journal';
import { adaptiveThresholdTuner } from './adaptive-threshold-tuner';
import { backwardPlanner } from './backward-planner';
import { decisionTraceLogger } from './decision-trace';
import { strategyWeightLearner } from '../learning/strategy-weight-learner';
import { resolveProvenanceFromHuntId } from '../hunter/custom-target-program';

export interface Evidence {
  type: 'technology' | 'vulnerability' | 'endpoint' | 'credential' | 'defense' | 'error';
  description: string;
  relevance: number;
  supports: boolean;
  timestamp: number;
}

export interface HuntContext {
  phase: string;
  findingsCount: number;
  endpointCount: number;
  techCount: number;
  vulnCount: number;
  cycleCount: number;
  elapsedTime: number;
  goal: string;
}

export interface StrategyDecision {
  action: 'continue' | 'pivot' | 'escalate' | 'abort' | 'stabilize' | 'accelerate';
  confidence: number;
  rationale: string;
  newStrategy?: string;
  recommendations: string[];
  subAction?: string;
}

export interface CounterfactualResult {
  expectedByNow: string[];
  actuallyFound: string[];
  missing: string[];
  confidence: number;
}

export interface HuntState {
  huntId: string;
  currentStrategy: string;
  cycleCount: number;
  hypothesisConfidence: number;
  gainHistory: number[];
  strategyHistory: string[];
  findingsTimeline: { cycle: number; count: number }[];
  pivotCount: number;
  startedAt: number;
  /** Findings count pushed directly by HunterEngine (engine-driven hunts don't
   *  register with huntOrchestrator, so this is the authoritative source). */
  externalFindingsCount?: number;
}

interface StrategyEdge {
  from: string;
  to: string;
  weight: number;
  condition?: string;
}

type StrategyGraph = Map<string, StrategyEdge[]>;

const STRATEGIES = [
  'port_scan',
  'subdomain_enum',
  'directory_fuzz',
  'parameter_fuzz',
  'sqli_test',
  'xss_test',
  'ssrf_test',
  'auth_bypass',
  'api_enum',
  'tech_fingerprint',
] as const;

type Strategy = typeof STRATEGIES[number];

const GAIN_WINDOW_SIZE = 10;
const PLATEAU_THRESHOLD = 0.1;
const MONITOR_INTERVAL_MS = 30_000;
const MAX_PIVOTS = 8;
const CONFIDENCE_DECAY_RATE = 0.02;

const GOAL_EXPECTATIONS: Record<string, { cycle: number; expected: string[] }[]> = {
  'SQL Injection': [
    { cycle: 2, expected: ['endpoints_discovered', 'tech_identified'] },
    { cycle: 5, expected: ['parameters_found', 'input_fields_mapped'] },
    { cycle: 8, expected: ['error_based_signal', 'injectable_param_candidate'] },
    { cycle: 12, expected: ['sqli_confirmed', 'data_extracted'] },
  ],
  'XSS': [
    { cycle: 2, expected: ['endpoints_discovered', 'tech_identified'] },
    { cycle: 5, expected: ['reflected_params_found', 'input_fields_mapped'] },
    { cycle: 8, expected: ['reflection_confirmed', 'filter_bypass_found'] },
    { cycle: 12, expected: ['xss_confirmed', 'dom_sink_found'] },
  ],
  'SSRF': [
    { cycle: 2, expected: ['endpoints_discovered', 'tech_identified'] },
    { cycle: 5, expected: ['url_params_found', 'file_include_params'] },
    { cycle: 8, expected: ['internal_interaction', 'dns_callback'] },
    { cycle: 12, expected: ['ssrf_confirmed', 'internal_access'] },
  ],
  'RCE': [
    { cycle: 2, expected: ['endpoints_discovered', 'tech_identified'] },
    { cycle: 4, expected: ['upload_endpoint', 'deserialization_point'] },
    { cycle: 7, expected: ['command_injection_candidate', 'template_injection_signal'] },
    { cycle: 10, expected: ['rce_confirmed', 'shell_obtained'] },
  ],
  'Auth Bypass': [
    { cycle: 2, expected: ['endpoints_discovered', 'auth_endpoints_found'] },
    { cycle: 5, expected: ['session_mechanics_understood', 'token_structure_known'] },
    { cycle: 8, expected: ['privilege_escalation_path', 'idor_candidate'] },
    { cycle: 12, expected: ['auth_bypass_confirmed', 'unauthorized_access'] },
  ],
  'Account Takeover': [
    { cycle: 2, expected: ['endpoints_discovered', 'auth_endpoints_found'] },
    { cycle: 5, expected: ['password_reset_flow_mapped', 'session_handling_analyzed'] },
    { cycle: 8, expected: ['token_weakness_found', 'race_condition_candidate'] },
    { cycle: 12, expected: ['ato_confirmed', 'session_hijack'] },
  ],
  'IDOR': [
    { cycle: 2, expected: ['endpoints_discovered', 'api_endpoints_found'] },
    { cycle: 5, expected: ['id_params_found', 'object_references_mapped'] },
    { cycle: 8, expected: ['horizontal_access_test', 'uuid_prediction'] },
    { cycle: 12, expected: ['idor_confirmed', 'data_leak'] },
  ],
  'API Security': [
    { cycle: 2, expected: ['endpoints_discovered', 'api_schema_found'] },
    { cycle: 5, expected: ['auth_mechanism_mapped', 'rate_limits_tested'] },
    { cycle: 8, expected: ['broken_auth_candidate', 'mass_assignment_signal'] },
    { cycle: 12, expected: ['api_vuln_confirmed', 'data_exposure'] },
  ],
};

const GOAL_TO_INITIAL_STRATEGY: Record<string, Strategy> = {
  'SQL Injection': 'parameter_fuzz',
  'XSS': 'parameter_fuzz',
  'SSRF': 'parameter_fuzz',
  'RCE': 'tech_fingerprint',
  'Auth Bypass': 'auth_bypass',
  'Account Takeover': 'auth_bypass',
  'IDOR': 'api_enum',
  'API Security': 'api_enum',
};

export class MetaReasoner extends EventEmitter {
  private huntStates: Map<string, HuntState> = new Map();
  private monitors: Map<string, NodeJS.Timeout> = new Map();
  private strategyGraph: StrategyGraph = new Map();
  private transitionSuccessHistory: Map<string, { successes: number; attempts: number }> = new Map();
  private learnedWeights: Map<string, number> = new Map();

  constructor() {
    super();
    this.setMaxListeners(50);
    this.initializeStrategyGraph();
    this.subscribeToCortex();
  }

  async loadLearnedWeights(): Promise<void> {
    // Called once at module load (see the bottom of this file), before any
    // hunt/programId exists — "unknown" is the only honest provenance here.
    // completeHunt() below refreshes this per-hunt with a real resolution.
    this.learnedWeights = await strategyWeightLearner.loadWeights("unknown");
  }

  private subscribeToCortex(): void {
    huntCortex.subscribe(SignalType.EVENT_EXPIRED, (signal: CortexSignal) => {
      if (signal.payload.originalUrgency > 0.8 && signal.huntId) {
        const state = this.huntStates.get(signal.huntId);
        if (state) {
          this.evaluateEnriched(signal.huntId);
        }
      }
    });

    huntCortex.subscribe(SignalType.VERIFICATION_FAILED, (signal: CortexSignal) => {
      const dependents = signal.payload.dependentFindings || [];
      if (dependents.length > 3 && signal.huntId) {
        this.evaluateEnriched(signal.huntId);
      }
    });

    huntCortex.subscribe(SignalType.VERIFICATION_DEGRADED, (signal: CortexSignal) => {
      if (signal.huntId) {
        const health = huntCortex.computeHuntHealth(signal.huntId);
        if (health.degraded_verifications > 3) {
          this.evaluateEnriched(signal.huntId);
        }
      }
    });

    // CNAME chain routes through a CDN edge node — shift to passive fingerprinting
    // before running any aggressive payload templates against this host.
    huntCortex.subscribe(SignalType.SHARED_INFRA_DETECTED, (signal: CortexSignal) => {
      const { warning, url } = signal.payload as { warning?: string; url?: string };
      if (signal.huntId) {
        const state = this.huntStates.get(signal.huntId);
        if (state && ['directory_fuzz', 'parameter_fuzz', 'sqli_test', 'xss_test'].includes(state.currentStrategy)) {
          state.currentStrategy = 'tech_fingerprint'; // passive — fingerprint before exploiting CDN edge
          this.emit('strategy:cdn_pivot', { huntId: signal.huntId, warning, url });
        }
      }
    });

    // Target is showing signs of fragility (high 5xx rate, latency spike) — shift
    // from aggressive fuzzing to low-impact logic-flaw templates.
    huntCortex.subscribe(SignalType.TARGET_FRAGILITY_HIGH, (signal: CortexSignal) => {
      if (signal.huntId) {
        const state = this.huntStates.get(signal.huntId);
        if (state && ['directory_fuzz', 'parameter_fuzz', 'sqli_test'].includes(state.currentStrategy)) {
          state.currentStrategy = 'api_enum'; // lower-impact, more precise
          this.emit('strategy:fragility_pivot', { huntId: signal.huntId, payload: signal.payload });
        }
      }
    });
  }

  private initializeStrategyGraph(): void {
    for (const s of STRATEGIES) {
      this.strategyGraph.set(s, []);
    }

    const edges: [string, string, number, string?][] = [
      ['port_scan', 'tech_fingerprint', 0.9, 'ports_found'],
      ['port_scan', 'subdomain_enum', 0.7],
      ['port_scan', 'api_enum', 0.6, 'http_ports_found'],

      ['subdomain_enum', 'port_scan', 0.8],
      ['subdomain_enum', 'directory_fuzz', 0.85],
      ['subdomain_enum', 'tech_fingerprint', 0.75],
      ['subdomain_enum', 'api_enum', 0.6],

      ['tech_fingerprint', 'directory_fuzz', 0.8],
      ['tech_fingerprint', 'sqli_test', 0.7, 'db_tech_found'],
      ['tech_fingerprint', 'xss_test', 0.65, 'frontend_framework_found'],
      ['tech_fingerprint', 'ssrf_test', 0.6, 'cloud_infra_found'],
      ['tech_fingerprint', 'api_enum', 0.7, 'api_framework_found'],
      ['tech_fingerprint', 'auth_bypass', 0.55, 'auth_framework_found'],

      ['directory_fuzz', 'parameter_fuzz', 0.85],
      ['directory_fuzz', 'api_enum', 0.75],
      ['directory_fuzz', 'auth_bypass', 0.6, 'admin_panel_found'],
      ['directory_fuzz', 'tech_fingerprint', 0.5],

      ['parameter_fuzz', 'sqli_test', 0.9, 'injectable_params_found'],
      ['parameter_fuzz', 'xss_test', 0.85, 'reflected_params_found'],
      ['parameter_fuzz', 'ssrf_test', 0.7, 'url_params_found'],
      ['parameter_fuzz', 'auth_bypass', 0.6, 'auth_params_found'],
      ['parameter_fuzz', 'directory_fuzz', 0.4],

      ['sqli_test', 'auth_bypass', 0.7, 'db_access_gained'],
      ['sqli_test', 'parameter_fuzz', 0.5, 'need_more_params'],
      ['sqli_test', 'xss_test', 0.4],
      ['sqli_test', 'directory_fuzz', 0.3],

      ['xss_test', 'auth_bypass', 0.6, 'session_theft_possible'],
      ['xss_test', 'parameter_fuzz', 0.5, 'need_more_params'],
      ['xss_test', 'ssrf_test', 0.4],
      ['xss_test', 'sqli_test', 0.35],

      ['ssrf_test', 'port_scan', 0.7, 'internal_network_access'],
      ['ssrf_test', 'api_enum', 0.65, 'internal_apis_found'],
      ['ssrf_test', 'auth_bypass', 0.5],
      ['ssrf_test', 'parameter_fuzz', 0.4],

      ['auth_bypass', 'api_enum', 0.8, 'authenticated_access'],
      ['auth_bypass', 'sqli_test', 0.6],
      ['auth_bypass', 'directory_fuzz', 0.55],
      ['auth_bypass', 'parameter_fuzz', 0.5],

      ['api_enum', 'parameter_fuzz', 0.85],
      ['api_enum', 'auth_bypass', 0.75],
      ['api_enum', 'sqli_test', 0.7, 'api_db_endpoints_found'],
      ['api_enum', 'ssrf_test', 0.6, 'api_fetch_endpoints_found'],
      ['api_enum', 'xss_test', 0.5],
    ];

    for (const [from, to, weight, condition] of edges) {
      const edgeList = this.strategyGraph.get(from);
      if (edgeList) {
        edgeList.push({ from, to, weight, condition });
      }
    }
  }

  // `weights` (2026-07-23 readiness handoff, Phase 2 regression fix): an
  // explicit override so evaluateEnriched() (below) can pass freshly-resolved,
  // hunt-scoped provenance weights instead of relying on this.learnedWeights —
  // a single shared field only refreshed at hunt COMPLETION (completeHunt()),
  // which meant a real hunt's mid-hunt decisions never saw its own real::
  // weights, only whatever the previous hunt's completion had left behind
  // (wrong-hunt weights at best, "unknown"'s boot default at worst). The sync
  // evaluate() path (no async DB read available) still falls back to the
  // shared field, opportunistically refreshed as a side effect below.
  getBestTransition(currentStrategy: string, context: HuntContext, weights: Map<string, number> = this.learnedWeights): string {
    const edges = this.strategyGraph.get(currentStrategy);
    if (!edges || edges.length === 0) {
      return 'tech_fingerprint';
    }

    const scored = edges.map(edge => {
      const historyKey = `${edge.from}->${edge.to}`;

      // Start from persisted cross-hunt weight if available, else hardcoded base
      let adjustedWeight = weights.get(historyKey) ?? edge.weight;

      // Blend with within-session history (60/40 toward base)
      const history = this.transitionSuccessHistory.get(historyKey);
      if (history && history.attempts > 0) {
        const successRate = history.successes / history.attempts;
        adjustedWeight = adjustedWeight * 0.6 + successRate * 0.4;
      }

      if (this.isGoalAligned(edge.to, context.goal)) {
        adjustedWeight *= 1.3;
      }

      if (context.vulnCount === 0 && context.cycleCount > 5) {
        if (['port_scan', 'subdomain_enum', 'tech_fingerprint'].includes(edge.to)) {
          adjustedWeight *= 0.7;
        }
      }

      if (context.endpointCount < 3 && ['sqli_test', 'xss_test', 'ssrf_test'].includes(edge.to)) {
        adjustedWeight *= 0.5;
      }

      return { strategy: edge.to, score: Math.min(1, adjustedWeight) };
    });

    scored.sort((a, b) => b.score - a.score);
    return scored[0].strategy;
  }

  private isGoalAligned(strategy: string, goal: string): boolean {
    const alignment: Record<string, string[]> = {
      'SQL Injection': ['sqli_test', 'parameter_fuzz', 'api_enum'],
      'XSS': ['xss_test', 'parameter_fuzz', 'directory_fuzz'],
      'SSRF': ['ssrf_test', 'parameter_fuzz', 'api_enum'],
      'RCE': ['tech_fingerprint', 'parameter_fuzz', 'directory_fuzz'],
      'Auth Bypass': ['auth_bypass', 'api_enum', 'parameter_fuzz'],
      'Account Takeover': ['auth_bypass', 'parameter_fuzz', 'xss_test'],
      'IDOR': ['api_enum', 'parameter_fuzz', 'auth_bypass'],
      'API Security': ['api_enum', 'auth_bypass', 'parameter_fuzz'],
    };
    return (alignment[goal] || []).includes(strategy);
  }

  updateConfidence(huntId: string, evidence: Evidence): number {
    const state = this.huntStates.get(huntId);
    if (!state) return 0;

    const prior = state.hypothesisConfidence;

    let likelihood: number;
    if (evidence.supports) {
      likelihood = 0.5 + evidence.relevance * 0.45;
    } else {
      likelihood = 0.5 - evidence.relevance * 0.35;
    }

    const evidenceProb = likelihood * prior + (1 - likelihood) * (1 - prior);
    let posterior = (likelihood * prior) / Math.max(evidenceProb, 0.001);

    const timeSinceStart = (Date.now() - state.startedAt) / 1000;
    const decayCycles = Math.floor(timeSinceStart / 30);
    const lastEvidenceAge = state.findingsTimeline.length > 0
      ? state.cycleCount - state.findingsTimeline[state.findingsTimeline.length - 1].cycle
      : state.cycleCount;

    if (lastEvidenceAge > 3 && !evidence.supports) {
      posterior -= CONFIDENCE_DECAY_RATE * lastEvidenceAge;
    }

    state.hypothesisConfidence = Math.min(0.99, Math.max(0.01, posterior));
    return state.hypothesisConfidence;
  }

  getGainRate(huntId: string): number {
    const state = this.huntStates.get(huntId);
    if (!state) return 0;

    if (state.findingsTimeline.length < 2) {
      return state.findingsTimeline.length > 0 ? 0.5 : 0;
    }

    const recent = state.findingsTimeline.slice(-GAIN_WINDOW_SIZE);

    let totalGain = 0;
    for (let i = 1; i < recent.length; i++) {
      const delta = recent[i].count - recent[i - 1].count;
      totalGain += Math.max(0, delta);
    }

    const maxPossibleGain = (recent.length - 1) * 5;
    const rate = totalGain / Math.max(maxPossibleGain, 1);

    const normalizedRate = Math.min(1, Math.max(0, rate));

    if (state.gainHistory.length >= GAIN_WINDOW_SIZE) {
      state.gainHistory.shift();
    }
    state.gainHistory.push(normalizedRate);

    return normalizedRate;
  }

  checkCounterfactuals(huntId: string): CounterfactualResult {
    const state = this.huntStates.get(huntId);
    if (!state) {
      return { expectedByNow: [], actuallyFound: [], missing: [], confidence: 0 };
    }

    const hunt = huntOrchestrator.getHunt(huntId);
    const goal = hunt?.goal || '';
    const expectations = GOAL_EXPECTATIONS[goal] || [];

    const expectedByNow: string[] = [];
    for (const exp of expectations) {
      if (state.cycleCount >= exp.cycle) {
        expectedByNow.push(...exp.expected);
      }
    }

    const actuallyFound = this.getActualFindings(huntId);

    const missing = expectedByNow.filter(e => !actuallyFound.includes(e));

    const totalExpected = expectedByNow.length || 1;
    const foundCount = expectedByNow.filter(e => actuallyFound.includes(e)).length;
    const confidence = foundCount / totalExpected;

    return {
      expectedByNow: Array.from(new Set(expectedByNow)),
      actuallyFound: Array.from(new Set(actuallyFound)),
      missing: Array.from(new Set(missing)),
      confidence,
    };
  }

  private getActualFindings(huntId: string): string[] {
    const findings: string[] = [];

    const memory = missionMemory.get(huntId);
    if (memory) {
      if (memory.endpoints.length > 0) findings.push('endpoints_discovered');
      if (memory.technologies.length > 0) findings.push('tech_identified');
      if (memory.subdomains.length > 0) findings.push('subdomains_found');
      if (memory.credentials.length > 0) findings.push('credentials_found');

      if (memory.endpoints.some(e => e.url.includes('/api'))) findings.push('api_endpoints_found');
      if (memory.endpoints.some(e => e.url.includes('/admin'))) findings.push('admin_panel_found');
      if (memory.endpoints.some(e => e.url.includes('login') || e.url.includes('auth'))) {
        findings.push('auth_endpoints_found');
      }

      for (const vuln of memory.vulnerabilities) {
        const t = vuln.type.toLowerCase();
        if (t.includes('sql')) {
          findings.push('injectable_param_candidate', 'sqli_confirmed');
        }
        if (t.includes('xss')) {
          findings.push('reflected_params_found', 'xss_confirmed');
        }
        if (t.includes('ssrf')) {
          findings.push('internal_interaction', 'ssrf_confirmed');
        }
        if (t.includes('rce') || t.includes('command')) {
          findings.push('command_injection_candidate', 'rce_confirmed');
        }
        if (t.includes('auth') || t.includes('bypass')) {
          findings.push('auth_bypass_confirmed', 'unauthorized_access');
        }
        if (t.includes('idor')) {
          findings.push('idor_confirmed', 'data_leak');
        }
        if (vuln.exploitable) {
          findings.push('exploitable_vuln_found');
        }
      }
    }

    const reasoningMemory = reasoningEngine.getMissionMemory(huntId);
    if (reasoningMemory) {
      if (reasoningMemory.discoveredEndpoints.size > 0) findings.push('endpoints_discovered');
      if (reasoningMemory.discoveredTechnologies.size > 0) findings.push('tech_identified');
      if (reasoningMemory.discoveredVulnerabilities.size > 0) findings.push('vuln_signal_found');

      Array.from(reasoningMemory.discoveredEndpoints.keys()).forEach(key => {
        if (key.includes('?') || key.includes('=')) findings.push('parameters_found');
        if (key.includes('/api')) findings.push('api_schema_found');
      });

      Array.from(reasoningMemory.discoveredTechnologies.keys()).forEach(key => {
        const lower = key.toLowerCase();
        if (lower.includes('mysql') || lower.includes('postgres') || lower.includes('mssql') || lower.includes('oracle')) {
          findings.push('db_tech_found');
        }
        if (lower.includes('react') || lower.includes('angular') || lower.includes('vue')) {
          findings.push('frontend_framework_found');
        }
        if (lower.includes('aws') || lower.includes('azure') || lower.includes('gcp')) {
          findings.push('cloud_infra_found');
        }
      });
    }

    return Array.from(new Set(findings));
  }

  evaluate(huntId: string): StrategyDecision {
    const state = this.huntStates.get(huntId);
    if (!state) {
      return {
        action: 'abort',
        confidence: 0,
        rationale: 'No hunt state found for this hunt ID',
        recommendations: ['Initialize hunt state before evaluation'],
      };
    }

    state.cycleCount++;

    const currentFindingsCount = this.getCurrentFindingsCount(huntId);
    state.findingsTimeline.push({ cycle: state.cycleCount, count: currentFindingsCount });

    const gainRate = this.getGainRate(huntId);
    const confidence = state.hypothesisConfidence;
    const counterfactuals = this.checkCounterfactuals(huntId);
    const recommendations: string[] = [];

    if (state.pivotCount >= MAX_PIVOTS) {
      recommendations.push('Maximum pivot count reached — consider manual review');
      recommendations.push('Current attack surface may be well-defended');
      this.emit('meta:abort', { huntId, reason: 'max_pivots_exceeded' });
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_evaluation',
        sourceSystem: 'meta-reasoner',
        data: { action: 'abort', reason: 'max_pivots_exceeded', pivotCount: state.pivotCount },
        confidenceAtEvent: confidence,
        reasoning: `Exhausted ${MAX_PIVOTS} strategy pivots`,
      });
      return {
        action: 'abort',
        confidence,
        rationale: `Exhausted ${MAX_PIVOTS} strategy pivots without achieving objective. Target may be well-hardened or out of scope for automated testing.`,
        recommendations,
      };
    }

    if (confidence < 0.1 && state.cycleCount > 10) {
      recommendations.push('Hypothesis confidence critically low');
      recommendations.push('Consider redefining hunt goal or target');
      this.emit('meta:abort', { huntId, reason: 'confidence_collapsed' });
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_evaluation',
        sourceSystem: 'meta-reasoner',
        data: { action: 'abort', reason: 'confidence_collapsed', confidence },
        confidenceAtEvent: confidence,
        reasoning: `Hypothesis confidence dropped to ${(confidence * 100).toFixed(1)}%`,
      });
      return {
        action: 'abort',
        confidence,
        rationale: `Hypothesis confidence dropped to ${(confidence * 100).toFixed(1)}% after ${state.cycleCount} cycles. No evidence supports the current goal.`,
        recommendations,
      };
    }

    if (gainRate < PLATEAU_THRESHOLD && state.cycleCount > 5) {
      const context = this.buildHuntContext(huntId, state);
      const newStrategy = this.getBestTransition(state.currentStrategy, context);

      if (counterfactuals.missing.length > counterfactuals.actuallyFound.length) {
        recommendations.push(`Missing expected findings: ${counterfactuals.missing.slice(0, 3).join(', ')}`);
        recommendations.push(`Consider escalating to manual testing for ${state.currentStrategy}`);

        if (confidence < 0.3) {
          this.emit('meta:pivot', { huntId, from: state.currentStrategy, to: newStrategy, reason: 'plateau_with_low_confidence' });
          state.currentStrategy = newStrategy;
          state.strategyHistory.push(newStrategy);
          state.pivotCount++;
          const escalateRationale = `Plateau detected (gain rate: ${(gainRate * 100).toFixed(1)}%) with low confidence (${(confidence * 100).toFixed(1)}%). Missing ${counterfactuals.missing.length} expected findings. Escalating for manual intervention.`;
          decisionTraceLogger.recordEvent({
            huntId,
            eventType: 'meta_pivot',
            sourceSystem: 'meta-reasoner',
            data: { action: 'escalate', fromStrategy: state.strategyHistory[state.strategyHistory.length - 2], toStrategy: newStrategy, gainRate },
            confidenceAtEvent: confidence,
            reasoning: escalateRationale,
          });
          return {
            action: 'escalate',
            confidence,
            rationale: escalateRationale,
            newStrategy,
            recommendations,
          };
        }
      }

      recommendations.push(`Current strategy '${state.currentStrategy}' showing diminishing returns`);
      recommendations.push(`Recommended pivot to '${newStrategy}'`);

      this.emit('meta:plateau', { huntId, gainRate, strategy: state.currentStrategy });
      this.emit('meta:pivot', { huntId, from: state.currentStrategy, to: newStrategy, reason: 'diminishing_returns' });

      state.currentStrategy = newStrategy;
      state.strategyHistory.push(newStrategy);
      state.pivotCount++;

      this.recordTransitionAttempt(state.strategyHistory[state.strategyHistory.length - 2], newStrategy);

      const pivotDecision: StrategyDecision = {
        action: 'pivot',
        confidence,
        rationale: `Information gain rate dropped to ${(gainRate * 100).toFixed(1)}% (below ${PLATEAU_THRESHOLD * 100}% threshold). Pivoting from '${state.strategyHistory[state.strategyHistory.length - 2]}' to '${newStrategy}'.`,
        newStrategy,
        recommendations,
      };
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_pivot',
        sourceSystem: 'meta-reasoner',
        data: { action: 'pivot', fromStrategy: state.strategyHistory[state.strategyHistory.length - 2], toStrategy: newStrategy, gainRate },
        confidenceAtEvent: confidence,
        reasoning: pivotDecision.rationale,
      });
      return pivotDecision;
    }

    if (confidence > 0.8 && gainRate > 0.3) {
      recommendations.push('Strong evidence supports current hypothesis');
      recommendations.push('Continue current strategy and deepen exploitation');
      const continueDecision: StrategyDecision = {
        action: 'continue',
        confidence,
        rationale: `High confidence (${(confidence * 100).toFixed(1)}%) with healthy gain rate (${(gainRate * 100).toFixed(1)}%). Current strategy '${state.currentStrategy}' is productive.`,
        recommendations,
      };
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_evaluation',
        sourceSystem: 'meta-reasoner',
        data: { action: 'continue', strategy: state.currentStrategy, gainRate, confidence },
        confidenceAtEvent: confidence,
        reasoning: continueDecision.rationale,
      });
      return continueDecision;
    }

    if (counterfactuals.missing.length > 0) {
      recommendations.push(`${counterfactuals.missing.length} expected findings still missing`);
    }
    if (counterfactuals.actuallyFound.length > 0) {
      recommendations.push(`${counterfactuals.actuallyFound.length} findings align with expectations`);
    }
    recommendations.push(`Current gain rate: ${(gainRate * 100).toFixed(1)}%`);

    const finalDecision: StrategyDecision = {
      action: 'continue',
      confidence,
      rationale: `Strategy '${state.currentStrategy}' performing within acceptable range. Confidence: ${(confidence * 100).toFixed(1)}%, Gain rate: ${(gainRate * 100).toFixed(1)}%.`,
      recommendations,
    };
    decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'meta_evaluation',
      sourceSystem: 'meta-reasoner',
      data: { action: 'continue', strategy: state.currentStrategy, gainRate, confidence },
      confidenceAtEvent: confidence,
      reasoning: finalDecision.rationale,
    });
    return finalDecision;
  }

  async evaluateEnriched(huntId: string): Promise<StrategyDecision> {
    const state = this.huntStates.get(huntId);
    if (!state) {
      return {
        action: 'abort',
        confidence: 0,
        rationale: 'No hunt state found for this hunt ID',
        recommendations: ['Initialize hunt state before evaluation'],
      };
    }

    // Resolve THIS hunt's own provenance-scoped weights fresh, every call —
    // not just at hunt completion (see getBestTransition's docstring above).
    // Also refresh the shared this.learnedWeights fallback so evaluate()'s
    // synchronous path (no async DB read available there) benefits on its
    // next call for this same hunt, rather than only after completeHunt().
    const huntProvenance = await resolveProvenanceFromHuntId(huntId);
    const huntWeights = await strategyWeightLearner.loadWeights(huntProvenance);
    this.learnedWeights = huntWeights;

    const health = huntCortex.computeHuntHealth(huntId);
    const hunt = huntOrchestrator.getHunt(huntId);
    const targetType = hunt?.goal || 'General';
    const thresholds = await adaptiveThresholdTuner.getThresholds(targetType);
    const recommendations: string[] = [];

    if (health.degraded_verifications > thresholds.maxDegraded) {
      const decision: StrategyDecision = {
        action: 'stabilize',
        confidence: state.hypothesisConfidence,
        rationale: `${health.degraded_verifications} verifications degrading (threshold: ${thresholds.maxDegraded}). Re-verify foundation before advancing.`,
        recommendations: ['Batch re-verification of degraded findings', 'Pause exploitation until foundation stabilizes'],
        subAction: 'batch_reverify',
      };
      await this.logDecision(huntId, state, decision, health);
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_evaluation',
        sourceSystem: 'meta-reasoner',
        data: { action: 'stabilize', health, subAction: 'batch_reverify' },
        confidenceAtEvent: state.hypothesisConfidence,
        reasoning: decision.rationale,
      });
      huntCortex.broadcast({
        signalType: SignalType.PIVOT_EXECUTED,
        sourceSystem: 'meta-reasoner',
        huntId,
        payload: { action: 'stabilize', rationale: decision.rationale },
        confidence: state.hypothesisConfidence,
      });
      return decision;
    }

    if (health.missed_events > thresholds.maxMissedEvents) {
      const decision: StrategyDecision = {
        action: 'accelerate',
        confidence: state.hypothesisConfidence,
        rationale: `Target is volatile — ${health.missed_events} events expired before processing (threshold: ${thresholds.maxMissedEvents}).`,
        recommendations: ['Reduce agent task depth', 'Focus on time-sensitive findings', 'Increase scan parallelism'],
        subAction: 'reduce_task_depth',
      };
      await this.logDecision(huntId, state, decision, health);
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_evaluation',
        sourceSystem: 'meta-reasoner',
        data: { action: 'accelerate', missedEvents: health.missed_events },
        confidenceAtEvent: state.hypothesisConfidence,
        reasoning: decision.rationale,
      });
      return decision;
    }

    if (health.avg_novelty_score < thresholds.noveltyFloor && state.cycleCount > 5) {
      const similarPast = await decisionJournal.findSimilar(
        health,
        { complexityScore: 0.5, volatilityScore: health.missed_events / 5, attackSurfaceBreadth: 0.5 }
      );

      const plan = backwardPlanner.getPlan(huntId);
      let plannerPivot: string | null = null;
      if (plan) {
        const pivots = backwardPlanner.suggestPivot(huntId, `${state.currentStrategy}_exhausted`);
        if (pivots && pivots.length > 0) {
          plannerPivot = pivots[0].strategy;
          recommendations.push(`Backward planner suggests: ${pivots[0].strategy} (${pivots[0].reason}, weight: ${pivots[0].weight})`);
        }
      }

      let newStrategy: string;
      let confidenceBoost = 0;

      if (plannerPivot && STRATEGIES.includes(plannerPivot as any)) {
        newStrategy = plannerPivot;
        recommendations.push('Strategy selected by backward planner (goal-first)');
      } else if (similarPast && similarPast.outcomeScore && similarPast.outcomeScore > 0.7 && similarPast.strategyAfter) {
        newStrategy = similarPast.strategyAfter;
        confidenceBoost = 0.2;
        recommendations.push(`Replaying successful pivot from past hunt (similarity match, outcome: ${(similarPast.outcomeScore * 100).toFixed(0)}%)`);
      } else {
        const context = this.buildHuntContext(huntId, state);
        newStrategy = this.getBestTransition(state.currentStrategy, context, huntWeights);
      }

      this.emit('meta:pivot', { huntId, from: state.currentStrategy, to: newStrategy, reason: 'novelty_exhausted' });

      state.currentStrategy = newStrategy;
      state.strategyHistory.push(newStrategy);
      state.pivotCount++;

      const decision: StrategyDecision = {
        action: 'pivot',
        confidence: Math.min(0.99, state.hypothesisConfidence + confidenceBoost),
        rationale: `Tool novelty exhausted (avg: ${(health.avg_novelty_score * 100).toFixed(1)}%, floor: ${(thresholds.noveltyFloor * 100).toFixed(1)}%). Pivoting to '${newStrategy}'.`,
        newStrategy,
        recommendations,
      };
      await this.logDecision(huntId, state, decision, health);
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_pivot',
        sourceSystem: 'meta-reasoner',
        data: { action: 'pivot', reason: 'novelty_exhausted', fromStrategy: state.strategyHistory[state.strategyHistory.length - 2], toStrategy: newStrategy, noveltyScore: health.avg_novelty_score },
        confidenceAtEvent: Math.min(0.99, state.hypothesisConfidence + confidenceBoost),
        reasoning: decision.rationale,
      });
      return decision;
    }

    if (health.health < thresholds.healthFloor) {
      const context = this.buildHuntContext(huntId, state);
      const newStrategy = this.getBestTransition(state.currentStrategy, context, huntWeights);

      this.emit('meta:pivot', { huntId, from: state.currentStrategy, to: newStrategy, reason: 'health_critical' });

      state.currentStrategy = newStrategy;
      state.strategyHistory.push(newStrategy);
      state.pivotCount++;

      const decision: StrategyDecision = {
        action: 'pivot',
        confidence: state.hypothesisConfidence,
        rationale: `Composite hunt health critical (${(health.health * 100).toFixed(1)}%, floor: ${(thresholds.healthFloor * 100).toFixed(1)}%). Multiple subsystems reporting issues. Full strategy pivot.`,
        newStrategy,
        recommendations: ['Hunt health degraded across multiple dimensions', `Neg evidence: ${health.negative_evidence_count}, Degraded: ${health.degraded_verifications}, Missed: ${health.missed_events}`],
      };
      await this.logDecision(huntId, state, decision, health);
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'meta_pivot',
        sourceSystem: 'meta-reasoner',
        data: { action: 'pivot', reason: 'health_critical', health: health.health, toStrategy: newStrategy },
        confidenceAtEvent: state.hypothesisConfidence,
        reasoning: decision.rationale,
      });
      return decision;
    }

    const decision: StrategyDecision = {
      action: 'continue',
      confidence: state.hypothesisConfidence,
      rationale: `Hunt healthy (${(health.health * 100).toFixed(1)}%). Novelty: ${(health.avg_novelty_score * 100).toFixed(1)}%. Strategy '${state.currentStrategy}' performing within acceptable range.`,
      recommendations: [`Health: ${(health.health * 100).toFixed(0)}%`, `Signals: ${health.signal_count}`],
    };
    await this.logDecision(huntId, state, decision, health);
    decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'meta_evaluation',
      sourceSystem: 'meta-reasoner',
      data: { action: 'continue', health: health.health, novelty: health.avg_novelty_score, strategy: state.currentStrategy },
      confidenceAtEvent: state.hypothesisConfidence,
      reasoning: decision.rationale,
    });
    return decision;
  }

  private async logDecision(huntId: string, state: HuntState, decision: StrategyDecision, health: Record<string, any>): Promise<void> {
    try {
      const profile = { complexityScore: 0.5, volatilityScore: 0.5, attackSurfaceBreadth: 0.5 };
      await decisionJournal.log({
        huntId,
        strategyBefore: state.strategyHistory.length > 1 ? state.strategyHistory[state.strategyHistory.length - 2] : state.currentStrategy,
        strategyAfter: decision.newStrategy || null,
        action: decision.action,
        rationale: decision.rationale,
        healthSnapshot: health,
        contextVector: decisionJournal.contextToVector(health, profile),
        findingsCount: this.getCurrentFindingsCount(huntId),
        cycleNumber: state.cycleCount,
        outcomeScore: null,
      });
    } catch (_err) {}
  }

  private getCurrentFindingsCount(huntId: string): number {
    // Engine-driven hunts push their authoritative count directly — prefer it.
    const state = this.huntStates.get(huntId);
    if (state?.externalFindingsCount !== undefined) return state.externalFindingsCount;

    let count = 0;
    const memory = missionMemory.get(huntId);
    if (memory) {
      count += memory.vulnerabilities.length;
      count += memory.endpoints.length;
      count += memory.technologies.length;
    }
    const reasoningMemory = reasoningEngine.getMissionMemory(huntId);
    if (reasoningMemory) {
      count += reasoningMemory.discoveredVulnerabilities.size;
      count += reasoningMemory.discoveredEndpoints.size;
      count += reasoningMemory.discoveredTechnologies.size;
    }
    return count;
  }

  /**
   * Push live hunt progress from an engine-driven hunt so the decision journal
   * and health computations carry real signal. Safe no-op if the hunt state was
   * never initialized.
   */
  syncHuntProgress(huntId: string, update: { findingsCount?: number; confidence?: number; strategy?: string }): void {
    const state = this.huntStates.get(huntId);
    if (!state) return;
    state.cycleCount++;
    if (update.findingsCount !== undefined) {
      state.externalFindingsCount = update.findingsCount;
      state.findingsTimeline.push({ cycle: state.cycleCount, count: update.findingsCount });
    }
    if (update.confidence !== undefined) state.hypothesisConfidence = update.confidence;
    if (update.strategy && update.strategy !== state.currentStrategy) {
      state.strategyHistory.push(update.strategy);
      state.currentStrategy = update.strategy;
    }
  }

  private buildHuntContext(huntId: string, state: HuntState): HuntContext {
    const hunt = huntOrchestrator.getHunt(huntId);
    const memory = missionMemory.get(huntId);

    return {
      phase: hunt?.phase || 'recon',
      findingsCount: hunt?.findings.length || 0,
      endpointCount: memory?.endpoints.length || 0,
      techCount: memory?.technologies.length || 0,
      vulnCount: memory?.vulnerabilities.length || 0,
      cycleCount: state.cycleCount,
      elapsedTime: Date.now() - state.startedAt,
      goal: hunt?.goal || '',
    };
  }

  private recordTransitionAttempt(from: string, to: string): void {
    const key = `${from}->${to}`;
    const record = this.transitionSuccessHistory.get(key) || { successes: 0, attempts: 0 };
    record.attempts++;
    this.transitionSuccessHistory.set(key, record);
  }

  recordTransitionSuccess(from: string, to: string): void {
    const key = `${from}->${to}`;
    const record = this.transitionSuccessHistory.get(key) || { successes: 0, attempts: 0 };
    record.successes++;
    this.transitionSuccessHistory.set(key, record);
  }

  initializeHuntState(huntId: string, initialStrategy?: string): HuntState {
    const hunt = huntOrchestrator.getHunt(huntId);
    const strategy = initialStrategy
      || GOAL_TO_INITIAL_STRATEGY[hunt?.goal || '']
      || 'port_scan';

    const state: HuntState = {
      huntId,
      currentStrategy: strategy,
      cycleCount: 0,
      hypothesisConfidence: 0.5,
      gainHistory: [],
      strategyHistory: [strategy],
      findingsTimeline: [],
      pivotCount: 0,
      startedAt: Date.now(),
    };

    this.huntStates.set(huntId, state);
    try {
      const hunt = huntOrchestrator.getHunt(huntId);
      if (hunt?.goal) {
        backwardPlanner.planHunt(huntId, hunt.goal);
      }
    } catch (_e) {}
    decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'hunt_start',
      sourceSystem: 'meta-reasoner',
      data: { initialStrategy: strategy, goal: hunt?.goal || '' },
      confidenceAtEvent: 0.5,
      reasoning: `Hunt initialized with strategy '${strategy}'`,
    });
    return state;
  }

  getHuntState(huntId: string): HuntState | undefined {
    return this.huntStates.get(huntId);
  }

  startMonitoring(huntId: string): void {
    if (this.monitors.has(huntId)) {
      return;
    }

    if (!this.huntStates.has(huntId)) {
      this.initializeHuntState(huntId);
    }

    const timer = setInterval(() => {
      const hunt = huntOrchestrator.getHunt(huntId);
      if (!hunt || hunt.status !== 'active') {
        this.stopMonitoring(huntId);
        return;
      }

      const basicDecision = this.evaluate(huntId);
      
      this.evaluateEnriched(huntId).then(enrichedDecision => {
        const decision = enrichedDecision.action !== 'continue' ? enrichedDecision : basicDecision;
        
        eventBus.publish(
          'meta:evaluation',
          'meta-reasoner',
          huntId,
          { decision, state: this.huntStates.get(huntId), enriched: enrichedDecision },
          ['cognitive']
        );

        if (decision.action === 'pivot' && decision.newStrategy) {
          eventBus.publish(
            'meta:pivot',
            'meta-reasoner',
            huntId,
            { newStrategy: decision.newStrategy, rationale: decision.rationale },
            ['cognitive', 'scanner', 'exploit']
          );
        }

        if (decision.action === 'abort') {
          eventBus.publish(
            'meta:abort',
            'meta-reasoner',
            huntId,
            { rationale: decision.rationale },
            ['cognitive']
          );
          this.stopMonitoring(huntId);
        }

        if (decision.action === 'stabilize') {
          eventBus.publish(
            'meta:stabilize',
            'meta-reasoner',
            huntId,
            { rationale: decision.rationale, subAction: decision.subAction },
            ['cognitive']
          );
        }

        if (decision.action === 'accelerate') {
          eventBus.publish(
            'meta:accelerate',
            'meta-reasoner',
            huntId,
            { rationale: decision.rationale, subAction: decision.subAction },
            ['cognitive']
          );
        }

        if ((global as any).io) {
          (global as any).io.emit('meta:decision', { huntId, decision });
        }
      }).catch(() => {
        eventBus.publish(
          'meta:evaluation',
          'meta-reasoner',
          huntId,
          { decision: basicDecision, state: this.huntStates.get(huntId) },
          ['cognitive']
        );

        if (basicDecision.action === 'pivot' && basicDecision.newStrategy) {
          eventBus.publish(
            'meta:pivot',
            'meta-reasoner',
            huntId,
            { newStrategy: basicDecision.newStrategy, rationale: basicDecision.rationale },
            ['cognitive', 'scanner', 'exploit']
          );
        }

        if (basicDecision.action === 'abort') {
          eventBus.publish(
            'meta:abort',
            'meta-reasoner',
            huntId,
            { rationale: basicDecision.rationale },
            ['cognitive']
          );
          this.stopMonitoring(huntId);
        }

        if ((global as any).io) {
          (global as any).io.emit('meta:decision', { huntId, decision: basicDecision });
        }
      });
    }, MONITOR_INTERVAL_MS);

    this.monitors.set(huntId, timer);
  }

  stopMonitoring(huntId: string): void {
    const timer = this.monitors.get(huntId);
    if (timer) {
      clearInterval(timer);
      this.monitors.delete(huntId);
    }
  }

  stopAllMonitoring(): void {
    Array.from(this.monitors.entries()).forEach(([_, timer]) => {
      clearInterval(timer);
    });
    this.monitors.clear();
  }

  async completeHunt(huntId: string, finalScore: number): Promise<void> {
    await decisionJournal.backfillOutcomes(huntId, finalScore);

    const hunt = huntOrchestrator.getHunt(huntId);
    const targetType = hunt?.goal || 'General';
    await adaptiveThresholdTuner.learnFromHunt(huntId, targetType, finalScore);

    // Recompute strategy weights from the now-scored journal entries and refresh in-memory map
    await strategyWeightLearner.learn();
    const provenance = await resolveProvenanceFromHuntId(huntId);
    this.learnedWeights = await strategyWeightLearner.loadWeights(provenance);
    
    huntCortex.broadcast({
      signalType: SignalType.FINDING_CONFIRMED,
      sourceSystem: 'meta-reasoner',
      huntId,
      payload: { finalScore, action: 'hunt_completed' },
      confidence: finalScore,
    });
    
    decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'hunt_complete',
      sourceSystem: 'meta-reasoner',
      data: { finalScore, state: this.huntStates.get(huntId) },
      confidenceAtEvent: finalScore,
      reasoning: `Hunt completed with score ${(finalScore * 100).toFixed(1)}%`,
    });
    this.stopMonitoring(huntId);
    // Free per-hunt state so the map doesn't grow unbounded across hunts.
    this.huntStates.delete(huntId);
  }

  getStats(): {
    activeMonitors: number;
    totalHuntStates: number;
    transitionHistory: number;
    huntSummaries: { huntId: string; strategy: string; cycles: number; confidence: number; pivots: number }[];
  } {
    const huntSummaries = Array.from(this.huntStates.values()).map(s => ({
      huntId: s.huntId,
      strategy: s.currentStrategy,
      cycles: s.cycleCount,
      confidence: s.hypothesisConfidence,
      pivots: s.pivotCount,
    }));

    return {
      activeMonitors: this.monitors.size,
      totalHuntStates: this.huntStates.size,
      transitionHistory: this.transitionSuccessHistory.size,
      huntSummaries,
    };
  }
}

export const metaReasoner = new MetaReasoner();

// Eagerly load persisted strategy weights so the first hunt benefits from past learning
metaReasoner.loadLearnedWeights().catch(() => {});

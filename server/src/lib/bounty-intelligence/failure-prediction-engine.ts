import fs from 'fs/promises';
import path from 'path';
import {
  PredictionFeatureVector,
  PredictionNode,
  ConditionalBranch,
  StrategyRecommendation,
  PredictionTrainingPoint,
} from './intelligence-types';

export interface ModelStats {
  totalTrainingPoints: number;
  techniqueBreakdown: Record<string, { total: number; successes: number; rate: number }>;
  predictionAccuracy: number;
  lastUpdated: string;
  clusterCount: number;
  confidenceLevel: number;
}

interface BaseRates {
  [cluster: string]: Record<string, number>;
}

interface ConditionalProbs {
  [technique: string]: Record<string, number>;
}

interface ModelAccuracy {
  predictions: number;
  correct: number;
  history: Array<{ timestamp: string; accuracy: number; sampleSize: number }>;
}

const HEURISTIC_BASELINES: Record<string, { base: number; conditions: Record<string, number> }> = {
  sqli: { base: 0.15, conditions: { 'no-waf': 0.35, 'verbose-errors': 0.40 } },
  xss: { base: 0.20, conditions: { 'no-waf': 0.45, 'no-csp': 0.50 } },
  ssrf: { base: 0.08, conditions: { 'file-upload': 0.35, 'cloud-hosted': 0.25 } },
  idor: { base: 0.25, conditions: { 'rest-api': 0.35, 'graphql': 0.40 } },
  'auth-bypass': { base: 0.10, conditions: { 'jwt': 0.20, 'oauth': 0.15 } },
  rce: { base: 0.03, conditions: { 'verbose-errors': 0.08, 'file-upload': 0.12 } },
  'path-traversal': { base: 0.12, conditions: { 'file-upload': 0.30, 'verbose-errors': 0.25 } },
  'open-redirect': { base: 0.18, conditions: { 'oauth': 0.35 } },
  ssti: { base: 0.06, conditions: { 'python-framework': 0.15 } },
  xxe: { base: 0.05, conditions: { 'soap-api': 0.25, 'xml-content-type': 0.30 } },
};

const CONDITIONAL_TREE_RULES: Array<{
  condition: string;
  detectFn: (fv: PredictionFeatureVector) => boolean;
  affectedTechniques: Record<string, number>;
  suggestedAction: string;
}> = [
  {
    condition: 'If file upload found',
    detectFn: (fv) => fv.campaignState.techniquesAttempted.some(t => t.includes('upload')) || fv.techStack.framework?.toLowerCase().includes('upload') || false,
    affectedTechniques: { ssrf: 0.35, 'path-traversal': 0.30, rce: 0.12 },
    suggestedAction: 'Test file upload for SSRF via URL fetch, path traversal via filename, RCE via file content',
  },
  {
    condition: 'If GraphQL introspection enabled',
    detectFn: (fv) => fv.defenseProfile.apiStyle === 'graphql',
    affectedTechniques: { idor: 0.40, sqli: 0.25 },
    suggestedAction: 'Enumerate GraphQL schema for IDOR via object references and injection via query parameters',
  },
  {
    condition: 'If verbose errors',
    detectFn: (fv) => fv.defenseProfile.errorVerbosity === 'verbose',
    affectedTechniques: { sqli: 0.40, 'path-traversal': 0.25, rce: 0.08 },
    suggestedAction: 'Leverage verbose error messages for SQL injection fingerprinting and path disclosure',
  },
  {
    condition: 'If no WAF',
    detectFn: (fv) => !fv.defenseProfile.wafType || fv.defenseProfile.wafStrictness === 'permissive',
    affectedTechniques: { xss: 0.45, sqli: 0.35 },
    suggestedAction: 'Direct payload injection without encoding bypass needed',
  },
  {
    condition: 'If JWT auth',
    detectFn: (fv) => fv.defenseProfile.authMechanisms.some(m => m.toLowerCase().includes('jwt')),
    affectedTechniques: { 'auth-bypass': 0.20, 'token-manipulation': 0.25 },
    suggestedAction: 'Test JWT algorithm confusion, none algorithm, key brute force, and claim manipulation',
  },
];

const DEFAULT_TECHNIQUES = ['sqli', 'xss', 'ssrf', 'idor', 'auth-bypass', 'rce', 'path-traversal', 'open-redirect', 'ssti', 'xxe'];

const TECHNIQUE_TIME_ESTIMATES: Record<string, number> = {
  sqli: 45, xss: 30, ssrf: 60, idor: 40, 'auth-bypass': 90,
  rce: 120, 'path-traversal': 35, 'open-redirect': 20, ssti: 50, xxe: 55,
  'token-manipulation': 60,
};

const TECHNIQUE_SEVERITY: Record<string, string> = {
  sqli: 'high', xss: 'medium', ssrf: 'high', idor: 'high', 'auth-bypass': 'critical',
  rce: 'critical', 'path-traversal': 'medium', 'open-redirect': 'low', ssti: 'high', xxe: 'high',
  'token-manipulation': 'high',
};

const TECHNIQUE_DEFAULT_PAYOUT: Record<string, number> = {
  sqli: 2000, xss: 500, ssrf: 3000, idor: 1500, 'auth-bypass': 5000,
  rce: 10000, 'path-traversal': 800, 'open-redirect': 200, ssti: 3000, xxe: 2500,
  'token-manipulation': 4000,
};

const HOURLY_OPPORTUNITY_COST = 50;

export class FailurePredictionEngine {
  private storageDir: string;
  private trainingData: PredictionTrainingPoint[];
  private baseRates: BaseRates;
  private conditionalProbs: ConditionalProbs;
  private modelAccuracy: ModelAccuracy;
  private payoutEstimator: ((technique: string, programId?: string) => Promise<number>) | null;
  private duplicateEstimator: ((technique: string, targetArea: string, programId?: string) => Promise<number>) | null;

  constructor(storageDir: string) {
    this.storageDir = path.join(storageDir, 'predictions');
    this.trainingData = [];
    this.baseRates = {};
    this.conditionalProbs = {};
    this.modelAccuracy = { predictions: 0, correct: 0, history: [] };
    this.payoutEstimator = null;
    this.duplicateEstimator = null;
    this.loadAll().catch(() => {});
  }

  private async ensureDir(): Promise<void> {
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
    await this.ensureDir();
    const filePath = path.join(this.storageDir, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  private async loadAll(): Promise<void> {
    await this.ensureDir();
    this.trainingData = await this.loadJson<PredictionTrainingPoint[]>('training-data.json', []);
    this.baseRates = await this.loadJson<BaseRates>('base-rates.json', {});
    this.conditionalProbs = await this.loadJson<ConditionalProbs>('conditional-probs.json', {});
    this.modelAccuracy = await this.loadJson<ModelAccuracy>('model-accuracy.json', { predictions: 0, correct: 0, history: [] });
  }

  private extractFeatures(fv: PredictionFeatureVector): string[] {
    const features: string[] = [];
    if (!fv.defenseProfile.wafType || fv.defenseProfile.wafStrictness === 'permissive') features.push('no-waf');
    if (fv.defenseProfile.errorVerbosity === 'verbose') features.push('verbose-errors');
    if (!fv.defenseProfile.cspPolicy.present || fv.defenseProfile.cspPolicy.strictness === 'none') features.push('no-csp');
    if (fv.defenseProfile.apiStyle === 'rest') features.push('rest-api');
    if (fv.defenseProfile.apiStyle === 'graphql') features.push('graphql');
    if (fv.defenseProfile.apiStyle === 'soap') features.push('soap-api');
    if (fv.defenseProfile.authMechanisms.some(m => m.toLowerCase().includes('jwt'))) features.push('jwt');
    if (fv.defenseProfile.authMechanisms.some(m => m.toLowerCase().includes('oauth'))) features.push('oauth');
    if (fv.techStack.framework?.toLowerCase().includes('django') || fv.techStack.framework?.toLowerCase().includes('flask') || fv.techStack.language?.toLowerCase() === 'python') features.push('python-framework');
    if (fv.techStack.cdn) features.push('cloud-hosted');
    return features;
  }

  private clusterKey(fv: PredictionFeatureVector): string {
    const parts = [
      fv.defenseProfile.wafStrictness,
      fv.defenseProfile.apiStyle,
      fv.defenseProfile.errorVerbosity,
      fv.industry || 'unknown',
    ];
    return parts.join(':');
  }

  private getBaseProbability(technique: string, fv: PredictionFeatureVector): number {
    const cluster = this.clusterKey(fv);
    const clusterRates = this.baseRates[cluster];
    if (clusterRates && clusterRates[technique] !== undefined) {
      return clusterRates[technique];
    }

    const matchingPoints = this.trainingData.filter(p => p.technique === technique);
    if (matchingPoints.length >= 10) {
      const successes = matchingPoints.filter(p => p.actualOutcome === 'success' || p.actualOutcome === 'partial').length;
      return successes / matchingPoints.length;
    }

    const heuristic = HEURISTIC_BASELINES[technique];
    if (heuristic) {
      const features = this.extractFeatures(fv);
      let maxProb = heuristic.base;
      for (const feat of features) {
        if (heuristic.conditions[feat] !== undefined && heuristic.conditions[feat] > maxProb) {
          maxProb = heuristic.conditions[feat];
        }
      }
      return maxProb;
    }

    return 0.10;
  }

  private buildConditionalBranches(technique: string, baseProbability: number, fv: PredictionFeatureVector): ConditionalBranch[] {
    const branches: ConditionalBranch[] = [];
    const features = this.extractFeatures(fv);

    for (const rule of CONDITIONAL_TREE_RULES) {
      if (rule.affectedTechniques[technique] === undefined) continue;

      const conditionMet = rule.detectFn(fv);
      const conditionProb = conditionMet ? 0.9 : this.estimateConditionProbability(rule.condition, fv);
      const updatedProb = rule.affectedTechniques[technique];
      const payout = TECHNIQUE_DEFAULT_PAYOUT[technique] || 1000;
      const time = TECHNIQUE_TIME_ESTIMATES[technique] || 60;
      const updatedEv = updatedProb * payout - (time / 60) * HOURLY_OPPORTUNITY_COST;

      branches.push({
        condition: rule.condition,
        conditionProbability: conditionProb,
        updatedProbability: updatedProb,
        updatedEvScore: updatedEv,
        suggestedAction: rule.suggestedAction,
      });
    }

    const heuristic = HEURISTIC_BASELINES[technique];
    if (heuristic) {
      for (const [condKey, condProb] of Object.entries(heuristic.conditions)) {
        const alreadyCovered = branches.some(b => b.updatedProbability === condProb);
        if (alreadyCovered) continue;
        if (features.includes(condKey)) continue;

        const payout = TECHNIQUE_DEFAULT_PAYOUT[technique] || 1000;
        const time = TECHNIQUE_TIME_ESTIMATES[technique] || 60;
        const updatedEv = condProb * payout - (time / 60) * HOURLY_OPPORTUNITY_COST;

        branches.push({
          condition: `If ${condKey.replace(/-/g, ' ')}`,
          conditionProbability: 0.3,
          updatedProbability: condProb,
          updatedEvScore: updatedEv,
          suggestedAction: `Investigate ${condKey.replace(/-/g, ' ')} condition for ${technique}`,
        });
      }
    }

    return branches;
  }

  private estimateConditionProbability(condition: string, fv: PredictionFeatureVector): number {
    if (condition.includes('file upload')) return 0.3;
    if (condition.includes('GraphQL')) return fv.defenseProfile.apiStyle === 'graphql' ? 0.9 : 0.1;
    if (condition.includes('verbose')) return fv.defenseProfile.errorVerbosity === 'verbose' ? 0.9 : 0.2;
    if (condition.includes('no WAF')) return !fv.defenseProfile.wafType ? 0.7 : 0.2;
    if (condition.includes('JWT')) return fv.defenseProfile.authMechanisms.some(m => m.toLowerCase().includes('jwt')) ? 0.9 : 0.15;
    return 0.3;
  }

  private async getExpectedPayout(technique: string, programId?: string): Promise<number> {
    if (this.payoutEstimator) {
      try {
        return await this.payoutEstimator(technique, programId);
      } catch {
        return TECHNIQUE_DEFAULT_PAYOUT[technique] || 1000;
      }
    }
    return TECHNIQUE_DEFAULT_PAYOUT[technique] || 1000;
  }

  private async getDuplicateProbability(technique: string, targetArea: string, programId?: string): Promise<number> {
    if (this.duplicateEstimator) {
      try {
        return await this.duplicateEstimator(technique, targetArea, programId);
      } catch {
        return 0.1;
      }
    }
    return 0.1;
  }

  private async buildPredictionNode(technique: string, fv: PredictionFeatureVector): Promise<PredictionNode> {
    const baseProbability = this.getBaseProbability(technique, fv);
    const conditionalBranches = this.buildConditionalBranches(technique, baseProbability, fv);
    const expectedTimeMinutes = TECHNIQUE_TIME_ESTIMATES[technique] || 60;
    const expectedPayout = await this.getExpectedPayout(technique);
    const duplicateProb = await this.getDuplicateProbability(technique, fv.industry);
    const timeCostHours = expectedTimeMinutes / 60;
    const evScore = baseProbability * (1 - duplicateProb) * expectedPayout - timeCostHours * HOURLY_OPPORTUNITY_COST;

    return {
      technique,
      baseProbability,
      conditionalBranches,
      expectedTimeMinutes,
      expectedSeverity: TECHNIQUE_SEVERITY[technique] || 'medium',
      expectedPayout,
      evScore,
    };
  }

  async predict(featureVector: PredictionFeatureVector, availableTechniques?: string[]): Promise<StrategyRecommendation> {
    const techniques = availableTechniques || DEFAULT_TECHNIQUES;
    const blocked = new Set(featureVector.campaignState.blockedTechniques);
    const activeTechniques = techniques.filter(t => !blocked.has(t));

    const nodes: PredictionNode[] = await Promise.all(
      activeTechniques.map(t => this.buildPredictionNode(t, featureVector))
    );

    nodes.sort((a, b) => b.evScore - a.evScore);

    const optimalPath = nodes
      .filter(n => n.evScore > 0)
      .slice(0, 5)
      .map(n => n.technique);

    const totalExpectedValue = nodes
      .filter(n => n.evScore > 0)
      .reduce((sum, n) => sum + n.evScore, 0);

    const dataPoints = this.trainingData.filter(p =>
      activeTechniques.includes(p.technique)
    ).length;
    const confidence = Math.min(0.95, 0.3 + (dataPoints / 100) * 0.65);

    const topTechnique = nodes[0];
    const reasoning = topTechnique
      ? `${topTechnique.technique} has highest EV of $${topTechnique.evScore.toFixed(2)} with ${(topTechnique.baseProbability * 100).toFixed(1)}% success probability. ` +
        `${nodes.filter(n => n.evScore > 0).length} techniques have positive EV. ` +
        `Based on ${dataPoints} historical data points.`
      : 'No techniques with positive expected value found.';

    return {
      rankedStrategies: nodes,
      optimalPath,
      totalExpectedValue,
      confidence,
      reasoning,
    };
  }

  async recordOutcome(point: PredictionTrainingPoint): Promise<void> {
    this.trainingData.push(point);

    const cluster = this.clusterKey(point.featureVector);
    if (!this.baseRates[cluster]) {
      this.baseRates[cluster] = {};
    }

    const technique = point.technique;
    const clusterPoints = this.trainingData.filter(
      p => p.technique === technique && this.clusterKey(p.featureVector) === cluster
    );

    const successes = clusterPoints.filter(
      p => p.actualOutcome === 'success' || p.actualOutcome === 'partial'
    ).length;

    const priorAlpha = 1;
    const priorBeta = 1;
    const posteriorAlpha = priorAlpha + successes;
    const posteriorBeta = priorBeta + (clusterPoints.length - successes);
    this.baseRates[cluster][technique] = posteriorAlpha / (posteriorAlpha + posteriorBeta);

    if (!this.conditionalProbs[technique]) {
      this.conditionalProbs[technique] = {};
    }

    const features = this.extractFeatures(point.featureVector);
    for (const feat of features) {
      const featPoints = this.trainingData.filter(
        p => p.technique === technique && this.extractFeatures(p.featureVector).includes(feat)
      );
      const featSuccesses = featPoints.filter(
        p => p.actualOutcome === 'success' || p.actualOutcome === 'partial'
      ).length;
      if (featPoints.length > 0) {
        this.conditionalProbs[technique][feat] = featSuccesses / featPoints.length;
      }
    }

    const isSuccess = point.actualOutcome === 'success' || point.actualOutcome === 'partial';
    const predicted = point.predictedProbability >= 0.5;
    this.modelAccuracy.predictions++;
    if ((isSuccess && predicted) || (!isSuccess && !predicted)) {
      this.modelAccuracy.correct++;
    }
    this.modelAccuracy.history.push({
      timestamp: new Date().toISOString(),
      accuracy: this.modelAccuracy.correct / this.modelAccuracy.predictions,
      sampleSize: this.modelAccuracy.predictions,
    });
    if (this.modelAccuracy.history.length > 1000) {
      this.modelAccuracy.history = this.modelAccuracy.history.slice(-1000);
    }

    await Promise.all([
      this.saveJson('training-data.json', this.trainingData),
      this.saveJson('base-rates.json', this.baseRates),
      this.saveJson('conditional-probs.json', this.conditionalProbs),
      this.saveJson('model-accuracy.json', this.modelAccuracy),
    ]);
  }

  async getDecisionTree(targetProfile: Record<string, any>): Promise<PredictionNode[]> {
    const fv: PredictionFeatureVector = {
      techStack: targetProfile.techStack || { language: null, framework: null, server: null, database: null, cdn: null, jsLibraries: [] },
      defenseProfile: targetProfile.defenseProfile || {
        wafType: null, wafStrictness: 'permissive',
        rateLimiting: { detected: false, threshold: null, resetWindow: null },
        errorVerbosity: 'standard',
        cspPolicy: { present: false, strictness: 'none', reportOnly: false },
        securityHeaders: { hsts: false, xFrameOptions: false, xContentType: false, referrerPolicy: null },
        cookieFlags: { httpOnly: false, secure: false, sameSite: null },
        authMechanisms: [],
        apiStyle: 'rest',
      },
      industry: targetProfile.industry || 'unknown',
      huntGoal: targetProfile.huntGoal || 'find-vulns',
      campaignState: targetProfile.campaignState || {
        tasksCompleted: 0, findingsSoFar: 0, timeElapsedMinutes: 0,
        techniquesAttempted: [], blockedTechniques: [],
      },
    };

    const nodes: PredictionNode[] = await Promise.all(
      DEFAULT_TECHNIQUES.map(t => this.buildPredictionNode(t, fv))
    );

    nodes.sort((a, b) => b.evScore - a.evScore);
    return nodes;
  }

  async getModelStats(): Promise<ModelStats> {
    const techniqueBreakdown: Record<string, { total: number; successes: number; rate: number }> = {};

    for (const point of this.trainingData) {
      if (!techniqueBreakdown[point.technique]) {
        techniqueBreakdown[point.technique] = { total: 0, successes: 0, rate: 0 };
      }
      techniqueBreakdown[point.technique].total++;
      if (point.actualOutcome === 'success' || point.actualOutcome === 'partial') {
        techniqueBreakdown[point.technique].successes++;
      }
    }

    for (const key of Object.keys(techniqueBreakdown)) {
      const entry = techniqueBreakdown[key];
      entry.rate = entry.total > 0 ? entry.successes / entry.total : 0;
    }

    const predictionAccuracy = this.modelAccuracy.predictions > 0
      ? this.modelAccuracy.correct / this.modelAccuracy.predictions
      : 0;

    const clusterCount = Object.keys(this.baseRates).length;

    const confidenceLevel = Math.min(0.95, 0.3 + (this.trainingData.length / 200) * 0.65);

    return {
      totalTrainingPoints: this.trainingData.length,
      techniqueBreakdown,
      predictionAccuracy,
      lastUpdated: this.trainingData.length > 0
        ? this.trainingData[this.trainingData.length - 1].timestamp
        : new Date().toISOString(),
      clusterCount,
      confidenceLevel,
    };
  }

  setPayoutEstimator(fn: (technique: string, programId?: string) => Promise<number>): void {
    this.payoutEstimator = fn;
  }

  setDuplicateEstimator(fn: (technique: string, targetArea: string, programId?: string) => Promise<number>): void {
    this.duplicateEstimator = fn;
  }
}

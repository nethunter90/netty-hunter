import { Router } from 'express';
import { hunterEngine } from '../lib/hunter/hunter-engine';
import { huntStrategyBuilder } from '../lib/hunter/hunt-strategy';
import { agentCoordinationTracker } from '../lib/hunter/agent-coordination';
import { solverPool } from '../lib/hunter/solver-pool';
import { validationGate } from '../lib/hunter/validation-gate';
import { planMemoryStore } from '../lib/hunter/plan-memory';
import { nucleiTemplateGenerator } from '../lib/hunter/nuclei-template-generator';
import { reportGenerator } from '../lib/hunter/report-generator';
import { backwardHuntEngine } from '../lib/hunter/backward-hunt';
import { roiModel } from '../lib/hunter/roi-model';
import { targetSelectionEngine } from '../lib/hunter/target-selection';
import { staticAnalyzer } from '../lib/hunter/static-analysis';
import { exploitChainIntelligence } from '../lib/hunter/chain-intelligence';
import { reinforcementStore } from '../lib/hunter/reinforcement-store';
import { autonomyMaturityTracker } from '../lib/hunter/autonomy-maturity';
import type { HunterConfig } from '../lib/hunter/types';

const router = Router();

router.post('/sessions', async (req, res) => {
  try {
    const config: HunterConfig = {
      target: req.body.target,
      stealthMode: req.body.stealthMode || 'balanced',
      requestBudget: req.body.requestBudget || 2000,
      maxIterations: req.body.maxIterations || 100,
      enabledProbes: req.body.enabledProbes,
      huntId: req.body.huntId,
      huntGoal: req.body.huntGoal,
      scope: req.body.scope,
      intelligenceOverrides: req.body.intelligenceOverrides,
    };

    if (!config.target) {
      return res.status(400).json({ error: 'Target is required' });
    }

    const session = await hunterEngine.startSession(config);
    res.json({ session: hunterEngine.getSessionStats(session.id) });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/sessions', (_req, res) => {
  const sessions = hunterEngine.getAllSessions().map(s => hunterEngine.getSessionStats(s.id));
  res.json({ sessions });
});

router.get('/sessions/:id', (req, res) => {
  const id = req.params.id as string;
  const stats = hunterEngine.getSessionStats(id);
  if (!stats) return res.status(404).json({ error: 'Session not found' });
  res.json({ session: stats });
});

router.get('/sessions/:id/findings', (req, res) => {
  const id = req.params.id as string;
  const findings = hunterEngine.getSessionFindings(id);
  res.json({ findings });
});

router.get('/sessions/:id/hypotheses', (req, res) => {
  const id = req.params.id as string;
  const hypotheses = hunterEngine.getHypothesisQueue(id);
  res.json({ hypotheses });
});

router.get('/sessions/:id/target-model', (req, res) => {
  const id = req.params.id as string;
  const model = hunterEngine.serializeTargetModel(id);
  if (!model) return res.status(404).json({ error: 'Session not found' });
  res.json({ targetModel: model });
});

router.get('/sessions/:id/observability', (req, res) => {
  const id = req.params.id as string;
  const observability = hunterEngine.getLiveObservability(id);
  if (!observability) return res.status(404).json({ error: 'Session not found' });
  res.json({ observability });
});

router.get('/sessions/:id/coordination', (req, res) => {
  const id = req.params.id as string;
  const state = agentCoordinationTracker.getCoordinationState(id);
  if (!state) return res.status(404).json({ error: 'No coordination state found for this session' });
  res.json({ coordination: state });
});

router.get('/sessions/:id/coordination/decisions', (req, res) => {
  const id = req.params.id as string;
  const decisions = agentCoordinationTracker.getCoordinatorDecisionLog(id);
  res.json({ decisions });
});

router.post('/sessions/:id/coordination/simulate', (req, res) => {
  const id = req.params.id as string;
  const { eventType, data } = req.body;
  if (!eventType) {
    return res.status(400).json({ error: 'eventType is required' });
  }
  agentCoordinationTracker.simulateFromReasoningEvent(id, eventType, data);
  const state = agentCoordinationTracker.getCoordinationState(id);
  res.json({ success: true, coordination: state });
});

router.get('/sessions/:id/reasoning', (req, res) => {
  const id = req.params.id as string;
  const snapshot = hunterEngine.getReasoningSnapshot(id);
  res.json({ reasoning: snapshot });
});

router.get('/sessions/:id/reasoning/findings', (req, res) => {
  const id = req.params.id as string;
  const findings = hunterEngine.getReasoningFindings(id);
  res.json({ findings });
});

router.post('/sessions/:id/pause', (req, res) => {
  const id = req.params.id as string;
  const result = hunterEngine.pauseSession(id);
  res.json({ success: result });
});

router.post('/sessions/:id/resume', async (req, res) => {
  const id = req.params.id as string;
  const result = await hunterEngine.resumeSession(id);
  res.json({ success: result });
});

router.post('/sessions/:id/stop', (req, res) => {
  const id = req.params.id as string;
  const result = hunterEngine.stopSession(id);
  res.json({ success: result });
});

router.get('/sessions/:id/waf', (req, res) => {
  const id = req.params.id as string;
  const wafProfile = hunterEngine.getWAFProfile(id);
  const boundaryMaps = hunterEngine.getWAFBoundaryMaps(id);
  const calibration = hunterEngine.getCalibrationEvents(id);
  const ruleProfile = hunterEngine.getWAFRuleProfile(id);
  const behaviorModel = hunterEngine.getWAFBehaviorModel(id);
  res.json({ wafProfile, boundaryMaps, calibration, ruleProfile, behaviorModel });
});

router.post('/sessions/:id/waf/escalate', async (req, res) => {
  try {
    const id = req.params.id as string;
    const { endpoint, parameters, categories } = req.body;
    if (!endpoint || !parameters || !categories) {
      return res.status(400).json({ error: 'endpoint, parameters, and categories are required' });
    }
    const results = await hunterEngine.runWAFEscalation(id, endpoint, parameters, categories);
    res.json({
      boundaryMaps: results,
      bypasses: results.filter(r => r.effectiveBypass).length,
      totalMapped: results.length,
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/calibration/metrics', (_req, res) => {
  const metrics = hunterEngine.getCalibrationMetrics();
  res.json({ metrics: metrics || { totalCalibrations: 0, passiveAccuracy: 0, byVendor: {}, bySignalType: {}, weightAdjustments: [] } });
});

router.post('/calibration/auto-tune', async (_req, res) => {
  try {
    const result = await hunterEngine.triggerAutoTune();
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/waf/rules', (req, res) => {
  const id = req.params.id as string;
  const ruleProfile = hunterEngine.getWAFRuleProfile(id);
  res.json({ ruleProfile });
});

router.get('/sessions/:id/waf/behavior', (req, res) => {
  const id = req.params.id as string;
  const behaviorModel = hunterEngine.getWAFBehaviorModel(id);
  res.json({ behaviorModel });
});

router.get('/sessions/:id/waf/evasion-ranking', async (req, res) => {
  try {
    const ranking = hunterEngine.getEvasionRanking(req.params.id);
    if (!ranking) {
      return res.json({ rankings: [], byCategory: {}, message: 'No evasion data available' });
    }
    res.json(ranking);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/waf/temporal', async (req, res) => {
  try {
    const analysis = hunterEngine.getTemporalAnalysis(req.params.id);
    if (!analysis) {
      return res.json({ phases: [], currentPhase: null, transitionPattern: 'no_data', predictedNextPhase: null, phaseTransitions: [] });
    }
    res.json(analysis);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/waf/clusters', async (req, res) => {
  try {
    const clusters = hunterEngine.getBlockClusters(req.params.id);
    res.json({ clusters, count: clusters.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/waf/anomalies', async (req, res) => {
  try {
    const anomalies = hunterEngine.getAnomalies(req.params.id);
    res.json({ anomalies, count: anomalies.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/waf/correlations', async (req, res) => {
  try {
    const matrix = hunterEngine.getRuleCorrelationMatrix(req.params.id);
    if (!matrix) {
      return res.json({ correlations: [], comprehensiveCategories: [], isolatedCategories: [], rulesetComplexity: 'minimal', lastUpdated: 0 });
    }
    res.json(matrix);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/vendor-profile/:vendor', async (req, res) => {
  try {
    const profile = hunterEngine.getVendorEvasionProfile(req.params.vendor);
    if (!profile) {
      return res.json({ vendor: req.params.vendor, totalSessions: 0, totalAttempts: 0, overallSuccessRate: 0, topTechniques: [], byCategory: {}, recommendedStrategies: [], lastUpdated: 0 });
    }
    res.json(profile);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/vendor-profile/:vendor/chains', async (req, res) => {
  try {
    const intel = hunterEngine.getExploitChainIntelligence(req.params.vendor);
    if (!intel) {
      return res.json({ vendor: req.params.vendor, successfulChains: [], failedPatterns: [], recommendedSequences: [], lastUpdated: 0 });
    }
    res.json(intel);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions/:id/chains/start', async (req, res) => {
  try {
    const chainId = hunterEngine.startExploitChain(req.params.id);
    if (!chainId) {
      return res.status(400).json({ error: 'No WAF profile or SignatureDB available for this session' });
    }
    res.json({ chainId });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions/:id/chains/:chainId/step', async (req, res) => {
  try {
    const { technique, category, succeeded } = req.body;
    if (!technique || !category || succeeded === undefined) {
      return res.status(400).json({ error: 'technique, category, and succeeded are required' });
    }
    hunterEngine.addExploitChainStep(req.params.chainId, technique, category, succeeded);
    res.json({ success: true });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/sessions/:id/chains/:chainId/complete', async (req, res) => {
  try {
    const record = hunterEngine.completeExploitChain(req.params.chainId, req.params.id);
    res.json({ record });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/intelligence', async (req, res) => {
  try {
    let intel = hunterEngine.getUnifiedIntelligence(req.params.id);
    if (!intel) {
      intel = hunterEngine.synthesizeIntelligenceForSession(req.params.id);
    }
    if (!intel) {
      return res.json({
        vendor: 'unknown',
        confidence: 0,
        dataQuality: 'insufficient',
        recommendations: {
          optimalTechniques: [],
          expectedBehavior: { currentPhase: 'unknown', predictedNextPhase: null, blockRate: 0, avgResponseTime: 0, adaptiveLearning: false, escalationRisk: false },
          riskLevel: 'low',
          riskFactors: [],
          suggestedPacing: { maxRequestsPerMinute: 60, cooldownAfterBlock: 5000, burstAllowed: true, reasoningForPacing: 'no data' },
          avoidTechniques: [],
          avoidCategories: [],
          exploitChains: { recommended: [], avoid: [] },
          wafProfile: { rulesetComplexity: 'minimal', comprehensiveCategories: [], isolatedCategories: [], bypassResistance: {}, sharedRulePairs: [] },
        },
        reasoning: [],
        sourceSummary: {},
        synthesizedAt: 0,
      });
    }
    res.json(intel);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/intelligence/:vendor', async (req, res) => {
  try {
    const intel = hunterEngine.synthesizeIntelligenceForVendor(req.params.vendor);
    if (!intel) {
      return res.json({ vendor: req.params.vendor, confidence: 0, dataQuality: 'insufficient', recommendations: {}, reasoning: [], sourceSummary: {}, synthesizedAt: 0 });
    }
    res.json(intel);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/strategy', (req, res) => {
  const id = req.params.id as string;
  const strategy = huntStrategyBuilder.getStrategy(id);
  if (!strategy) {
    return res.json({ strategy: null, message: 'No strategy found for this session' });
  }
  res.json({ strategy: huntStrategyBuilder.summarize(strategy) });
});

router.post('/sessions/:id/strategy/adapt', (req, res) => {
  const id = req.params.id as string;
  const { reason, action, details } = req.body;
  if (!reason || !action) {
    return res.status(400).json({ error: 'reason and action are required' });
  }
  huntStrategyBuilder.adaptStrategy(id, reason, action, details || '');
  const strategy = huntStrategyBuilder.getStrategy(id);
  res.json({ strategy: strategy ? huntStrategyBuilder.summarize(strategy) : null });
});

router.post('/sessions/:id/strategy/add-step', (req, res) => {
  const id = req.params.id as string;
  const { tool, purpose, commandTemplate } = req.body;
  if (!tool || !purpose || !commandTemplate) {
    return res.status(400).json({ error: 'tool, purpose, and commandTemplate are required' });
  }
  const step = huntStrategyBuilder.addDynamicStep(id, tool, purpose, commandTemplate);
  if (!step) {
    return res.status(404).json({ error: 'Strategy not found for this session' });
  }
  res.json({ step });
});

router.get('/sessions/:id/plan', (req, res) => {
  const id = req.params.id as string;
  const summary = planMemoryStore.getPlanSummary(id);
  if (!summary) return res.status(404).json({ error: 'No plan found for this session' });
  res.json({ plan: summary });
});

router.post('/sessions/:id/plan/advance', (req, res) => {
  const id = req.params.id as string;
  const nextPhase = planMemoryStore.advancePhase(id, req.body.outcomes || []);
  res.json({ nextPhase });
});

router.get('/sessions/:id/validation-stats', (req, res) => {
  const id = req.params.id as string;
  const stats = validationGate.getStats(id);
  res.json({ stats });
});

router.get('/sessions/:id/nuclei-templates', (req, res) => {
  const id = req.params.id as string;
  const templates = nucleiTemplateGenerator.getTemplates(id);
  const stats = nucleiTemplateGenerator.getStats(id);
  res.json({ templates, stats });
});

router.get('/sessions/:id/nuclei-templates/:templateId', (req, res) => {
  const { id, templateId } = req.params;
  const template = nucleiTemplateGenerator.getTemplate(id, templateId);
  if (!template) return res.status(404).json({ error: 'Template not found' });
  res.json({ template });
});

router.get('/sessions/:id/nuclei-templates/download/all', (req, res) => {
  const id = req.params.id as string;
  const yaml = nucleiTemplateGenerator.getAllTemplateYAMLs(id);
  if (!yaml) return res.json({ yaml: '' });
  res.setHeader('Content-Type', 'text/yaml');
  res.setHeader('Content-Disposition', `attachment; filename="sentinel-templates-${id}.yaml"`);
  res.send(yaml);
});

router.get('/sessions/:id/reports', (req, res) => {
  const id = req.params.id as string;
  const reports = reportGenerator.getReports(id);
  const stats = reportGenerator.getStats(id);
  res.json({ reports: reports.map(r => ({ ...r, markdown: undefined })), stats });
});

router.get('/sessions/:id/reports/:reportId', (req, res) => {
  const { id, reportId } = req.params;
  const report = reportGenerator.getReport(id, reportId);
  if (!report) return res.status(404).json({ error: 'Report not found' });
  res.json({ report });
});

router.post('/sessions/:id/reports/generate', async (req, res) => {
  const id = req.params.id as string;
  const platform = req.body.platform || 'generic';
  const session = hunterEngine.getSessionStats(id);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  const findings = hunterEngine.getSessionFindings(id);
  if (!findings || findings.length === 0) return res.json({ reports: [], message: 'No findings to report' });
  const reports = await reportGenerator.generateBatchReports(findings, platform, id);
  res.json({ reports: reports.map(r => ({ id: r.id, title: r.title, severity: r.severity, platform: r.platform, wordCount: r.wordCount })), count: reports.length });
});

router.get('/sessions/:id/reports/:reportId/download', (req, res) => {
  const { id, reportId } = req.params;
  const report = reportGenerator.getReport(id, reportId);
  if (!report) return res.status(404).json({ error: 'Report not found' });
  res.setHeader('Content-Type', 'text/markdown');
  res.setHeader('Content-Disposition', `attachment; filename="${report.title.replace(/[^a-zA-Z0-9-_]/g, '_')}.md"`);
  res.send(report.markdown);
});

router.post('/sessions/:id/backward-hunt', (req, res) => {
  const id = req.params.id as string;
  const { objective } = req.body;
  if (!objective) return res.status(400).json({ error: 'objective is required' });
  backwardHuntEngine.createBackwardHunt(id, objective);
  res.json({ backwardHunt: backwardHuntEngine.getSummary(id) });
});

router.get('/sessions/:id/backward-hunt', (req, res) => {
  const id = req.params.id as string;
  const summary = backwardHuntEngine.getSummary(id);
  if (!summary) return res.status(404).json({ error: 'No backward hunt found for this session' });
  res.json({ backwardHunt: summary });
});

router.post('/sessions/:id/backward-hunt/hypotheses', (req, res) => {
  const id = req.params.id as string;
  const hypotheses = backwardHuntEngine.generateHypotheses(id);
  res.json({ hypotheses });
});

router.post('/sessions/:id/backward-hunt/step-result', (req, res) => {
  const id = req.params.id as string;
  const { stepDescription, success, result } = req.body;
  backwardHuntEngine.recordStepResult(id, stepDescription || '', success, result);
  res.json({ state: backwardHuntEngine.getSummary(id) });
});

router.get('/roi/global', (req, res) => {
  const stats = roiModel.getGlobalStats();
  res.json(stats);
});

router.get('/roi/program/:programId', (req, res) => {
  const { programId } = req.params;
  const profile = roiModel.calculateEVForProgram(programId);
  res.json({ profile });
});

router.get('/roi/thresholds', (req, res) => {
  res.json({ thresholds: roiModel.getThresholds() });
});

router.post('/roi/override', (req, res) => {
  const { scope, type, values, reason } = req.body;
  if (!scope || !type || !values) {
    return res.status(400).json({ error: 'scope, type, and values are required' });
  }
  roiModel.setManualOverride(scope, { type, values, reason: reason || 'Manual override', active: true });
  res.json({ success: true, thresholds: roiModel.getThresholds() });
});

router.delete('/roi/override', (req, res) => {
  const { scope, type } = req.body;
  if (!scope || !type) {
    return res.status(400).json({ error: 'scope and type are required' });
  }
  roiModel.clearManualOverride(scope, type);
  res.json({ success: true, thresholds: roiModel.getThresholds() });
});

router.get('/roi/multiplier/:vulnType', (req, res) => {
  const { vulnType } = req.params;
  const programId = req.query.programId as string | undefined;
  const multiplier = roiModel.getPriorityMultiplier(vulnType, programId);
  res.json({ vulnType, multiplier, programId: programId || null });
});

router.post('/targets/program', (req, res) => {
  try {
    const metadata = req.body;
    if (!metadata.programId || !metadata.platform) {
      return res.status(400).json({ error: 'programId and platform are required' });
    }
    targetSelectionEngine.addProgram(metadata);
    const score = targetSelectionEngine.scoreProgram(metadata.programId);
    res.json({ success: true, score });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/targets/program/:programId', (req, res) => {
  try {
    const { programId } = req.params;
    const score = targetSelectionEngine.scoreProgram(programId);
    res.json({ score });
  } catch (err: any) {
    res.status(404).json({ error: err.message });
  }
});

router.get('/targets/rank', (_req, res) => {
  try {
    const rankings = targetSelectionEngine.rankAll();
    res.json({ rankings, count: rankings.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/targets/queue', (req, res) => {
  try {
    const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : undefined;
    const queue = targetSelectionEngine.getTargetQueue(limit);
    res.json({ queue, count: queue.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/targets/program/:programId/outcome', (req, res) => {
  try {
    const { programId } = req.params;
    const { accepted, payout, vulnType } = req.body;
    if (accepted === undefined || payout === undefined || !vulnType) {
      return res.status(400).json({ error: 'accepted, payout, and vulnType are required' });
    }
    targetSelectionEngine.updateFromOutcome(programId, { accepted, payout, vulnType });
    const score = targetSelectionEngine.scoreProgram(programId);
    res.json({ success: true, score });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/static-analysis/analyze', async (req, res) => {
  try {
    const { directory } = req.body;
    if (!directory) {
      return res.status(400).json({ error: 'directory is required' });
    }
    const result = await staticAnalyzer.analyzeDirectory(directory);
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/static-analysis/routes', async (req, res) => {
  try {
    const { directory } = req.body;
    if (!directory) {
      return res.status(400).json({ error: 'directory is required' });
    }
    const routes = await staticAnalyzer.extractRoutes(directory);
    res.json({ routes, count: routes.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/static-analysis/hypotheses', async (req, res) => {
  try {
    const { directory } = req.body;
    if (!directory) {
      return res.status(400).json({ error: 'directory is required' });
    }
    const result = await staticAnalyzer.analyzeDirectory(directory);
    res.json({ hypotheses: result.hypotheses, count: result.hypotheses.length, stats: result.stats });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/chains/record', (req, res) => {
  try {
    const record = exploitChainIntelligence.recordChain(req.body);
    res.json({ record });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.post('/chains/:chainId/outcome', (req, res) => {
  try {
    const { chainId } = req.params;
    const { bounty } = req.body;
    if (bounty === undefined) {
      return res.status(400).json({ error: 'bounty is required' });
    }
    const success = exploitChainIntelligence.recordOutcome(chainId, bounty);
    if (!success) return res.status(404).json({ error: 'Chain not found' });
    res.json({ success: true });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

router.get('/chains/patterns', (_req, res) => {
  try {
    const patterns = exploitChainIntelligence.getChainPatterns();
    res.json({ patterns, count: patterns.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/chains/recommend', (req, res) => {
  try {
    const { techStack, wafVendor } = req.body;
    const recommendations = exploitChainIntelligence.getRecommendations({
      techStack: techStack || [],
      wafVendor,
    });
    res.json({ recommendations, count: recommendations.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/chains/avoid', (req, res) => {
  try {
    const wafVendor = req.query.wafVendor as string | undefined;
    const avoid = exploitChainIntelligence.getChainsToAvoid({ wafVendor });
    res.json({ avoid, count: avoid.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/chains/roi', (_req, res) => {
  try {
    const roi = exploitChainIntelligence.getChainROI();
    res.json({ roi, count: roi.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/chains/stats', (_req, res) => {
  try {
    const stats = exploitChainIntelligence.getStats();
    res.json(stats);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/sessions/:id/solvers', (req, res) => {
  const id = req.params.id as string;
  const state = solverPool.getPoolState(id);
  if (!state) return res.status(404).json({ error: 'No solver pool found for this session' });
  res.json({ solverPool: state });
});

router.post('/sessions/:id/solvers/spawn', (req, res) => {
  const id = req.params.id as string;
  const { endpoints, vulnClasses } = req.body;
  if (!endpoints || !Array.isArray(endpoints) || endpoints.length === 0) {
    return res.status(400).json({ error: 'endpoints array is required' });
  }
  const solvers = solverPool.spawnSolvers(id, endpoints, vulnClasses);
  const state = solverPool.getPoolState(id);
  res.json({ spawned: solvers.length, solverPool: state });
});

router.post('/sessions/:id/solvers/:solverId/complete', (req, res) => {
  const { id, solverId } = req.params;
  const result = req.body.result || { findingsCount: 0, vulnsFound: [], confidence: 0 };
  solverPool.completeSolver(id, solverId, result);
  const state = solverPool.getPoolState(id);
  res.json({ success: true, solverPool: state });
});

router.post('/sessions/:id/solvers/:solverId/cancel', (req, res) => {
  const { id, solverId } = req.params;
  solverPool.cancelSolver(id, solverId);
  const state = solverPool.getPoolState(id);
  res.json({ success: true, solverPool: state });
});

router.get('/sessions/:id/solvers/decisions', (req, res) => {
  const id = req.params.id as string;
  const decisions = solverPool.getDecisionLog(id);
  res.json({ decisions });
});

// === Reinforcement Store Routes ===
router.get('/reinforcement/snapshot', async (_req, res) => {
  try {
    const snapshot = await reinforcementStore.getSnapshot();
    res.json(snapshot);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/tools', async (_req, res) => {
  try {
    const profiles = await reinforcementStore.getAllToolProfiles();
    res.json({ profiles, count: profiles.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/tools/:tool', async (req, res) => {
  try {
    const profile = await reinforcementStore.getToolProfile(req.params.tool);
    if (!profile) return res.status(404).json({ error: 'Tool profile not found' });
    res.json({ profile });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/reinforcement/tools/recommend', async (req, res) => {
  try {
    const { context } = req.body;
    if (!context) {
      return res.status(400).json({ error: 'context is required' });
    }
    const recommendations = await reinforcementStore.getToolRecommendation(context);
    res.json({ recommendations, count: recommendations.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/frameworks', async (_req, res) => {
  try {
    const profiles = await reinforcementStore.getAllFrameworkVulnProfiles();
    res.json({ profiles, count: profiles.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/frameworks/:framework', async (req, res) => {
  try {
    const priorities = await reinforcementStore.getFrameworkPriorities(req.params.framework);
    res.json({ framework: req.params.framework, priorities, count: priorities.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/programs/platforms', async (_req, res) => {
  try {
    const ranking = await reinforcementStore.getPlatformRanking();
    res.json({ ranking, count: ranking.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/programs', async (_req, res) => {
  try {
    const profiles = await reinforcementStore.getAllProgramTypeProfiles();
    res.json({ profiles, count: profiles.length });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/calibration', async (_req, res) => {
  try {
    const calibration = await reinforcementStore.getCalibration();
    res.json(calibration);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/reinforcement/calibration/correct', (req, res) => {
  try {
    const { confidence } = req.body;
    if (confidence === undefined || typeof confidence !== 'number') {
      return res.status(400).json({ error: 'confidence (number) is required' });
    }
    const corrected = reinforcementStore.calibrateConfidence(confidence);
    res.json({ original: confidence, corrected });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/reinforcement/exploration', async (_req, res) => {
  try {
    const stats = await reinforcementStore.getExplorationStats();
    res.json(stats);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/score', async (_req, res) => {
  try {
    const score = await autonomyMaturityTracker.getMaturityScore();
    res.json(score);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/brier-trend', async (_req, res) => {
  try {
    const trend = await autonomyMaturityTracker.getBrierTrend();
    res.json(trend);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/noise', async (_req, res) => {
  try {
    const report = await autonomyMaturityTracker.getNoiseReport();
    res.json(report);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/exploration-health', async (_req, res) => {
  try {
    const health = await autonomyMaturityTracker.getExplorationHealth();
    res.json(health);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/milestones', (_req, res) => {
  try {
    const reports = autonomyMaturityTracker.getMilestoneReports();
    res.json(reports);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/milestones/:milestone', (req, res) => {
  try {
    const milestone = parseInt(req.params.milestone);
    if (isNaN(milestone)) return res.status(400).json({ error: 'Invalid milestone number' });
    const report = autonomyMaturityTracker.getMilestoneReport(milestone);
    if (!report) return res.status(404).json({ error: `No milestone report for hunt ${milestone}` });
    res.json(report);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/report', async (_req, res) => {
  try {
    const report = await autonomyMaturityTracker.generateMilestoneReport();
    res.json(report);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/hunt-count', (_req, res) => {
  try {
    res.json({ huntCount: autonomyMaturityTracker.getHuntCount() });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/domain-gates', async (_req, res) => {
  try {
    const report = await autonomyMaturityTracker.getDomainGateReport();
    res.json(report);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/domain-gates/:domain', async (req, res) => {
  try {
    const report = await autonomyMaturityTracker.getDomainGateReport();
    const gate = report.gates.find(g => g.domain === req.params.domain);
    if (!gate) return res.status(404).json({ error: `Unknown domain: ${req.params.domain}` });
    res.json(gate);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/maturity/regressions', async (_req, res) => {
  try {
    const report = await autonomyMaturityTracker.getDomainGateReport();
    res.json({
      regressions: report.regressions,
      gatingActive: report.gatingActive,
      globalLevelCap: report.globalLevelCap,
      weakestDomain: report.weakestDomain,
      weakestScore: report.weakestScore,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;

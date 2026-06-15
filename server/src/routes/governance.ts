import { Router } from 'express';
import {
  coreGovernance,
  decisionLogger,
  driftDetector,
  promptInjectionDetector,
  selfAttestationService
} from '../governance';
import { getAllPillars } from '../governance/pillars';
import { governanceImmunizer } from '../lib/governance/governance-immunizer';
import { egressAllocator } from '../lib/stealth/egress-route-allocator';
import { pool } from '../db';
import type {
  GovernanceVerdict,
  GovernancePillar,
  RiskLevel,
  AuditEvent
} from '../governance/types';

const router = Router();

router.get('/stats', (_req, res) => {
  res.json(coreGovernance.getStats());
});

router.get('/pillars', (_req, res) => {
  res.json(getAllPillars());
});

router.get('/decisions', (req, res) => {
  const { huntId, agentId, verdict, pillar, riskLevel, limit } = req.query;
  const decisions = coreGovernance.getDecisions({
    huntId: huntId as string | undefined,
    agentId: agentId as string | undefined,
    verdict: verdict as GovernanceVerdict | undefined,
    pillar: pillar as GovernancePillar | undefined,
    riskLevel: riskLevel as RiskLevel | undefined,
    limit: limit ? parseInt(limit as string, 10) : undefined
  });
  res.json(decisions);
});

router.get('/decisions/logged', (req, res) => {
  const { date, verdict, pillar, limit } = req.query;
  const decisions = decisionLogger.readDecisions({
    date: date as string | undefined,
    verdict: verdict as string | undefined,
    pillar: pillar as string | undefined,
    limit: limit ? parseInt(limit as string, 10) : undefined
  });
  res.json(decisions);
});

router.get('/decisions/logged/dates', (_req, res) => {
  res.json(decisionLogger.getAvailableDates());
});

router.get('/decisions/:id', (req, res) => {
  const decision = decisionLogger.getDecisionById(req.params.id);
  if (!decision) return res.status(404).json({ error: 'Decision not found' });
  return res.json(decision);
});

router.get('/decisions/:id/replay', (req, res) => {
  const replay = decisionLogger.getReplayData(req.params.id);
  if (!replay) return res.status(404).json({ error: 'Replay data not found' });
  return res.json(replay);
});

router.get('/audit', (req, res) => {
  const { category, severity, huntId, limit } = req.query;
  const events = coreGovernance.getAuditLog({
    category: category as AuditEvent['category'] | undefined,
    severity: severity as AuditEvent['severity'] | undefined,
    huntId: huntId as string | undefined,
    limit: limit ? parseInt(limit as string, 10) : undefined
  });
  res.json(events);
});

router.get('/drift', (req, res) => {
  const recentWindow = req.query.recentWindow
    ? parseInt(req.query.recentWindow as string, 10)
    : undefined;
  const baselineWindow = req.query.baselineWindow
    ? parseInt(req.query.baselineWindow as string, 10)
    : undefined;
  res.json(driftDetector.analyze(recentWindow, baselineWindow));
});

router.get('/drift/snapshots', (req, res) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : undefined;
  res.json(driftDetector.getSnapshots(limit));
});

router.get('/injection/stats', (_req, res) => {
  res.json(promptInjectionDetector.getStats());
});

router.post('/injection/check', (req, res) => {
  const { input, agentId, agentName } = req.body;
  if (!input || typeof input !== 'string') {
    return res.status(400).json({ error: 'input string required' });
  }
  const result = promptInjectionDetector.detect(input, agentId, agentName);
  return res.json(result);
});

router.get('/attestations', (req, res) => {
  const { agentId, huntId, pillar, minConfidence, limit } = req.query;
  res.json(selfAttestationService.getAttestations({
    agentId: agentId as string | undefined,
    huntId: huntId as string | undefined,
    pillar: pillar as GovernancePillar | undefined,
    minConfidence: minConfidence ? parseFloat(minConfidence as string) : undefined,
    limit: limit ? parseInt(limit as string, 10) : undefined
  }));
});

router.get('/attestations/agent/:agentId', (req, res) => {
  res.json(selfAttestationService.getAgentAttestationSummary(req.params.agentId));
});

// ─── Governance Immunizer ─────────────────────────────────────────────────────

router.get('/immunizer/status', (_req, res) => {
  res.json(governanceImmunizer.getStatus());
});

router.post('/immunizer/check', async (_req, res) => {
  try {
    const analysis = driftDetector.analyze(3_600_000, 86_400_000);
    const result = await governanceImmunizer.runImmunizationCheck(analysis);
    res.json({ analysis, result });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/immunizer/events', async (req, res) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 50;
  try {
    const result = await pool.query(
      `SELECT * FROM immunization_events ORDER BY timestamp DESC LIMIT $1`,
      [limit]
    );
    res.json(result.rows);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Governance Snapshots ─────────────────────────────────────────────────────

router.post('/snapshots/manual', async (_req, res) => {
  try {
    const snapshot = driftDetector.takeSnapshot();
    const id = await governanceImmunizer.persistSnapshot(snapshot, 'manual');
    res.json({ id, snapshot });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/snapshots/persisted', async (req, res) => {
  try {
    const type = req.query.type as string | undefined;
    const snapshot = await governanceImmunizer.loadLatestSnapshot(type);
    if (!snapshot) return res.status(404).json({ error: 'No snapshot found' });
    return res.json(snapshot);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// ─── Egress Route Pool ────────────────────────────────────────────────────────

router.get('/egress/status', (_req, res) => {
  res.json(egressAllocator.getPoolStatus());
});

export default router;

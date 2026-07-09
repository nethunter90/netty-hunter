import { v4 as uuidv4 } from 'uuid';
import { CoreGovernance } from './core-governance';
import { DecisionLogger } from './decision-logger';
import { SelfAttestationService } from './self-attestation';
import { DriftDetector } from './drift-detector';
import { PromptInjectionDetector } from './enforcement/prompt-injection-detector';
import { governanceImmunizer } from '../lib/governance/governance-immunizer';
import { pool } from '../db';

export const coreGovernance = new CoreGovernance();
export const decisionLogger = new DecisionLogger();
export const selfAttestationService = new SelfAttestationService();
export const driftDetector = new DriftDetector();
export const promptInjectionDetector = new PromptInjectionDetector(coreGovernance);

// Activates the previously-dead persistence layer: decisionLogger.log() ran its
// full WAL/flush machinery from startup but had zero callers, so every decision
// recorded via coreGovernance.recordDecision() vanished on restart.
coreGovernance.setDecisionLogger(decisionLogger);

driftDetector.setSnapshotProvider(() => {
  const stats = coreGovernance.getStats();
  const pillarActivity: Record<string, number> = {};
  for (const [pillar, count] of Object.entries(stats.pillarCounts)) {
    pillarActivity[pillar] = count;
  }

  return {
    id: uuidv4(),
    timestamp: new Date(),
    config: {
      realToolsMode: process.env.REAL_TOOLS === 'true',
      scopeEnforcement: true,
      autoStealth: true,
      pillarSensitivities: {} as any,
      agentPermissions: {}
    },
    verdicts: { ...stats.verdictCounts, total: stats.totalDecisions } as any,
    pillarActivity: pillarActivity as any,
    agentActivity: {},
    riskDistribution: stats.riskCounts as any
  };
});

driftDetector.startAutoSnapshot(300000);

// Persist every auto-snapshot to DB for watchdog continuity across restarts
driftDetector.setPostSnapshotCallback((snap) => {
  governanceImmunizer.persistSnapshot(snap, 'auto').catch(() => {});
});

// Initialize frozen baseline, start 90s watchdog, and warm snapshot buffer from DB
governanceImmunizer.initialize().then(() => {
  governanceImmunizer.startWatchdog(driftDetector);
  driftDetector.loadSnapshotsFromDB(pool).catch(() => {});
}).catch((err: unknown) => {
  console.error('[GovernanceImmunizer] initialization failed:', err);
});

export {
  CoreGovernance,
  DecisionLogger,
  SelfAttestationService,
  DriftDetector,
  PromptInjectionDetector,
};

export * from './types';
export * from './pillars';

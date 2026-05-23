import { v4 as uuidv4 } from 'uuid';
import { CoreGovernance } from './core-governance';
import { DecisionLogger } from './decision-logger';
import { SelfAttestationService } from './self-attestation';
import { DriftDetector } from './drift-detector';
import { DesktopAgentGovernance } from './enforcement/desktop-agent-governance';
import { PromptInjectionDetector } from './enforcement/prompt-injection-detector';
import { GovernanceProxy } from './enforcement/governance-proxy';

export const coreGovernance = new CoreGovernance();
export const decisionLogger = new DecisionLogger();
export const selfAttestationService = new SelfAttestationService();
export const driftDetector = new DriftDetector();
export const desktopAgentGovernance = new DesktopAgentGovernance(coreGovernance);
export const promptInjectionDetector = new PromptInjectionDetector(coreGovernance);
export const governanceProxy = new GovernanceProxy(coreGovernance);

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

export {
  CoreGovernance,
  DecisionLogger,
  SelfAttestationService,
  DriftDetector,
  DesktopAgentGovernance,
  PromptInjectionDetector,
  GovernanceProxy
};

export * from './types';
export * from './pillars';

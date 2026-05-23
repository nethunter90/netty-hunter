import { reasoningEngine, MissionMemory } from './reasoning-engine';
import { huntOrchestrator } from '../orchestration/layer1-hunt-orchestrator';
import { ProposedAction } from './decision-engine';
import { HuntPhase } from '../orchestration/types';
import { huntCortex, SignalType } from './hunt-cortex';
import { TOOL_FALLBACK_CHAINS } from './seed-knowledge';

export interface SituationContext {
  huntGoal: string;
  huntPhase: string;
  techCount: number;
  endpointCount: number;
  vulnCount: number;
  lastToolUsed: string;
  lastToolSuccess: boolean;
  cycleNumber: number;
  failedToolsOnTarget: string[];
}

export interface DecisionRecord {
  id: string;
  timestamp: number;
  huntGoal: string;
  huntPhase: string;
  situationHash: string;
  context: SituationContext;
  decision: string;
  action: ProposedAction;
  outcome?: 'success' | 'failure' | 'unknown';
}

export interface FallbackDecision {
  action: 'proceed' | 'modify' | 'defer' | 'skip';
  confidence: number;
  tier: 1 | 2 | 3 | 4;
  rationale: string;
  modifiedAction?: ProposedAction;
}

type ToolRiskLevel = 'safe' | 'moderate' | 'risky';

const PHASE_PLAYBOOKS: Record<string, string[]> = {
  recon: ['subfinder', 'httpx', 'whatweb', 'nmap'],
  scanning: ['nuclei', 'nikto', 'ffuf'],
  exploitation: ['sqlmap'],
  reporting: [],
};

const SAFE_TOOLS = new Set(['subfinder', 'httpx', 'whatweb', 'whois', 'dig']);
const MODERATE_TOOLS = new Set(['nuclei', 'nikto', 'ffuf', 'gobuster', 'nmap']);
const RISKY_TOOLS = new Set(['hydra', 'metasploit', 'custom_exploit']);

const MAX_JOURNAL_SIZE = 1000;
const SIMILARITY_THRESHOLD = 0.85;
const MAX_NUMERIC_TECH = 50;
const MAX_NUMERIC_ENDPOINT = 200;
const MAX_NUMERIC_VULN = 100;

export class OfflineFallbackEngine {
  private journal: DecisionRecord[] = [];

  recordDecision(record: DecisionRecord): void {
    this.journal.push(record);
    if (this.journal.length > MAX_JOURNAL_SIZE) {
      this.journal = this.journal.slice(-MAX_JOURNAL_SIZE);
    }
  }

  decide(huntId: string, proposedAction: ProposedAction): FallbackDecision {
    const hunt = huntOrchestrator.getHunt(huntId);
    const memory = reasoningEngine.getMissionMemory(huntId);

    const phase = hunt?.phase || 'recon';
    const goal = hunt?.goal || memory?.goal || '';

    const tier1 = this.tryTier1(memory, proposedAction, goal);
    if (tier1) {
      huntCortex.broadcast({
        signalType: SignalType.FALLBACK_USED,
        sourceSystem: 'fallback',
        huntId,
        payload: { tier: tier1.tier, action: tier1.action, riskLevel: tier1.rationale },
        confidence: tier1.confidence,
      });
      return tier1;
    }

    const context = this.buildContext(huntId, memory, phase, goal);

    const tier2 = this.tryTier2(context, proposedAction);
    if (tier2) {
      huntCortex.broadcast({
        signalType: SignalType.FALLBACK_USED,
        sourceSystem: 'fallback',
        huntId,
        payload: { tier: tier2.tier, action: tier2.action, riskLevel: tier2.rationale },
        confidence: tier2.confidence,
      });
      return tier2;
    }

    const tier3 = this.tryTier3(proposedAction, phase);
    if (tier3) {
      huntCortex.broadcast({
        signalType: SignalType.FALLBACK_USED,
        sourceSystem: 'fallback',
        huntId,
        payload: { tier: tier3.tier, action: tier3.action, riskLevel: tier3.rationale },
        confidence: tier3.confidence,
      });
      return tier3;
    }

    const tier4 = this.applyTier4(proposedAction, phase);
    huntCortex.broadcast({
      signalType: SignalType.FALLBACK_USED,
      sourceSystem: 'fallback',
      huntId,
      payload: { tier: tier4.tier, action: tier4.action, riskLevel: tier4.rationale },
      confidence: tier4.confidence,
    });
    return tier4;
  }

  private tryTier1(memory: MissionMemory | undefined, proposedAction: ProposedAction, goal: string): FallbackDecision | null {
    if (!memory) return null;

    const successfulSameTool = memory.actionHistory.some(
      a => a.tool === proposedAction.tool && a.success && memory.goal === goal
    );

    if (successfulSameTool) {
      return {
        action: 'proceed',
        confidence: 0.9,
        tier: 1,
        rationale: `Tool "${proposedAction.tool}" has succeeded before on this hunt with the same goal`,
      };
    }

    return null;
  }

  private tryTier2(context: SituationContext, proposedAction: ProposedAction): FallbackDecision | null {
    const similar = this.findSimilarDecision(context);
    if (!similar) return null;

    if (similar.outcome === 'failure') {
      return {
        action: 'skip',
        confidence: 0.75,
        tier: 2,
        rationale: `Similar past situation (hash: ${similar.situationHash}) resulted in failure with "${similar.action.tool}"`,
      };
    }

    if (similar.outcome === 'success') {
      if (similar.action.tool === proposedAction.tool) {
        return {
          action: 'proceed',
          confidence: 0.8,
          tier: 2,
          rationale: `Similar past situation succeeded with the same tool "${proposedAction.tool}"`,
        };
      }

      return {
        action: 'modify',
        confidence: 0.75,
        tier: 2,
        rationale: `Similar past situation succeeded with "${similar.action.tool}" instead of "${proposedAction.tool}"`,
        modifiedAction: { ...similar.action, target: proposedAction.target },
      };
    }

    return null;
  }

  private tryTier3(proposedAction: ProposedAction, phase: string): FallbackDecision | null {
    if (phase === 'reporting') {
      return {
        action: 'proceed',
        confidence: 0.95,
        tier: 3,
        rationale: 'Reporting phase — no risk, always proceed',
      };
    }

    const playbook = PHASE_PLAYBOOKS[phase];
    if (!playbook) return null;

    const toolInPlaybook = playbook.includes(proposedAction.tool);

    if (phase === 'exploitation') {
      if (proposedAction.confidence > 0.8 && this.isExploitationAllowed(proposedAction)) {
        return {
          action: 'proceed',
          confidence: proposedAction.confidence,
          tier: 3,
          rationale: `Exploitation phase — confidence ${proposedAction.confidence} > 0.8 and tool parameters are within safe limits`,
        };
      }

      if (proposedAction.tool === 'sqlmap' && !this.isExploitationAllowed(proposedAction)) {
        const safeParams = { ...proposedAction.parameters, flags: '--batch --risk=1' };
        return {
          action: 'modify',
          confidence: 0.7,
          tier: 3,
          rationale: 'Exploitation phase — sqlmap restricted to --risk=1 without AI oversight',
          modifiedAction: { ...proposedAction, parameters: safeParams },
        };
      }

      return {
        action: 'defer',
        confidence: 0.6,
        tier: 3,
        rationale: `Exploitation phase — deferring "${proposedAction.tool}" (confidence ${proposedAction.confidence} <= 0.8)`,
      };
    }

    if (toolInPlaybook) {
      if (phase === 'scanning' && proposedAction.tool === 'nuclei') {
        const safeParams = this.ensureLowRiskTemplates(proposedAction.parameters);
        if (safeParams !== proposedAction.parameters) {
          return {
            action: 'modify',
            confidence: 0.85,
            tier: 3,
            rationale: 'Scanning phase — nuclei restricted to low-risk templates first',
            modifiedAction: { ...proposedAction, parameters: safeParams },
          };
        }
      }

      return {
        action: 'proceed',
        confidence: 0.85,
        tier: 3,
        rationale: `Phase "${phase}" playbook includes "${proposedAction.tool}"`,
      };
    }

    return null;
  }

  private applyTier4(proposedAction: ProposedAction, phase: string): FallbackDecision {
    const risk = this.getToolRiskLevel(proposedAction.tool, proposedAction.parameters);

    if (risk === 'safe') {
      return {
        action: 'proceed',
        confidence: 0.8,
        tier: 4,
        rationale: `Tool "${proposedAction.tool}" classified as safe — auto-proceeding`,
      };
    }

    if (risk === 'moderate') {
      if (phase === 'recon' || phase === 'scanning') {
        return {
          action: 'proceed',
          confidence: 0.65,
          tier: 4,
          rationale: `Tool "${proposedAction.tool}" is moderate risk but phase "${phase}" allows it`,
        };
      }

      return {
        action: 'defer',
        confidence: 0.5,
        tier: 4,
        rationale: `Tool "${proposedAction.tool}" is moderate risk and phase "${phase}" requires AI oversight`,
      };
    }

    return {
      action: 'defer',
      confidence: 0.3,
      tier: 4,
      rationale: `Tool "${proposedAction.tool}" classified as risky — deferring without AI`,
    };
  }

  getToolRiskLevel(tool: string, parameters: any): ToolRiskLevel {
    if (tool === 'nmap') {
      const flags = typeof parameters?.flags === 'string' ? parameters.flags : '';
      if (flags.includes('-sT')) {
        return 'moderate';
      }
      return 'safe';
    }

    if (tool === 'sqlmap') {
      const flags = typeof parameters?.flags === 'string' ? parameters.flags : '';
      const riskMatch = flags.match(/--risk[=\s]+(\d)/);
      if (riskMatch && parseInt(riskMatch[1], 10) > 1) {
        return 'risky';
      }
      return 'moderate';
    }

    if (SAFE_TOOLS.has(tool)) return 'safe';
    if (MODERATE_TOOLS.has(tool)) return 'moderate';
    if (RISKY_TOOLS.has(tool)) return 'risky';

    return 'moderate';
  }

  findSimilarDecision(context: SituationContext): DecisionRecord | null {
    let bestMatch: DecisionRecord | null = null;
    let bestSimilarity = 0;

    for (const record of this.journal) {
      if (record.context.huntGoal !== context.huntGoal) continue;
      if (record.context.huntPhase !== context.huntPhase) continue;
      if (record.outcome === 'unknown') continue;

      const similarity = this.computeSimilarity(context, record.context);

      if (similarity >= SIMILARITY_THRESHOLD && similarity > bestSimilarity) {
        bestSimilarity = similarity;
        bestMatch = record;
      }
    }

    return bestMatch;
  }

  private computeSimilarity(a: SituationContext, b: SituationContext): number {
    const normA = [
      a.techCount / MAX_NUMERIC_TECH,
      a.endpointCount / MAX_NUMERIC_ENDPOINT,
      a.vulnCount / MAX_NUMERIC_VULN,
    ];
    const normB = [
      b.techCount / MAX_NUMERIC_TECH,
      b.endpointCount / MAX_NUMERIC_ENDPOINT,
      b.vulnCount / MAX_NUMERIC_VULN,
    ];

    const dotProduct = normA[0] * normB[0] + normA[1] * normB[1] + normA[2] * normB[2];
    const magA = Math.sqrt(normA[0] ** 2 + normA[1] ** 2 + normA[2] ** 2);
    const magB = Math.sqrt(normB[0] ** 2 + normB[1] ** 2 + normB[2] ** 2);

    if (magA === 0 || magB === 0) {
      return magA === 0 && magB === 0 ? 1 : 0;
    }

    return dotProduct / (magA * magB);
  }

  getJournal(): DecisionRecord[] {
    return [...this.journal];
  }

  clearJournal(): void {
    this.journal = [];
  }

  private buildContext(
    huntId: string,
    memory: MissionMemory | undefined,
    phase: string,
    goal: string
  ): SituationContext {
    const actionHistory = memory?.actionHistory || [];
    const lastAction = actionHistory[actionHistory.length - 1];

    const failedTools = actionHistory
      .filter(a => !a.success)
      .map(a => a.tool);
    const uniqueFailedTools = Array.from(new Set(failedTools));

    return {
      huntGoal: goal,
      huntPhase: phase,
      techCount: memory?.discoveredTechnologies.size || 0,
      endpointCount: memory?.discoveredEndpoints.size || 0,
      vulnCount: memory?.discoveredVulnerabilities.size || 0,
      lastToolUsed: lastAction?.tool || 'none',
      lastToolSuccess: lastAction?.success ?? true,
      cycleNumber: actionHistory.length,
      failedToolsOnTarget: uniqueFailedTools,
    };
  }

  private isExploitationAllowed(action: ProposedAction): boolean {
    if (action.tool === 'sqlmap') {
      const flags = typeof action.parameters?.flags === 'string' ? action.parameters.flags : '';
      const riskMatch = flags.match(/--risk[=\s]+(\d)/);
      if (riskMatch && parseInt(riskMatch[1], 10) >= 3) {
        return false;
      }
      if (!flags.includes('--batch')) {
        return false;
      }
      return true;
    }

    if (RISKY_TOOLS.has(action.tool)) {
      return false;
    }

    return true;
  }

  private ensureLowRiskTemplates(parameters: any): any {
    if (!parameters) return { severity: 'low,medium' };
    if (parameters.severity && typeof parameters.severity === 'string') {
      if (parameters.severity.includes('critical') || parameters.severity.includes('high')) {
        return { ...parameters, severity: 'low,medium' };
      }
    }
    if (!parameters.severity) {
      return { ...parameters, severity: 'low,medium' };
    }
    return parameters;
  }

  getFallbackTool(primaryTool: string): { tool: string; degradationCoefficient: number; reason: string } | null {
    const chain = TOOL_FALLBACK_CHAINS.find(c => c.primary === primaryTool);
    if (!chain || chain.fallbacks.length === 0) return null;
    return chain.fallbacks[0];
  }

  getAllFallbackChains(): typeof TOOL_FALLBACK_CHAINS {
    return TOOL_FALLBACK_CHAINS;
  }

  private hashContext(context: SituationContext): string {
    return `${context.huntGoal}:${context.huntPhase}:${context.techCount}:${context.endpointCount}:${context.vulnCount}`;
  }
}

export const offlineFallback = new OfflineFallbackEngine();

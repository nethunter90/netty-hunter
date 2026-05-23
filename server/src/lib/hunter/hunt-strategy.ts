/**
 * HuntStrategyBuilder — lib/hunter singleton
 *
 * Builds, tracks, and adapts multi-step hunt strategies per session.
 */
import { v4 as uuidv4 } from 'uuid';
import type { HuntStrategy, StrategyStep } from './types';

class HuntStrategyBuilderImpl {
  private strategies: Map<string, HuntStrategy> = new Map();

  createStrategy(sessionId: string, objective: string, initialSteps?: Partial<StrategyStep>[]): HuntStrategy {
    const now = Date.now();
    const defaultSteps: StrategyStep[] = [
      { id: uuidv4(), tool: 'nmap',       purpose: 'Port and service enumeration',        commandTemplate: 'nmap -sV -sC {hostname}',      status: 'pending', dynamic: false, addedAt: now },
      { id: uuidv4(), tool: 'nuclei',     purpose: 'Template-based vulnerability scan',   commandTemplate: 'nuclei -u {target} -severity medium,high,critical', status: 'pending', dynamic: false, addedAt: now },
      { id: uuidv4(), tool: 'ffuf',       purpose: 'Directory and endpoint discovery',    commandTemplate: 'ffuf -u {target}/FUZZ -w {wordlist}', status: 'pending', dynamic: false, addedAt: now },
      { id: uuidv4(), tool: 'curl_probe', purpose: 'Security header and CORS analysis',   commandTemplate: 'curl -sI {target}',            status: 'pending', dynamic: false, addedAt: now },
    ];

    const steps: StrategyStep[] = initialSteps?.map(s => ({
      id:              s.id      ?? uuidv4(),
      tool:            s.tool    ?? 'custom',
      purpose:         s.purpose ?? 'Custom step',
      commandTemplate: s.commandTemplate ?? '',
      status:          'pending',
      dynamic:         false,
      addedAt:         now,
    })) ?? defaultSteps;

    const strategy: HuntStrategy = {
      sessionId,
      objective,
      currentPhase:  'recon',
      phaseHistory:  [],
      steps,
      adaptations:   [],
      createdAt:     now,
      updatedAt:     now,
    };

    this.strategies.set(sessionId, strategy);
    return strategy;
  }

  getStrategy(sessionId: string): HuntStrategy | null {
    return this.strategies.get(sessionId) ?? null;
  }

  summarize(strategy: HuntStrategy): object {
    return {
      sessionId:       strategy.sessionId,
      objective:       strategy.objective,
      currentPhase:    strategy.currentPhase,
      totalSteps:      strategy.steps.length,
      completedSteps:  strategy.steps.filter(s => s.status === 'done').length,
      pendingSteps:    strategy.steps.filter(s => s.status === 'pending').length,
      adaptations:     strategy.adaptations.length,
      phaseHistory:    strategy.phaseHistory,
      nextTool:        strategy.steps.find(s => s.status === 'pending')?.tool ?? null,
    };
  }

  adaptStrategy(sessionId: string, reason: string, action: string, details: string): void {
    const strategy = this.strategies.get(sessionId);
    if (!strategy) return;

    strategy.adaptations.push({ reason, action, details, at: Date.now() });
    strategy.updatedAt = Date.now();

    // Apply common adaptation actions
    if (action === 'skip_recon' || action === 'skip') {
      strategy.steps
        .filter(s => s.status === 'pending' && ['nmap', 'ffuf'].includes(s.tool))
        .forEach(s => { s.status = 'skipped'; });
    }
    if (action === 'focus_sqli') {
      strategy.steps.push({
        id: uuidv4(), tool: 'sqlmap', purpose: 'Focused SQL injection testing',
        commandTemplate: 'sqlmap -u {target} --batch --level=2 --risk=2',
        status: 'pending', dynamic: true, addedAt: Date.now(),
      });
    }
    if (action === 'advance_phase') {
      strategy.phaseHistory.push(strategy.currentPhase);
      const PHASES = ['recon', 'hypothesis', 'probe', 'exploit', 'verify', 'report'];
      const idx = PHASES.indexOf(strategy.currentPhase);
      strategy.currentPhase = PHASES[Math.min(idx + 1, PHASES.length - 1)];
    }
  }

  addDynamicStep(sessionId: string, tool: string, purpose: string, commandTemplate: string): StrategyStep | null {
    const strategy = this.strategies.get(sessionId);
    if (!strategy) return null;

    const step: StrategyStep = {
      id:              uuidv4(),
      tool,
      purpose,
      commandTemplate,
      status:          'pending',
      dynamic:         true,
      addedAt:         Date.now(),
    };
    strategy.steps.push(step);
    strategy.updatedAt = Date.now();
    return step;
  }

  markStepComplete(sessionId: string, tool: string): void {
    const strategy = this.strategies.get(sessionId);
    if (!strategy) return;
    const step = strategy.steps.find(s => s.tool === tool && s.status === 'running');
    if (step) { step.status = 'done'; strategy.updatedAt = Date.now(); }
  }
}

export const huntStrategyBuilder = new HuntStrategyBuilderImpl();

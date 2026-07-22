import { Hunt, HuntPhase, Finding, ResourceClass, StealthLevel } from './types';
import { v4 as uuidv4 } from 'uuid';
import { missionMemory } from './mission-memory';
import { agentLoop } from './layer2-agent-loop';
import { eventBus } from './layer3-event-bus';
import { agentRegistry } from './agent-registry';
import { coverageValidator, taskPlannerAgent, analystAgent } from './layer4-cognitive-agents';
import { missionChainManager, _registerHuntOrchestrator } from './mission-chain-manager';
import { metaReasoner } from '../intelligence/meta-reasoning';
import { decisionTraceLogger } from '../intelligence/decision-trace';
import { resolveCustomTargetProgram } from '../hunter/custom-target-program';

export class HuntOrchestrator {
  private hunts: Map<string, Hunt> = new Map();
  private monitors: Map<string, NodeJS.Timeout> = new Map();

  async createHunt(config: {
    target: string;
    goal: string;
    scope: { inScope: string[]; outOfScope: string[] };
    expectedPayout?: number;
    priority?: 'low' | 'medium' | 'high' | 'critical';
    autoAdvance?: boolean;
    stealthMode?: StealthLevel;
    resourceClass?: ResourceClass;
  }): Promise<Hunt> {
    const hunt: Hunt = {
      id: uuidv4(),
      target: config.target,
      goal: config.goal,
      phase: 'recon',
      status: 'active',
      scope: config.scope,
      startedAt: new Date(),
      phaseStartedAt: new Date(),
      autoAdvance: config.autoAdvance !== false,
      stealthMode: config.stealthMode || 'balanced',
      resourceClass: config.resourceClass || 'standard',
      phaseTimeouts: {
        recon: 10 * 60 * 1000,
        scanning: 15 * 60 * 1000,
        exploitation: 20 * 60 * 1000,
        reporting: 5 * 60 * 1000
      },
      findings: [],
      metadata: {
        expectedPayout: config.expectedPayout,
        priority: config.priority || 'medium',
        tags: []
      }
    };

    this.hunts.set(hunt.id, hunt);

    // 2026-07-22 (Phase 2, external-tool chokepoint): this subsystem had no
    // ScopeGuard-backed programId anywhere — dispatchTool() (which every tool
    // exec now goes through) requires one to scope-check before dispatch.
    // resolveCustomTargetProgram() finds-or-creates a real program row scoped
    // to config.scope.inScope (falls back to "*.<hostname>" if empty), the
    // same helper routes/hunt.ts uses for ad-hoc/custom-target launches.
    const programId = await resolveCustomTargetProgram(config.target, config.scope.inScope);
    await missionMemory.initialize(hunt.id, [config.target], programId);

    console.log(`[HuntOrchestrator] Created hunt: ${hunt.id} for ${hunt.target} (stealth=${hunt.stealthMode}, resource=${hunt.resourceClass})`);

    return hunt;
  }

  async startHunt(huntId: string): Promise<void> {
    const hunt = this.hunts.get(huntId);
    if (!hunt) {
      throw new Error(`Hunt not found: ${huntId}`);
    }

    console.log(`[HuntOrchestrator] Starting hunt: ${huntId}`);

    metaReasoner.initializeHuntState(huntId);

    missionChainManager.startHunt(huntId);

    await this.transitionToPhase(huntId, 'recon');

    if (hunt.autoAdvance) {
      this.startMonitoring(huntId);
    }
  }

  private async transitionToPhase(huntId: string, phase: HuntPhase): Promise<void> {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return;

    console.log(`[HuntOrchestrator] ${huntId} transitioning to ${phase}`);

    if (hunt.phase !== phase) {
      agentLoop.stopAllAgents(huntId);
      agentLoop.clearHuntScans(huntId);
    }

    const oldPhase = hunt.phase;
    hunt.phase = phase;
    hunt.phaseStartedAt = new Date();

    agentLoop.setHuntConfig(huntId, hunt.stealthMode, hunt.resourceClass);

    switch (phase) {
      case 'recon':
        for (let i = 0; i < 2; i++) {
          const agentId = agentLoop.createAgent('recon', huntId);
          agentLoop.startAgent(agentId);
        }
        break;

      case 'scanning': {
        const memory = missionMemory.get(huntId);
        const endpointCount = memory?.endpoints.length || 0;
        const agentCount = Math.min(3, Math.max(2, endpointCount));
        for (let i = 0; i < agentCount; i++) {
          const agentId = agentLoop.createAgent('scanner', huntId);
          agentLoop.startAgent(agentId);
        }
        // Ask task planner to build a structured scan plan from discovered endpoints
        try {
          const endpoints = (memory?.endpoints || []).map(e => typeof e === 'string' ? e : String(e));
          await taskPlannerAgent.createPlan(hunt.goal, endpoints);
        } catch { /* non-critical */ }
        console.log(`[HuntOrchestrator] Scanning ${endpointCount} endpoints with ${agentCount} scanner agents (stealth=${hunt.stealthMode}, resource=${hunt.resourceClass})`);
        break;
      }

      case 'exploitation': {
        let coverage: { coverage: number; gaps: string[]; suggestions: string[] };
        try {
          coverage = await coverageValidator.validate(huntId, hunt.goal);
        } catch (err: any) {
          console.warn(`[HuntOrchestrator] Coverage validation failed: ${err.message}, using fallback`);
          coverage = { coverage: 0, gaps: ['Validation failed'], suggestions: [] };
        }
        console.log(`[HuntOrchestrator] Coverage: ${coverage.coverage}%`, coverage);

        const memory = missionMemory.get(huntId);
        const vulnCount = memory?.vulnerabilities.length || 0;
        if (vulnCount > 0) {
          for (let i = 0; i < 2; i++) {
            const agentId = agentLoop.createAgent('exploit', huntId);
            agentLoop.startAgent(agentId);
          }
          console.log(`[HuntOrchestrator] Exploiting ${vulnCount} vulnerabilities`);
        } else {
          console.log(`[HuntOrchestrator] No vulnerabilities to exploit, advancing`);
          await this.advanceToNextPhase(huntId);
          return;
        }
        break;
      }

      case 'reporting':
        // Surface cross-finding patterns before generating the final report
        try {
          await analystAgent.findPatterns(huntId);
        } catch { /* non-critical */ }
        await this.generateReport(huntId);
        await this.completeHunt(huntId);
        break;

      case 'completed':
        await this.completeHunt(huntId);
        break;
    }

    decisionTraceLogger.recordEvent({
      huntId,
      eventType: 'phase_advance',
      sourceSystem: 'hunt-orchestrator',
      data: { oldPhase, newPhase: phase, endpointCount: missionMemory.get(huntId)?.endpoints.length || 0 },
      confidenceAtEvent: 0.5,
    });

    eventBus.publish(
      'phase_changed',
      'orchestrator',
      huntId,
      { oldPhase, newPhase: phase },
      ['cognitive']
    );

    if ((global as any).io) {
      (global as any).io.emit('hunt:phase_changed', { huntId, oldPhase, newPhase: phase });
    }
  }

  private startMonitoring(huntId: string): void {
    const timer = setInterval(() => {
      this.checkProgress(huntId);
    }, 10000);

    this.monitors.set(huntId, timer);
  }

  private async checkProgress(huntId: string): Promise<void> {
    const hunt = this.hunts.get(huntId);
    if (!hunt || hunt.status !== 'active') {
      return;
    }

    const phaseComplete = await this.isPhaseComplete(huntId);

    if (phaseComplete) {
      await this.advanceToNextPhase(huntId);
    }
  }

  private async isPhaseComplete(huntId: string): Promise<boolean> {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return false;

    const memory = missionMemory.get(huntId);
    if (!memory) return false;

    const workDone = agentLoop.isPhaseWorkComplete(huntId);

    const phaseAge = Date.now() - (hunt.phaseStartedAt?.getTime() || hunt.startedAt.getTime());
    const phaseTimeout = hunt.phaseTimeouts[hunt.phase as keyof typeof hunt.phaseTimeouts];
    const timedOut = phaseTimeout && phaseAge > phaseTimeout;

    if (timedOut) {
      console.log(`[HuntOrchestrator] Phase ${hunt.phase} timed out after ${Math.round(phaseAge / 1000)}s`);
      return true;
    }

    switch (hunt.phase) {
      case 'recon':
        if (phaseAge < 15000) return false;
        const hasEndpoints = memory.endpoints.length > 0;
        const hasNotes = memory.notes.length > 0;
        const reconDone = workDone && (hasEndpoints || hasNotes);
        if (reconDone) {
          console.log(`[HuntOrchestrator] Recon complete: ${memory.endpoints.length} endpoints, ${memory.technologies.length} techs, ${memory.subdomains.length} subdomains`);
        }
        return reconDone;

      case 'scanning': {
        if (phaseAge < 30000) return false;
        const TOOL_TIMEOUT_MS = 300000;
        const PHASE_HARD_TIMEOUT_MS = 600000;
        const activeTools = agentLoop.getActiveToolsInfo(huntId);
        if (workDone && activeTools.length === 0) {
          console.log(`[HuntOrchestrator] Scanning complete (all tools finished): ${memory.vulnerabilities.length} vulnerabilities found`);
          return true;
        }
        if (activeTools.length > 0) {
          const stalledTools = activeTools.filter(t => t.runningFor > TOOL_TIMEOUT_MS);
          if (stalledTools.length > 0) {
            stalledTools.forEach(t => {
              console.log(`[HuntOrchestrator] Killing stalled tool: ${t.tool} (running ${Math.round(t.runningFor / 1000)}s > ${TOOL_TIMEOUT_MS / 1000}s limit)`);
            });
            agentLoop.clearHuntScans(huntId);
            console.log(`[HuntOrchestrator] Cleared stalled tools, advancing scan phase`);
            return true;
          }
          if (phaseAge > PHASE_HARD_TIMEOUT_MS) {
            console.log(`[HuntOrchestrator] Scanning phase hard timeout (${PHASE_HARD_TIMEOUT_MS / 1000}s) — forcing completion with ${memory.vulnerabilities.length} vulnerabilities`);
            agentLoop.clearHuntScans(huntId);
            return true;
          }
          if (phaseAge % 30000 < 10100) {
            const toolNames = activeTools.map(t => `${t.tool}(${Math.round(t.runningFor / 1000)}s)`).join(', ');
            console.log(`[HuntOrchestrator] Scanning: waiting for active tools: ${toolNames}`);
          }
          return false;
        }
        if (memory.vulnerabilities.length > 0 && phaseAge > 180000) {
          console.log(`[HuntOrchestrator] Scanning phase timeout with results: ${memory.vulnerabilities.length} vulnerabilities found`);
          return true;
        }
        return false;
      }

      case 'exploitation':
        if (phaseAge < 10000) return false;
        return workDone;

      case 'reporting':
        return true;

      default:
        return workDone;
    }
  }

  private async advanceToNextPhase(huntId: string): Promise<void> {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return;

    const memory = missionMemory.get(huntId);

    const phaseOrder: HuntPhase[] = ['recon', 'scanning', 'exploitation', 'reporting', 'completed'];
    const currentIndex = phaseOrder.indexOf(hunt.phase);

    if (currentIndex < phaseOrder.length - 1) {
      let nextPhase = phaseOrder[currentIndex + 1];

      if (nextPhase === 'exploitation' && memory && memory.vulnerabilities.length === 0) {
        console.log(`[HuntOrchestrator] No vulnerabilities found, skipping exploitation -> reporting`);
        nextPhase = 'reporting';
      }

      if (nextPhase === 'scanning' && memory && memory.endpoints.length === 0) {
        const target = hunt.target;
        if (target && target.startsWith('http')) {
          missionMemory.addEndpoints(huntId, [{
            url: target.replace(/\/$/, ''),
            method: 'GET',
            statusCode: 200,
            title: 'Target (fallback)',
            discoveredBy: 'orchestrator',
            discoveredAt: new Date()
          }]);
          console.log(`[HuntOrchestrator] No endpoints from recon — injected base target as fallback: ${target}`);
        } else {
          console.log(`[HuntOrchestrator] No endpoints discovered and no HTTP target, skipping scanning -> reporting`);
          nextPhase = 'reporting';
        }
      }

      console.log(`[HuntOrchestrator] Auto-advancing ${huntId}: ${hunt.phase} -> ${nextPhase}`);
      await this.transitionToPhase(huntId, nextPhase);
    }
  }

  private async generateReport(huntId: string): Promise<void> {
    const hunt = this.hunts.get(huntId);
    const memory = missionMemory.get(huntId);

    if (!hunt || !memory) return;

    console.log(`[HuntOrchestrator] Generating report for ${huntId}`);

    const findings: Finding[] = memory.vulnerabilities.map(v => ({
      id: v.id || uuidv4(),
      huntId,
      severity: v.severity,
      title: v.type,
      description: v.description,
      evidence: [v.evidence],
      discoveredBy: 'scanner',
      discoveredAt: new Date(),
      endpoint: v.endpoint,
      status: 'unverified' as const
    }));

    hunt.findings = findings;

    const severityCounts: Record<string, number> = {};
    findings.forEach(f => {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
    });

    const duration = (hunt.completedAt || new Date()).getTime() - hunt.startedAt.getTime();

    console.log(`[HuntOrchestrator] Report generated:`);
    console.log(`  Target: ${hunt.target}`);
    console.log(`  Duration: ${Math.round(duration / 1000)}s`);
    console.log(`  Findings: ${findings.length}`);
    console.log(`  Severities:`, severityCounts);
    console.log(`  Endpoints: ${memory.endpoints.length}`);
    console.log(`  Technologies: ${memory.technologies.length}`);
    console.log(`  Subdomains: ${memory.subdomains.length}`);

    if ((global as any).io) {
      (global as any).io.emit('hunt:report', {
        huntId,
        target: hunt.target,
        goal: hunt.goal,
        duration,
        findings: findings.length,
        severityCounts,
        attackSurface: {
          endpoints: memory.endpoints.length,
          technologies: memory.technologies.length,
          subdomains: memory.subdomains.length,
        },
        notes: memory.notes,
      });
    }
  }

  private async completeHunt(huntId: string): Promise<void> {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return;

    console.log(`[HuntOrchestrator] Completing hunt: ${huntId}`);

    missionChainManager.stopHunt(huntId);

    agentLoop.stopAllAgents(huntId);

    const timer = this.monitors.get(huntId);
    if (timer) {
      clearInterval(timer);
      this.monitors.delete(huntId);
    }

    hunt.status = 'completed';
    hunt.completedAt = new Date();
    hunt.phase = 'completed';

    for (const finding of hunt.findings) {
      decisionTraceLogger.recordEvent({
        huntId,
        eventType: 'finding_confirmed',
        sourceSystem: 'hunt-orchestrator',
        data: { findingId: finding.id, severity: finding.severity, title: finding.title, endpoint: finding.endpoint },
        confidenceAtEvent: finding.severity === 'critical' ? 0.9 : finding.severity === 'high' ? 0.8 : 0.6,
      });
    }

    const duration = hunt.completedAt.getTime() - hunt.startedAt.getTime();
    const finalScore = hunt.findings.length > 0 ? Math.min(1, 0.3 + hunt.findings.length * 0.1) : 0.1;

    try {
      await metaReasoner.completeHunt(huntId, finalScore);
    } catch (_e) {}

    eventBus.publish(
      'hunt_complete',
      'orchestrator',
      huntId,
      {
        findingsCount: hunt.findings.length,
        duration
      },
      []
    );

    if ((global as any).io) {
      (global as any).io.emit('hunt:completed', { huntId, findings: hunt.findings.length });
    }

    console.log(`[HuntOrchestrator] Hunt completed: ${huntId}`);
  }

  pauseHunt(huntId: string): void {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return;

    missionChainManager.stopHunt(huntId);
    agentLoop.stopAllAgents(huntId);
    hunt.status = 'paused';

    const timer = this.monitors.get(huntId);
    if (timer) {
      clearInterval(timer);
      this.monitors.delete(huntId);
    }

    if ((global as any).io) {
      (global as any).io.emit('hunt:paused', { huntId });
    }

    console.log(`[HuntOrchestrator] Hunt paused: ${huntId}`);
  }

  /** Terminal stop — halts all agents/monitoring and marks the hunt aborted.
   *  Unlike pauseHunt this is not resumable; used by the Lab "Stop" control. */
  abortHunt(huntId: string): boolean {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return false;

    missionChainManager.stopHunt(huntId);
    agentLoop.stopAllAgents(huntId);
    hunt.status = 'aborted';

    const timer = this.monitors.get(huntId);
    if (timer) {
      clearInterval(timer);
      this.monitors.delete(huntId);
    }

    if ((global as any).io) {
      (global as any).io.emit('hunt:aborted', { huntId });
    }

    console.log(`[HuntOrchestrator] Hunt aborted: ${huntId}`);
    return true;
  }

  async resumeHunt(huntId: string): Promise<void> {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return;

    hunt.status = 'active';
    missionChainManager.startHunt(huntId);
    await this.transitionToPhase(huntId, hunt.phase);

    if (hunt.autoAdvance) {
      this.startMonitoring(huntId);
    }

    if ((global as any).io) {
      (global as any).io.emit('hunt:resumed', { huntId });
    }

    console.log(`[HuntOrchestrator] Hunt resumed: ${huntId}`);
  }

  getHunt(huntId: string): Hunt | null {
    return this.hunts.get(huntId) || null;
  }

  getAllHunts(): Hunt[] {
    return Array.from(this.hunts.values());
  }

  getActiveHunts(): Hunt[] {
    return Array.from(this.hunts.values()).filter(h => h.status === 'active');
  }

  getStatus(huntId: string): any {
    const hunt = this.hunts.get(huntId);
    if (!hunt) return null;

    const memory = missionMemory.get(huntId);
    const agentStats = agentLoop.getStats(huntId);

    return {
      hunt,
      attackSurface: {
        domains: memory?.domains.length || 0,
        subdomains: memory?.subdomains.length || 0,
        endpoints: memory?.endpoints.length || 0,
        technologies: memory?.technologies.length || 0,
        vulnerabilities: memory?.vulnerabilities.length || 0
      },
      agents: agentStats
    };
  }
}

export const huntOrchestrator = new HuntOrchestrator();
_registerHuntOrchestrator(huntOrchestrator);

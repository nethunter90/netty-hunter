import { v4 as uuidv4 } from 'uuid';
import {
  GovernanceDecision,
  GovernanceVerdict,
  GovernancePillar,
  RiskLevel,
  AuditEvent,
  Scope
} from './types';
import { determineRiskLevel } from './pillars';
import { ScopeGuard } from '../middleware/scopeGuard';

const ALWAYS_ALLOWED = [
  'nvd.nist.gov',
  'cve.mitre.org',
  'exploit-db.com',
  'cvedetails.com',
  'github.com/advisories',
  'raw.githubusercontent.com',
  'api.github.com',
  'crt.sh',
  'dns.google',
  'shodan.io',
  'api.shodan.io',
  'virustotal.com',
  'www.virustotal.com',
  'urlscan.io',
  'otx.alienvault.com'
];

export class CoreGovernance {
  private auditLog: AuditEvent[] = [];
  private decisions: GovernanceDecision[] = [];
  // Optional persistence sink — decisionLogger.log() was a fully-built WAL/
  // NDJSON persistence layer with zero callers anywhere in the codebase, so
  // every decision recorded here vanished on restart despite the persistence
  // machinery running the whole time. Wired in by governance/index.ts (which
  // owns both singletons) rather than importing DecisionLogger directly here,
  // to avoid constructing a second logger instance with its own competing
  // flush interval and WAL file.
  private decisionLogger: { log(decision: GovernanceDecision): void } | null = null;

  setDecisionLogger(logger: { log(decision: GovernanceDecision): void }): void {
    this.decisionLogger = logger;
  }

  private broadcast(event: string, data: any): void {
    if ((global as any).io) {
      (global as any).io.emit('governance:event', { event, data });
    }
  }

  recordDecision(params: {
    agentId: string;
    agentName: string;
    action: string;
    actionType: GovernanceDecision['actionType'];
    verdict: GovernanceVerdict;
    pillar: GovernancePillar;
    confidence: number;
    reason: string;
    coachMessage: string;
    replay?: GovernanceDecision['replay'];
    quorum?: GovernanceDecision['quorum'];
    originalAction?: string;
    modifiedAction?: string;
    modifications?: string[];
    huntId?: string;
  }): GovernanceDecision {
    const decision: GovernanceDecision = {
      id: uuidv4(),
      timestamp: new Date(),
      agentId: params.agentId,
      agentName: params.agentName,
      action: params.action,
      actionType: params.actionType,
      verdict: params.verdict,
      pillar: params.pillar,
      confidence: params.confidence,
      riskLevel: determineRiskLevel(params.pillar, params.verdict, params.confidence),
      reason: params.reason,
      coachMessage: params.coachMessage,
      replay: params.replay || {},
      quorum: params.quorum,
      originalAction: params.originalAction,
      modifiedAction: params.modifiedAction,
      modifications: params.modifications,
      huntId: params.huntId
    };

    this.decisions.push(decision);

    if (this.decisions.length > 10000) {
      this.decisions = this.decisions.slice(-5000);
    }

    try { this.decisionLogger?.log(decision); } catch { /* non-critical — persistence is best-effort */ }

    this.broadcast('decision', {
      id: decision.id,
      verdict: decision.verdict,
      pillar: decision.pillar,
      riskLevel: decision.riskLevel,
      action: decision.action,
      agentName: decision.agentName,
      coachMessage: decision.coachMessage,
      timestamp: decision.timestamp
    });

    this.audit({
      category: 'governance',
      severity: decision.verdict === 'blocked' ? 'warning' : 'info',
      message: `${decision.verdict.toUpperCase()}: ${decision.action} [${decision.pillar}]`,
      metadata: {
        decisionId: decision.id,
        verdict: decision.verdict,
        pillar: decision.pillar,
        riskLevel: decision.riskLevel,
        confidence: decision.confidence
      },
      huntId: params.huntId,
      agentId: params.agentId,
      governanceDecisionId: decision.id
    });

    return decision;
  }

  audit(params: Omit<AuditEvent, 'id' | 'timestamp'>): AuditEvent {
    const event: AuditEvent = {
      id: uuidv4(),
      timestamp: new Date(),
      ...params
    };

    this.auditLog.push(event);

    if (this.auditLog.length > 50000) {
      this.auditLog = this.auditLog.slice(-25000);
    }

    if (event.severity === 'critical' || event.severity === 'error') {
      this.broadcast('audit', {
        id: event.id,
        category: event.category,
        severity: event.severity,
        message: event.message,
        timestamp: event.timestamp
      });
    }

    return event;
  }

  async verifyScope(target: string, huntId?: string): Promise<{
    inScope: boolean;
    reason: string;
    matchedRule?: string;
    sharedInfraWarning?: string;
  }> {
    for (const allowed of ALWAYS_ALLOWED) {
      if (target.includes(allowed)) {
        return { inScope: true, reason: 'Target is always-allowed domain', matchedRule: allowed };
      }
    }

    const scopeGuard = ScopeGuard.getInstance();
    const programId = huntId && /^\d+$/.test(huntId) ? parseInt(huntId, 10) : null;

    if (programId !== null) {
      const result = await scopeGuard.isInScope(target, programId);
      return { inScope: result.allowed, reason: result.reason, sharedInfraWarning: result.sharedInfraWarning };
    }

    return { inScope: true, reason: 'No program scope defined — open scope' };
  }

  getDecisions(filters?: {
    huntId?: string;
    agentId?: string;
    verdict?: GovernanceVerdict;
    pillar?: GovernancePillar;
    riskLevel?: RiskLevel;
    limit?: number;
  }): GovernanceDecision[] {
    let results = [...this.decisions];

    if (filters?.huntId) results = results.filter(d => d.huntId === filters.huntId);
    if (filters?.agentId) results = results.filter(d => d.agentId === filters.agentId);
    if (filters?.verdict) results = results.filter(d => d.verdict === filters.verdict);
    if (filters?.pillar) results = results.filter(d => d.pillar === filters.pillar);
    if (filters?.riskLevel) results = results.filter(d => d.riskLevel === filters.riskLevel);

    results.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    if (filters?.limit) {
      results = results.slice(0, filters.limit);
    }

    return results;
  }

  getAuditLog(filters?: {
    category?: AuditEvent['category'];
    severity?: AuditEvent['severity'];
    huntId?: string;
    limit?: number;
  }): AuditEvent[] {
    let results = [...this.auditLog];

    if (filters?.category) results = results.filter(e => e.category === filters.category);
    if (filters?.severity) results = results.filter(e => e.severity === filters.severity);
    if (filters?.huntId) results = results.filter(e => e.huntId === filters.huntId);

    results.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    if (filters?.limit) {
      results = results.slice(0, filters.limit);
    }

    return results;
  }

  getStats(): {
    totalDecisions: number;
    verdictCounts: Record<GovernanceVerdict, number>;
    riskCounts: Record<RiskLevel, number>;
    pillarCounts: Record<string, number>;
    totalAuditEvents: number;
  } {
    const verdictCounts: Record<GovernanceVerdict, number> = { approved: 0, modified: 0, blocked: 0 };
    const riskCounts: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    const pillarCounts: Record<string, number> = {};

    for (const d of this.decisions) {
      verdictCounts[d.verdict]++;
      riskCounts[d.riskLevel]++;
      pillarCounts[d.pillar] = (pillarCounts[d.pillar] || 0) + 1;
    }

    return {
      totalDecisions: this.decisions.length,
      verdictCounts,
      riskCounts,
      pillarCounts,
      totalAuditEvents: this.auditLog.length
    };
  }
}

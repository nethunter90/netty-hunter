import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';
import { SelfAttestation, GovernancePillar, RiskLevel } from './types';

const ATTESTATION_DIR = path.join(process.cwd(), 'logs', 'self-attestation');

export class SelfAttestationService {
  private attestations: SelfAttestation[] = [];
  private sessionId: string;

  constructor() {
    this.sessionId = uuidv4();
    try {
      fs.mkdirSync(ATTESTATION_DIR, { recursive: true });
    } catch {}
  }

  attest(params: {
    agentId: string;
    agentName: string;
    action: string;
    justification: string;
    confidence: number;
    targetInfo: string;
    toolsConsidered: string[];
    alternativesRejected?: Array<{ alternative: string; reason: string }>;
    evidenceBasis?: string[];
    riskLevel: RiskLevel;
    riskFactors?: string[];
    riskMitigations?: string[];
    governancePillar: GovernancePillar;
    inputState?: Record<string, any>;
    decisionTree?: Array<{ step: string; options: string[]; chosen: string; reasoning: string }>;
    toolchainSnapshot?: string[];
    huntId?: string;
  }): SelfAttestation {
    const attestation: SelfAttestation = {
      id: uuidv4(),
      timestamp: new Date(),
      agentId: params.agentId,
      agentName: params.agentName,
      action: params.action,
      justification: params.justification,
      confidence: params.confidence,
      context: {
        targetInfo: params.targetInfo,
        toolsConsidered: params.toolsConsidered,
        alternativesRejected: params.alternativesRejected || [],
        evidenceBasis: params.evidenceBasis || [],
        riskAssessment: {
          level: params.riskLevel,
          factors: params.riskFactors || [],
          mitigations: params.riskMitigations || []
        },
        governancePillar: params.governancePillar
      },
      replay: {
        inputState: params.inputState || {},
        decisionTree: params.decisionTree || [],
        toolchainSnapshot: params.toolchainSnapshot || [],
        environmentSnapshot: {
          realToolsMode: process.env.REAL_TOOLS === 'true',
          timestamp: new Date().toISOString(),
          sessionId: this.sessionId
        }
      },
      sessionId: this.sessionId,
      huntId: params.huntId
    };

    this.attestations.push(attestation);

    if (this.attestations.length > 5000) {
      this.attestations = this.attestations.slice(-2500);
    }

    this.persistAttestation(attestation);

    return attestation;
  }

  private persistAttestation(attestation: SelfAttestation): void {
    const date = new Date().toISOString().split('T')[0];
    const file = path.join(ATTESTATION_DIR, `attestations-${date}.ndjson`);
    const line = JSON.stringify({
      ...attestation,
      timestamp: attestation.timestamp instanceof Date
        ? attestation.timestamp.toISOString()
        : attestation.timestamp
    }) + '\n';

    try {
      fs.appendFileSync(file, line);
    } catch (err) {
      console.error('[SelfAttestation] Write error:', err);
    }
  }

  getAttestations(filters?: {
    agentId?: string;
    huntId?: string;
    pillar?: GovernancePillar;
    minConfidence?: number;
    limit?: number;
  }): SelfAttestation[] {
    let results = [...this.attestations];

    if (filters?.agentId) results = results.filter(a => a.agentId === filters.agentId);
    if (filters?.huntId) results = results.filter(a => a.huntId === filters.huntId);
    if (filters?.pillar) results = results.filter(a => a.context.governancePillar === filters.pillar);
    if (filters?.minConfidence) results = results.filter(a => a.confidence >= filters.minConfidence!);

    results.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

    if (filters?.limit) results = results.slice(0, filters.limit);

    return results;
  }

  getAttestationById(id: string): SelfAttestation | null {
    return this.attestations.find(a => a.id === id) || null;
  }

  getAgentAttestationSummary(agentId: string): {
    total: number;
    avgConfidence: number;
    pillarBreakdown: Record<string, number>;
    riskBreakdown: Record<RiskLevel, number>;
    recentActions: string[];
  } {
    const agentAttestations = this.attestations.filter(a => a.agentId === agentId);
    const pillarBreakdown: Record<string, number> = {};
    const riskBreakdown: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0, critical: 0 };

    let totalConfidence = 0;
    for (const a of agentAttestations) {
      totalConfidence += a.confidence;
      pillarBreakdown[a.context.governancePillar] = (pillarBreakdown[a.context.governancePillar] || 0) + 1;
      riskBreakdown[a.context.riskAssessment.level]++;
    }

    return {
      total: agentAttestations.length,
      avgConfidence: agentAttestations.length > 0 ? totalConfidence / agentAttestations.length : 0,
      pillarBreakdown,
      riskBreakdown,
      recentActions: agentAttestations.slice(-10).map(a => a.action)
    };
  }

  readFromDisk(date?: string): SelfAttestation[] {
    const targetDate = date || new Date().toISOString().split('T')[0];
    const file = path.join(ATTESTATION_DIR, `attestations-${targetDate}.ndjson`);

    if (!fs.existsSync(file)) return [];

    try {
      return fs.readFileSync(file, 'utf-8')
        .split('\n')
        .filter(line => line.trim())
        .map(line => {
          try { return JSON.parse(line) as SelfAttestation; } catch { return null; }
        })
        .filter((a): a is SelfAttestation => a !== null);
    } catch {
      return [];
    }
  }

  getStats(): {
    totalInMemory: number;
    sessionId: string;
    avgConfidence: number;
  } {
    const totalConf = this.attestations.reduce((sum, a) => sum + a.confidence, 0);
    return {
      totalInMemory: this.attestations.length,
      sessionId: this.sessionId,
      avgConfidence: this.attestations.length > 0 ? totalConf / this.attestations.length : 0
    };
  }
}

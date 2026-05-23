import { offensiveGraphDB, NodeType, EdgeRelationship } from './offensive-graph-db';
import { eventBus } from '../orchestration/layer3-event-bus';
import { missionMemory } from '../orchestration/mission-memory';
import type { AgentEvent } from '../orchestration/types';

class GraphWiring {
  private wired = false;

  initialize(): void {
    if (this.wired) return;
    this.wired = true;

    eventBus.on('vulnerability_found', (event: AgentEvent) => {
      this.onVulnerabilityFound(event).catch(err => {
        console.error('[GraphWiring] Error processing vulnerability:', err);
      });
    });

    eventBus.on('tool_completed', (event: AgentEvent) => {
      this.onToolCompleted(event).catch(err => {
        console.error('[GraphWiring] Error processing tool result:', err);
      });
    });

    eventBus.on('phase_changed', (event: AgentEvent) => {
      this.onPhaseChanged(event).catch(err => {
        console.error('[GraphWiring] Error processing phase change:', err);
      });
    });

    eventBus.on('endpoint_characterized', (event: AgentEvent) => {
      this.onEndpointCharacterized(event).catch(err => {
        console.error('[GraphWiring] Error processing endpoint:', err);
      });
    });

    eventBus.on('finding_verified', (event: AgentEvent) => {
      this.onFindingVerified(event).catch(err => {
        console.error('[GraphWiring] Error processing finding_verified:', err);
      });
    });

    eventBus.on('finding_rejected', (event: AgentEvent) => {
      this.onFindingRejected(event).catch(err => {
        console.error('[GraphWiring] Error processing finding_rejected:', err);
      });
    });

    console.log('[GraphWiring] Event wiring initialized for offensive graph DB');
  }

  private async onVulnerabilityFound(event: AgentEvent): Promise<void> {
    const huntId = event.huntId;
    if (!huntId) return;

    const vuln = event.data?.vulnerability as any;
    if (!vuln) return;

    const vulnLabel = vuln.type || vuln.title || 'unknown-vuln';
    const vulnNode = await offensiveGraphDB.addNode(huntId, 'vulnerability', vulnLabel, {
      severity: vuln.severity || 'medium',
      confidence: vuln.confidence || 0.7,
      properties: {
        description: vuln.description,
        evidence: typeof vuln.evidence === 'string' ? vuln.evidence.slice(0, 500) : '',
        endpoint: vuln.endpoint,
        cve: vuln.cve,
        cvss: vuln.cvss,
      },
    });

    if (vuln.endpoint) {
      const epNode = await offensiveGraphDB.addNode(huntId, 'endpoint', vuln.endpoint, {
        confidence: 0.9,
        properties: { method: vuln.method || 'GET' },
      });

      await offensiveGraphDB.addEdge(huntId, epNode.id, vulnNode.id, 'targets', {
        weight: SEVERITY_WEIGHT[vuln.severity] || 2,
        properties: { technique: vuln.type },
      });
    }

    const toolName = vuln.discoveredBy || event.data?.tool || 'unknown-tool';
    const toolNode = await offensiveGraphDB.addNode(huntId, 'tool', toolName, {
      confidence: 0.9,
      properties: { agentType: event.agentId },
    });

    await offensiveGraphDB.addEdge(huntId, toolNode.id, vulnNode.id, 'discovered_by', {
      weight: SEVERITY_WEIGHT[vuln.severity] || 2,
      properties: { timestamp: Date.now() },
    });

    if (vuln.type) {
      const technique = mapVulnToTechnique(vuln.type);
      if (technique) {
        const techNode = await offensiveGraphDB.addNode(huntId, 'technique', technique, {
          confidence: 0.8,
          properties: { vulnType: vuln.type },
        });

        await offensiveGraphDB.addEdge(huntId, techNode.id, vulnNode.id, 'exploits', {
          weight: SEVERITY_WEIGHT[vuln.severity] || 2,
        });

        await offensiveGraphDB.addEdge(huntId, toolNode.id, techNode.id, 'produces', {
          weight: 1.5,
        });
      }
    }
  }

  private async onToolCompleted(event: AgentEvent): Promise<void> {
    const huntId = event.huntId;
    if (!huntId) return;

    const toolName = event.data?.tool || event.agentId || 'unknown';
    const target = event.data?.target || '';

    const toolNode = await offensiveGraphDB.addNode(huntId, 'tool', toolName, {
      confidence: 0.9,
      properties: { lastRun: Date.now(), target },
    });

    if (target) {
      const epNode = await offensiveGraphDB.addNode(huntId, 'endpoint', target, {
        confidence: 0.8,
      });

      await offensiveGraphDB.addEdge(huntId, toolNode.id, epNode.id, 'targets', {
        weight: 1.0,
        properties: { action: 'scanned' },
      });
    }
  }

  private async onPhaseChanged(event: AgentEvent): Promise<void> {
    const huntId = event.huntId;
    if (!huntId) return;

    const memory = missionMemory.get(huntId);
    if (!memory) return;

    for (const ep of memory.endpoints) {
      await offensiveGraphDB.addNode(huntId, 'endpoint', ep.url, {
        confidence: 0.9,
        properties: {
          method: ep.method || 'GET',
          statusCode: ep.statusCode,
          title: ep.title,
          discoveredBy: ep.discoveredBy,
        },
      });
    }
  }

  private async onEndpointCharacterized(event: AgentEvent): Promise<void> {
    const huntId = event.huntId;
    if (!huntId) return;

    const ep = event.data?.endpoint as any;
    if (!ep?.url) return;

    const epNode = await offensiveGraphDB.addNode(huntId, 'endpoint', ep.url, {
      confidence: 0.9,
      properties: {
        method: ep.method,
        statusCode: ep.statusCode,
        technologies: ep.technologies,
      },
    });

    if (ep.discoveredBy === 'chain-reasoner') {
      const parentUrl = ep.properties?.parentEndpoint || event.data?.parentEndpoint;
      if (parentUrl) {
        const parentNode = offensiveGraphDB.findNode(huntId, 'endpoint', parentUrl);
        if (parentNode) {
          await offensiveGraphDB.addEdge(huntId, parentNode.id, epNode.id, 'derived_from', {
            weight: 1.5,
            properties: { technique: ep.properties?.technique || 'chain-reasoning' },
          });
        }
      }
    }
  }

  private async onFindingVerified(event: AgentEvent): Promise<void> {
    const huntId = event.huntId;
    if (!huntId) return;
    const vulnType = event.data?.vulnType as string;
    const findingId = String(event.data?.findingId ?? '');
    if (!vulnType || !findingId) return;

    const existing = offensiveGraphDB.findNode(huntId, 'vulnerability', vulnType);
    if (!existing) return;
    // Idempotency: first write for this findingId wins — prevents duplicate events
    // or out-of-order finding_rejected arriving later from overwriting a confirmed verdict.
    if (existing.properties?.verificationId === findingId) return;

    await offensiveGraphDB.addNode(huntId, 'vulnerability', vulnType, {
      properties: {
        verified: true,
        verifiedAt: Date.now(),
        finalConfidence: event.data?.finalConfidence,
        verificationId: findingId,
      },
    });
  }

  private async onFindingRejected(event: AgentEvent): Promise<void> {
    const huntId = event.huntId;
    if (!huntId) return;
    const vulnType = event.data?.vulnType as string;
    const findingId = String(event.data?.findingId ?? '');
    if (!vulnType || !findingId) return;

    const existing = offensiveGraphDB.findNode(huntId, 'vulnerability', vulnType);
    if (!existing) return;
    if (existing.properties?.verificationId === findingId) return;

    await offensiveGraphDB.addNode(huntId, 'vulnerability', vulnType, {
      properties: {
        verified: false,
        rejectedAt: Date.now(),
        verdict: event.data?.verdict,
        verificationId: findingId,
      },
    });
  }

  async populateFromMemory(huntId: string): Promise<{ nodes: number; edges: number }> {
    const memory = missionMemory.get(huntId);
    if (!memory) return { nodes: 0, edges: 0 };

    let nodeCount = 0;
    let edgeCount = 0;

    for (const ep of memory.endpoints) {
      await offensiveGraphDB.addNode(huntId, 'endpoint', ep.url, {
        confidence: 0.9,
        properties: {
          method: ep.method || 'GET',
          statusCode: ep.statusCode,
          title: ep.title,
          discoveredBy: ep.discoveredBy,
        },
      });
      nodeCount++;
    }

    for (const vuln of memory.vulnerabilities) {
      const vulnNode = await offensiveGraphDB.addNode(huntId, 'vulnerability', vuln.type || 'unknown', {
        severity: vuln.severity || 'medium',
        confidence: 0.7,
        properties: {
          description: vuln.description,
          endpoint: vuln.endpoint,
          evidence: typeof vuln.evidence === 'string' ? vuln.evidence.slice(0, 500) : '',
        },
      });
      nodeCount++;

      if (vuln.endpoint) {
        const epNode = offensiveGraphDB.findNode(huntId, 'endpoint', vuln.endpoint);
        if (epNode) {
          await offensiveGraphDB.addEdge(huntId, epNode.id, vulnNode.id, 'targets', {
            weight: SEVERITY_WEIGHT[vuln.severity] || 2,
          });
          edgeCount++;
        }
      }

      const technique = mapVulnToTechnique(vuln.type || '');
      if (technique) {
        const techNode = await offensiveGraphDB.addNode(huntId, 'technique', technique, {
          confidence: 0.8,
        });
        nodeCount++;
        await offensiveGraphDB.addEdge(huntId, techNode.id, vulnNode.id, 'exploits', {
          weight: SEVERITY_WEIGHT[vuln.severity] || 2,
        });
        edgeCount++;
      }
    }

    for (const tech of memory.technologies) {
      const techLabel = typeof tech === 'string' ? tech : (tech as any).name || String(tech);
      await offensiveGraphDB.addNode(huntId, 'technique', `tech:${techLabel}`, {
        confidence: 0.6,
        properties: { category: 'technology-stack' },
      });
      nodeCount++;
    }

    return { nodes: nodeCount, edges: edgeCount };
  }
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

function mapVulnToTechnique(vulnType: string): string | null {
  const lc = vulnType.toLowerCase();
  if (lc.includes('sql') || lc.includes('injection')) return 'SQL-Injection';
  if (lc.includes('xss') || lc.includes('cross-site scripting')) return 'XSS';
  if (lc.includes('csrf')) return 'CSRF';
  if (lc.includes('ssrf')) return 'SSRF';
  if (lc.includes('rce') || lc.includes('remote code')) return 'Remote-Code-Execution';
  if (lc.includes('idor') || lc.includes('insecure direct')) return 'IDOR';
  if (lc.includes('path traversal') || lc.includes('directory traversal') || lc.includes('lfi')) return 'Path-Traversal';
  if (lc.includes('auth') && lc.includes('bypass')) return 'Authentication-Bypass';
  if (lc.includes('cors')) return 'CORS-Misconfiguration';
  if (lc.includes('header') || lc.includes('security header')) return 'Missing-Security-Headers';
  if (lc.includes('info') && lc.includes('disclosure')) return 'Information-Disclosure';
  if (lc.includes('open redirect')) return 'Open-Redirect';
  if (lc.includes('upload') || lc.includes('file upload')) return 'Unrestricted-File-Upload';
  if (lc.includes('deserialization')) return 'Insecure-Deserialization';
  if (lc.includes('xxe')) return 'XXE';
  if (lc.includes('privilege') || lc.includes('escalation')) return 'Privilege-Escalation';
  if (lc.includes('session')) return 'Session-Management';
  if (lc.includes('misconfig')) return 'Misconfiguration';
  return null;
}

export const graphWiring = new GraphWiring();

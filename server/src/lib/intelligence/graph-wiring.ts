import { offensiveGraphDB, NodeType, EdgeRelationship } from './offensive-graph-db';
import { eventBus } from './event-bus';
import { reasoningEngine } from './reasoning-engine';

interface AgentEvent {
  huntId?: string;
  agentId?: string;
  data?: Record<string, unknown>;
}

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
    const toolNode = await offensiveGraphDB.addNode(huntId, 'tool', toolName as string, {
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

    const toolName = (event.data?.tool || event.agentId || 'unknown') as string;
    const target = (event.data?.target || '') as string;

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

    const memory = reasoningEngine.getMissionMemory(huntId);
    if (!memory) return;

    for (const [url] of memory.discoveredEndpoints) {
      await offensiveGraphDB.addNode(huntId, 'endpoint', url, {
        confidence: 0.9,
        properties: { method: 'GET' },
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
        const parentNode = offensiveGraphDB.findNode(huntId, 'endpoint', parentUrl as string);
        if (parentNode) {
          await offensiveGraphDB.addEdge(huntId, parentNode.id, epNode.id, 'derived_from', {
            weight: 1.5,
            properties: { technique: ep.properties?.technique || 'chain-reasoning' },
          });
        }
      }
    }
  }

  async populateFromMemory(huntId: string): Promise<{ nodes: number; edges: number }> {
    const memory = reasoningEngine.getMissionMemory(huntId);
    if (!memory) return { nodes: 0, edges: 0 };

    let nodeCount = 0;
    let edgeCount = 0;

    for (const [url] of memory.discoveredEndpoints) {
      await offensiveGraphDB.addNode(huntId, 'endpoint', url, {
        confidence: 0.9,
        properties: { method: 'GET' },
      });
      nodeCount++;
    }

    for (const [vulnKey] of memory.discoveredVulnerabilities) {
      const vulnNode = await offensiveGraphDB.addNode(huntId, 'vulnerability', vulnKey, {
        severity: 'medium',
        confidence: 0.7,
        properties: { description: vulnKey },
      });
      nodeCount++;

      const technique = mapVulnToTechnique(vulnKey);
      if (technique) {
        const techNode = await offensiveGraphDB.addNode(huntId, 'technique', technique, {
          confidence: 0.8,
        });
        nodeCount++;
        await offensiveGraphDB.addEdge(huntId, techNode.id, vulnNode.id, 'exploits', {
          weight: 2,
        });
        edgeCount++;
      }
    }

    for (const [techKey] of memory.discoveredTechnologies) {
      await offensiveGraphDB.addNode(huntId, 'technique', `tech:${techKey}`, {
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

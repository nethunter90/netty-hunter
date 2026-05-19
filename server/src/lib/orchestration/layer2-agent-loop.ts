import { Agent, AgentType, ResourceClass, StealthLevel, RESOURCE_CLASS_LIMITS } from './types';
import { v4 as uuidv4 } from 'uuid';
import { agentRegistry } from './agent-registry';
import { endpointClaims } from './endpoint-claims';
import { missionMemory } from './mission-memory';
import { eventBus } from './layer3-event-bus';
import { metaAgents } from './layer5-meta-agents';
import { nmapToFindings, extractInjectableTargets } from './tool-parsers';
import { toolRunner } from '../stealth/tool-runner';
import { timingObfuscation } from '../stealth/timing-obfuscation';

interface HuntConfig {
  stealthMode: StealthLevel;
  resourceClass: ResourceClass;
}

interface ActiveToolEntry {
  huntId: string;
  tool: string;
  target: string;
  startedAt: number;
  executionStartedAt: number;
}

export class AgentLoop {
  private timers: Map<string, NodeJS.Timeout> = new Map();
  private completedScans: Set<string> = new Set();
  private huntConfigs: Map<string, HuntConfig> = new Map();
  private activeTools: Map<string, ActiveToolEntry> = new Map();
  private toolCounter = 0;
  private cycleRunning: Set<string> = new Set();

  private configs: Record<string, {
    maxConcurrent: number;
    timeout: number;
    interval: number;
    tools: string[];
  }> = {
    recon: {
      maxConcurrent: 3,
      timeout: 5 * 60 * 1000,
      interval: 5000,
      tools: ['subfinder', 'httpx', 'nmap', 'whatweb', 'crawl', 'amass', 'gobuster', 'ffuf', 'wappalyzer', 'masscan', 'eyewitness']
    },
    scanner: {
      maxConcurrent: 2,
      timeout: 10 * 60 * 1000,
      interval: 5000,
      tools: ['nikto', 'nuclei', 'sqlmap']
    },
    exploit: {
      maxConcurrent: 1,
      timeout: 15 * 60 * 1000,
      interval: 5000,
      tools: ['sqlmap', 'custom_exploit']
    },
    support: {
      maxConcurrent: 5,
      timeout: 1 * 60 * 1000,
      interval: 5000,
      tools: ['hydra', 'hashcat']
    }
  };

  setHuntConfig(huntId: string, stealthMode: StealthLevel, resourceClass: ResourceClass): void {
    this.huntConfigs.set(huntId, { stealthMode, resourceClass });
    console.log(`[AgentLoop] Hunt config set: stealth=${stealthMode}, resource=${resourceClass} for ${huntId}`);
  }

  getHuntConfig(huntId: string): HuntConfig {
    return this.huntConfigs.get(huntId) || { stealthMode: 'balanced', resourceClass: 'standard' };
  }

  private getActiveHeavyToolCount(huntId: string): number {
    const config = this.getHuntConfig(huntId);
    const limits = RESOURCE_CLASS_LIMITS[config.resourceClass];
    let count = 0;
    Array.from(this.activeTools.values()).forEach(entry => {
      if (entry.huntId === huntId && limits.heavyTools.includes(entry.tool)) {
        count++;
      }
    });
    return count;
  }

  private getActiveTotalToolCount(huntId: string): number {
    let count = 0;
    Array.from(this.activeTools.values()).forEach(entry => {
      if (entry.huntId === huntId) count++;
    });
    return count;
  }

  private canRunTool(huntId: string, tool: string): boolean {
    const config = this.getHuntConfig(huntId);
    const limits = RESOURCE_CLASS_LIMITS[config.resourceClass];
    const isHeavy = limits.heavyTools.includes(tool);

    if (this.getActiveTotalToolCount(huntId) >= limits.maxTotalTools) {
      return false;
    }

    if (isHeavy && this.getActiveHeavyToolCount(huntId) >= limits.maxHeavyTools) {
      return false;
    }

    return true;
  }

  private tryAcquireTool(huntId: string, tool: string, target: string): string | null {
    if (!this.canRunTool(huntId, tool)) {
      return null;
    }
    const id = `tool_${++this.toolCounter}`;
    const now = Date.now();
    this.activeTools.set(id, { huntId, tool, target, startedAt: now, executionStartedAt: now });
    return id;
  }

  private registerActiveTool(huntId: string, tool: string, target: string): string {
    const id = `tool_${++this.toolCounter}`;
    const now = Date.now();
    this.activeTools.set(id, { huntId, tool, target, startedAt: now, executionStartedAt: now });
    return id;
  }

  private markExecutionStarted(toolId: string): void {
    const entry = this.activeTools.get(toolId);
    if (entry) {
      entry.executionStartedAt = Date.now();
    }
  }

  private unregisterActiveTool(toolId: string): void {
    this.activeTools.delete(toolId);
  }

  private reconAgentIndex: Map<string, number> = new Map();

  createAgent(type: AgentType, huntId: string): string {
    const config = this.configs[type];

    let tools = config.tools;
    if (type === 'recon') {
      const idx = this.reconAgentIndex.get(huntId) || 0;
      this.reconAgentIndex.set(huntId, idx + 1);
      const allTools = config.tools;
      if (idx === 0) {
        tools = allTools.filter((_, i) => i % 2 === 0);
      } else {
        tools = allTools.filter((_, i) => i % 2 === 1);
      }
      console.log(`[AgentLoop] Recon agent #${idx} tools: ${tools.join(', ')}`);
    }

    const agent: Agent = {
      id: uuidv4(),
      type,
      huntId,
      status: 'idle',
      claimedTargets: [],
      maxConcurrent: config.maxConcurrent,
      timeout: config.timeout,
      startedAt: new Date(),
      lastActivity: new Date(),
      invocations: 0,
      successCount: 0,
      errorCount: 0,
      metadata: {
        availableTools: tools
      }
    };

    agentRegistry.register(agent);
    console.log(`[AgentLoop] Created ${type} agent: ${agent.id}`);

    return agent.id;
  }

  startAgent(agentId: string): void {
    const agent = agentRegistry.get(agentId);
    if (!agent) {
      console.error(`[AgentLoop] Agent not found: ${agentId}`);
      return;
    }

    const config = this.configs[agent.type];

    this.subscribeToEvents(agent);

    const timer = setInterval(async () => {
      await this.executeAgentCycle(agentId);
    }, config.interval);

    this.timers.set(agentId, timer);
    console.log(`[AgentLoop] Started ${agent.type} agent: ${agentId}`);
  }

  private async executeAgentCycle(agentId: string): Promise<void> {
    if (this.cycleRunning.has(agentId)) {
      return;
    }

    const agent = agentRegistry.get(agentId);
    if (!agent || agent.status === 'stopped') {
      return;
    }

    this.cycleRunning.add(agentId);
    try {
      agentRegistry.updateStatus(agentId, 'working');

      let targets = this.getTargets(agent);

      if (targets.length === 0) {
        targets = await this.getTargetsFromEvents(agent);
      }

      if (targets.length === 0) {
        agentRegistry.updateStatus(agentId, 'idle');
        return;
      }

      if (agent.type === 'recon') {
        const primaryTarget = targets[0];
        agentRegistry.updateClaims(agentId, [primaryTarget]);
        console.log(`[AgentLoop] Recon agent ${agentId.substring(0, 8)} working on ${primaryTarget} (no claim lock)`);

        const didWork = await this.executeTask(agent, primaryTarget);

        agentRegistry.updateClaims(agentId, []);
        agentRegistry.updateStatus(agentId, didWork ? 'idle' : 'stopped');
        if (didWork) {
          eventBus.publishClaimReleased(agentId, agent.huntId, primaryTarget);
        }
        return;
      }

      const claimed: string[] = [];
      for (const target of targets) {
        if (claimed.length >= agent.maxConcurrent) break;

        if (endpointClaims.claim(target, agentId)) {
          claimed.push(target);
        }
      }

      if (claimed.length === 0) {
        agentRegistry.updateStatus(agentId, 'waiting');
        return;
      }

      agentRegistry.updateClaims(agentId, claimed);

      const results = await Promise.all(
        claimed.map(target => this.executeTask(agent, target))
      );

      claimed.forEach((target, i) => {
        endpointClaims.release(target, agentId);
        if (results[i]) {
          eventBus.publishClaimReleased(agentId, agent.huntId, target);
        }
      });

      agentRegistry.updateClaims(agentId, []);
      agentRegistry.updateStatus(agentId, 'idle');

    } catch (error) {
      console.error(`[AgentLoop] Error in agent ${agentId}:`, error);
      agentRegistry.updateStatus(agentId, 'errored');
    } finally {
      this.cycleRunning.delete(agentId);
    }
  }

  private getTargets(agent: Agent): string[] {
    const memory = missionMemory.get(agent.huntId);
    if (!memory) return [];

    switch (agent.type) {
      case 'recon': {
        const targets = new Set<string>();
        for (const d of memory.domains) targets.add(d);
        for (const s of memory.subdomains) targets.add(s);
        for (const d of memory.domains) {
          try {
            const parsed = new URL(d.startsWith('http') ? d : `http://${d}`);
            const hostWithPort = parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
            targets.add(hostWithPort);
            targets.add(parsed.hostname);
            targets.add(d.startsWith('http') ? d : `http://${d}`);
          } catch {}
        }
        if (targets.size === 0 && memory.endpoints.length > 0) {
          for (const ep of memory.endpoints) {
            try {
              const parsed = new URL(ep.url);
              const hostWithPort = parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname;
              targets.add(hostWithPort);
              targets.add(ep.url);
            } catch {}
          }
        }
        return [...targets];
      }

      case 'scanner':
        return memory.endpoints.map(e => e.url);

      case 'exploit':
        return memory.endpoints.map(e => e.url);

      case 'support':
        return memory.endpoints.map(e => e.url);

      default:
        return [];
    }
  }

  private async getTargetsFromEvents(agent: Agent): Promise<string[]> {
    const pendingEvents = eventBus.getPending(agent.type, agent.huntId);
    const targets: string[] = [];

    for (const event of pendingEvents) {
      switch (event.type) {
        case 'endpoint_characterized':
          if (agent.type === 'scanner') {
            targets.push(event.data.endpoint.url);
          }
          break;

        case 'scan_complete':
          if (agent.type === 'exploit') {
            targets.push(event.data.target);
          }
          break;

        case 'claim_released': {
          const claimTarget = event.data.target;
          const tools = (agent.metadata?.availableTools as string[]) || [];
          const allDone = tools.every(t => this.completedScans.has(`${agent.huntId}:${t}:${claimTarget}`));
          if (!allDone) {
            targets.push(claimTarget);
          }
          break;
        }
      }

      eventBus.markProcessed(event.id);

      if (targets.length >= agent.maxConcurrent) break;
    }

    return targets;
  }

  private async executeTask(agent: Agent, target: string): Promise<boolean> {
    const metaAgent = metaAgents[agent.type];
    if (!metaAgent) return false;

    const tools = agent.metadata.availableTools as string[];
    const huntConfig = this.getHuntConfig(agent.huntId);
    let didWork = false;

    const phaseType = agent.type === 'recon' ? 'recon' : agent.type === 'exploit' ? 'exploit' : 'scan';

    for (const tool of tools) {
      const runKey = `${agent.huntId}:${tool}:${target}`;
      if (this.completedScans.has(runKey)) {
        continue;
      }

      if (huntConfig.stealthMode !== 'aggressive') {
        const risk = toolRunner.getToolRisk(tool);
        const delay = timingObfuscation.getDelay(phaseType as any, huntConfig.stealthMode, risk, target);
        if (delay > 0) {
          console.log(`[AgentLoop] Stealth delay: ${Math.round(delay / 1000)}s before ${tool} (mode=${huntConfig.stealthMode}, risk=${risk})`);
          await new Promise(r => setTimeout(r, delay));
          const a = agentRegistry.get(agent.id);
          if (!a || a.status === 'stopped') return didWork;
        }
        timingObfuscation.recordAction(target);
      }

      let toolId = this.tryAcquireTool(agent.huntId, tool, target);
      if (!toolId) {
        const limits = RESOURCE_CLASS_LIMITS[huntConfig.resourceClass];
        console.log(`[AgentLoop] Concurrency limit reached for ${tool} (${huntConfig.resourceClass}: max ${limits.maxHeavyTools} heavy). Queuing...`);

        let waited = 0;
        const maxWait = 300000;
        while (!toolId && waited < maxWait) {
          await new Promise(r => setTimeout(r, 5000));
          waited += 5000;
          const a = agentRegistry.get(agent.id);
          if (!a || a.status === 'stopped') return didWork;
          toolId = this.tryAcquireTool(agent.huntId, tool, target);
        }
        if (!toolId) {
          console.log(`[AgentLoop] Concurrency wait timeout for ${tool}, skipping`);
          continue;
        }
      }

      try {
        console.log(`[AgentLoop] ${agent.type} running ${tool} on ${target}`);

        const parameters: Record<string, any> = {};
        parameters.stealthMode = huntConfig.stealthMode;

        if (tool === 'sqlmap') {
          const memory = missionMemory.get(agent.huntId);
          if (memory) {
            const niktoFindings = memory.vulnerabilities
              .filter((v: any) => {
                const ev = typeof v.evidence === 'string' ? v.evidence : '';
                return ev.includes('"tool":"nikto"');
              })
              .map((v: any) => {
                try {
                  const parsed = JSON.parse(v.evidence);
                  return { uri: parsed.uri || '/', description: v.description, severity: v.severity, id: v.id, method: parsed.method || 'GET', osvdbId: parsed.osvdbId };
                } catch { return null; }
              })
              .filter(Boolean);

            const injectableTargets = extractInjectableTargets(niktoFindings as any, target);
            if (injectableTargets.length > 0) {
              parameters.injectableTargets = injectableTargets;
              console.log(`[AgentLoop] SQLMap: ${injectableTargets.length} injectable targets extracted from nikto findings`);
            }
          }
        }

        const result = await metaAgent.execute(agent.id, {
          tool,
          target,
          parameters
        });

        didWork = true;
        this.completedScans.add(runKey);

        if (result.success && result.result) {
          if (result.result.skipped) {
            console.log(`[AgentLoop] ${tool} skipped on ${target}: ${result.result.reason || 'no details'}`);
          } else {
            await this.ingestResults(agent, target, tool, result.result);
          }
        }
      } finally {
        this.unregisterActiveTool(toolId);
      }
    }
    return didWork;
  }

  private async ingestResults(
    agent: Agent,
    target: string,
    tool: string,
    result: any
  ): Promise<void> {
    const huntId = agent.huntId;

    const runKey = `${huntId}:${tool}:${target}`;
    this.completedScans.add(runKey);

    switch (tool) {
      case 'nmap':
        if (result.parsed) {
          const { endpoints, technologies, notes } = nmapToFindings(result.parsed, agent.id);
          if (endpoints.length > 0) {
            missionMemory.addEndpoints(huntId, endpoints);
            endpoints.forEach(e => {
              eventBus.publishEndpointCharacterized(agent.id, huntId, e);
            });
          }
          if (technologies.length > 0) {
            missionMemory.addTechnologies(huntId, technologies.map(t => ({
              ...t, category: t.category || 'unknown', confidence: t.confidence || 0.8
            })));
          }
          notes.forEach(n => missionMemory.addNote(huntId, n));
          console.log(`[AgentLoop] Nmap ingested: ${endpoints.length} endpoints, ${technologies.length} techs`);
        }
        break;

      case 'subfinder':
        if (result.subdomains) {
          missionMemory.addSubdomains(huntId, result.subdomains);
        }
        break;

      case 'httpx':
        if (result.endpoints) {
          const endpoints = result.endpoints.map((e: any) => ({
            url: e.url,
            method: 'GET',
            statusCode: e.status_code,
            title: e.title,
            discoveredBy: agent.id,
            discoveredAt: new Date()
          }));
          missionMemory.addEndpoints(huntId, endpoints);
          endpoints.forEach((e: any) => {
            eventBus.publishEndpointCharacterized(agent.id, huntId, e);
          });
        }
        break;

      case 'whatweb':
        if (result.technologies) {
          const techs = Array.isArray(result.technologies)
            ? result.technologies.map((t: any) => ({
                name: t.name,
                version: t.version,
                category: t.category || 'unknown',
                confidence: t.confidence || 0.7,
              }))
            : [];
          missionMemory.addTechnologies(huntId, techs);
        }
        break;

      case 'crawl':
        if (result.endpoints && Array.isArray(result.endpoints)) {
          const crawlEndpoints = result.endpoints.map((e: any) => ({
            url: e.url,
            method: e.method || 'GET',
            discoveredBy: 'crawl',
            discoveredAt: new Date()
          }));
          missionMemory.addEndpoints(huntId, crawlEndpoints);
          crawlEndpoints.forEach((e: any) => {
            eventBus.publishEndpointCharacterized(agent.id, huntId, e);
          });
          console.log(`[AgentLoop] Crawl ingested: ${crawlEndpoints.length} endpoints`);
        }
        break;

      case 'amass':
        if (result.subdomains && Array.isArray(result.subdomains)) {
          missionMemory.addSubdomains(huntId, result.subdomains);
          console.log(`[AgentLoop] Amass ingested: ${result.subdomains.length} subdomains`);
        }
        break;

      case 'gobuster':
      case 'ffuf':
        if (result.endpoints && Array.isArray(result.endpoints)) {
          const dirEndpoints = result.endpoints.map((e: any) => ({
            url: e.url,
            method: e.method || 'GET',
            statusCode: e.statusCode,
            discoveredBy: tool,
            discoveredAt: new Date()
          }));
          missionMemory.addEndpoints(huntId, dirEndpoints);
          dirEndpoints.forEach((e: any) => {
            eventBus.publishEndpointCharacterized(agent.id, huntId, e);
          });
          console.log(`[AgentLoop] ${tool} ingested: ${dirEndpoints.length} endpoints`);
        }
        break;

      case 'wappalyzer':
        if (result.technologies && Array.isArray(result.technologies)) {
          const wpTechs = result.technologies.map((t: any) => ({
            name: t.name,
            version: t.version,
            category: t.category || 'unknown',
            confidence: t.confidence || 0.8,
          }));
          missionMemory.addTechnologies(huntId, wpTechs);
          console.log(`[AgentLoop] Wappalyzer ingested: ${wpTechs.length} technologies`);
        }
        break;

      case 'masscan':
        if (result.endpoints && Array.isArray(result.endpoints)) {
          const portEndpoints = result.endpoints.map((e: any) => ({
            url: e.url,
            method: e.method || 'TCP',
            service: e.service,
            discoveredBy: 'masscan',
            discoveredAt: new Date()
          }));
          missionMemory.addEndpoints(huntId, portEndpoints);
          portEndpoints.forEach((e: any) => {
            eventBus.publishEndpointCharacterized(agent.id, huntId, e);
          });
          console.log(`[AgentLoop] Masscan ingested: ${portEndpoints.length} port endpoints`);
        }
        if (result.ports && Array.isArray(result.ports)) {
          result.ports.forEach((p: any) => {
            if (p.service) {
              missionMemory.addTechnologies(huntId, [{
                name: p.service,
                category: 'service',
                confidence: 0.7,
              }]);
            }
          });
        }
        break;

      case 'eyewitness':
        if (result.technologies && Array.isArray(result.technologies)) {
          missionMemory.addTechnologies(huntId, result.technologies.map((t: any) => ({
            name: t.name,
            version: t.version,
            category: t.category || 'web-server',
            confidence: t.confidence || 0.7,
          })));
        }
        if (result.screenshots && Array.isArray(result.screenshots)) {
          missionMemory.addNote(huntId, `EyeWitness captured ${result.screenshots.length} screenshot(s): ${result.screenshots.join(', ')}`);
        }
        if (result.reportPath) {
          missionMemory.addNote(huntId, `EyeWitness report: ${result.reportPath}`);
        }
        console.log(`[AgentLoop] EyeWitness ingested: ${(result.technologies || []).length} techs, ${(result.screenshots || []).length} screenshots`);
        break;

      case 'nuclei':
      case 'nikto':
        if (result.vulnerabilities && Array.isArray(result.vulnerabilities)) {
          const vulns = result.vulnerabilities.map((v: any) => ({
            id: v.id || uuidv4(),
            type: v.type || 'unknown',
            severity: v.severity || 'medium',
            endpoint: v.endpoint || target,
            description: v.description || '',
            evidence: typeof v.evidence === 'string' ? v.evidence : JSON.stringify(v),
            exploitable: v.exploitable !== false
          }));
          missionMemory.addVulnerabilities(huntId, vulns);

          vulns.forEach((v: any) => {
            eventBus.publishVulnerabilityFound(agent.id, huntId, v);
          });

          eventBus.publishScanComplete(agent.id, huntId, target, vulns);
          console.log(`[AgentLoop] ${tool} ingested: ${vulns.length} vulnerabilities`);
        }
        if (result.technologies && Array.isArray(result.technologies)) {
          missionMemory.addTechnologies(huntId, result.technologies.map((t: any) => ({
            name: t.name,
            version: t.version,
            category: t.category || 'unknown',
            confidence: t.confidence || 0.7,
          })));
        }
        break;

      case 'sqlmap':
        if (result.vulnerabilities && Array.isArray(result.vulnerabilities)) {
          const vulns = result.vulnerabilities.map((v: any) => ({
            id: v.id || uuidv4(),
            type: v.type || 'SQL Injection',
            severity: v.severity || 'critical',
            endpoint: v.endpoint || target,
            description: v.description || '',
            evidence: typeof v.evidence === 'string' ? v.evidence : JSON.stringify(v),
            exploitable: true,
          }));
          missionMemory.addVulnerabilities(huntId, vulns);

          vulns.forEach((v: any) => {
            eventBus.publishVulnerabilityFound(agent.id, huntId, v);
          });
          console.log(`[AgentLoop] sqlmap ingested: ${vulns.length} SQL injection points`);
        }
        break;
    }
  }

  private subscribeToEvents(agent: Agent): void {
    const subscriptions: Record<string, string[]> = {
      recon: ['mission_phase_complete', 'defense_detected'],
      scanner: ['claim_released', 'endpoint_characterized'],
      exploit: ['scan_complete', 'vulnerability_found'],
      support: ['tool_fallback', 'defense_detected'],
      cognitive: ['vulnerability_found', 'mission_phase_complete']
    };

    const events = subscriptions[agent.type] || [];

    eventBus.subscribe(agent.type, events, (event) => {
      console.log(`[AgentLoop] ${agent.type} received event: ${event.type}`);
    });
  }

  stopAgent(agentId: string): void {
    const timer = this.timers.get(agentId);
    if (timer) {
      clearInterval(timer);
      this.timers.delete(agentId);
    }

    this.cycleRunning.delete(agentId);

    const agent = agentRegistry.get(agentId);
    if (agent) {
      const released = endpointClaims.releaseAll(agentId);
      released.forEach(target => {
        eventBus.publishClaimReleased(agentId, agent.huntId, target);
      });

      agentRegistry.updateStatus(agentId, 'stopped');
      console.log(`[AgentLoop] Stopped agent: ${agentId}`);
    }
  }

  stopAllAgents(huntId: string): void {
    const agents = agentRegistry.getByHunt(huntId);
    agents.forEach(agent => this.stopAgent(agent.id));
    this.reconAgentIndex.delete(huntId);
  }

  isPhaseWorkComplete(huntId: string): boolean {
    const agents = agentRegistry.getByHunt(huntId).filter(a => a.status !== 'stopped');
    if (agents.length === 0) return true;

    const activeEntries = Array.from(this.activeTools.values());
    for (let i = 0; i < activeEntries.length; i++) {
      if (activeEntries[i].huntId === huntId) {
        return false;
      }
    }

    for (const agent of agents) {
      const tools = (agent.metadata.availableTools as string[]) || [];
      const memory = missionMemory.get(huntId);
      if (!memory) continue;

      const targets = this.getTargets(agent);
      const primaryTarget = targets[0];
      if (!primaryTarget) continue;

      for (const tool of tools) {
        const runKey = `${huntId}:${tool}:${primaryTarget}`;
        if (!this.completedScans.has(runKey)) {
          return false;
        }
      }
    }

    return true;
  }

  clearHuntScans(huntId: string): void {
    const prefix = `${huntId}:`;
    const toDelete = Array.from(this.completedScans).filter(key => key.startsWith(prefix));
    toDelete.forEach(key => this.completedScans.delete(key));

    const toolsToRemove: string[] = [];
    Array.from(this.activeTools.entries()).forEach(([id, entry]) => {
      if (entry.huntId === huntId) toolsToRemove.push(id);
    });
    toolsToRemove.forEach(id => this.activeTools.delete(id));

    if (toDelete.length > 0 || toolsToRemove.length > 0) {
      console.log(`[AgentLoop] clearHuntScans: cleared ${toDelete.length} completed scans, ${toolsToRemove.length} active tool entries for ${huntId}`);
    }
  }

  getActiveToolsInfo(huntId: string): { tool: string; target: string; runningFor: number }[] {
    const result: { tool: string; target: string; runningFor: number }[] = [];
    Array.from(this.activeTools.values()).forEach(entry => {
      if (entry.huntId === huntId) {
        result.push({ tool: entry.tool, target: entry.target, runningFor: Date.now() - entry.executionStartedAt });
      }
    });
    return result;
  }

  getStats(huntId: string): any {
    return agentRegistry.getStats(huntId);
  }
}

export const agentLoop = new AgentLoop();

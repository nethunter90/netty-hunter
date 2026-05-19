import fs from 'fs/promises';
import path from 'path';
import {
  ToolExecutionRecord,
  DataFlowEdge,
  ToolFlowDAG,
  Playbook,
  PlaybookStep,
  ExecutionPhase,
} from './intelligence-types';

export interface SynergyScore {
  toolA: string;
  toolB: string;
  score: number;
  sampleSize: number;
  context: string;
}

export interface PlaybookSummary {
  id: string;
  name: string;
  description: string;
  stepCount: number;
  successRate: number;
  timesExecuted: number;
  avgTimeMinutes: number;
  lastUsed: string;
}

export interface PlaybookRecommendation {
  playbook: PlaybookSummary;
  applicabilityScore: number;
  reasoning: string;
}

export interface SynergyMap {
  pairs: SynergyScore[];
  topChains: { tools: string[]; combinedScore: number; sampleSize: number }[];
  lastUpdated: string;
}

interface ToolEffectivenessEntry {
  tool: string;
  totalExecutions: number;
  findingProducingExecutions: number;
  effectivenessRate: number;
}

interface PairStats {
  toolA: string;
  toolB: string;
  coOccurrences: number;
  findingCoOccurrences: number;
  contexts: Record<string, { coOccurrences: number; findingCoOccurrences: number }>;
}

export class ToolSynergyEngine {
  private storageDir: string;
  private synergyScores: PairStats[];
  private toolEffectiveness: Map<string, ToolEffectivenessEntry>;
  private dagCache: Map<string, ToolFlowDAG>;

  constructor(storageDir: string) {
    this.storageDir = path.join(storageDir, 'synergy');
    this.synergyScores = [];
    this.toolEffectiveness = new Map();
    this.dagCache = new Map();
    this.loadState().catch(() => {});
  }

  private async ensureDir(subPath: string): Promise<void> {
    await fs.mkdir(path.join(this.storageDir, subPath), { recursive: true });
  }

  private async loadJson<T>(filePath: string, fallback: T): Promise<T> {
    try {
      const data = await fs.readFile(path.join(this.storageDir, filePath), 'utf-8');
      return JSON.parse(data) as T;
    } catch {
      return fallback;
    }
  }

  private async saveJson(filePath: string, data: any): Promise<void> {
    const full = path.join(this.storageDir, filePath);
    await fs.mkdir(path.dirname(full), { recursive: true });
    await fs.writeFile(full, JSON.stringify(data, null, 2), 'utf-8');
  }

  private async loadState(): Promise<void> {
    const scores = await this.loadJson<PairStats[]>('synergy-scores.json', []);
    this.synergyScores = scores;

    const effectiveness = await this.loadJson<ToolEffectivenessEntry[]>('tool-effectiveness.json', []);
    this.toolEffectiveness.clear();
    for (const entry of effectiveness) {
      this.toolEffectiveness.set(entry.tool, entry);
    }
  }

  private async saveScores(): Promise<void> {
    await this.saveJson('synergy-scores.json', this.synergyScores);
  }

  private async saveEffectiveness(): Promise<void> {
    await this.saveJson(
      'tool-effectiveness.json',
      Array.from(this.toolEffectiveness.values())
    );
  }

  private async loadDAG(campaignId: string): Promise<ToolFlowDAG> {
    if (this.dagCache.has(campaignId)) {
      return this.dagCache.get(campaignId)!;
    }
    const dag = await this.loadJson<ToolFlowDAG | null>(
      `executions/${campaignId}.json`,
      null
    );
    if (dag) {
      this.dagCache.set(campaignId, dag);
      return dag;
    }
    const newDag: ToolFlowDAG = {
      campaignId,
      nodes: [],
      edges: [],
      findingPaths: [],
    };
    this.dagCache.set(campaignId, newDag);
    return newDag;
  }

  private async saveDAG(dag: ToolFlowDAG): Promise<void> {
    await this.saveJson(`executions/${dag.campaignId}.json`, dag);
  }

  async recordExecution(record: ToolExecutionRecord): Promise<void> {
    const dag = await this.loadDAG(record.campaignId);

    dag.nodes.push(record);

    if (record.input.sourceRecordId) {
      const edge: DataFlowEdge = {
        sourceId: record.input.sourceRecordId,
        targetId: record.id,
        consumedFields: record.input.consumedFields,
        fieldMapping: this.inferFieldMapping(dag, record),
      };
      dag.edges.push(edge);
    }

    this.updateToolEffectiveness(record);
    await this.saveDAG(dag);
    await this.saveEffectiveness();
  }

  async completeCampaignDAG(campaignId: string): Promise<void> {
    const dag = await this.loadDAG(campaignId);

    const findingPaths = this.extractFindingPaths(dag);
    dag.findingPaths = findingPaths;

    this.updateSynergyScores(dag);
    await this.saveScores();

    const playbooks = this.generatePlaybooks(dag, findingPaths);
    for (const playbook of playbooks) {
      await this.saveJson(`playbooks/${playbook.id}.json`, playbook);
    }

    await this.saveDAG(dag);
  }

  async getSynergyScores(
    tools?: string[],
    targetProfile?: Record<string, any>
  ): Promise<SynergyScore[]> {
    const context = targetProfile ? this.profileToContext(targetProfile) : null;

    return this.synergyScores
      .filter((ps) => {
        if (tools && tools.length > 0) {
          if (!tools.includes(ps.toolA) && !tools.includes(ps.toolB)) return false;
        }
        return true;
      })
      .map((ps) => {
        const ctxStats = context && ps.contexts[context] ? ps.contexts[context] : null;
        const co = ctxStats ? ctxStats.coOccurrences : ps.coOccurrences;
        const fco = ctxStats ? ctxStats.findingCoOccurrences : ps.findingCoOccurrences;
        const pA = this.getEffectivenessRate(ps.toolA);
        const pB = this.getEffectivenessRate(ps.toolB);
        const pAB = co > 0 ? fco / co : 0;
        const denominator = pA * pB;
        const score = denominator > 0 ? pAB / denominator : 0;

        return {
          toolA: ps.toolA,
          toolB: ps.toolB,
          score: Math.round(score * 1000) / 1000,
          sampleSize: co,
          context: context || 'global',
        };
      })
      .sort((a, b) => b.score - a.score);
  }

  async listPlaybooks(): Promise<PlaybookSummary[]> {
    await this.ensureDir('playbooks');
    const files = await this.readDirSafe('playbooks');
    const summaries: PlaybookSummary[] = [];

    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      const playbook = await this.loadJson<Playbook | null>(`playbooks/${file}`, null);
      if (!playbook) continue;
      summaries.push(this.toPlaybookSummary(playbook));
    }

    return summaries.sort((a, b) => b.successRate - a.successRate);
  }

  async getPlaybook(id: string): Promise<Playbook | null> {
    return this.loadJson<Playbook | null>(`playbooks/${id}.json`, null);
  }

  async recommendPlaybooks(
    targetProfile: Record<string, any>
  ): Promise<PlaybookRecommendation[]> {
    const playbooks = await this.listAllPlaybooks();
    const recommendations: PlaybookRecommendation[] = [];

    for (const playbook of playbooks) {
      const { score, reasoning } = this.computeApplicability(playbook, targetProfile);
      if (score > 0) {
        recommendations.push({
          playbook: this.toPlaybookSummary(playbook),
          applicabilityScore: Math.round(score * 1000) / 1000,
          reasoning,
        });
      }
    }

    return recommendations.sort((a, b) => b.applicabilityScore - a.applicabilityScore);
  }

  async updatePlaybookStats(
    playbookId: string,
    success: boolean,
    timeMinutes: number,
    findingSeverity?: number
  ): Promise<void> {
    const playbook = await this.getPlaybook(playbookId);
    if (!playbook) return;

    const stats = playbook.stats;
    const prevTotal = stats.timesUsed;
    stats.timesUsed += 1;
    stats.avgDurationMinutes =
      (stats.avgDurationMinutes * prevTotal + timeMinutes) / stats.timesUsed;
    stats.successRate =
      (stats.successRate * prevTotal + (success ? 1 : 0)) / stats.timesUsed;
    if (success && findingSeverity !== undefined) {
      stats.avgFindingsPerRun =
        (stats.avgFindingsPerRun * prevTotal + findingSeverity) / stats.timesUsed;
    }
    stats.lastUsed = new Date().toISOString();

    await this.saveJson(`playbooks/${playbookId}.json`, playbook);
  }

  async getSynergyMap(): Promise<SynergyMap> {
    const pairs = await this.getSynergyScores();
    const chains = this.extractTopChains(pairs);

    return {
      pairs,
      topChains: chains,
      lastUpdated: new Date().toISOString(),
    };
  }

  private inferFieldMapping(
    dag: ToolFlowDAG,
    record: ToolExecutionRecord
  ): Record<string, string> {
    const mapping: Record<string, string> = {};
    if (!record.input.sourceRecordId) return mapping;

    const sourceNode = dag.nodes.find((n) => n.id === record.input.sourceRecordId);
    if (!sourceNode) return mapping;

    for (const field of record.input.consumedFields) {
      if (field in sourceNode.output.structuredFields) {
        mapping[field] = field;
      }
    }
    return mapping;
  }

  private updateToolEffectiveness(record: ToolExecutionRecord): void {
    let entry = this.toolEffectiveness.get(record.tool);
    if (!entry) {
      entry = {
        tool: record.tool,
        totalExecutions: 0,
        findingProducingExecutions: 0,
        effectivenessRate: 0,
      };
      this.toolEffectiveness.set(record.tool, entry);
    }
    entry.totalExecutions += 1;
    if (record.effectiveness.ledToFinding) {
      entry.findingProducingExecutions += 1;
    }
    entry.effectivenessRate =
      entry.totalExecutions > 0
        ? entry.findingProducingExecutions / entry.totalExecutions
        : 0;
  }

  private getEffectivenessRate(tool: string): number {
    const entry = this.toolEffectiveness.get(tool);
    return entry ? entry.effectivenessRate : 0.1;
  }

  private extractFindingPaths(dag: ToolFlowDAG): string[][] {
    const adjacency = new Map<string, string[]>();
    for (const edge of dag.edges) {
      if (!adjacency.has(edge.sourceId)) adjacency.set(edge.sourceId, []);
      adjacency.get(edge.sourceId)!.push(edge.targetId);
    }

    const targetIds = new Set(dag.edges.map((e) => e.targetId));
    const rootNodes = dag.nodes.filter((n) => !targetIds.has(n.id));

    const findingNodes = new Set(
      dag.nodes.filter((n) => n.effectiveness.ledToFinding).map((n) => n.id)
    );

    const paths: string[][] = [];

    for (const root of rootNodes) {
      this.dfs(root.id, [root.id], adjacency, findingNodes, paths);
    }

    return paths;
  }

  private dfs(
    nodeId: string,
    currentPath: string[],
    adjacency: Map<string, string[]>,
    findingNodes: Set<string>,
    result: string[][]
  ): void {
    if (findingNodes.has(nodeId)) {
      result.push([...currentPath]);
    }

    const neighbors = adjacency.get(nodeId) || [];
    for (const neighbor of neighbors) {
      if (!currentPath.includes(neighbor)) {
        currentPath.push(neighbor);
        this.dfs(neighbor, currentPath, adjacency, findingNodes, result);
        currentPath.pop();
      }
    }
  }

  private updateSynergyScores(dag: ToolFlowDAG): void {
    const nodeMap = new Map<string, ToolExecutionRecord>();
    for (const node of dag.nodes) {
      nodeMap.set(node.id, node);
    }

    for (const edge of dag.edges) {
      const source = nodeMap.get(edge.sourceId);
      const target = nodeMap.get(edge.targetId);
      if (!source || !target) continue;

      const toolA = source.tool;
      const toolB = target.tool;
      const producedFinding =
        source.effectiveness.ledToFinding || target.effectiveness.ledToFinding;

      let pair = this.synergyScores.find(
        (p) => p.toolA === toolA && p.toolB === toolB
      );
      if (!pair) {
        pair = {
          toolA,
          toolB,
          coOccurrences: 0,
          findingCoOccurrences: 0,
          contexts: {},
        };
        this.synergyScores.push(pair);
      }

      pair.coOccurrences += 1;
      if (producedFinding) pair.findingCoOccurrences += 1;

      const ctx = source.phase;
      if (!pair.contexts[ctx]) {
        pair.contexts[ctx] = { coOccurrences: 0, findingCoOccurrences: 0 };
      }
      pair.contexts[ctx].coOccurrences += 1;
      if (producedFinding) pair.contexts[ctx].findingCoOccurrences += 1;
    }
  }

  private generatePlaybooks(dag: ToolFlowDAG, findingPaths: string[][]): Playbook[] {
    const nodeMap = new Map<string, ToolExecutionRecord>();
    for (const node of dag.nodes) {
      nodeMap.set(node.id, node);
    }

    const playbooks: Playbook[] = [];
    const seen = new Set<string>();

    for (const p of findingPaths) {
      const toolChain = p
        .map((id) => nodeMap.get(id)?.tool)
        .filter((t): t is string => !!t);
      const chainKey = toolChain.join('->');
      if (seen.has(chainKey)) continue;
      seen.add(chainKey);

      const steps: PlaybookStep[] = toolChain.map((tool, idx) => {
        const record = nodeMap.get(p[idx]);
        return {
          order: idx + 1,
          tool,
          phase: record?.phase || ('recon' as ExecutionPhase),
          defaultParams: this.abstractParams(record?.input.params || {}),
          inputMapping: idx > 0 ? this.buildInputMapping(dag, p[idx - 1], p[idx]) : {},
          requiredOutputFields: record
            ? Object.keys(record.output.structuredFields)
            : [],
          gateCondition:
            record && record.effectiveness.producedActionableOutput
              ? 'hasActionableOutput'
              : null,
        };
      });

      const playbookId = `pb-${dag.campaignId}-${playbooks.length + 1}`;
      const playbook: Playbook = {
        id: playbookId,
        name: `${toolChain[0]}-to-${toolChain[toolChain.length - 1]}`,
        steps,
        applicableWhen: {
          techStack: {},
          defenseProfile: {},
          huntGoal: [],
        },
        stats: {
          timesUsed: 0,
          successRate: 0,
          avgFindingsPerRun: 0,
          avgDurationMinutes: 0,
          lastUsed: null,
        },
      };

      playbooks.push(playbook);
    }

    return playbooks;
  }

  private abstractParams(params: Record<string, unknown>): Record<string, unknown> {
    const abstracted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string' && (value.includes('.') || value.includes('/'))) {
        abstracted[key] = `{{${key}}}`;
      } else {
        abstracted[key] = value;
      }
    }
    return abstracted;
  }

  private buildInputMapping(
    dag: ToolFlowDAG,
    sourceId: string,
    targetId: string
  ): Record<string, string> {
    const edge = dag.edges.find(
      (e) => e.sourceId === sourceId && e.targetId === targetId
    );
    return edge ? edge.fieldMapping : {};
  }

  private profileToContext(profile: Record<string, any>): string {
    const parts: string[] = [];
    if (profile.industry) parts.push(profile.industry);
    if (profile.techStack?.framework) parts.push(profile.techStack.framework);
    if (profile.defenseProfile?.wafType) parts.push(profile.defenseProfile.wafType);
    return parts.length > 0 ? parts.join(':') : 'default';
  }

  private toPlaybookSummary(playbook: Playbook): PlaybookSummary {
    const tools = playbook.steps.map((s) => s.tool);
    return {
      id: playbook.id,
      name: playbook.name,
      description: `${tools.join(' → ')} (${playbook.steps.length} steps)`,
      stepCount: playbook.steps.length,
      successRate: playbook.stats.successRate,
      timesExecuted: playbook.stats.timesUsed,
      avgTimeMinutes: playbook.stats.avgDurationMinutes,
      lastUsed: playbook.stats.lastUsed || '',
    };
  }

  private computeApplicability(
    playbook: Playbook,
    targetProfile: Record<string, any>
  ): { score: number; reasoning: string } {
    let score = 0;
    const reasons: string[] = [];

    if (playbook.applicableWhen.huntGoal.length > 0 && targetProfile.huntGoal) {
      if (playbook.applicableWhen.huntGoal.includes(targetProfile.huntGoal)) {
        score += 0.3;
        reasons.push(`Matches hunt goal: ${targetProfile.huntGoal}`);
      }
    }

    const techStack = playbook.applicableWhen.techStack;
    if (techStack && targetProfile.techStack) {
      let techMatches = 0;
      let techTotal = 0;
      for (const [key, value] of Object.entries(techStack)) {
        if (value) {
          techTotal++;
          if (targetProfile.techStack[key] === value) techMatches++;
        }
      }
      if (techTotal > 0) {
        const techScore = (techMatches / techTotal) * 0.3;
        score += techScore;
        if (techMatches > 0)
          reasons.push(`Tech stack match: ${techMatches}/${techTotal}`);
      }
    }

    const defProfile = playbook.applicableWhen.defenseProfile;
    if (defProfile && targetProfile.defenseProfile) {
      let defMatches = 0;
      let defTotal = 0;
      for (const [key, value] of Object.entries(defProfile)) {
        if (value !== undefined && value !== null) {
          defTotal++;
          if (targetProfile.defenseProfile[key] === value) defMatches++;
        }
      }
      if (defTotal > 0) {
        const defScore = (defMatches / defTotal) * 0.2;
        score += defScore;
        if (defMatches > 0)
          reasons.push(`Defense profile match: ${defMatches}/${defTotal}`);
      }
    }

    if (playbook.stats.timesUsed > 0) {
      score += playbook.stats.successRate * 0.2;
      reasons.push(
        `Historical success rate: ${(playbook.stats.successRate * 100).toFixed(0)}%`
      );
    }

    if (reasons.length === 0) {
      score = 0.1;
      reasons.push('No specific match criteria; baseline recommendation');
    }

    return {
      score: Math.min(score, 1),
      reasoning: reasons.join('; '),
    };
  }

  private async readDirSafe(subPath: string): Promise<string[]> {
    try {
      return await fs.readdir(path.join(this.storageDir, subPath));
    } catch {
      return [];
    }
  }

  private async listAllPlaybooks(): Promise<Playbook[]> {
    await this.ensureDir('playbooks');
    const files = await this.readDirSafe('playbooks');
    const playbooks: Playbook[] = [];
    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      const pb = await this.loadJson<Playbook | null>(`playbooks/${file}`, null);
      if (pb) playbooks.push(pb);
    }
    return playbooks;
  }

  private extractTopChains(
    pairs: SynergyScore[]
  ): { tools: string[]; combinedScore: number; sampleSize: number }[] {
    const chains: { tools: string[]; combinedScore: number; sampleSize: number }[] = [];
    const adjacency = new Map<string, SynergyScore[]>();

    for (const pair of pairs) {
      if (!adjacency.has(pair.toolA)) adjacency.set(pair.toolA, []);
      adjacency.get(pair.toolA)!.push(pair);
    }

    for (const pair of pairs) {
      if (pair.score <= 1.0) continue;

      const extensions = adjacency.get(pair.toolB) || [];
      for (const ext of extensions) {
        if (ext.score <= 1.0) continue;
        if (ext.toolB === pair.toolA) continue;

        chains.push({
          tools: [pair.toolA, pair.toolB, ext.toolB],
          combinedScore:
            Math.round(pair.score * ext.score * 1000) / 1000,
          sampleSize: Math.min(pair.sampleSize, ext.sampleSize),
        });
      }
    }

    chains.sort((a, b) => b.combinedScore - a.combinedScore);
    return chains.slice(0, 20);
  }
}

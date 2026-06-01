import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../../db';

export type NodeType = 'endpoint' | 'vulnerability' | 'tool' | 'technique' | 'payload';
export type EdgeRelationship = 'discovered_by' | 'derived_from' | 'confirmed_by' | 'exploits' | 'targets' | 'chains_to' | 'produces' | 'requires';

export interface GraphNodeData {
  id: string;
  huntId: string;
  nodeType: NodeType;
  label: string;
  confidence: number;
  severity?: string;
  properties: Record<string, any>;
  createdAt: number;
}

export interface GraphEdgeData {
  id: string;
  huntId: string;
  sourceId: string;
  targetId: string;
  relationship: EdgeRelationship;
  weight: number;
  properties: Record<string, any>;
  createdAt: number;
}

export interface AttackPathResult {
  path: GraphNodeData[];
  edges: GraphEdgeData[];
  totalWeight: number;
  maxSeverity: string;
  confidence: number;
}

export interface CentralityResult {
  nodeId: string;
  label: string;
  nodeType: NodeType;
  degree: number;
  inDegree: number;
  outDegree: number;
  betweenness: number;
  pageRank: number;
  compositeScore: number;
}

export interface PatternResult {
  pattern: string;
  frequency: number;
  confidence: number;
  nodeTypes: string[];
  relationships: string[];
  huntIds: string[];
  examplePath: string[];
}

export interface GraphStats {
  totalNodes: number;
  totalEdges: number;
  nodesByType: Record<string, number>;
  edgesByRelationship: Record<string, number>;
  huntCount: number;
  avgDegree: number;
  density: number;
  connectedComponents: number;
}

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

class OffensiveGraphDB extends EventEmitter {
  private nodes: Map<string, GraphNodeData> = new Map();
  private edges: Map<string, GraphEdgeData> = new Map();
  private adjacency: Map<string, Set<string>> = new Map();
  private reverseAdj: Map<string, Set<string>> = new Map();
  private nodesByHunt: Map<string, Set<string>> = new Map();
  private nodesByType: Map<NodeType, Set<string>> = new Map();
  private nodesByLabel: Map<string, Set<string>> = new Map();
  private initialized = false;

  // Write-through analytics cache — invalidated on every node/edge mutation.
  // Prevents re-running O(N²) path-ranking and PageRank on every tool-selection tick.
  private huntCentralityCache: Map<string, CentralityResult[]> = new Map();
  private huntPathsCache: Map<string, AttackPathResult[]> = new Map();

  async initialize(): Promise<void> {
    if (this.initialized) return;
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS "graph_nodes" (
          "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
          "hunt_id" varchar NOT NULL,
          "node_type" text NOT NULL,
          "label" text NOT NULL,
          "confidence" real NOT NULL DEFAULT 0.5,
          "severity" text,
          "properties" jsonb DEFAULT '{}',
          "created_at" timestamp DEFAULT now()
        )
      `);
      await pool.query(`
        CREATE TABLE IF NOT EXISTS "graph_edges" (
          "id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
          "hunt_id" varchar NOT NULL,
          "source_id" varchar NOT NULL,
          "target_id" varchar NOT NULL,
          "relationship" text NOT NULL,
          "weight" real NOT NULL DEFAULT 1.0,
          "properties" jsonb DEFAULT '{}',
          "created_at" timestamp DEFAULT now()
        )
      `);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_graph_nodes_hunt ON graph_nodes(hunt_id)`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type)`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_graph_edges_hunt ON graph_edges(hunt_id)`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_id)`);
      await pool.query(`CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_id)`);
      this.initialized = true;
      await this.loadFromDb();
      console.log(`[OffensiveGraphDB] Initialized: ${this.nodes.size} nodes, ${this.edges.size} edges`);
    } catch (err) {
      this.initialized = true;
      console.error(`[OffensiveGraphDB] Init error:`, err);
    }
  }

  private async loadFromDb(): Promise<void> {
    try {
      const nodesResult = await pool.query(`SELECT * FROM graph_nodes ORDER BY created_at ASC`);
      for (const row of nodesResult.rows) {
        const node: GraphNodeData = {
          id: row.id,
          huntId: row.hunt_id,
          nodeType: row.node_type as NodeType,
          label: row.label,
          confidence: row.confidence ?? 0.5,
          severity: row.severity || undefined,
          properties: typeof row.properties === 'string' ? JSON.parse(row.properties) : (row.properties || {}),
          createdAt: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
        };
        this.indexNode(node);
      }

      const edgesResult = await pool.query(`SELECT * FROM graph_edges ORDER BY created_at ASC`);
      for (const row of edgesResult.rows) {
        const edge: GraphEdgeData = {
          id: row.id,
          huntId: row.hunt_id,
          sourceId: row.source_id,
          targetId: row.target_id,
          relationship: row.relationship as EdgeRelationship,
          weight: row.weight ?? 1.0,
          properties: typeof row.properties === 'string' ? JSON.parse(row.properties) : (row.properties || {}),
          createdAt: row.created_at ? new Date(row.created_at).getTime() : Date.now(),
        };
        this.indexEdge(edge);
      }
    } catch (_err) {}
  }

  private indexNode(node: GraphNodeData): void {
    this.nodes.set(node.id, node);
    if (!this.adjacency.has(node.id)) this.adjacency.set(node.id, new Set());
    if (!this.reverseAdj.has(node.id)) this.reverseAdj.set(node.id, new Set());

    if (!this.nodesByHunt.has(node.huntId)) this.nodesByHunt.set(node.huntId, new Set());
    this.nodesByHunt.get(node.huntId)!.add(node.id);

    if (!this.nodesByType.has(node.nodeType)) this.nodesByType.set(node.nodeType, new Set());
    this.nodesByType.get(node.nodeType)!.add(node.id);

    const labelKey = `${node.nodeType}:${node.label}`.toLowerCase();
    if (!this.nodesByLabel.has(labelKey)) this.nodesByLabel.set(labelKey, new Set());
    this.nodesByLabel.get(labelKey)!.add(node.id);
  }

  private indexEdge(edge: GraphEdgeData): void {
    this.edges.set(edge.id, edge);
    if (!this.adjacency.has(edge.sourceId)) this.adjacency.set(edge.sourceId, new Set());
    this.adjacency.get(edge.sourceId)!.add(edge.id);
    if (!this.reverseAdj.has(edge.targetId)) this.reverseAdj.set(edge.targetId, new Set());
    this.reverseAdj.get(edge.targetId)!.add(edge.id);
  }

  async addNode(huntId: string, nodeType: NodeType, label: string, opts?: {
    confidence?: number;
    severity?: string;
    properties?: Record<string, any>;
    id?: string;
  }): Promise<GraphNodeData> {
    await this.initialize();

    const existing = this.findNode(huntId, nodeType, label);
    if (existing) {
      if (opts?.confidence && opts.confidence > existing.confidence) {
        existing.confidence = opts.confidence;
      }
      if (opts?.properties) {
        existing.properties = { ...existing.properties, ...opts.properties };
      }
      return existing;
    }

    const node: GraphNodeData = {
      id: opts?.id || uuidv4(),
      huntId,
      nodeType,
      label,
      confidence: opts?.confidence ?? 0.5,
      severity: opts?.severity,
      properties: opts?.properties || {},
      createdAt: Date.now(),
    };

    this.indexNode(node);
    this.huntCentralityCache.delete(node.huntId);
    this.huntPathsCache.delete(node.huntId);

    try {
      await pool.query(
        `INSERT INTO graph_nodes (id, hunt_id, node_type, label, confidence, severity, properties) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
        [node.id, node.huntId, node.nodeType, node.label, node.confidence, node.severity || null, JSON.stringify(node.properties)]
      );
    } catch (_err) {}

    this.emit('node:added', node);
    return node;
  }

  async addEdge(huntId: string, sourceId: string, targetId: string, relationship: EdgeRelationship, opts?: {
    weight?: number;
    properties?: Record<string, any>;
    id?: string;
  }): Promise<GraphEdgeData> {
    await this.initialize();

    const existing = this.findEdge(sourceId, targetId, relationship);
    if (existing) {
      if (opts?.weight && opts.weight > existing.weight) {
        existing.weight = opts.weight;
      }
      return existing;
    }

    const edge: GraphEdgeData = {
      id: opts?.id || uuidv4(),
      huntId,
      sourceId,
      targetId,
      relationship,
      weight: opts?.weight ?? 1.0,
      properties: opts?.properties || {},
      createdAt: Date.now(),
    };

    this.indexEdge(edge);
    this.huntCentralityCache.delete(edge.huntId);
    this.huntPathsCache.delete(edge.huntId);

    try {
      await pool.query(
        `INSERT INTO graph_edges (id, hunt_id, source_id, target_id, relationship, weight, properties) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
        [edge.id, edge.huntId, edge.sourceId, edge.targetId, edge.relationship, edge.weight, JSON.stringify(edge.properties)]
      );
    } catch (_err) {}

    this.emit('edge:added', edge);
    return edge;
  }

  findNode(huntId: string, nodeType: NodeType, label: string): GraphNodeData | null {
    const labelKey = `${nodeType}:${label}`.toLowerCase();
    const candidates = this.nodesByLabel.get(labelKey);
    if (!candidates) return null;
    for (const id of candidates) {
      const node = this.nodes.get(id);
      if (node && node.huntId === huntId) return node;
    }
    return null;
  }

  findNodeGlobal(nodeType: NodeType, label: string): GraphNodeData[] {
    const labelKey = `${nodeType}:${label}`.toLowerCase();
    const candidates = this.nodesByLabel.get(labelKey);
    if (!candidates) return [];
    return Array.from(candidates).map(id => this.nodes.get(id)!).filter(Boolean);
  }

  private findEdge(sourceId: string, targetId: string, relationship: EdgeRelationship): GraphEdgeData | null {
    const edgeIds = this.adjacency.get(sourceId);
    if (!edgeIds) return null;
    for (const eid of edgeIds) {
      const edge = this.edges.get(eid);
      if (edge && edge.targetId === targetId && edge.relationship === relationship) return edge;
    }
    return null;
  }

  getNode(id: string): GraphNodeData | null {
    return this.nodes.get(id) || null;
  }

  getEdge(id: string): GraphEdgeData | null {
    return this.edges.get(id) || null;
  }

  getNeighbors(nodeId: string, direction: 'out' | 'in' | 'both' = 'both'): GraphNodeData[] {
    const result = new Set<string>();
    if (direction === 'out' || direction === 'both') {
      const outEdges = this.adjacency.get(nodeId);
      if (outEdges) {
        for (const eid of outEdges) {
          const edge = this.edges.get(eid);
          if (edge) result.add(edge.targetId);
        }
      }
    }
    if (direction === 'in' || direction === 'both') {
      const inEdges = this.reverseAdj.get(nodeId);
      if (inEdges) {
        for (const eid of inEdges) {
          const edge = this.edges.get(eid);
          if (edge) result.add(edge.sourceId);
        }
      }
    }
    return Array.from(result).map(id => this.nodes.get(id)!).filter(Boolean);
  }

  getEdgesFrom(nodeId: string): GraphEdgeData[] {
    const edgeIds = this.adjacency.get(nodeId);
    if (!edgeIds) return [];
    return Array.from(edgeIds).map(id => this.edges.get(id)!).filter(Boolean);
  }

  getEdgesTo(nodeId: string): GraphEdgeData[] {
    const edgeIds = this.reverseAdj.get(nodeId);
    if (!edgeIds) return [];
    return Array.from(edgeIds).map(id => this.edges.get(id)!).filter(Boolean);
  }

  getHuntNodes(huntId: string): GraphNodeData[] {
    const ids = this.nodesByHunt.get(huntId);
    if (!ids) return [];
    return Array.from(ids).map(id => this.nodes.get(id)!).filter(Boolean);
  }

  getHuntEdges(huntId: string): GraphEdgeData[] {
    return Array.from(this.edges.values()).filter(e => e.huntId === huntId);
  }

  getNodesByType(nodeType: NodeType): GraphNodeData[] {
    const ids = this.nodesByType.get(nodeType);
    if (!ids) return [];
    return Array.from(ids).map(id => this.nodes.get(id)!).filter(Boolean);
  }

  findShortestPath(startId: string, endId: string, maxDepth = 10): AttackPathResult | null {
    if (!this.nodes.has(startId) || !this.nodes.has(endId)) return null;
    if (startId === endId) return { path: [this.nodes.get(startId)!], edges: [], totalWeight: 0, maxSeverity: 'info', confidence: 1 };

    const visited = new Set<string>();
    const queue: Array<{ nodeId: string; path: string[]; edges: string[]; weight: number; depth: number }> = [
      { nodeId: startId, path: [startId], edges: [], weight: 0, depth: 0 }
    ];

    while (queue.length > 0) {
      queue.sort((a, b) => a.weight - b.weight);
      const current = queue.shift()!;

      if (current.nodeId === endId) {
        const pathNodes = current.path.map(id => this.nodes.get(id)!).filter(Boolean);
        const pathEdges = current.edges.map(id => this.edges.get(id)!).filter(Boolean);
        let maxSev = 'info';
        let minConf = 1;
        for (const n of pathNodes) {
          if (n.severity && (SEVERITY_WEIGHT[n.severity] || 0) > (SEVERITY_WEIGHT[maxSev] || 0)) maxSev = n.severity;
          if (n.confidence < minConf) minConf = n.confidence;
        }
        return { path: pathNodes, edges: pathEdges, totalWeight: current.weight, maxSeverity: maxSev, confidence: minConf };
      }

      if (current.depth >= maxDepth) continue;
      if (visited.has(current.nodeId)) continue;
      visited.add(current.nodeId);

      const outEdges = this.adjacency.get(current.nodeId);
      if (!outEdges) continue;

      for (const eid of outEdges) {
        const edge = this.edges.get(eid);
        if (!edge || visited.has(edge.targetId)) continue;
        queue.push({
          nodeId: edge.targetId,
          path: [...current.path, edge.targetId],
          edges: [...current.edges, eid],
          weight: current.weight + (1 / edge.weight),
          depth: current.depth + 1,
        });
      }
    }
    return null;
  }

  findAllPaths(startId: string, endId: string, maxDepth = 6): AttackPathResult[] {
    if (!this.nodes.has(startId) || !this.nodes.has(endId)) return [];
    const results: AttackPathResult[] = [];

    const dfs = (nodeId: string, path: string[], edges: string[], visited: Set<string>, depth: number) => {
      if (depth > maxDepth) return;
      if (nodeId === endId && path.length > 1) {
        const pathNodes = path.map(id => this.nodes.get(id)!).filter(Boolean);
        const pathEdges = edges.map(id => this.edges.get(id)!).filter(Boolean);
        let maxSev = 'info';
        let totalWeight = 0;
        let minConf = 1;
        for (const n of pathNodes) {
          if (n.severity && (SEVERITY_WEIGHT[n.severity] || 0) > (SEVERITY_WEIGHT[maxSev] || 0)) maxSev = n.severity;
          if (n.confidence < minConf) minConf = n.confidence;
        }
        for (const e of pathEdges) totalWeight += (1 / e.weight);
        results.push({ path: pathNodes, edges: pathEdges, totalWeight, maxSeverity: maxSev, confidence: minConf });
        return;
      }

      const outEdges = this.adjacency.get(nodeId);
      if (!outEdges) return;

      for (const eid of outEdges) {
        const edge = this.edges.get(eid);
        if (!edge || visited.has(edge.targetId)) continue;
        visited.add(edge.targetId);
        dfs(edge.targetId, [...path, edge.targetId], [...edges, eid], visited, depth + 1);
        visited.delete(edge.targetId);
      }
    };

    const visited = new Set<string>([startId]);
    dfs(startId, [startId], [], visited, 0);

    return results.sort((a, b) => a.totalWeight - b.totalWeight);
  }

  rankAttackPaths(huntId: string, targetType: NodeType = 'vulnerability'): AttackPathResult[] {
    const cacheKey = `${huntId}:${targetType}`;
    const cached = this.huntPathsCache.get(cacheKey);
    if (cached) return cached;

    const endpoints = this.getHuntNodes(huntId).filter(n => n.nodeType === 'endpoint');
    const targets = this.getHuntNodes(huntId).filter(n => n.nodeType === targetType);

    const allPaths: AttackPathResult[] = [];
    for (const ep of endpoints) {
      for (const vuln of targets) {
        const paths = this.findAllPaths(ep.id, vuln.id, 6);
        allPaths.push(...paths);
      }
    }

    const result = allPaths.sort((a, b) => {
      const sevDiff = (SEVERITY_WEIGHT[b.maxSeverity] || 0) - (SEVERITY_WEIGHT[a.maxSeverity] || 0);
      if (sevDiff !== 0) return sevDiff;
      const confDiff = b.confidence - a.confidence;
      if (Math.abs(confDiff) > 0.1) return confDiff;
      return a.totalWeight - b.totalWeight;
    }).slice(0, 50);

    this.huntPathsCache.set(cacheKey, result);
    return result;
  }

  computeCentrality(huntId?: string): CentralityResult[] {
    if (huntId) {
      const cached = this.huntCentralityCache.get(huntId);
      if (cached) return cached;
    }

    const nodeIds = huntId
      ? Array.from(this.nodesByHunt.get(huntId) || [])
      : Array.from(this.nodes.keys());

    if (nodeIds.length === 0) return [];

    const nodeSet = new Set(nodeIds);
    const results: CentralityResult[] = [];

    const pageRankScores = this.computePageRank(nodeSet, 20, 0.85);
    const betweennessScores = this.computeBetweenness(nodeSet);

    for (const nid of nodeIds) {
      const node = this.nodes.get(nid);
      if (!node) continue;

      let outDegree = 0;
      let inDegree = 0;
      const outEdges = this.adjacency.get(nid);
      if (outEdges) {
        for (const eid of outEdges) {
          const e = this.edges.get(eid);
          if (e && nodeSet.has(e.targetId)) outDegree++;
        }
      }
      const inEdges = this.reverseAdj.get(nid);
      if (inEdges) {
        for (const eid of inEdges) {
          const e = this.edges.get(eid);
          if (e && nodeSet.has(e.sourceId)) inDegree++;
        }
      }

      const degree = inDegree + outDegree;
      const betweenness = betweennessScores.get(nid) || 0;
      const pageRank = pageRankScores.get(nid) || 0;
      const compositeScore = (degree * 0.2) + (betweenness * 0.3) + (pageRank * 100 * 0.3) + ((SEVERITY_WEIGHT[node.severity || 'info'] || 1) * 0.2);

      results.push({
        nodeId: nid,
        label: node.label,
        nodeType: node.nodeType,
        degree,
        inDegree,
        outDegree,
        betweenness,
        pageRank,
        compositeScore,
      });
    }

    const sorted = results.sort((a, b) => b.compositeScore - a.compositeScore);
    if (huntId) this.huntCentralityCache.set(huntId, sorted);
    return sorted;
  }

  private computePageRank(nodeSet: Set<string>, iterations: number, dampingFactor: number): Map<string, number> {
    const n = nodeSet.size;
    if (n === 0) return new Map();

    const ranks = new Map<string, number>();
    const initialRank = 1 / n;
    for (const nid of nodeSet) ranks.set(nid, initialRank);

    for (let iter = 0; iter < iterations; iter++) {
      const newRanks = new Map<string, number>();
      for (const nid of nodeSet) newRanks.set(nid, (1 - dampingFactor) / n);

      for (const nid of nodeSet) {
        const outEdges = this.adjacency.get(nid);
        if (!outEdges || outEdges.size === 0) {
          const share = (ranks.get(nid) || 0) / n;
          for (const target of nodeSet) {
            newRanks.set(target, (newRanks.get(target) || 0) + dampingFactor * share);
          }
          continue;
        }

        let validOutCount = 0;
        for (const eid of outEdges) {
          const e = this.edges.get(eid);
          if (e && nodeSet.has(e.targetId)) validOutCount++;
        }
        if (validOutCount === 0) continue;

        const share = (ranks.get(nid) || 0) / validOutCount;
        for (const eid of outEdges) {
          const e = this.edges.get(eid);
          if (e && nodeSet.has(e.targetId)) {
            newRanks.set(e.targetId, (newRanks.get(e.targetId) || 0) + dampingFactor * share);
          }
        }
      }

      for (const [k, v] of newRanks) ranks.set(k, v);
    }

    return ranks;
  }

  private computeBetweenness(nodeSet: Set<string>): Map<string, number> {
    const scores = new Map<string, number>();
    for (const nid of nodeSet) scores.set(nid, 0);

    const nodeArray = Array.from(nodeSet);
    const sampleSize = Math.min(nodeArray.length, 50);
    const sample = nodeArray.slice(0, sampleSize);

    for (const source of sample) {
      const stack: string[] = [];
      const pred = new Map<string, string[]>();
      const sigma = new Map<string, number>();
      const dist = new Map<string, number>();
      const delta = new Map<string, number>();

      for (const nid of nodeSet) {
        pred.set(nid, []);
        sigma.set(nid, 0);
        dist.set(nid, -1);
        delta.set(nid, 0);
      }

      sigma.set(source, 1);
      dist.set(source, 0);
      const queue = [source];

      while (queue.length > 0) {
        const v = queue.shift()!;
        stack.push(v);
        const outEdges = this.adjacency.get(v);
        if (!outEdges) continue;

        for (const eid of outEdges) {
          const e = this.edges.get(eid);
          if (!e || !nodeSet.has(e.targetId)) continue;
          const w = e.targetId;

          if (dist.get(w) === -1) {
            dist.set(w, (dist.get(v) || 0) + 1);
            queue.push(w);
          }
          if (dist.get(w) === (dist.get(v) || 0) + 1) {
            sigma.set(w, (sigma.get(w) || 0) + (sigma.get(v) || 0));
            pred.get(w)!.push(v);
          }
        }
      }

      while (stack.length > 0) {
        const w = stack.pop()!;
        for (const v of (pred.get(w) || [])) {
          const contribution = ((sigma.get(v) || 0) / (sigma.get(w) || 1)) * (1 + (delta.get(w) || 0));
          delta.set(v, (delta.get(v) || 0) + contribution);
        }
        if (w !== source) {
          scores.set(w, (scores.get(w) || 0) + (delta.get(w) || 0));
        }
      }
    }

    if (sampleSize < nodeArray.length) {
      const scale = nodeArray.length / sampleSize;
      for (const [k, v] of scores) scores.set(k, v * scale);
    }

    return scores;
  }

  minePatterns(minFrequency = 2, maxPatternLength = 4): PatternResult[] {
    const patternMap = new Map<string, { count: number; huntIds: Set<string>; nodeTypes: Set<string>; relationships: Set<string>; examples: string[][] }>();

    for (const [huntId, nodeIds] of this.nodesByHunt) {
      const vulnNodes = Array.from(nodeIds)
        .map(id => this.nodes.get(id)!)
        .filter(n => n && n.nodeType === 'vulnerability');

      for (const vuln of vulnNodes) {
        const paths = this.traceBackward(vuln.id, maxPatternLength);
        for (const path of paths) {
          const signature = path
            .map(nid => {
              const n = this.nodes.get(nid);
              return n ? n.nodeType : 'unknown';
            })
            .join(' -> ');

          if (!patternMap.has(signature)) {
            patternMap.set(signature, { count: 0, huntIds: new Set(), nodeTypes: new Set(), relationships: new Set(), examples: [] });
          }
          const p = patternMap.get(signature)!;
          p.count++;
          p.huntIds.add(huntId);

          for (const nid of path) {
            const n = this.nodes.get(nid);
            if (n) p.nodeTypes.add(n.nodeType);
          }
          for (let i = 0; i < path.length - 1; i++) {
            const outEdges = this.adjacency.get(path[i]);
            if (outEdges) {
              for (const eid of outEdges) {
                const e = this.edges.get(eid);
                if (e && e.targetId === path[i + 1]) p.relationships.add(e.relationship);
              }
            }
          }

          if (p.examples.length < 3) {
            p.examples.push(path.map(nid => this.nodes.get(nid)?.label || nid));
          }
        }
      }
    }

    const results: PatternResult[] = [];
    for (const [pattern, data] of patternMap) {
      if (data.count >= minFrequency) {
        results.push({
          pattern,
          frequency: data.count,
          confidence: Math.min(1, data.count / 10),
          nodeTypes: Array.from(data.nodeTypes),
          relationships: Array.from(data.relationships),
          huntIds: Array.from(data.huntIds),
          examplePath: data.examples[0] || [],
        });
      }
    }

    return results.sort((a, b) => b.frequency - a.frequency);
  }

  private traceBackward(nodeId: string, maxDepth: number): string[][] {
    const results: string[][] = [];

    const dfs = (current: string, path: string[], visited: Set<string>, depth: number) => {
      if (depth >= maxDepth || path.length >= maxDepth) {
        if (path.length >= 2) results.push([...path]);
        return;
      }

      const inEdges = this.reverseAdj.get(current);
      if (!inEdges || inEdges.size === 0) {
        if (path.length >= 2) results.push([...path]);
        return;
      }

      let extended = false;
      for (const eid of inEdges) {
        const e = this.edges.get(eid);
        if (!e || visited.has(e.sourceId)) continue;
        visited.add(e.sourceId);
        dfs(e.sourceId, [e.sourceId, ...path], visited, depth + 1);
        visited.delete(e.sourceId);
        extended = true;
      }

      if (!extended && path.length >= 2) {
        results.push([...path]);
      }
    };

    dfs(nodeId, [nodeId], new Set([nodeId]), 0);
    return results;
  }

  getStats(huntId?: string): GraphStats {
    const nodes = huntId ? this.getHuntNodes(huntId) : Array.from(this.nodes.values());
    const edges = huntId ? this.getHuntEdges(huntId) : Array.from(this.edges.values());
    const nodeSet = new Set(nodes.map(n => n.id));

    const nodesByType: Record<string, number> = {};
    for (const n of nodes) nodesByType[n.nodeType] = (nodesByType[n.nodeType] || 0) + 1;

    const edgesByRel: Record<string, number> = {};
    for (const e of edges) edgesByRel[e.relationship] = (edgesByRel[e.relationship] || 0) + 1;

    const n = nodes.length;
    const m = edges.length;
    const avgDegree = n > 0 ? (2 * m) / n : 0;
    const density = n > 1 ? m / (n * (n - 1)) : 0;

    const visited = new Set<string>();
    let components = 0;
    for (const node of nodes) {
      if (visited.has(node.id)) continue;
      components++;
      const stack = [node.id];
      while (stack.length > 0) {
        const curr = stack.pop()!;
        if (visited.has(curr)) continue;
        visited.add(curr);
        for (const neighbor of this.getNeighbors(curr, 'both')) {
          if (nodeSet.has(neighbor.id) && !visited.has(neighbor.id)) stack.push(neighbor.id);
        }
      }
    }

    return {
      totalNodes: n,
      totalEdges: m,
      nodesByType,
      edgesByRelationship: edgesByRel,
      huntCount: this.nodesByHunt.size,
      avgDegree: Math.round(avgDegree * 100) / 100,
      density: Math.round(density * 10000) / 10000,
      connectedComponents: components,
    };
  }

  queryNodes(filters: {
    huntId?: string;
    nodeType?: NodeType;
    severity?: string;
    labelContains?: string;
    minConfidence?: number;
  }): GraphNodeData[] {
    let results = Array.from(this.nodes.values());
    if (filters.huntId) results = results.filter(n => n.huntId === filters.huntId);
    if (filters.nodeType) results = results.filter(n => n.nodeType === filters.nodeType);
    if (filters.severity) results = results.filter(n => n.severity === filters.severity);
    if (filters.labelContains) {
      const lc = filters.labelContains.toLowerCase();
      results = results.filter(n => n.label.toLowerCase().includes(lc));
    }
    if (filters.minConfidence) results = results.filter(n => n.confidence >= filters.minConfidence!);
    return results;
  }

  async clearHunt(huntId: string): Promise<void> {
    const nodeIds = this.nodesByHunt.get(huntId);
    if (nodeIds) {
      for (const nid of nodeIds) {
        this.nodes.delete(nid);
        this.adjacency.delete(nid);
        this.reverseAdj.delete(nid);
      }
    }
    this.nodesByHunt.delete(huntId);

    const edgesToRemove: string[] = [];
    for (const [eid, edge] of this.edges) {
      if (edge.huntId === huntId) edgesToRemove.push(eid);
    }
    for (const eid of edgesToRemove) this.edges.delete(eid);

    try {
      await pool.query(`DELETE FROM graph_edges WHERE hunt_id = $1`, [huntId]);
      await pool.query(`DELETE FROM graph_nodes WHERE hunt_id = $1`, [huntId]);
    } catch (_err) {}
  }

  getHuntIds(): string[] {
    return Array.from(this.nodesByHunt.keys());
  }
}

export const offensiveGraphDB = new OffensiveGraphDB();

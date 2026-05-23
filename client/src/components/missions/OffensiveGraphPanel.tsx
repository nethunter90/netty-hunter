import { useState, useEffect, useCallback, useRef } from 'react';
import { useSharedSocket } from '@/context/SocketContext';
import { Network, Target, Cpu, Shield, Crosshair, Zap, BarChart3, GitBranch, RefreshCw, Search, ChevronDown } from 'lucide-react';

interface GraphNode {
  id: string;
  huntId: string;
  nodeType: string;
  label: string;
  confidence: number;
  severity?: string;
  properties: Record<string, any>;
  createdAt: number;
}

interface GraphEdge {
  id: string;
  huntId: string;
  sourceId: string;
  targetId: string;
  relationship: string;
  weight: number;
  properties: Record<string, any>;
}

interface CentralityNode {
  nodeId: string;
  label: string;
  nodeType: string;
  degree: number;
  inDegree: number;
  outDegree: number;
  betweenness: number;
  pageRank: number;
  compositeScore: number;
}

interface GraphStats {
  totalNodes: number;
  totalEdges: number;
  nodesByType: Record<string, number>;
  edgesByRelationship: Record<string, number>;
  huntCount: number;
  avgDegree: number;
  density: number;
  connectedComponents: number;
}

interface PatternResult {
  pattern: string;
  frequency: number;
  confidence: number;
  nodeTypes: string[];
  relationships: string[];
  huntIds: string[];
  examplePath: string[];
}

interface AttackPathResult {
  path: GraphNode[];
  edges: GraphEdge[];
  totalWeight: number;
  maxSeverity: string;
  confidence: number;
}

const NODE_COLORS: Record<string, { bg: string; border: string; text: string; icon: typeof Network }> = {
  endpoint: { bg: 'bg-blue-500/20', border: 'border-blue-500/40', text: 'text-blue-400', icon: Target },
  vulnerability: { bg: 'bg-red-500/20', border: 'border-red-500/40', text: 'text-red-400', icon: Shield },
  tool: { bg: 'bg-green-500/20', border: 'border-green-500/40', text: 'text-green-400', icon: Cpu },
  technique: { bg: 'bg-purple-500/20', border: 'border-purple-500/40', text: 'text-purple-400', icon: Crosshair },
  payload: { bg: 'bg-orange-500/20', border: 'border-orange-500/40', text: 'text-orange-400', icon: Zap },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  low: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  info: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
};

type TabId = 'overview' | 'centrality' | 'paths' | 'patterns';

export function OffensiveGraphPanel() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [centrality, setCentrality] = useState<CentralityNode[]>([]);
  const [patterns, setPatterns] = useState<PatternResult[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPathResult[]>([]);
  const [huntIds, setHuntIds] = useState<string[]>([]);
  const [selectedHunt, setSelectedHunt] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [filterType, setFilterType] = useState<string>('all');
  const [searchLabel, setSearchLabel] = useState('');
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { socket: sharedSocket } = useSharedSocket();

  const fetchStats = useCallback(async () => {
    try {
      const url = selectedHunt ? `/api/graph/stats/${selectedHunt}` : '/api/graph/stats';
      const res = await fetch(url);
      const data = await res.json();
      if (data.success) setStats(data.data);
    } catch (_e) {}
  }, [selectedHunt]);

  const fetchHunts = useCallback(async () => {
    try {
      const res = await fetch('/api/graph/hunts');
      const data = await res.json();
      if (data.success) {
        setHuntIds(data.data.map((h: any) => h.huntId));
      }
    } catch (_e) {}
  }, []);

  const fetchGraph = useCallback(async () => {
    if (!selectedHunt) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/graph/graph/${selectedHunt}`);
      const data = await res.json();
      if (data.success) {
        setNodes(data.data.nodes);
        setEdges(data.data.edges);
        setStats(data.data.stats);
      }
    } catch (_e) {}
    setLoading(false);
  }, [selectedHunt]);

  const fetchCentrality = useCallback(async () => {
    if (!selectedHunt) return;
    try {
      const res = await fetch(`/api/graph/centrality/${selectedHunt}`);
      const data = await res.json();
      if (data.success) setCentrality(data.data.nodes);
    } catch (_e) {}
  }, [selectedHunt]);

  const fetchPatterns = useCallback(async () => {
    try {
      const res = await fetch('/api/graph/patterns?minFrequency=1');
      const data = await res.json();
      if (data.success) setPatterns(data.data.patterns);
    } catch (_e) {}
  }, []);

  const fetchAttackPaths = useCallback(async () => {
    if (!selectedHunt) return;
    try {
      const res = await fetch(`/api/graph/paths/rank/${selectedHunt}`);
      const data = await res.json();
      if (data.success) setAttackPaths(data.data.paths);
    } catch (_e) {}
  }, [selectedHunt]);

  const populateFromMemory = useCallback(async () => {
    if (!selectedHunt) return;
    setLoading(true);
    try {
      await fetch(`/api/graph/populate/${selectedHunt}`, { method: 'POST' });
      await fetchGraph();
    } catch (_e) {}
    setLoading(false);
  }, [selectedHunt, fetchGraph]);

  useEffect(() => {
    fetchHunts();
    fetchStats();
  }, [fetchHunts, fetchStats]);

  useEffect(() => {
    if (!sharedSocket) return;

    const refreshGraph = () => {
      fetchStats();
      if (selectedHunt) fetchGraph();
    };

    sharedSocket.on('finding:added', refreshGraph);
    sharedSocket.on('finding:verified', refreshGraph);
    sharedSocket.on('hunt:completed', refreshGraph);
    sharedSocket.on('chain:finding_processed', refreshGraph);

    return () => {
      sharedSocket.off('finding:added', refreshGraph);
      sharedSocket.off('finding:verified', refreshGraph);
      sharedSocket.off('hunt:completed', refreshGraph);
      sharedSocket.off('chain:finding_processed', refreshGraph);
    };
  }, [sharedSocket, selectedHunt, fetchStats, fetchGraph]);

  useEffect(() => {
    if (selectedHunt) {
      fetchGraph();
      if (activeTab === 'centrality') fetchCentrality();
      if (activeTab === 'paths') fetchAttackPaths();
      if (activeTab === 'patterns') fetchPatterns();
    }
  }, [selectedHunt, activeTab, fetchGraph, fetchCentrality, fetchAttackPaths, fetchPatterns]);

  useEffect(() => {
    if (activeTab === 'overview' && nodes.length > 0) {
      drawGraph();
    }
  }, [activeTab, nodes, edges, filterType]);

  const drawGraph = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const rect = canvas.parentElement?.getBoundingClientRect();
    canvas.width = rect?.width || 600;
    canvas.height = 360;

    ctx.fillStyle = '#0d0d0d';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const filteredNodes = filterType === 'all' ? nodes : nodes.filter(n => n.nodeType === filterType);
    const nodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredEdges = edges.filter(e => nodeIds.has(e.sourceId) && nodeIds.has(e.targetId));

    if (filteredNodes.length === 0) {
      ctx.fillStyle = '#666';
      ctx.font = '12px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('No nodes to display', canvas.width / 2, canvas.height / 2);
      return;
    }

    const positions = new Map<string, { x: number; y: number }>();
    const padding = 60;
    const w = canvas.width - padding * 2;
    const h = canvas.height - padding * 2;

    const typeGroups = new Map<string, GraphNode[]>();
    for (const n of filteredNodes) {
      if (!typeGroups.has(n.nodeType)) typeGroups.set(n.nodeType, []);
      typeGroups.get(n.nodeType)!.push(n);
    }

    const typeOrder = ['endpoint', 'tool', 'technique', 'vulnerability', 'payload'];
    const orderedTypes = typeOrder.filter(t => typeGroups.has(t));
    for (const t of typeGroups.keys()) {
      if (!orderedTypes.includes(t)) orderedTypes.push(t);
    }

    const colWidth = orderedTypes.length > 1 ? w / (orderedTypes.length - 1) : 0;
    orderedTypes.forEach((type, colIdx) => {
      const group = typeGroups.get(type) || [];
      const x = padding + colIdx * colWidth;
      const rowHeight = group.length > 1 ? h / (group.length - 1) : 0;
      group.forEach((node, rowIdx) => {
        const y = padding + (group.length > 1 ? rowIdx * rowHeight : h / 2);
        const jitter = (Math.sin(node.id.charCodeAt(0) * 7) * 20);
        positions.set(node.id, { x: x + jitter, y: y + jitter * 0.5 });
      });
    });

    for (const edge of filteredEdges) {
      const from = positions.get(edge.sourceId);
      const to = positions.get(edge.targetId);
      if (!from || !to) continue;

      ctx.beginPath();
      ctx.moveTo(from.x, from.y);
      ctx.lineTo(to.x, to.y);
      ctx.strokeStyle = `rgba(100, 200, 255, ${Math.min(0.6, edge.weight * 0.15)})`;
      ctx.lineWidth = Math.min(3, edge.weight * 0.5);
      ctx.stroke();

      const midX = (from.x + to.x) / 2;
      const midY = (from.y + to.y) / 2;
      ctx.fillStyle = 'rgba(100, 200, 255, 0.4)';
      ctx.font = '8px monospace';
      ctx.textAlign = 'center';
      ctx.fillText(edge.relationship, midX, midY - 4);
    }

    const colorMap: Record<string, string> = {
      endpoint: '#3b82f6',
      vulnerability: '#ef4444',
      tool: '#22c55e',
      technique: '#a855f7',
      payload: '#f97316',
    };

    for (const node of filteredNodes) {
      const pos = positions.get(node.id);
      if (!pos) continue;

      const color = colorMap[node.nodeType] || '#888';
      const radius = node.nodeType === 'vulnerability' ? 8 : 6;

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius + 3, 0, Math.PI * 2);
      ctx.fillStyle = `${color}33`;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(pos.x, pos.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = `${color}88`;
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.fillStyle = '#ddd';
      ctx.font = '9px monospace';
      ctx.textAlign = 'center';
      const displayLabel = node.label.length > 25 ? node.label.slice(0, 22) + '...' : node.label;
      ctx.fillText(displayLabel, pos.x, pos.y + radius + 12);
    }

    const legendX = 10;
    let legendY = canvas.height - 15;
    ctx.font = '9px monospace';
    for (const type of orderedTypes.reverse()) {
      const color = colorMap[type] || '#888';
      ctx.fillStyle = color;
      ctx.fillRect(legendX, legendY - 7, 8, 8);
      ctx.fillStyle = '#aaa';
      ctx.textAlign = 'left';
      ctx.fillText(`${type} (${typeGroups.get(type)?.length || 0})`, legendX + 12, legendY);
      legendY -= 14;
    }
  }, [nodes, edges, filterType]);

  const tabs: { id: TabId; label: string; icon: typeof Network }[] = [
    { id: 'overview', label: 'Graph', icon: Network },
    { id: 'centrality', label: 'Centrality', icon: BarChart3 },
    { id: 'paths', label: 'Attack Paths', icon: GitBranch },
    { id: 'patterns', label: 'Patterns', icon: Search },
  ];

  const filteredNodes = filterType === 'all'
    ? nodes.filter(n => !searchLabel || n.label.toLowerCase().includes(searchLabel.toLowerCase()))
    : nodes.filter(n => n.nodeType === filterType && (!searchLabel || n.label.toLowerCase().includes(searchLabel.toLowerCase())));

  return (
    <div className="flex flex-col h-full bg-[#0d0d0d] text-gray-200" data-testid="offensive-graph-panel">
      <div className="flex items-center justify-between px-3 py-2 border-b border-[#2d2d2d]">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold text-cyan-400">OFFENSIVE INTELLIGENCE GRAPH</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <select
              value={selectedHunt}
              onChange={e => setSelectedHunt(e.target.value)}
              className="text-[10px] bg-[#1a1a2e] border border-[#333] rounded px-2 py-1 text-gray-300 appearance-none pr-5"
              data-testid="select-hunt"
            >
              <option value="">All Hunts</option>
              {huntIds.map(id => (
                <option key={id} value={id}>{id.slice(0, 8)}...</option>
              ))}
            </select>
            <ChevronDown className="w-3 h-3 absolute right-1 top-1.5 text-gray-500 pointer-events-none" />
          </div>
          {selectedHunt && (
            <button
              onClick={populateFromMemory}
              className="text-[10px] px-2 py-1 bg-cyan-500/10 border border-cyan-500/30 rounded text-cyan-400 hover:bg-cyan-500/20"
              data-testid="button-populate"
            >
              Populate
            </button>
          )}
          <button
            onClick={() => { fetchStats(); if (selectedHunt) fetchGraph(); }}
            className="p-1 text-gray-500 hover:text-gray-300"
            data-testid="button-refresh-graph"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {stats && (
        <div className="flex gap-3 px-3 py-2 border-b border-[#2d2d2d] text-[10px]">
          <span className="text-gray-500">Nodes: <span className="text-cyan-400">{stats.totalNodes}</span></span>
          <span className="text-gray-500">Edges: <span className="text-cyan-400">{stats.totalEdges}</span></span>
          <span className="text-gray-500">Density: <span className="text-cyan-400">{stats.density.toFixed(4)}</span></span>
          <span className="text-gray-500">Components: <span className="text-cyan-400">{stats.connectedComponents}</span></span>
          <span className="text-gray-500">Avg Degree: <span className="text-cyan-400">{stats.avgDegree}</span></span>
        </div>
      )}

      <div className="flex border-b border-[#2d2d2d]">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-[10px] font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
            data-testid={`tab-${tab.id}`}
          >
            <tab.icon className="w-3 h-3" />
            {tab.label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto p-3">
        {activeTab === 'overview' && (
          <div className="space-y-3">
            <div className="flex items-center gap-2 mb-2">
              <select
                value={filterType}
                onChange={e => setFilterType(e.target.value)}
                className="text-[10px] bg-[#1a1a2e] border border-[#333] rounded px-2 py-1 text-gray-300"
                data-testid="select-filter-type"
              >
                <option value="all">All Types</option>
                <option value="endpoint">Endpoints</option>
                <option value="vulnerability">Vulnerabilities</option>
                <option value="tool">Tools</option>
                <option value="technique">Techniques</option>
                <option value="payload">Payloads</option>
              </select>
              <input
                type="text"
                placeholder="Search labels..."
                value={searchLabel}
                onChange={e => setSearchLabel(e.target.value)}
                className="text-[10px] bg-[#1a1a2e] border border-[#333] rounded px-2 py-1 text-gray-300 flex-1"
                data-testid="input-search-label"
              />
            </div>

            <div className="border border-[#2d2d2d] rounded overflow-hidden">
              <canvas ref={canvasRef} className="w-full" style={{ height: 360 }} data-testid="graph-canvas" />
            </div>

            {stats && stats.totalNodes > 0 && (
              <div className="grid grid-cols-2 gap-2">
                <div className="border border-[#2d2d2d] rounded p-2">
                  <div className="text-[10px] text-gray-500 mb-1.5">Nodes by Type</div>
                  {Object.entries(stats.nodesByType).map(([type, count]) => {
                    const config = NODE_COLORS[type] || NODE_COLORS.endpoint;
                    return (
                      <div key={type} className="flex items-center justify-between text-[10px] py-0.5">
                        <span className={config.text}>{type}</span>
                        <span className="text-gray-400">{count}</span>
                      </div>
                    );
                  })}
                </div>
                <div className="border border-[#2d2d2d] rounded p-2">
                  <div className="text-[10px] text-gray-500 mb-1.5">Edges by Relationship</div>
                  {Object.entries(stats.edgesByRelationship).map(([rel, count]) => (
                    <div key={rel} className="flex items-center justify-between text-[10px] py-0.5">
                      <span className="text-cyan-400">{rel}</span>
                      <span className="text-gray-400">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {filteredNodes.length > 0 && (
              <div className="border border-[#2d2d2d] rounded">
                <div className="px-2 py-1.5 border-b border-[#2d2d2d] text-[10px] text-gray-500">
                  Nodes ({filteredNodes.length})
                </div>
                <div className="max-h-48 overflow-auto">
                  {filteredNodes.slice(0, 100).map(node => {
                    const config = NODE_COLORS[node.nodeType] || NODE_COLORS.endpoint;
                    const Icon = config.icon;
                    return (
                      <div key={node.id} className="flex items-center gap-2 px-2 py-1 border-b border-[#1a1a1a] hover:bg-[#1a1a2e]" data-testid={`graph-node-${node.id}`}>
                        <Icon className={`w-3 h-3 ${config.text}`} />
                        <span className="text-[10px] text-gray-300 truncate flex-1">{node.label}</span>
                        <span className={`text-[9px] px-1 rounded ${config.bg} ${config.text} border ${config.border}`}>{node.nodeType}</span>
                        {node.severity && (
                          <span className={`text-[9px] px-1 rounded border ${SEVERITY_COLORS[node.severity] || ''}`}>{node.severity}</span>
                        )}
                        <span className="text-[9px] text-gray-600">{(node.confidence * 100).toFixed(0)}%</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {nodes.length === 0 && !loading && (
              <div className="flex flex-col items-center justify-center py-12 text-gray-500">
                <Network className="w-8 h-8 mb-2 opacity-20" />
                <p className="text-xs">No graph data yet</p>
                <p className="text-[10px] mt-1">Run a hunt to populate the intelligence graph</p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'centrality' && (
          <div className="space-y-2">
            <div className="text-[10px] text-gray-500 mb-2">
              Nodes ranked by composite centrality score (degree + betweenness + PageRank + severity)
            </div>
            {centrality.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-xs">
                {selectedHunt ? 'No centrality data — select a hunt with graph nodes' : 'Select a hunt first'}
              </div>
            ) : (
              <div className="border border-[#2d2d2d] rounded">
                <div className="grid grid-cols-7 gap-1 px-2 py-1 text-[9px] text-gray-500 border-b border-[#2d2d2d] font-medium">
                  <span className="col-span-2">Node</span>
                  <span className="text-center">Type</span>
                  <span className="text-center">Degree</span>
                  <span className="text-center">Between.</span>
                  <span className="text-center">PageRank</span>
                  <span className="text-center">Score</span>
                </div>
                {centrality.slice(0, 50).map((c, idx) => {
                  const config = NODE_COLORS[c.nodeType] || NODE_COLORS.endpoint;
                  return (
                    <div key={c.nodeId} className="grid grid-cols-7 gap-1 px-2 py-1 text-[10px] border-b border-[#1a1a1a] hover:bg-[#1a1a2e]" data-testid={`centrality-row-${idx}`}>
                      <span className="col-span-2 text-gray-300 truncate">{c.label}</span>
                      <span className={`text-center ${config.text}`}>{c.nodeType}</span>
                      <span className="text-center text-gray-400">{c.degree}</span>
                      <span className="text-center text-gray-400">{c.betweenness.toFixed(1)}</span>
                      <span className="text-center text-gray-400">{c.pageRank.toFixed(4)}</span>
                      <span className="text-center text-cyan-400 font-medium">{c.compositeScore.toFixed(2)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'paths' && (
          <div className="space-y-2">
            <div className="text-[10px] text-gray-500 mb-2">
              Attack paths ranked by severity, confidence, and path weight
            </div>
            {attackPaths.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-xs">
                {selectedHunt ? 'No attack paths found — ensure endpoints and vulnerabilities exist in the graph' : 'Select a hunt first'}
              </div>
            ) : (
              attackPaths.slice(0, 20).map((ap, idx) => (
                <div key={idx} className="border border-[#2d2d2d] rounded p-2" data-testid={`attack-path-${idx}`}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] text-gray-500">Path #{idx + 1}</span>
                    <div className="flex items-center gap-2">
                      <span className={`text-[9px] px-1.5 rounded border ${SEVERITY_COLORS[ap.maxSeverity] || ''}`}>
                        {ap.maxSeverity}
                      </span>
                      <span className="text-[9px] text-gray-500">conf: {(ap.confidence * 100).toFixed(0)}%</span>
                      <span className="text-[9px] text-gray-500">weight: {ap.totalWeight.toFixed(2)}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 flex-wrap">
                    {ap.path.map((node, ni) => {
                      const config = NODE_COLORS[node.nodeType] || NODE_COLORS.endpoint;
                      return (
                        <div key={ni} className="flex items-center gap-1">
                          <span className={`text-[9px] px-1.5 py-0.5 rounded ${config.bg} ${config.text} border ${config.border}`}>
                            {node.label.length > 20 ? node.label.slice(0, 17) + '...' : node.label}
                          </span>
                          {ni < ap.path.length - 1 && (
                            <span className="text-gray-600 text-[10px]">→</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
                  {ap.edges.length > 0 && (
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {ap.edges.map((edge, ei) => (
                        <span key={ei} className="text-[8px] text-cyan-500/60">{edge.relationship}</span>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}

        {activeTab === 'patterns' && (
          <div className="space-y-2">
            <div className="text-[10px] text-gray-500 mb-2">
              Recurring attack patterns mined across hunts
            </div>
            {patterns.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-xs">
                No patterns detected yet — patterns emerge after multiple hunts
              </div>
            ) : (
              patterns.map((p, idx) => (
                <div key={idx} className="border border-[#2d2d2d] rounded p-2" data-testid={`pattern-${idx}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-mono text-purple-400">{p.pattern}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] text-gray-500">freq: {p.frequency}</span>
                      <span className="text-[9px] text-gray-500">conf: {(p.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </div>
                  <div className="flex gap-1 flex-wrap">
                    {p.relationships.map((r, ri) => (
                      <span key={ri} className="text-[8px] px-1 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">{r}</span>
                    ))}
                  </div>
                  {p.examplePath.length > 0 && (
                    <div className="mt-1 text-[9px] text-gray-500">
                      Example: {p.examplePath.join(' → ')}
                    </div>
                  )}
                  <div className="text-[8px] text-gray-600 mt-0.5">
                    Seen in {p.huntIds.length} hunt{p.huntIds.length !== 1 ? 's' : ''}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

import { useState, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Wrench, CheckCircle, XCircle, RefreshCw, Shield, Eye, Zap,
  Globe, Search, Bug, Lock, Radio, Terminal, FileKey, Wifi,
  AlertTriangle, ChevronDown, ChevronRight
} from 'lucide-react';

interface ToolStatus {
  name: string;
  installed: boolean;
  path?: string;
  version?: string;
  category: string;
  critical: boolean;
  description: string;
  stealthImpact: string;
  useCases: string[];
  commandCount: number;
  requiresRoot: boolean;
}

interface ToolSummary {
  total: number;
  installed: number;
  missing: number;
  criticalMissing: number;
  categories: Record<string, number>;
  categoriesInstalled: Record<string, number>;
}

const CATEGORY_META: Record<string, { label: string; icon: any; color: string; borderColor: string }> = {
  recon: { label: 'Reconnaissance', icon: Globe, color: 'text-blue-400', borderColor: 'border-blue-500' },
  enum: { label: 'Enumeration', icon: Search, color: 'text-yellow-400', borderColor: 'border-yellow-500' },
  vuln: { label: 'Vulnerability', icon: Bug, color: 'text-red-400', borderColor: 'border-red-500' },
  exploit: { label: 'Exploitation', icon: Zap, color: 'text-orange-400', borderColor: 'border-orange-500' },
  proxy: { label: 'Proxy', icon: Eye, color: 'text-purple-400', borderColor: 'border-purple-500' },
  secrets: { label: 'Secrets', icon: FileKey, color: 'text-emerald-400', borderColor: 'border-emerald-500' },
  wireless: { label: 'Wireless', icon: Wifi, color: 'text-cyan-400', borderColor: 'border-cyan-500' },
  util: { label: 'Utilities', icon: Terminal, color: 'text-gray-400', borderColor: 'border-gray-500' },
};

const STEALTH_COLORS: Record<string, string> = {
  low: 'text-green-400 bg-green-400/10 border-green-400/30',
  medium: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  high: 'text-orange-400 bg-orange-400/10 border-orange-400/30',
  'very-high': 'text-red-400 bg-red-400/10 border-red-400/30',
};

const CATEGORY_ORDER = ['recon', 'enum', 'vuln', 'exploit', 'proxy', 'secrets', 'wireless', 'util'];

export function ToolReadiness() {
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [summary, setSummary] = useState<ToolSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(CATEGORY_ORDER));

  const fetchTools = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/bounty/tools');
      const data = await response.json();
      if (data.success && data.tools) {
        setTools(data.tools);
        setSummary(data.summary || null);
      }
    } catch (error) {
      console.error('Failed to fetch tool status:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTools();
    const interval = setInterval(fetchTools, 30000);
    return () => clearInterval(interval);
  }, []);

  const toggleCategory = (cat: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat); else next.add(cat);
      return next;
    });
  };

  const toolsByCategory = CATEGORY_ORDER.reduce((acc, cat) => {
    acc[cat] = tools.filter(t => t.category === cat);
    return acc;
  }, {} as Record<string, ToolStatus[]>);

  const installedCount = summary?.installed ?? tools.filter(t => t.installed).length;
  const totalCount = summary?.total ?? tools.length;
  const criticalMissing = summary?.criticalMissing ?? tools.filter(t => t.critical && !t.installed).length;
  const pct = totalCount > 0 ? Math.round((installedCount / totalCount) * 100) : 0;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6">
      <div className="mb-4">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">Tool Readiness</h1>
          <Badge className="bg-cyan-400/10 text-cyan-400 border-cyan-400/30 text-[10px]">
            39 Tools · 8 Categories
          </Badge>
        </div>
        <p className="text-sm text-gray-400">Full arsenal status across all integrated security tools</p>
      </div>

      <Card className="bg-[#252526] border-[#3d3d3d] p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-4">
            <div>
              <span className="text-2xl font-bold font-mono text-gray-100" data-testid="text-tool-summary">
                {installedCount}/{totalCount}
              </span>
              <span className="text-sm text-gray-400 ml-2">tools available</span>
            </div>
            <div className="w-40 h-2.5 bg-[#1e1e1e] rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-500 ${
                  pct === 100 ? 'bg-green-400' : pct > 60 ? 'bg-cyan-400' : pct > 30 ? 'bg-yellow-400' : 'bg-red-400'
                }`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="text-xs font-mono text-gray-500">{pct}%</span>
          </div>
          <Button
            onClick={fetchTools}
            disabled={loading}
            className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 hover:bg-[#333]"
            variant="outline"
            data-testid="button-refresh-tools"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Scanning...' : 'Re-scan'}
          </Button>
        </div>

        {criticalMissing > 0 && (
          <div className="flex items-center gap-2 px-3 py-2 rounded bg-red-400/10 border border-red-400/30" data-testid="critical-warning">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-xs text-red-400">
              {criticalMissing} critical tool{criticalMissing !== 1 ? 's' : ''} missing — install on Kali Linux for full capability
            </span>
          </div>
        )}

        <div className="grid grid-cols-4 gap-2 mt-3">
          {CATEGORY_ORDER.map(cat => {
            const meta = CATEGORY_META[cat];
            const catTools = toolsByCategory[cat] || [];
            const catInstalled = catTools.filter(t => t.installed).length;
            const Icon = meta.icon;
            return (
              <div key={cat} className="bg-[#1a1a1a] rounded px-2 py-1.5 flex items-center gap-2" data-testid={`stat-category-${cat}`}>
                <Icon className={`w-3.5 h-3.5 ${meta.color}`} />
                <div className="flex-1 min-w-0">
                  <div className="text-[10px] text-gray-500 truncate">{meta.label}</div>
                  <div className="text-xs font-mono text-gray-300">{catInstalled}/{catTools.length}</div>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <ScrollArea className="flex-1">
        <div className="space-y-4 pr-2">
          {CATEGORY_ORDER.filter(cat => (toolsByCategory[cat] || []).length > 0).map(cat => {
            const meta = CATEGORY_META[cat];
            const catTools = toolsByCategory[cat];
            const catInstalled = catTools.filter(t => t.installed).length;
            const expanded = expandedCategories.has(cat);
            const Icon = meta.icon;

            return (
              <div key={cat}>
                <button
                  onClick={() => toggleCategory(cat)}
                  className="w-full flex items-center gap-2 mb-2 group"
                  data-testid={`button-toggle-${cat}`}
                >
                  {expanded ? (
                    <ChevronDown className="w-3.5 h-3.5 text-gray-500" />
                  ) : (
                    <ChevronRight className="w-3.5 h-3.5 text-gray-500" />
                  )}
                  <Icon className={`w-4 h-4 ${meta.color}`} />
                  <span className={`text-sm font-semibold ${meta.color}`}>{meta.label}</span>
                  <Badge className="bg-gray-700/50 text-gray-400 border-gray-600 text-[10px] ml-auto">
                    {catInstalled}/{catTools.length}
                  </Badge>
                </button>

                {expanded && (
                  <div className="grid grid-cols-2 gap-2 ml-6">
                    {catTools.map(tool => (
                      <Card
                        key={tool.name}
                        className={`bg-[#252526] border-[#3d3d3d] p-3 ${
                          tool.installed
                            ? `border-l-2 ${meta.borderColor}`
                            : 'border-l-2 border-l-gray-600'
                        }`}
                        data-testid={`card-tool-${tool.name}`}
                      >
                        <div className="flex items-start justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-gray-200">{tool.name}</span>
                            {tool.critical && (
                              <span className="text-[9px] px-1 py-0.5 rounded bg-red-400/10 border border-red-400/30 text-red-400 font-medium">
                                CRITICAL
                              </span>
                            )}
                            {tool.requiresRoot && (
                              <span className="text-[9px] px-1 py-0.5 rounded bg-yellow-400/10 border border-yellow-400/30 text-yellow-400">
                                ROOT
                              </span>
                            )}
                          </div>
                          {tool.installed ? (
                            <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                          ) : (
                            <XCircle className="w-4 h-4 text-red-400/50 flex-shrink-0" />
                          )}
                        </div>
                        <p className="text-[11px] text-gray-400 mb-1.5">{tool.description}</p>
                        <div className="flex items-center gap-2 flex-wrap">
                          {tool.stealthImpact && tool.stealthImpact !== 'unknown' && (
                            <span className={`text-[9px] px-1.5 py-0.5 rounded border ${STEALTH_COLORS[tool.stealthImpact] || 'text-gray-400'}`}>
                              Stealth: {tool.stealthImpact}
                            </span>
                          )}
                          {tool.commandCount > 0 && (
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#1a1a1a] text-gray-500 border border-[#3d3d3d]">
                              {tool.commandCount} cmd{tool.commandCount !== 1 ? 's' : ''}
                            </span>
                          )}
                        </div>
                        {tool.installed && tool.version && (
                          <p className="text-[10px] text-gray-500 mt-1 font-mono truncate" title={tool.version}>{tool.version}</p>
                        )}
                        {!tool.installed && (
                          <p className="text-[10px] text-red-400/70 mt-1">Not installed — available on Kali Linux</p>
                        )}
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}

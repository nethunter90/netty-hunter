import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  Wrench, CheckCircle2, XCircle, RefreshCw, ChevronDown, ChevronUp,
  Globe, Search, Bug, Zap, Shield, Lock, Radio, Terminal,
  Package, BookOpen
} from "lucide-react";
import { toolsAPI } from "../lib/api";
import toast from "react-hot-toast";

// ── Types ─────────────────────────────────────────────────────────────────────

type KaliCategory = "recon" | "scanning" | "fuzzing" | "exploitation" | "web" | "credential" | "network" | "reporting";

interface CatalogTool {
  name: string;
  displayName: string;
  binary: string;
  category: KaliCategory;
  commandTemplate: string;
  vulnClasses: string[];
  rateLimit: number;
  riskLevel: "low" | "medium" | "high";
  stealthRating: number;
  parserType: string;
  description: string;
  available?: boolean;
  path?: string;
  version?: string;
}

// ── Category metadata ─────────────────────────────────────────────────────────

const CAT_META: Record<KaliCategory, { label: string; icon: React.ElementType; color: string; border: string }> = {
  recon:        { label: "Reconnaissance", icon: Globe,    color: "text-blue-400",    border: "border-blue-500/40"    },
  scanning:     { label: "Scanning",        icon: Search,   color: "text-yellow-400",  border: "border-yellow-500/40"  },
  fuzzing:      { label: "Fuzzing",         icon: Zap,      color: "text-orange-400",  border: "border-orange-500/40"  },
  exploitation: { label: "Exploitation",    icon: Bug,      color: "text-red-400",     border: "border-red-500/40"     },
  web:          { label: "Web Analysis",    icon: Shield,   color: "text-purple-400",  border: "border-purple-500/40"  },
  credential:   { label: "Credentials",     icon: Lock,     color: "text-emerald-400", border: "border-emerald-500/40" },
  network:      { label: "Network",         icon: Radio,    color: "text-cyan-400",    border: "border-cyan-500/40"    },
  reporting:    { label: "Reporting",       icon: Terminal, color: "text-gray-400",    border: "border-gray-500/40"    },
};

const CAT_ORDER: KaliCategory[] = ["recon", "scanning", "fuzzing", "exploitation", "web", "credential", "network", "reporting"];

const RISK_COLORS: Record<string, string> = {
  low:    "text-green-400 bg-green-400/10 border-green-400/30",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  high:   "text-red-400 bg-red-400/10 border-red-400/30",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function ToolsPage() {
  const [catalog, setCatalog] = useState<CatalogTool[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [installedOnly, setInstalledOnly] = useState(false);
  const [expandedCategories, setExpandedCategories] = useState<Set<KaliCategory>>(new Set(CAT_ORDER));
  const [expandedTool, setExpandedTool] = useState<string | null>(null);

  const fetchTools = useCallback(async () => {
    setLoading(true);
    try {
      const res = await toolsAPI.list();
      setCatalog(res.data.catalog || []);
    } catch {
      toast.error("Failed to load tool catalog");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchTools(); }, [fetchTools]);

  const installedCount = useMemo(() => catalog.filter(t => t.available).length, [catalog]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return catalog.filter(t => {
      if (installedOnly && !t.available) return false;
      if (!q) return true;
      return (
        t.name.includes(q) ||
        t.displayName.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.category.includes(q) ||
        t.vulnClasses.some(vc => vc.includes(q))
      );
    });
  }, [catalog, search, installedOnly]);

  const byCategory = useMemo(() => {
    const map = new Map<KaliCategory, CatalogTool[]>();
    CAT_ORDER.forEach(c => map.set(c, []));
    filtered.forEach(t => map.get(t.category as KaliCategory)?.push(t));
    return map;
  }, [filtered]);

  const toggleCategory = (cat: KaliCategory) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      next.has(cat) ? next.delete(cat) : next.add(cat);
      return next;
    });
  };

  return (
    <div className="flex flex-col h-full bg-hack-bg text-hack-text font-mono overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-hack-border bg-hack-surface flex-shrink-0">
        <div className="flex items-center gap-3">
          <Wrench className="w-4 h-4 text-hack-accent" />
          <span className="text-hack-accent font-semibold text-sm tracking-wider">KALI TOOL REGISTRY</span>
          <span className="text-[11px] text-hack-dim border border-hack-border rounded px-2 py-0.5">
            {loading ? "..." : `${installedCount} installed / ${catalog.length} total`}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setInstalledOnly(v => !v)}
            className={`px-3 py-1 text-[11px] rounded border transition-all ${
              installedOnly
                ? "border-hack-accent/50 bg-hack-accent/10 text-hack-accent"
                : "border-hack-border text-hack-dim hover:text-hack-text"
            }`}
          >
            <CheckCircle2 className="w-3 h-3 inline mr-1" />
            INSTALLED ONLY
          </button>
          <button
            onClick={fetchTools}
            disabled={loading}
            className="flex items-center gap-1 px-2 py-1 text-[11px] border border-hack-border text-hack-dim hover:text-hack-text rounded"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Search + summary chips */}
      <div className="px-6 py-2 border-b border-hack-border bg-hack-surface/50 flex flex-col gap-2 flex-shrink-0">
        <input
          className="w-full bg-hack-surface border border-hack-border rounded px-3 py-1.5 text-[11px] text-hack-text placeholder-hack-dim/50 focus:border-hack-accent outline-none"
          placeholder="Search tools, categories, or vuln classes…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <div className="flex gap-2 flex-wrap">
          {CAT_ORDER.map(cat => {
            const tools = byCategory.get(cat) || [];
            const installed = tools.filter(t => t.available).length;
            const meta = CAT_META[cat];
            const Icon = meta.icon;
            return (
              <button
                key={cat}
                onClick={() => { setSearch(""); toggleCategory(cat); }}
                className={`flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] transition-all ${meta.border} ${meta.color} bg-transparent hover:bg-white/5`}
              >
                <Icon className="w-3 h-3" />
                {meta.label}
                <span className="opacity-60">({installed}/{tools.length})</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Tool list */}
      <div className="flex-1 overflow-auto p-4 space-y-3">
        {loading ? (
          <div className="text-center py-20 text-hack-dim text-[11px]">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-3 text-hack-accent" />
            Scanning for installed tools…
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-20 text-hack-dim text-[11px]">
            <Package className="w-8 h-8 mx-auto mb-3 opacity-30" />
            No tools match your filter.
          </div>
        ) : (
          CAT_ORDER.map(cat => {
            const tools = byCategory.get(cat) || [];
            if (tools.length === 0) return null;
            const meta = CAT_META[cat];
            const Icon = meta.icon;
            const installedInCat = tools.filter(t => t.available).length;
            const isOpen = expandedCategories.has(cat);

            return (
              <div key={cat} className={`border rounded bg-hack-panel ${meta.border}`}>
                {/* Category header */}
                <button
                  onClick={() => toggleCategory(cat)}
                  className="w-full flex items-center justify-between px-4 py-2.5 hover:bg-white/3 transition-all"
                >
                  <div className="flex items-center gap-2">
                    <Icon className={`w-4 h-4 ${meta.color}`} />
                    <span className={`text-[12px] font-semibold ${meta.color}`}>{meta.label.toUpperCase()}</span>
                    <span className="text-[10px] text-hack-dim">
                      {installedInCat} installed / {tools.length} total
                    </span>
                  </div>
                  {isOpen
                    ? <ChevronUp className="w-3.5 h-3.5 text-hack-dim" />
                    : <ChevronDown className="w-3.5 h-3.5 text-hack-dim" />}
                </button>

                {/* Tool grid */}
                {isOpen && (
                  <div className="border-t border-hack-border/30 grid grid-cols-2 gap-2 p-3">
                    {tools.map(tool => {
                      const isExpanded = expandedTool === tool.name;
                      return (
                        <div
                          key={tool.name}
                          className={`border rounded p-3 transition-all cursor-pointer hover:border-hack-border ${
                            tool.available
                              ? "border-hack-border/60 bg-hack-surface/30"
                              : "border-hack-border/20 bg-hack-surface/10 opacity-50"
                          }`}
                          onClick={() => setExpandedTool(isExpanded ? null : tool.name)}
                        >
                          {/* Tool card header */}
                          <div className="flex items-start justify-between gap-2">
                            <div className="flex items-center gap-1.5 min-w-0">
                              {tool.available
                                ? <CheckCircle2 className="w-3.5 h-3.5 text-hack-green flex-shrink-0" />
                                : <XCircle className="w-3.5 h-3.5 text-hack-dim flex-shrink-0" />}
                              <span className="text-[12px] font-semibold text-hack-text truncate">{tool.displayName}</span>
                            </div>
                            <div className="flex items-center gap-1 flex-shrink-0">
                              <span className={`text-[9px] px-1.5 py-0.5 rounded border ${RISK_COLORS[tool.riskLevel]}`}>
                                {tool.riskLevel}
                              </span>
                              <span className="text-[9px] text-hack-dim border border-hack-border/40 px-1.5 py-0.5 rounded">
                                S{tool.stealthRating}
                              </span>
                              {isExpanded ? <ChevronUp className="w-3 h-3 text-hack-dim" /> : <ChevronDown className="w-3 h-3 text-hack-dim" />}
                            </div>
                          </div>

                          {/* Binary + version */}
                          <div className="mt-1 text-[10px] text-hack-dim">
                            <code className="text-hack-accent/60">{tool.binary}</code>
                            {tool.available && tool.version && (
                              <span className="ml-1 text-hack-dim/60 truncate">— {tool.version.slice(0, 35)}</span>
                            )}
                            {!tool.available && (
                              <span className="ml-1 text-hack-dim/40 italic">not installed</span>
                            )}
                          </div>

                          {/* Description */}
                          <p className="mt-1.5 text-[10px] text-hack-dim/80 leading-relaxed line-clamp-2">
                            {tool.description}
                          </p>

                          {/* Expanded detail */}
                          {isExpanded && (
                            <div
                              className="mt-3 space-y-2 border-t border-hack-border/30 pt-2"
                              onClick={e => e.stopPropagation()}
                            >
                              {/* Command template */}
                              <div>
                                <span className="text-[9px] text-hack-dim/60 block mb-0.5">COMMAND TEMPLATE</span>
                                <code className="text-[10px] text-hack-accent/80 break-all leading-relaxed">
                                  {tool.commandTemplate}
                                </code>
                              </div>

                              {/* Vuln classes */}
                              {tool.vulnClasses.length > 0 && (
                                <div>
                                  <span className="text-[9px] text-hack-dim/60 block mb-1">DETECTS</span>
                                  <div className="flex flex-wrap gap-1">
                                    {tool.vulnClasses.map(vc => (
                                      <span key={vc} className="text-[9px] px-1.5 py-0.5 rounded border border-hack-accent/20 bg-hack-accent/10 text-hack-accent/80">
                                        {vc}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Install status / path */}
                              {tool.available ? (
                                <div className="text-[10px] text-green-400/80">
                                  <CheckCircle2 className="w-3 h-3 inline mr-1" />
                                  {tool.path}
                                </div>
                              ) : (
                                <div className="text-[10px] text-hack-dim/50 flex items-center gap-1">
                                  <BookOpen className="w-3 h-3" />
                                  <code>apt install {tool.binary}</code>
                                </div>
                              )}

                              {/* Rate limit */}
                              <div className="text-[10px] text-hack-dim/60">
                                Rate limit: {tool.rateLimit}s · Parser: {tool.parserType}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

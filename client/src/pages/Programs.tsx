import React, { useEffect, useState } from "react";
import { Target, Plus, Star, TrendingUp, Clock, DollarSign, RefreshCw, Trash2 } from "lucide-react";
import { bountyAPI } from "../lib/api";
import toast from "react-hot-toast";

interface Program {
  id: number;
  name: string;
  platform: string;
  scope: string[];
  outOfScope: string[];
  maxPayout: number;
  avgPayout: number;
  responseTime: number;
  roiScore: number;
  active: boolean;
  tags: string[];
}

const PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack", "other"];
const PLATFORM_COLORS: Record<string, string> = {
  hackerone: "text-green-400", bugcrowd: "text-orange-400", intigriti: "text-purple-400",
  synack: "text-cyan-400", yeswehack: "text-yellow-400", other: "text-hack-dim",
};

export default function Programs() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [rankings, setRankings] = useState<Record<number, number>>({});
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    name: "", platform: "hackerone", programHandle: "",
    scope: "", outOfScope: "", maxPayout: "5000", avgPayout: "500",
    responseTime: "72", tags: "",
  });

  const load = () => {
    setLoading(true);
    Promise.all([bountyAPI.getPrograms(), bountyAPI.rankPrograms()])
      .then(([p, r]) => {
        setPrograms(p.data || []);
        const rankMap: Record<number, number> = {};
        (r.data || []).forEach((s: Record<string, unknown>) => { rankMap[Number(s.programId)] = Number(s.rank); });
        setRankings(rankMap);
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await bountyAPI.createProgram({
        name: form.name,
        platform: form.platform,
        programHandle: form.programHandle || undefined,
        scope: form.scope.split("\n").map(s => s.trim()).filter(Boolean),
        outOfScope: form.outOfScope.split("\n").map(s => s.trim()).filter(Boolean),
        maxPayout: parseInt(form.maxPayout) || 0,
        avgPayout: parseFloat(form.avgPayout) || 0,
        responseTime: parseFloat(form.responseTime) || 72,
        tags: form.tags.split(",").map(t => t.trim()).filter(Boolean),
      });
      toast.success("Program added");
      setShowForm(false);
      load();
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } };
      toast.error(error.response?.data?.error || "Failed to create program");
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Archive this program?")) return;
    await bountyAPI.deleteProgram(id);
    toast.success("Program archived");
    load();
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-hack-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Target className="w-4 h-4 text-hack-accent" />
          <span className="text-sm font-mono font-bold text-hack-accent">BUG BOUNTY PROGRAMS</span>
          <span className="text-[10px] text-hack-dim font-mono ml-2">({programs.length} programs)</span>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="hack-btn flex items-center gap-1">
            <RefreshCw className="w-3 h-3" /> REFRESH
          </button>
          <button onClick={() => setShowForm(!showForm)} className="hack-btn-primary flex items-center gap-1">
            <Plus className="w-3 h-3" /> ADD PROGRAM
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto terminal-scroll p-4 space-y-4">
        {/* Add Program Form */}
        {showForm && (
          <div className="hack-panel p-4 border-hack-accent/30">
            <h3 className="text-xs font-mono text-hack-accent mb-3">NEW PROGRAM</h3>
            <form onSubmit={handleCreate} className="grid grid-cols-3 gap-3">
              <div>
                <label className="hack-label">Program Name *</label>
                <input className="hack-input w-full" value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="MyTarget Corp" required />
              </div>
              <div>
                <label className="hack-label">Platform</label>
                <select className="hack-input w-full" value={form.platform} onChange={e => setForm({...form, platform: e.target.value})}>
                  {PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div>
                <label className="hack-label">Program Handle</label>
                <input className="hack-input w-full" value={form.programHandle} onChange={e => setForm({...form, programHandle: e.target.value})} placeholder="program-handle" />
              </div>
              <div>
                <label className="hack-label">In-Scope (one per line)</label>
                <textarea className="hack-input w-full h-20 resize-none" value={form.scope} onChange={e => setForm({...form, scope: e.target.value})} placeholder="*.example.com&#10;app.example.com&#10;api.example.com" />
              </div>
              <div>
                <label className="hack-label">Out-of-Scope (one per line)</label>
                <textarea className="hack-input w-full h-20 resize-none" value={form.outOfScope} onChange={e => setForm({...form, outOfScope: e.target.value})} placeholder="blog.example.com&#10;docs.example.com" />
              </div>
              <div className="space-y-2">
                <div>
                  <label className="hack-label">Max Payout ($)</label>
                  <input type="number" className="hack-input w-full" value={form.maxPayout} onChange={e => setForm({...form, maxPayout: e.target.value})} />
                </div>
                <div>
                  <label className="hack-label">Avg Response Time (hrs)</label>
                  <input type="number" className="hack-input w-full" value={form.responseTime} onChange={e => setForm({...form, responseTime: e.target.value})} />
                </div>
                <div>
                  <label className="hack-label">Tags (comma-separated)</label>
                  <input className="hack-input w-full" value={form.tags} onChange={e => setForm({...form, tags: e.target.value})} placeholder="web, api, fintech" />
                </div>
              </div>
              <div className="col-span-3 flex justify-end gap-2">
                <button type="button" onClick={() => setShowForm(false)} className="hack-btn">CANCEL</button>
                <button type="submit" className="hack-btn-primary">CREATE PROGRAM</button>
              </div>
            </form>
          </div>
        )}

        {/* Programs list */}
        {loading ? (
          <div className="text-[10px] text-hack-dim animate-pulse font-mono">Scanning programs...</div>
        ) : programs.length === 0 ? (
          <div className="hack-panel p-8 text-center">
            <Target className="w-8 h-8 text-hack-dim mx-auto mb-2" strokeWidth={1} />
            <div className="text-xs text-hack-dim font-mono">No programs configured</div>
            <div className="text-[10px] text-hack-dim font-mono mt-1">Add a bug bounty program to start hunting</div>
          </div>
        ) : (
          <div className="space-y-2">
            {programs.map(prog => (
              <div key={prog.id} className="hack-panel p-3 hover:border-hack-muted transition-colors group">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2 flex-1 min-w-0">
                    {rankings[prog.id] && (
                      <div className="w-6 h-6 rounded bg-hack-accent/10 border border-hack-accent/30 flex items-center justify-center text-[9px] font-mono text-hack-accent flex-shrink-0">
                        #{rankings[prog.id]}
                      </div>
                    )}
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-hack-text">{prog.name}</span>
                        <span className={`text-[9px] font-mono ${PLATFORM_COLORS[prog.platform] || "text-hack-dim"}`}>
                          [{prog.platform}]
                        </span>
                        {prog.tags && (prog.tags as string[]).slice(0, 3).map(t => (
                          <span key={t} className="text-[9px] font-mono text-hack-dim bg-hack-muted px-1 rounded">{t}</span>
                        ))}
                      </div>
                      <div className="flex gap-3 mt-1">
                        <span className="flex items-center gap-1 text-[10px] text-hack-dim font-mono">
                          <DollarSign className="w-2.5 h-2.5" /> {prog.maxPayout > 0 ? `$${prog.maxPayout.toLocaleString()}` : "N/A"}
                        </span>
                        <span className="flex items-center gap-1 text-[10px] text-hack-dim font-mono">
                          <Clock className="w-2.5 h-2.5" /> {prog.responseTime || "?"}h response
                        </span>
                        <span className="flex items-center gap-1 text-[10px] text-hack-dim font-mono">
                          <Target className="w-2.5 h-2.5" /> {(prog.scope as string[]).length} in-scope
                        </span>
                        {prog.roiScore > 0 && (
                          <span className="flex items-center gap-1 text-[10px] text-hack-accent font-mono">
                            <TrendingUp className="w-2.5 h-2.5" /> ROI: {prog.roiScore}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button onClick={() => handleDelete(prog.id)} className="hack-btn-danger p-1.5">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                {/* Scope */}
                {(prog.scope as string[]).length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {(prog.scope as string[]).slice(0, 5).map(s => (
                      <span key={s} className="text-[9px] font-mono text-hack-cyan bg-hack-cyan/5 border border-hack-cyan/20 px-1.5 py-0.5 rounded">
                        {s}
                      </span>
                    ))}
                    {(prog.scope as string[]).length > 5 && (
                      <span className="text-[9px] font-mono text-hack-dim">+{(prog.scope as string[]).length - 5} more</span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

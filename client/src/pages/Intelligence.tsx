import React, { useEffect, useState } from "react";
import {
  Brain, TrendingUp, Shield, Network, Zap, Activity,
  ChevronUp, ChevronDown, Minus, RefreshCw
} from "lucide-react";
import { bountyAPI } from "../lib/api";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, Tooltip, ResponsiveContainer } from "recharts";

export default function Intelligence() {
  const [rlStats, setRlStats] = useState<Record<string, unknown> | null>(null);
  const [autonomy, setAutonomy] = useState<Record<string, unknown> | null>(null);
  const [exploitChains, setExploitChains] = useState<Record<string, unknown>[]>([]);
  const [wafProfiles, setWafProfiles] = useState<Record<string, unknown>[]>([]);
  const [roiRanking, setRoiRanking] = useState<Record<string, unknown>[]>([]);
  const [prebuiltChains, setPrebuiltChains] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"autonomy" | "rl" | "waf" | "chains" | "roi">("autonomy");

  const load = () => {
    setLoading(true);
    Promise.all([
      bountyAPI.getRlStats(),
      bountyAPI.getAutonomy(),
      bountyAPI.getExploitChains(),
      bountyAPI.getWafProfiles(),
      bountyAPI.getRoiRanking(10000),
      bountyAPI.getPrebuiltChains(),
    ]).then(([rl, aut, chains, waf, roi, prebuilt]) => {
      setRlStats(rl.data);
      setAutonomy(aut.data);
      setExploitChains(chains.data || []);
      setWafProfiles(waf.data || []);
      setRoiRanking(roi.data || []);
      setPrebuiltChains(prebuilt.data || {});
    }).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const TREND_ICON: Record<string, React.ReactNode> = {
    improving: <ChevronUp className="w-3 h-3 text-hack-accent" />,
    stable: <Minus className="w-3 h-3 text-hack-dim" />,
    declining: <ChevronDown className="w-3 h-3 text-hack-red" />,
  };

  const tabs = [
    { id: "autonomy", label: "AUTONOMY", icon: Brain },
    { id: "rl", label: "REINFORCEMENT", icon: Activity },
    { id: "waf", label: "WAF INTEL", icon: Shield },
    { id: "chains", label: "EXPLOIT CHAINS", icon: Network },
    { id: "roi", label: "ROI MODEL", icon: TrendingUp },
  ];

  // Prepare radar chart data for domain scores
  const radarData = autonomy?.domainScores
    ? Object.entries(autonomy.domainScores as Record<string, Record<string, unknown>>).map(([domain, ds]) => ({
        domain: domain.replace(/_/g, "\n"),
        score: Math.round(Number(ds.score || 0) * 100),
      }))
    : [];

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-hack-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-hack-purple" />
          <span className="text-sm font-mono font-bold text-hack-purple">INTELLIGENCE SUITE</span>
        </div>
        <button onClick={load} className="hack-btn flex items-center gap-1"><RefreshCw className="w-3 h-3" /> REFRESH</button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-hack-border flex-shrink-0">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <button key={tab.id} onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`flex items-center gap-1.5 px-4 py-2 text-[10px] font-mono border-b-2 transition-colors ${activeTab === tab.id ? "text-hack-accent border-hack-accent" : "text-hack-dim border-transparent hover:text-hack-text"}`}>
              <Icon className="w-3 h-3" />
              {tab.label}
            </button>
          );
        })}
      </div>

      <div className="flex-1 overflow-y-auto terminal-scroll p-4">
        {loading ? (
          <div className="text-[10px] text-hack-dim animate-pulse font-mono">Loading intelligence data...</div>
        ) : (
          <>
            {/* Autonomy Tab */}
            {activeTab === "autonomy" && (
              <div className="space-y-4">
                {!autonomy ? (
                  <div className="text-[10px] text-hack-dim font-mono">No autonomy data. Complete at least one hunt.</div>
                ) : (
                  <div className="grid grid-cols-3 gap-4">
                    {/* CAMS score */}
                    <div className="hack-panel p-4 text-center">
                      <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">Composite Score (CAMS)</div>
                      <div className="text-4xl font-mono font-bold text-hack-purple mb-1">
                        {String(autonomy.compositeScore || 0)}
                      </div>
                      <div className="text-[10px] text-hack-dim font-mono">{String(autonomy.maturityLevel || "Nascent")}</div>
                      {autonomy.readyForFullAutonomy ? (
                        <div className="mt-2 text-[9px] text-hack-accent font-mono">FULL AUTONOMY READY</div>
                      ) : (
                        <div className="mt-2 text-[9px] text-hack-dim font-mono">Hunt #{Number(autonomy.huntNumber || 0)} of 50 required</div>
                      )}
                    </div>

                    {/* Brier score */}
                    <div className="hack-panel p-4 text-center">
                      <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">Brier Score (Calibration)</div>
                      <div className="text-4xl font-mono font-bold text-hack-cyan mb-1">
                        {Number(autonomy.brierScore || 0).toFixed(3)}
                      </div>
                      <div className="text-[10px] text-hack-dim font-mono">
                        {Number(autonomy.brierScore || 0) < 0.1 ? "Excellent" : Number(autonomy.brierScore || 0) < 0.2 ? "Good" : "Needs calibration"}
                      </div>
                    </div>

                    {/* RL Noise */}
                    <div className="hack-panel p-4 text-center">
                      <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">RL Noise Level</div>
                      <div className={`text-4xl font-mono font-bold mb-1 ${Number(autonomy.reinforcementNoise || 0) > 0.1 ? "text-hack-red" : "text-hack-accent"}`}>
                        {Number(autonomy.reinforcementNoise || 0).toFixed(4)}
                      </div>
                      <div className="text-[10px] text-hack-dim font-mono">
                        {Number(autonomy.reinforcementNoise || 0) > 0.1 ? "High noise" : "Low noise"}
                      </div>
                    </div>

                    {/* Domain scores radar */}
                    {radarData.length > 0 && (
                      <div className="col-span-2 hack-panel p-4">
                        <div className="text-[10px] text-hack-dim font-mono uppercase mb-3">Domain Scores</div>
                        <ResponsiveContainer width="100%" height={200}>
                          <RadarChart data={radarData}>
                            <PolarGrid stroke="#1e1e3f" />
                            <PolarAngleAxis dataKey="domain" tick={{ fontSize: 8, fill: "#6060a0", fontFamily: "monospace" }} />
                            <Tooltip contentStyle={{ background: "#141420", border: "1px solid #1e1e3f", fontSize: 10, fontFamily: "monospace" }} />
                            <Radar name="Score" dataKey="score" stroke="#8844ff" fill="#8844ff" fillOpacity={0.15} />
                          </RadarChart>
                        </ResponsiveContainer>
                      </div>
                    )}

                    {/* Domain breakdown */}
                    <div className="hack-panel p-4">
                      <div className="text-[10px] text-hack-dim font-mono uppercase mb-3">Per-Domain Gating</div>
                      <div className="space-y-2">
                        {Object.entries((autonomy.domainScores as Record<string, Record<string, unknown>>) || {}).map(([domain, ds]) => (
                          <div key={domain}>
                            <div className="flex items-center justify-between text-[9px] font-mono mb-0.5">
                              <div className="flex items-center gap-1">
                                {TREND_ICON[String(ds.trend)] || TREND_ICON.stable}
                                <span className="text-hack-text">{domain.replace(/_/g, " ")}</span>
                              </div>
                              <span className={ds.regressionDetected ? "text-hack-red" : "text-hack-dim"}>
                                {String(ds.maturityLevel || "")} {ds.regressionDetected ? "⚠" : ""}
                              </span>
                            </div>
                            <div className="h-1 bg-hack-muted rounded">
                              <div className="h-1 rounded" style={{
                                width: `${Math.round(Number(ds.score || 0) * 100)}%`,
                                backgroundColor: Number(ds.score || 0) > 0.7 ? "#00ff88" : Number(ds.score || 0) > 0.4 ? "#ffcc00" : "#ff3355"
                              }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Recommendations */}
                    {(autonomy.recommendations as string[])?.length > 0 && (
                      <div className="col-span-3 hack-panel p-4">
                        <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">AI Recommendations</div>
                        {(autonomy.recommendations as string[]).map((r: string, i: number) => (
                          <div key={i} className="flex gap-2 text-[10px] font-mono text-hack-text mb-1">
                            <Zap className="w-3 h-3 text-hack-yellow flex-shrink-0 mt-0.5" />
                            {r}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Reinforcement Tab */}
            {activeTab === "rl" && rlStats && (
              <div className="grid grid-cols-3 gap-3">
                {Object.entries((rlStats.stats as Record<string, Record<string, unknown>>) || {}).map(([domain, stats]) => (
                  <div key={domain} className="hack-panel p-3">
                    <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">{domain.replace(/_/g, " ")}</div>
                    <div className="text-xl font-mono font-bold text-hack-blue mb-0.5">{Number(stats.entries || 0)}</div>
                    <div className="text-[9px] text-hack-dim font-mono">entries</div>
                    <div className="mt-2 h-1 bg-hack-muted rounded">
                      <div className="h-1 rounded bg-hack-blue" style={{ width: `${Math.round(Number(stats.avgSuccessRate || 0) * 100)}%` }} />
                    </div>
                    <div className="text-[9px] text-hack-dim font-mono mt-0.5">avg success: {Math.round(Number(stats.avgSuccessRate || 0) * 100)}%</div>
                  </div>
                ))}
                <div className="hack-panel p-3">
                  <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">Brier Score</div>
                  <div className="text-xl font-mono font-bold text-hack-purple">{Number(rlStats.brierScore || 0).toFixed(4)}</div>
                  <div className="text-[9px] text-hack-dim font-mono mt-1">Lower = better calibration</div>
                </div>
              </div>
            )}

            {/* WAF Intel Tab */}
            {activeTab === "waf" && (
              <div className="space-y-2">
                {wafProfiles.length === 0 ? (
                  <div className="text-[10px] text-hack-dim font-mono">No WAF profiles yet. Run hunts to build WAF intelligence.</div>
                ) : wafProfiles.map((p: Record<string, unknown>) => (
                  <div key={Number(p.id)} className="hack-panel p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Shield className="w-3.5 h-3.5 text-hack-orange" />
                        <span className="text-xs font-mono font-bold text-hack-text">{String(p.vendor || "Unknown WAF")}</span>
                        <span className="text-[10px] text-hack-dim font-mono">{String(p.targetDomain || "")}</span>
                      </div>
                      <span className="text-[9px] font-mono text-hack-accent">{Number(p.successfulBypasses || 0)} bypasses</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Exploit Chains Tab */}
            {activeTab === "chains" && (
              <div className="space-y-3">
                <div className="text-[10px] text-hack-dim font-mono mb-2">Pre-built Attack Trees</div>
                {Object.entries(prebuiltChains).map(([key, chain]) => (
                  <div key={key} className="hack-panel p-3">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Network className="w-3.5 h-3.5 text-hack-purple" />
                        <span className="text-xs font-mono font-bold text-hack-text">{String((chain as Record<string, unknown>).name || "")}</span>
                      </div>
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border severity-${String((chain as Record<string, unknown>).estimatedSeverity || "medium")}`}>
                        {String((chain as Record<string, unknown>).estimatedSeverity || "").toUpperCase()}
                      </span>
                    </div>
                    <div className="text-[10px] text-hack-dim font-mono mb-2">{String((chain as Record<string, unknown>).description || "")}</div>
                    <div className="flex gap-1 flex-wrap">
                      {((chain as Record<string, unknown>).steps as Record<string, unknown>[])?.map((step, i) => (
                        <span key={i} className="text-[9px] font-mono text-hack-cyan bg-hack-cyan/5 border border-hack-cyan/20 px-1.5 py-0.5 rounded">
                          {i + 1}. {String(step.vulnClass || "")}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}

                {exploitChains.length > 0 && (
                  <>
                    <div className="text-[10px] text-hack-dim font-mono mt-4 mb-2">Active Chains</div>
                    {exploitChains.map((c: Record<string, unknown>) => (
                      <div key={Number(c.id)} className="hack-panel p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono text-hack-text">{String(c.name || "")}</span>
                          <span className="text-[9px] text-hack-dim font-mono">{String(c.status || "")} — {Math.round(Number(c.successRate || 0) * 100)}% success</span>
                        </div>
                      </div>
                    ))}
                  </>
                )}
              </div>
            )}

            {/* ROI Tab */}
            {activeTab === "roi" && (
              <div className="space-y-2">
                <div className="text-[10px] text-hack-dim font-mono mb-2">Vulnerability Classes ranked by Expected Value</div>
                {roiRanking.map((r: Record<string, unknown>, i: number) => (
                  <div key={String(r.vulnClass)} className="flex items-center gap-3 p-2 hack-panel">
                    <div className="w-4 text-[9px] font-mono text-hack-dim">#{i + 1}</div>
                    <div className="w-32 text-[10px] font-mono text-hack-text">{String(r.vulnClass || "")}</div>
                    <div className="flex-1">
                      <div className="h-1 bg-hack-muted rounded">
                        <div className="h-1 rounded bg-gradient-to-r from-hack-red to-hack-orange"
                          style={{ width: `${Math.min(100, (Number(r.expectedValue) / 2000) * 100)}%` }} />
                      </div>
                    </div>
                    <div className="text-[10px] font-mono text-hack-accent w-20 text-right">
                      ${Number(r.expectedValue || 0).toFixed(0)} EV
                    </div>
                    <div className="text-[9px] font-mono text-hack-dim w-20 text-right">
                      ROI: {Number(r.roi || 0).toFixed(1)}x
                    </div>
                    <div className="text-[9px] font-mono text-hack-dim w-16 text-right">
                      {Math.round(Number(r.successRate || 0) * 100)}% hit
                    </div>
                    <div className="text-[9px] font-mono text-hack-yellow w-16 text-right">
                      thresh: {Number(r.confidenceThreshold || 0).toFixed(2)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

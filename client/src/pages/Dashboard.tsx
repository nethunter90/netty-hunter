import React, { useEffect, useState } from "react";
import {
  ShieldAlert, Target, Play, TrendingUp, Zap, Activity, Brain, Crosshair
} from "lucide-react";
import { hunterAPI, bountyAPI } from "../lib/api";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff3355",
  high: "#ff8800",
  medium: "#ffcc00",
  low: "#4488ff",
  info: "#6060a0",
};

export default function Dashboard() {
  const [stats, setStats] = useState({ programs: 0, campaigns: 0, findings: 0, critical: 0, high: 0 });
  const [findings, setFindings] = useState<Record<string, unknown>[]>([]);
  const [autonomy, setAutonomy] = useState<Record<string, unknown> | null>(null);
  const [autonomyHistory, setAutonomyHistory] = useState<unknown[]>([]);
  const [roiRanking, setRoiRanking] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      bountyAPI.getPrograms(),
      hunterAPI.getCampaigns(),
      hunterAPI.getFindings(),
      bountyAPI.getAutonomy(),
      bountyAPI.getAutonomyHistory(),
      bountyAPI.getRoiRanking(10000),
    ]).then(([programs, campaigns, findingsRes, autonomyRes, historyRes, roiRes]) => {
      const f = findingsRes.data || [];
      setFindings(f.slice(0, 5));
      setStats({
        programs: programs.data?.length || 0,
        campaigns: campaigns.data?.length || 0,
        findings: f.length,
        critical: f.filter((x: Record<string, unknown>) => x.severity === "critical").length,
        high: f.filter((x: Record<string, unknown>) => x.severity === "high").length,
      });
      setAutonomy(autonomyRes.data);
      setAutonomyHistory(historyRes.data || []);
      setRoiRanking((roiRes.data || []).slice(0, 8));
    }).catch(() => {}).finally(() => setLoading(false));
  }, []);

  const statCards = [
    { label: "Programs", value: stats.programs, icon: Target, color: "text-hack-cyan" },
    { label: "Campaigns", value: stats.campaigns, icon: Play, color: "text-hack-blue" },
    { label: "Findings", value: stats.findings, icon: ShieldAlert, color: "text-hack-accent" },
    { label: "Critical", value: stats.critical, icon: Zap, color: "text-hack-red" },
  ];

  return (
    <div className="h-full overflow-y-auto terminal-scroll p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-sm font-mono font-bold text-hack-accent glow-green">MISSION CONTROL</h1>
          <p className="text-[10px] text-hack-dim font-mono">Bug Bounty Intelligence Dashboard</p>
        </div>
        <div className="text-[10px] text-hack-dim font-mono">
          {new Date().toISOString().slice(0, 19).replace("T", " ")} UTC
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-3">
        {statCards.map(card => {
          const Icon = card.icon;
          return (
            <div key={card.label} className="hack-panel p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] text-hack-dim font-mono uppercase">{card.label}</span>
                <Icon className={`w-3.5 h-3.5 ${card.color}`} strokeWidth={1.5} />
              </div>
              <div className={`text-2xl font-mono font-bold ${card.color}`}>
                {loading ? "—" : card.value}
              </div>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-3 gap-3">
        {/* Recent Findings */}
        <div className="col-span-2 hack-panel p-3">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert className="w-3.5 h-3.5 text-hack-accent" />
            <span className="text-[10px] font-mono uppercase text-hack-dim">Recent Findings</span>
          </div>
          {loading ? (
            <div className="text-[10px] text-hack-dim animate-pulse">Loading...</div>
          ) : findings.length === 0 ? (
            <div className="text-[10px] text-hack-dim font-mono">No findings yet. Start a hunt.</div>
          ) : (
            <div className="space-y-1.5">
              {findings.map((f: Record<string, unknown>, i) => (
                <div key={i} className="flex items-center gap-2 p-2 bg-hack-surface rounded border border-hack-border hover:border-hack-muted transition-colors">
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase severity-${f.severity}`}>
                    {String(f.severity || "").slice(0, 4).toUpperCase()}
                  </span>
                  <span className="text-[10px] font-mono text-hack-text truncate flex-1">{String(f.title || "")}</span>
                  <span className="text-[9px] text-hack-dim font-mono">{String(f.vulnType || "")}</span>
                  <span className={`text-[9px] font-mono px-1 rounded border uppercase ${f.verificationStatus === "confirmed" ? "text-hack-accent border-hack-accent/30" : "text-hack-dim border-hack-border"}`}>
                    {String(f.verificationStatus || "new")}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Autonomy Score */}
        <div className="hack-panel p-3">
          <div className="flex items-center gap-2 mb-3">
            <Brain className="w-3.5 h-3.5 text-hack-purple" />
            <span className="text-[10px] font-mono uppercase text-hack-dim">Autonomy Score</span>
          </div>
          {autonomy ? (
            <div className="space-y-2">
              <div className="text-center">
                <div className="text-3xl font-mono font-bold text-hack-purple">
                  {String((autonomy as Record<string, unknown>).compositeScore || 0)}
                </div>
                <div className="text-[10px] text-hack-dim font-mono">{String((autonomy as Record<string, unknown>).maturityLevel || "Nascent")}</div>
              </div>
              {/* Domain bars */}
              {autonomy.domainScores && Object.entries(autonomy.domainScores as Record<string, Record<string, unknown>>).slice(0, 4).map(([domain, ds]) => (
                <div key={domain}>
                  <div className="flex justify-between text-[9px] font-mono text-hack-dim mb-0.5">
                    <span>{domain.replace(/_/g, " ")}</span>
                    <span>{Math.round(Number(ds.score || 0) * 100)}%</span>
                  </div>
                  <div className="h-1 bg-hack-muted rounded">
                    <div
                      className="h-1 rounded transition-all"
                      style={{
                        width: `${Math.round(Number(ds.score || 0) * 100)}%`,
                        backgroundColor: Number(ds.score || 0) > 0.7 ? "#00ff88" : Number(ds.score || 0) > 0.4 ? "#ffcc00" : "#ff3355"
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-[10px] text-hack-dim font-mono">No autonomy data. Complete hunts to build history.</div>
          )}
        </div>
      </div>

      {/* ROI Ranking */}
      <div className="hack-panel p-3">
        <div className="flex items-center gap-2 mb-3">
          <TrendingUp className="w-3.5 h-3.5 text-hack-green" />
          <span className="text-[10px] font-mono uppercase text-hack-dim">Vulnerability ROI Ranking</span>
        </div>
        {roiRanking.length > 0 ? (
          <ResponsiveContainer width="100%" height={120}>
            <BarChart data={roiRanking} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="vulnClass" tick={{ fontSize: 9, fill: "#6060a0", fontFamily: "monospace" }} />
              <YAxis tick={{ fontSize: 9, fill: "#6060a0", fontFamily: "monospace" }} />
              <Tooltip
                contentStyle={{ background: "#141420", border: "1px solid #1e1e3f", fontFamily: "monospace", fontSize: 10 }}
                labelStyle={{ color: "#00ff88" }}
              />
              <Bar dataKey="expectedValue" radius={[2, 2, 0, 0]}>
                {roiRanking.map((_: unknown, i) => (
                  <Cell key={i} fill={i === 0 ? "#ff3355" : i < 3 ? "#ff8800" : "#4488ff"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="text-[10px] text-hack-dim font-mono">Loading ROI data...</div>
        )}
      </div>

      {/* Autonomy history */}
      {autonomyHistory.length > 1 && (
        <div className="hack-panel p-3">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-3.5 h-3.5 text-hack-cyan" />
            <span className="text-[10px] font-mono uppercase text-hack-dim">Autonomy Maturity History</span>
          </div>
          <ResponsiveContainer width="100%" height={80}>
            <LineChart data={autonomyHistory}>
              <XAxis dataKey="huntNumber" tick={{ fontSize: 9, fill: "#6060a0" }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 9, fill: "#6060a0" }} />
              <Tooltip contentStyle={{ background: "#141420", border: "1px solid #1e1e3f", fontSize: 10, fontFamily: "monospace" }} />
              <Line type="monotone" dataKey="compositeScore" stroke="#8844ff" dot={false} strokeWidth={1.5} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

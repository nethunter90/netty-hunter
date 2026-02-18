import React, { useEffect, useState } from "react";
import {
  ShieldAlert, CheckCircle2, XCircle, AlertTriangle, Filter,
  FileText, Code2, Search, ExternalLink, RefreshCw
} from "lucide-react";
import { hunterAPI } from "../lib/api";
import toast from "react-hot-toast";

interface Finding {
  id: number;
  title: string;
  vulnType: string;
  severity: string;
  confidence: number;
  verificationStatus: string;
  description: string;
  exploitPayload?: string;
  cvssScore?: number;
  status: string;
  createdAt: string;
  dedupHash?: string;
  nucleiTemplate?: string;
  reportDraft?: string;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_BG: Record<string, string> = {
  critical: "bg-hack-red/5 border-hack-red/20",
  high: "bg-hack-orange/5 border-hack-orange/20",
  medium: "bg-hack-yellow/5 border-hack-yellow/20",
  low: "bg-hack-blue/5 border-hack-blue/20",
  info: "bg-hack-muted border-hack-border",
};

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filtered, setFiltered] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [detailTab, setDetailTab] = useState<"details" | "nuclei" | "report">("details");
  const [verifying, setVerifying] = useState(false);
  const [generatingReport, setGeneratingReport] = useState(false);

  const load = () => {
    setLoading(true);
    hunterAPI.getFindings().then(r => {
      const f = r.data || [];
      // Sort by severity
      f.sort((a: Finding, b: Finding) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
      setFindings(f);
      setFiltered(f);
    }).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    let f = [...findings];
    if (filterSeverity !== "all") f = f.filter(x => x.severity === filterSeverity);
    if (filterStatus !== "all") f = f.filter(x => x.verificationStatus === filterStatus);
    if (search) f = f.filter(x =>
      x.title.toLowerCase().includes(search.toLowerCase()) ||
      x.vulnType.toLowerCase().includes(search.toLowerCase())
    );
    setFiltered(f);
  }, [filterSeverity, filterStatus, search, findings]);

  const verify = async (id: number) => {
    setVerifying(true);
    try {
      await hunterAPI.verifyFinding(id);
      toast.success("Verification complete");
      load();
    } catch {
      toast.error("Verification failed");
    } finally {
      setVerifying(false);
    }
  };

  const generateNuclei = async (id: number) => {
    try {
      const res = await hunterAPI.getNucleiTemplate(id);
      setSelected(prev => prev ? { ...prev, nucleiTemplate: res.data } : null);
      setDetailTab("nuclei");
      toast.success("Nuclei template generated");
    } catch {
      toast.error("Failed to generate template");
    }
  };

  const generateReport = async (id: number) => {
    setGeneratingReport(true);
    try {
      const res = await hunterAPI.generateReport(id, { programName: "Target Program" });
      setSelected(prev => prev ? { ...prev, reportDraft: res.data.reportMarkdown } : null);
      setDetailTab("report");
      toast.success("Report generated");
    } catch {
      toast.error("Failed to generate report");
    } finally {
      setGeneratingReport(false);
    }
  };

  const VERIFICATION_ICON: Record<string, React.ReactNode> = {
    confirmed: <CheckCircle2 className="w-3 h-3 text-hack-accent" />,
    rejected: <XCircle className="w-3 h-3 text-hack-red" />,
    pending: <AlertTriangle className="w-3 h-3 text-hack-yellow" />,
    inconclusive: <AlertTriangle className="w-3 h-3 text-hack-orange" />,
  };

  return (
    <div className="h-full flex overflow-hidden">
      {/* Left: Findings List */}
      <div className="w-96 flex flex-col border-r border-hack-border flex-shrink-0">
        {/* Filters */}
        <div className="p-3 border-b border-hack-border space-y-2 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5 text-hack-accent" />
              <span className="text-[10px] font-mono uppercase text-hack-accent">Findings ({filtered.length})</span>
            </div>
            <button onClick={load} className="text-hack-dim hover:text-hack-text">
              <RefreshCw className="w-3 h-3" />
            </button>
          </div>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-hack-dim" />
            <input className="hack-input w-full pl-7 text-[10px]" placeholder="Search findings..." value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <div className="flex gap-1 flex-wrap">
            {["all", ...SEVERITY_ORDER].map(s => (
              <button key={s} onClick={() => setFilterSeverity(s)}
                className={`px-2 py-0.5 text-[9px] font-mono uppercase rounded border transition-all ${filterSeverity === s ? `severity-${s === "all" ? "info" : s} border` : "text-hack-dim border-hack-border hover:text-hack-text"}`}>
                {s}
              </button>
            ))}
          </div>
          <div className="flex gap-1">
            {["all", "confirmed", "pending", "rejected"].map(s => (
              <button key={s} onClick={() => setFilterStatus(s)}
                className={`px-2 py-0.5 text-[9px] font-mono uppercase rounded border transition-all ${filterStatus === s ? "text-hack-accent border-hack-accent/30 bg-hack-accent/5" : "text-hack-dim border-hack-border hover:text-hack-text"}`}>
                {s}
              </button>
            ))}
          </div>
        </div>

        {/* List */}
        <div className="flex-1 overflow-y-auto terminal-scroll">
          {loading ? (
            <div className="p-4 text-[10px] text-hack-dim animate-pulse font-mono">Loading findings...</div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center">
              <ShieldAlert className="w-8 h-8 text-hack-dim mx-auto mb-2" strokeWidth={1} />
              <div className="text-xs text-hack-dim font-mono">No findings found</div>
            </div>
          ) : (
            filtered.map(f => (
              <div key={f.id} onClick={() => setSelected(f)}
                className={`p-3 border-b border-hack-border cursor-pointer transition-colors hover:bg-hack-muted/30 ${selected?.id === f.id ? "bg-hack-muted/50 border-l-2 border-l-hack-accent" : ""} ${SEVERITY_BG[f.severity]}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-1.5 flex-1 min-w-0">
                    {VERIFICATION_ICON[f.verificationStatus] || VERIFICATION_ICON.pending}
                    <span className="text-[10px] font-mono text-hack-text truncate">{f.title}</span>
                  </div>
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border flex-shrink-0 severity-${f.severity}`}>
                    {f.severity.slice(0, 4).toUpperCase()}
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-[9px] text-hack-dim font-mono">{f.vulnType}</span>
                  <span className="text-[9px] text-hack-dim font-mono">conf:{Math.round(f.confidence * 100)}%</span>
                  {f.cvssScore && <span className="text-[9px] text-hack-orange font-mono">CVSS:{f.cvssScore}</span>}
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Right: Finding Detail */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {!selected ? (
          <div className="flex-1 flex items-center justify-center text-hack-dim">
            <div className="text-center">
              <ShieldAlert className="w-12 h-12 mx-auto mb-3" strokeWidth={0.8} />
              <div className="text-xs font-mono">Select a finding to view details</div>
            </div>
          </div>
        ) : (
          <>
            {/* Detail Header */}
            <div className="p-4 border-b border-hack-border flex-shrink-0">
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-mono uppercase severity-${selected.severity} mb-2`}>
                    {selected.severity}
                  </div>
                  <h2 className="text-sm font-mono font-bold text-hack-text">{selected.title}</h2>
                  <div className="flex items-center gap-3 mt-1 text-[10px] text-hack-dim font-mono">
                    <span>{selected.vulnType}</span>
                    <span>Confidence: {Math.round(selected.confidence * 100)}%</span>
                    {selected.cvssScore && <span className="text-hack-orange">CVSS: {selected.cvssScore}</span>}
                    {VERIFICATION_ICON[selected.verificationStatus]}
                    <span>{selected.verificationStatus}</span>
                  </div>
                </div>
                <div className="flex gap-2 flex-shrink-0">
                  <button onClick={() => verify(selected.id)} disabled={verifying}
                    className="hack-btn flex items-center gap-1 text-[10px]">
                    <CheckCircle2 className="w-3 h-3" /> VERIFY
                  </button>
                  <button onClick={() => generateNuclei(selected.id)}
                    className="hack-btn flex items-center gap-1 text-[10px]">
                    <Code2 className="w-3 h-3" /> NUCLEI
                  </button>
                  <button onClick={() => generateReport(selected.id)} disabled={generatingReport}
                    className="hack-btn flex items-center gap-1 text-[10px]">
                    <FileText className="w-3 h-3" /> REPORT
                  </button>
                </div>
              </div>
            </div>

            {/* Tabs */}
            <div className="flex border-b border-hack-border flex-shrink-0">
              {(["details", "nuclei", "report"] as const).map(tab => (
                <button key={tab} onClick={() => setDetailTab(tab)}
                  className={`px-4 py-2 text-[10px] font-mono uppercase border-b-2 transition-colors ${detailTab === tab ? "text-hack-accent border-hack-accent" : "text-hack-dim border-transparent hover:text-hack-text"}`}>
                  {tab}
                </button>
              ))}
            </div>

            {/* Tab Content */}
            <div className="flex-1 overflow-y-auto terminal-scroll p-4">
              {detailTab === "details" && (
                <div className="space-y-4">
                  <div>
                    <div className="hack-label">Description</div>
                    <div className="text-[11px] font-mono text-hack-text leading-relaxed bg-hack-surface p-3 rounded border border-hack-border">
                      {selected.description}
                    </div>
                  </div>
                  {selected.exploitPayload && (
                    <div>
                      <div className="hack-label">Exploit Payload</div>
                      <pre className="text-[10px] font-mono text-hack-orange bg-hack-surface p-3 rounded border border-hack-border overflow-x-auto">
                        {selected.exploitPayload.slice(0, 1000)}
                      </pre>
                    </div>
                  )}
                  {selected.dedupHash && (
                    <div>
                      <div className="hack-label">Dedup Hash</div>
                      <div className="text-[10px] font-mono text-hack-dim">{selected.dedupHash}</div>
                    </div>
                  )}
                  <div>
                    <div className="hack-label">Created</div>
                    <div className="text-[10px] font-mono text-hack-dim">{new Date(selected.createdAt).toISOString()}</div>
                  </div>
                </div>
              )}

              {detailTab === "nuclei" && (
                selected.nucleiTemplate ? (
                  <pre className="text-[10px] font-mono text-hack-text leading-relaxed whitespace-pre-wrap">
                    {selected.nucleiTemplate}
                  </pre>
                ) : (
                  <div className="text-[10px] text-hack-dim font-mono">
                    No Nuclei template generated yet. Click the NUCLEI button to generate one.
                  </div>
                )
              )}

              {detailTab === "report" && (
                selected.reportDraft ? (
                  <div className="text-[11px] font-mono text-hack-text leading-relaxed whitespace-pre-wrap">
                    {selected.reportDraft}
                  </div>
                ) : (
                  <div className="text-[10px] text-hack-dim font-mono">
                    No report generated yet. Click the REPORT button to generate a submission-ready report.
                  </div>
                )
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

import { useState, useEffect } from "react";
import {
  Terminal, Play, Square, Eye, Brain, Target, RefreshCw, CheckCircle2,
} from "lucide-react";
import { hunterAPI, bountyAPI } from "../lib/api";
import { getSocket } from "../lib/socket";
import toast from "react-hot-toast";
import { LiveActivityFeed } from "../components/LiveActivityFeed";
import { EgressPoolPanel } from "../components/hunt/EgressPoolPanel";
import GoalPresetPicker from "../components/hunt/GoalPresetPicker";
import { huntStore, useHuntStore } from "../lib/huntStore";

const PHASE_ICONS: Record<string, React.ReactNode> = {
  observe:     <Eye className="w-3 h-3 text-hack-cyan" />,
  hypothesize: <Brain className="w-3 h-3 text-hack-purple" />,
  probe:       <Target className="w-3 h-3 text-hack-orange" />,
  update:      <RefreshCw className="w-3 h-3 text-hack-blue" />,
  complete:    <CheckCircle2 className="w-3 h-3 text-hack-accent" />,
};

function ts(): string {
  return new Date().toISOString().slice(11, 23);
}

export default function HuntConsole() {
  const [programs, setPrograms] = useState<Record<string, unknown>[]>([]);
  const [selectedProgram, setSelectedProgram] = useState<number>(0);
  const [targetUrl, setTargetUrl] = useState("");
  const [huntMode, setHuntMode] = useState<"forward" | "backward">("forward");
  const [goal, setGoal] = useState("");
  const [maxIterations, setMaxIterations] = useState(10);
  const [loading, setLoading] = useState(false);
  const [templates, setTemplates] = useState<Record<string, unknown>[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<string>("");
  const [corpusEnrichment, setCorpusEnrichment] = useState(false);
  const [proxyEnabled, setProxyEnabled] = useState(huntStore.proxyEnabled);
  const [wafBypassEnabled, setWafBypassEnabled] = useState(huntStore.wafBypassEnabled);
  const [customPriority, setCustomPriority] = useState<string[]>([]);

  // Live hunt progress is owned by huntStore and fed by the always-mounted event
  // bridge (huntEventBridge.ts). This panel is a pure reader — switching panels
  // no longer drops history, because the subscription lives above the routing.
  const { activeSessions, activityEvents, hypStats, externalHunt } = useHuntStore();

  const socket = getSocket();

  // Keep proxy/WAF toggles (form controls) mirrored into the store for startHunt.
  useEffect(() => { huntStore.setProxyEnabled(proxyEnabled); }, [proxyEnabled]);
  useEffect(() => { huntStore.setWafBypassEnabled(wafBypassEnabled); }, [wafBypassEnabled]);

  useEffect(() => {
    bountyAPI.getPrograms().then(r => setPrograms(r.data || []));
    bountyAPI.getHuntTemplates().then(r => setTemplates(r.data || []));

    // B3: check for any hunt running from another panel so the launch button is
    // correctly disabled and a banner is shown.
    hunterAPI.getStatus().then((r: { data: { running: boolean; hunt: { id: string; kind: string; targetUrl: string } | null } }) => {
      if (r.data.running && r.data.hunt) {
        // If the running hunt is one we're already tracking (in the store), don't
        // show the external banner for it.
        const alreadyTracked = huntStore.activeSessions.some(s => s.sessionUuid === r.data.hunt!.id);
        if (!alreadyTracked) {
          huntStore.setExternalHunt(r.data.hunt);
        }
      }
    }).catch(() => {});
  }, []);


  const startHunt = async () => {
    if (!selectedProgram && selectedProgram !== -1) return toast.error("Select a program first");
    if (!targetUrl) return toast.error("Enter target URL");
    if (huntMode === "backward" && !goal && customPriority.length === 0) {
      return toast.error("Enter a hunt goal or pick a custom priority order for backward mode");
    }

    setLoading(true);
    huntStore.clearForNewHunt();

    try {
      const res = await hunterAPI.startHunt({
        programId: selectedProgram,
        targetUrl,
        mode: huntMode,
        goal: goal || undefined,
        maxIterations,
        templateId: selectedTemplate || undefined,
        budget: { maxRequests: 2000, maxTime: 3600 },
        corpusEnrichment,
        proxyEnabled,
        wafBypassEnabled,
        customVulnPriority: customPriority.length > 0 ? customPriority : undefined,
      });

      const session = {
        sessionUuid: res.data.sessionUuid || `backward-${res.data.planId}`,
        targetUrl,
        status: "running" as const,
        phase: "observe",
        iteration: 0,
        findings: 0,
      };
      // B3: we're now tracking this hunt — clear any external banner
      huntStore.setExternalHunt(null);
      huntStore.updateSessions(prev => [...prev, session]);

      if (res.data.sessionUuid) {
        socket.emit("subscribe:hunt", { sessionUuid: res.data.sessionUuid });
      }
    } catch (err: unknown) {
      const axiosErr = err as { response?: { status?: number; data?: { error?: string; activeHunt?: { id: string; kind: string; targetUrl: string } } } };
      const resp = axiosErr.response;
      if (resp?.status === 409 && resp.data?.activeHunt) {
        // B3: another hunt is already running — surface it so the user knows
        huntStore.setExternalHunt(resp.data.activeHunt);
        toast.error(`Another hunt is already running: ${resp.data.activeHunt.targetUrl}`);
        huntStore.pushEvent({ type: "error", ts: ts(), message: `Hunt already running: ${resp.data.activeHunt.targetUrl}` });
      } else {
        toast.error(resp?.data?.error || "Failed to start hunt");
        huntStore.pushEvent({ type: "error", ts: ts(), message: `Failed to start: ${resp?.data?.error}` });
      }
    } finally {
      setLoading(false);
    }
  };

  const stopHunt = async (uuid: string) => {
    // B2: mark stopping immediately (disables button, shows indicator), but don't
    // remove from state until the REST call confirms the backend accepted the stop.
    huntStore.updateSessions(prev => prev.map(s =>
      s.sessionUuid === uuid ? { ...s, status: "stopping" } : s
    ));
    try {
      await hunterAPI.stopHunt(uuid);
      // Backend confirmed stop — remove from state.
      // If the engine emits hunt:aborted via socket first, that handler also removes it.
      huntStore.updateSessions(prev => prev.filter(s => s.sessionUuid !== uuid));
    } catch {
      // Stop failed (maybe already gone) — revert to running so the user can retry
      huntStore.updateSessions(prev => prev.map(s =>
        s.sessionUuid === uuid ? { ...s, status: "running" } : s
      ));
      toast.error("Stop request failed — hunt may have already ended");
    }
  };

  const isRunning = activeSessions.some(s => s.status === "running" || s.status === "stopping");

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-hack-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-hack-accent" />
          <span className="text-sm font-mono font-bold text-hack-accent">HUNT CONSOLE</span>
        </div>
        <div className="text-[10px] text-hack-dim font-mono">
          Active: {activeSessions.filter(s => s.status === "running").length}
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Left: Config */}
        <div className="w-72 border-r border-hack-border flex flex-col overflow-hidden flex-shrink-0">
          <div className="p-3 space-y-3 overflow-y-auto flex-1">
            <div>
              <label className="hack-label">Target Program</label>
              <select
                className="hack-input w-full"
                value={selectedProgram}
                onChange={e => setSelectedProgram(parseInt(e.target.value))}
              >
                <option value={0}>-- Select Program --</option>
                <option value={-1}>★ Custom / Local Lab</option>
                {programs.map((p: any) => (
                  <option key={Number(p.id)} value={Number(p.id)}>{String(p.name)}</option>
                ))}
              </select>
              {selectedProgram === -1 && (
                <div className="text-[9px] text-hack-yellow font-mono mt-1">
                  Custom target — scope validation bypassed. For local labs, CTF, Juice Shop, etc.
                </div>
              )}
            </div>

            <div>
              <label className="hack-label">Target URL</label>
              <input
                className="hack-input w-full"
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                placeholder="https://target.example.com"
              />
            </div>

            <div>
              <label className="hack-label">Hunt Mode</label>
              <div className="flex gap-1">
                {(["forward", "backward"] as const).map(m => (
                  <button key={m} onClick={() => setHuntMode(m)}
                    className={`flex-1 py-1.5 text-[10px] font-mono uppercase rounded border transition-all ${huntMode === m ? "bg-hack-accent/10 text-hack-accent border-hack-accent/30" : "text-hack-dim border-hack-border hover:text-hack-text"}`}>
                    {m === "forward" ? "→ FORWARD" : "← BACKWARD"}
                  </button>
                ))}
              </div>
              <div className="text-[9px] text-hack-dim font-mono mt-1">
                {huntMode === "forward" ? "Observe → Hypothesize → Probe → Update" : "Goal-first hunting using pre-built attack trees"}
              </div>
            </div>

            {huntMode === "backward" && (
              <GoalPresetPicker
                goal={goal}
                setGoal={setGoal}
                customPriority={customPriority}
                setCustomPriority={setCustomPriority}
              />
            )}

            <div>
              <label className="hack-label">Hunt Template</label>
              <select className="hack-input w-full" value={selectedTemplate} onChange={e => setSelectedTemplate(e.target.value)}>
                <option value="">-- Auto-select --</option>
                {templates.map((t: any) => (
                  <option key={String(t.id)} value={String(t.id)}>{String(t.name)}</option>
                ))}
              </select>
              {selectedTemplate && (
                <div className="text-[9px] text-hack-dim mt-1 font-mono">
                  {String((templates.find((t: any) => String(t.id) === selectedTemplate) as any)?.description || "")}
                </div>
              )}
            </div>

            <div>
              <label className="hack-label">Max Iterations: {maxIterations}</label>
              <input type="range" min={1} max={50} value={maxIterations} onChange={e => setMaxIterations(parseInt(e.target.value))} className="w-full accent-hack-accent" />
            </div>

            <div>
              <label className="hack-label">Corpus Enrichment</label>
              <button
                type="button"
                onClick={() => setCorpusEnrichment(v => !v)}
                className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${corpusEnrichment ? 'bg-hack-accent/70' : 'bg-hack-border'}`}
              >
                <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${corpusEnrichment ? 'translate-x-4' : 'translate-x-1'}`} />
              </button>
              <span className={`ml-2 text-[10px] font-mono ${corpusEnrichment ? 'text-hack-accent' : 'text-hack-dim'}`}>
                {corpusEnrichment ? 'ON' : 'OFF'}
              </span>
              <div className="text-[9px] text-hack-dim font-mono mt-1">
                Inject domain knowledge + methodology hints into hypothesis generation
              </div>
            </div>

            <div>
              <label className="hack-label">Proxy Routing (Tor)</label>
              <div className="flex items-center">
                <button
                  type="button"
                  onClick={() => setProxyEnabled(v => !v)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${proxyEnabled ? 'bg-hack-red/70' : 'bg-hack-border'}`}
                >
                  <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${proxyEnabled ? 'translate-x-4' : 'translate-x-1'}`} />
                </button>
                <span className={`ml-2 text-[10px] font-mono ${proxyEnabled ? 'text-hack-red' : 'text-hack-dim'}`}>
                  {proxyEnabled ? 'ON' : 'OFF'}
                </span>
              </div>
              <div className="text-[9px] text-hack-dim font-mono mt-1">
                Routes all tool traffic through Tor (proxychains4). Requires <span className="text-hack-yellow">tor</span> running on 127.0.0.1:9050
              </div>
            </div>

            <div>
              <label className="hack-label">WAF Bypass / Evasion</label>
              <div className="flex items-center">
                <button
                  type="button"
                  onClick={() => setWafBypassEnabled(v => !v)}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none ${wafBypassEnabled ? 'bg-hack-red/70' : 'bg-hack-border'}`}
                >
                  <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${wafBypassEnabled ? 'translate-x-4' : 'translate-x-1'}`} />
                </button>
                <span className={`ml-2 text-[10px] font-mono ${wafBypassEnabled ? 'text-hack-red' : 'text-hack-dim'}`}>
                  {wafBypassEnabled ? 'ON' : 'OFF'}
                </span>
              </div>
              <div className="text-[9px] text-hack-dim font-mono mt-1">
                Off by default — some program scopes explicitly disallow WAF evasion techniques. Only enable for a program whose rules you've confirmed permit it (a program marked "disallowed" in Programs is blocked regardless of this toggle).
              </div>
            </div>

            {externalHunt && (
              <div className="text-[9px] font-mono text-hack-yellow bg-hack-yellow/5 border border-hack-yellow/20 rounded p-2 mb-2">
                <span className="text-hack-yellow/70">{externalHunt.kind.toUpperCase()} running:</span>{" "}
                {externalHunt.targetUrl.length > 30
                  ? externalHunt.targetUrl.slice(0, 30) + "…"
                  : externalHunt.targetUrl}
              </div>
            )}
            <button
              onClick={startHunt}
              disabled={loading || (!selectedProgram && selectedProgram !== -1) || !targetUrl || !!externalHunt}
              className="hack-btn-primary w-full flex items-center justify-center gap-2 py-2.5 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading
                ? <span className="w-3 h-3 border border-hack-bg border-t-transparent rounded-full animate-spin" />
                : <Play className="w-3.5 h-3.5" />}
              {loading ? "INITIALIZING..." : "LAUNCH HUNT"}
            </button>
          </div>

          {/* Active sessions */}
          {activeSessions.length > 0 && (
            <div className="border-t border-hack-border p-3 space-y-2 flex-shrink-0">
              <div className="text-[10px] text-hack-dim font-mono uppercase mb-2">Active Hunts</div>
              {activeSessions.map(session => (
                <div key={session.sessionUuid} className="hack-panel p-2 text-[10px] font-mono">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-1.5">
                      <span className={`status-dot ${session.status === "running" ? "status-running" : session.status === "stopping" ? "status-running opacity-50" : "status-complete"}`} />
                      <span className="text-hack-text truncate max-w-[140px]">{session.targetUrl}</span>
                    </div>
                    {session.status === "running" && (
                      <button onClick={() => stopHunt(session.sessionUuid)} className="text-hack-red hover:text-hack-red/80">
                        <Square className="w-3 h-3" />
                      </button>
                    )}
                    {session.status === "stopping" && (
                      <span className="text-hack-yellow text-[9px] animate-pulse">…</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-hack-dim">
                    {PHASE_ICONS[session.phase]}
                    <span>{session.phase} #{session.iteration}</span>
                    {session.findings > 0 && (
                      <span className="text-hack-orange ml-auto">{session.findings} findings</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          <EgressPoolPanel socket={socket} />
        </div>

        {/* Right: Hypothesis Board + Live Activity Feed */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Hypothesis stats bar — always visible during/after a hunt */}
          {(isRunning || hypStats.confirmed > 0 || hypStats.rejected > 0) && (
            <div className="flex items-center gap-4 px-3 py-1.5 border-b border-hack-border bg-hack-surface flex-shrink-0 text-[9px] font-mono">
              <Brain className="w-3 h-3 text-hack-purple flex-shrink-0" />
              {isRunning && proxyEnabled && (
                <span className="flex items-center gap-1 px-1.5 py-0.5 rounded bg-hack-red/15 border border-hack-red/40 text-hack-red font-bold tracking-widest uppercase animate-pulse">
                  PROXY LIVE
                </span>
              )}
              <span className="text-hack-dim tracking-widest uppercase">hypotheses</span>
              <div className="flex items-center gap-3 ml-2">
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-dim inline-block" />
                  <span className="text-hack-dim">{hypStats.pending} pending</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-orange inline-block animate-pulse" />
                  <span className="text-hack-orange">{hypStats.probing} probing</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-accent inline-block" />
                  <span className="text-hack-accent">{hypStats.confirmed} confirmed</span>
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-hack-red inline-block" />
                  <span className="text-hack-red">{hypStats.rejected} rejected</span>
                </span>
              </div>
            </div>
          )}
          <div className="flex-1 overflow-hidden">
            <LiveActivityFeed
              events={activityEvents}
              isRunning={isRunning}
              title="hunt-engine — /bin/hunter"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

import React, { useEffect, useState } from "react";
import { Settings as SettingsIcon, Save, Eye, EyeOff, CheckCircle2, Cpu, RefreshCw, CheckCircle, Trash2, Power } from "lucide-react";
import api from "../lib/api";
import toast from "react-hot-toast";

interface SettingField {
  key: string;
  label: string;
  placeholder: string;
  secret: boolean;
  group: string;
}

const FIELDS: SettingField[] = [
  // Platforms
  { key: "HACKERONE_USERNAME",   label: "HackerOne Username",     placeholder: "your-h1-handle",          secret: false, group: "Platforms" },
  { key: "HACKERONE_TOKEN",      label: "HackerOne API Token",     placeholder: "••••••••••••",            secret: true,  group: "Platforms" },
  { key: "BUGCROWD_TOKEN",       label: "Bugcrowd Token",          placeholder: "••••••••••••",            secret: true,  group: "Platforms" },
  { key: "INTIGRITI_TOKEN",      label: "Intigriti Token",         placeholder: "••••••••••••",            secret: true,  group: "Platforms" },
  { key: "YESWEHACK_TOKEN",      label: "YesWeHack Token",         placeholder: "••••••••••••",            secret: true,  group: "Platforms" },
  // Notifications
  { key: "SLACK_WEBHOOK_URL",    label: "Slack Webhook URL",       placeholder: "https://hooks.slack.com/…", secret: false, group: "Notifications" },
  { key: "DISCORD_WEBHOOK_URL",  label: "Discord Webhook URL",     placeholder: "https://discord.com/api/…", secret: false, group: "Notifications" },
  { key: "NOTIFY_WEBHOOK_URL",   label: "Generic Webhook URL",     placeholder: "https://your-server/hook",  secret: false, group: "Notifications" },
  // Intelligence
  { key: "NVD_API_KEY",          label: "NVD API Key",             placeholder: "nvd-key-…",              secret: true,  group: "Intelligence" },
  { key: "OOB_HOST",             label: "OOB Callback Host",       placeholder: "http://your-ip:3001",    secret: false, group: "Intelligence" },
  { key: "OPENAI_API_KEY",       label: "OpenAI API Key",          placeholder: "sk-…",                   secret: true,  group: "Intelligence" },
  { key: "ANTHROPIC_API_KEY",    label: "Anthropic API Key",       placeholder: "sk-ant-…",               secret: true,  group: "Intelligence" },
  { key: "CLAUDE_REASON_MODEL",  label: "Claude Reasoning Model",  placeholder: "claude-sonnet-5 (default) — try claude-opus-4-8 to test a full hunt on Opus", secret: false, group: "Intelligence" },
];

const GROUPS = [...new Set(FIELDS.map(f => f.group))];

interface PlatformToggle {
  key: string;
  label: string;
}

// One toggle per hacker platform — flipping it off disconnects that platform
// (no outbound scope-fetch or report-submission calls) without touching the
// stored credential.
const PLATFORM_TOGGLES: PlatformToggle[] = [
  { key: "HACKERONE_ENABLED", label: "HackerOne" },
  { key: "BUGCROWD_ENABLED",  label: "Bugcrowd" },
  { key: "INTIGRITI_ENABLED", label: "Intigriti" },
  { key: "YESWEHACK_ENABLED", label: "YesWeHack" },
  { key: "SYNACK_ENABLED",    label: "Synack" },
];

interface LocalRuntime {
  name: string;
  label: string;
  url: string;
  models: string[];
}

interface LocalModelsResponse {
  runtimes: LocalRuntime[];
  active: { url: string; model: string };
}

export default function SettingsPage() {
  const [values, setValues] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [saved, setSaved] = useState<Set<string>>(new Set());
  const [dirty, setDirty] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);

  const [scanning, setScanning] = useState(false);
  const [localModels, setLocalModels] = useState<LocalModelsResponse | null>(null);
  const [selectedModel, setSelectedModel] = useState<{ url: string; model: string } | null>(null);

  useEffect(() => {
    api.get("/settings").then((r: { data: Record<string, string> }) => {
      setValues(r.data || {});
    }).catch(() => {});
  }, []);

  const toggleReveal = (key: string) => {
    setRevealed(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const handleSave = async () => {
    // Only send fields the user actually edited. Untouched secrets are held in
    // state as masked sentinels (••••1234); re-sending them would overwrite the
    // real stored value, so they must be excluded.
    const payload = Object.fromEntries(
      Object.entries(values).filter(([k, v]) => dirty.has(k) && v)
    );
    if (Object.keys(payload).length === 0) {
      toast("No changes to save");
      return;
    }
    setSaving(true);
    try {
      await api.post("/settings", payload);
      setSaved(new Set(Object.keys(payload)));
      setDirty(new Set());
      toast.success("Settings saved — restart server to apply env var changes");
    } catch {
      toast.error("Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  const isPlatformEnabled = (key: string) => values[key] !== "false";

  const handleTogglePlatform = async (toggle: PlatformToggle) => {
    const next = isPlatformEnabled(toggle.key) ? "false" : "true";
    try {
      await api.post("/settings", { [toggle.key]: next });
      setValues(v => ({ ...v, [toggle.key]: next }));
      toast.success(`${toggle.label} ${next === "true" ? "connected" : "disconnected"}`);
    } catch {
      toast.error(`Failed to toggle ${toggle.label}`);
    }
  };

  const handleClear = async (field: SettingField) => {
    if (!window.confirm(`Clear ${field.label}?`)) return;
    try {
      await api.delete(`/settings/${field.key}`);
      setValues(v => ({ ...v, [field.key]: "" }));
      setDirty(prev => { const next = new Set(prev); next.delete(field.key); return next; });
      setSaved(prev => { const next = new Set(prev); next.delete(field.key); return next; });
      toast.success(`${field.label} cleared`);
    } catch {
      toast.error("Failed to clear");
    }
  };

  const handleScanLocalModels = async () => {
    setScanning(true);
    try {
      const r = await api.get<LocalModelsResponse>("/settings/local-models");
      setLocalModels(r.data);
      setSelectedModel(r.data.active);
      if (r.data.runtimes.length === 0) toast.error("No local LLM runtimes detected");
      else toast.success(`Found ${r.data.runtimes.length} runtime(s)`);
    } catch {
      toast.error("Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const handleActivateModel = async (url: string, model: string) => {
    try {
      await api.post("/settings", { OLLAMA_BASE_URL: url, OLLAMA_DEFAULT_MODEL: model });
      setSelectedModel({ url, model });
      toast.success(`Active model set to ${model}`);
    } catch {
      toast.error("Failed to set active model");
    }
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="flex items-center justify-between p-4 border-b border-hack-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <SettingsIcon className="w-4 h-4 text-hack-accent" />
          <span className="text-sm font-mono font-bold text-hack-accent">SETTINGS</span>
          <span className="text-[10px] text-hack-dim font-mono ml-2">API keys &amp; integrations</span>
        </div>
        <button onClick={handleSave} disabled={saving} className="hack-btn-primary flex items-center gap-1 text-[10px]">
          <Save className="w-3 h-3" /> {saving ? "SAVING…" : "SAVE ALL"}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto terminal-scroll p-4 space-y-6">
        <div className="hack-panel p-3 border-hack-yellow/30 bg-hack-yellow/5">
          <div className="text-[10px] font-mono text-hack-yellow">
            ⚠ Values are stored encrypted in the database and injected as environment variables at runtime.
            A server restart is required for changes to take effect on existing processes.
          </div>
        </div>

        {GROUPS.map(group => (
          <div key={group}>
            <div className="text-[10px] font-mono text-hack-dim uppercase tracking-widest mb-3">{group}</div>

            {group === "Platforms" && (
              <div className="hack-panel p-3 mb-3 space-y-2">
                <div className="flex items-center gap-2 mb-1">
                  <Power className="w-3.5 h-3.5 text-hack-accent" />
                  <span className="text-xs font-mono text-hack-text">Platform Connections</span>
                </div>
                <div className="text-[10px] font-mono text-hack-dim mb-1">
                  Disconnecting a platform stops all scope fetches and report submissions to it — credentials stay saved.
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {PLATFORM_TOGGLES.map(toggle => {
                    const enabled = isPlatformEnabled(toggle.key);
                    return (
                      <button
                        key={toggle.key}
                        onClick={() => handleTogglePlatform(toggle)}
                        className={`flex items-center justify-between px-2 py-1.5 rounded border text-[10px] font-mono transition-all ${
                          enabled
                            ? "border-hack-accent/50 text-hack-accent bg-hack-accent/5"
                            : "border-hack-red/40 text-hack-red bg-hack-red/5"
                        }`}
                      >
                        <span>{toggle.label}</span>
                        <span>{enabled ? "CONNECTED" : "DISCONNECTED"}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            <div className="space-y-3">
              {FIELDS.filter(f => f.group === group).map(field => (
                <div key={field.key} className="hack-panel p-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="hack-label">{field.label}</label>
                    <div className="flex items-center gap-1">
                      {saved.has(field.key) && values[field.key] && (
                        <CheckCircle2 className="w-3 h-3 text-hack-accent" />
                      )}
                      <span className="text-[9px] font-mono text-hack-dim">{field.key}</span>
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <input
                      className="hack-input flex-1"
                      type={field.secret && !revealed.has(field.key) ? "password" : "text"}
                      placeholder={field.placeholder}
                      value={values[field.key] || ""}
                      onChange={e => {
                        setValues(v => ({ ...v, [field.key]: e.target.value }));
                        setDirty(prev => new Set(prev).add(field.key));
                      }}
                    />
                    {field.secret && (
                      <button onClick={() => toggleReveal(field.key)} className="hack-btn p-1.5">
                        {revealed.has(field.key) ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                      </button>
                    )}
                    {values[field.key] && (
                      <button
                        onClick={() => handleClear(field)}
                        title={`Clear ${field.label}`}
                        className="hack-btn p-1.5 text-hack-red hover:bg-hack-red/10"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}

        {/* ── Local AI Auto-Detector ─────────────────────────────────── */}
        <div>
          <div className="text-[10px] font-mono text-hack-dim uppercase tracking-widest mb-3">Local AI</div>

          <div className="hack-panel p-3 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-hack-accent" />
                <span className="text-xs font-mono text-hack-text">Local Model Detector</span>
              </div>
              <button onClick={handleScanLocalModels} disabled={scanning} className="hack-btn-primary flex items-center gap-1 text-[10px]">
                <RefreshCw className={`w-3 h-3 ${scanning ? "animate-spin" : ""}`} />
                {scanning ? "SCANNING…" : "SCAN"}
              </button>
            </div>

            <div className="text-[10px] font-mono text-hack-dim">
              Probes Ollama · LM Studio · Jan · LocalAI · vLLM on localhost
            </div>

            {selectedModel && (
              <div className="flex items-center gap-2 text-[10px] font-mono">
                <span className="text-hack-dim">Active:</span>
                <span className="text-hack-accent">{selectedModel.model}</span>
                <span className="text-hack-dim">@ {selectedModel.url}</span>
              </div>
            )}

            {localModels && localModels.runtimes.length === 0 && (
              <div className="text-[10px] font-mono text-hack-yellow">No local LLM runtimes found. Start Ollama or LM Studio first.</div>
            )}

            {localModels && localModels.runtimes.map(runtime => (
              <div key={runtime.name} className="border border-hack-border rounded p-2 space-y-2">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-hack-accent font-bold">{runtime.label}</span>
                  <span className="text-[9px] font-mono text-hack-dim">{runtime.url}</span>
                  <span className="text-[9px] font-mono text-hack-green ml-auto">{runtime.models.length} model(s)</span>
                </div>
                <div className="space-y-1 max-h-40 overflow-y-auto terminal-scroll">
                  {runtime.models.map(model => {
                    const isActive = selectedModel?.url === runtime.url && selectedModel?.model === model;
                    return (
                      <div key={model} className="flex items-center justify-between">
                        <span className={`text-[10px] font-mono ${isActive ? "text-hack-accent" : "text-hack-text"}`}>
                          {model}
                        </span>
                        <button
                          onClick={() => handleActivateModel(runtime.url, model)}
                          className={`text-[9px] font-mono px-2 py-0.5 rounded border transition-all ${
                            isActive
                              ? "border-hack-accent text-hack-accent bg-hack-accent/10"
                              : "border-hack-border text-hack-dim hover:border-hack-accent hover:text-hack-accent"
                          }`}
                        >
                          {isActive ? <CheckCircle className="w-3 h-3 inline" /> : "USE"}
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

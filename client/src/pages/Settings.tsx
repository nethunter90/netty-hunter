import React, { useEffect, useState } from "react";
import { Settings as SettingsIcon, Save, Eye, EyeOff, CheckCircle2 } from "lucide-react";
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
];

const GROUPS = [...new Set(FIELDS.map(f => f.group))];

export default function SettingsPage() {
  const [values, setValues] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [saved, setSaved] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);

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
    setSaving(true);
    try {
      await api.post("/settings", values);
      setSaved(new Set(Object.keys(values).filter(k => values[k])));
      toast.success("Settings saved — restart server to apply env var changes");
    } catch {
      toast.error("Failed to save settings");
    } finally {
      setSaving(false);
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
                      onChange={e => setValues(v => ({ ...v, [field.key]: e.target.value }))}
                    />
                    {field.secret && (
                      <button onClick={() => toggleReveal(field.key)} className="hack-btn p-1.5">
                        {revealed.has(field.key) ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

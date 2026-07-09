/**
 * Backward-mode goal input, shared by HuntConsole and Orchestration.
 *
 * Free-text goals get matched against a small set of canned attack trees via
 * fragile keyword matching server-side (BackwardHuntEngine.matchObjective) —
 * this widget sidesteps that ambiguity two ways: curated presets that are
 * guaranteed to hit the right tree, and a "custom priority order" mode that
 * bypasses goal-text matching entirely by letting the user directly pick and
 * order the vuln classes to prioritize.
 */
import { useState } from "react";

const GOAL_PRESETS = [
  { key: "custom_text", label: "Type your own goal" },
  { key: "rce", label: "Achieve remote code execution (RCE)", goal: "Achieve remote code execution (RCE)" },
  { key: "account_takeover", label: "Full account takeover", goal: "Achieve full account takeover" },
  { key: "data_exfil", label: "Exfiltrate sensitive data / PII", goal: "Exfiltrate sensitive data / PII" },
  { key: "custom_priority", label: "Custom priority order (pick vuln classes)" },
] as const;

const VULN_CLASS_OPTIONS = [
  "rce", "sqli", "xss", "ssrf", "xxe", "ssti", "idor", "auth_bypass",
  "broken_auth", "csrf", "cors", "open_redirect", "info_disclosure",
  "misconfig", "hidden_endpoints", "exposed_panels", "security_headers",
  "http_smuggling", "nosqli", "race_condition", "mass_assignment",
  "business_logic", "jwt_confusion", "crlf_injection",
];

interface Props {
  goal: string;
  setGoal: (v: string) => void;
  customPriority: string[];
  setCustomPriority: (v: string[]) => void;
  disabled?: boolean;
}

export default function GoalPresetPicker({ goal, setGoal, customPriority, setCustomPriority, disabled }: Props) {
  const [presetKey, setPresetKey] = useState<string>("custom_text");

  const handlePresetChange = (key: string) => {
    setPresetKey(key);
    const preset = GOAL_PRESETS.find(p => p.key === key);
    if (preset && "goal" in preset) setGoal(preset.goal);
    if (key === "custom_text") setGoal("");
    if (key !== "custom_priority") setCustomPriority([]);
  };

  const toggleVulnClass = (vc: string) => {
    if (customPriority.includes(vc)) {
      setCustomPriority(customPriority.filter(v => v !== vc));
    } else {
      setCustomPriority([...customPriority, vc]);
    }
  };

  return (
    <div>
      <label className="hack-label">Goal Preset</label>
      <select
        className="hack-input w-full mb-2"
        value={presetKey}
        onChange={e => handlePresetChange(e.target.value)}
        disabled={disabled}
      >
        {GOAL_PRESETS.map(p => <option key={p.key} value={p.key}>{p.label}</option>)}
      </select>

      {presetKey !== "custom_priority" && (
        <>
          <label className="hack-label">Goal</label>
          <input
            className="hack-input w-full mb-2"
            placeholder="e.g. Achieve RCE on admin panel"
            value={goal}
            onChange={e => setGoal(e.target.value)}
            disabled={disabled}
          />
        </>
      )}

      {presetKey === "custom_priority" && (
        <div className="mb-2">
          <label className="hack-label">Click vuln classes in the order you want them prioritized</label>
          <div className="flex flex-wrap gap-1 mb-1">
            {VULN_CLASS_OPTIONS.map(vc => {
              const idx = customPriority.indexOf(vc);
              const selected = idx !== -1;
              return (
                <button
                  key={vc}
                  type="button"
                  disabled={disabled}
                  onClick={() => toggleVulnClass(vc)}
                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded border transition-all ${
                    selected
                      ? "bg-hack-accent/20 border-hack-accent text-hack-accent"
                      : "border-hack-border text-hack-dim hover:border-hack-text"
                  }`}
                >
                  {selected ? `${idx + 1}. ` : ""}{vc}
                </button>
              );
            })}
          </div>
          {customPriority.length > 0 && (
            <div className="text-[9px] text-hack-dim font-mono">
              Order: {customPriority.join(" → ")}{" "}
              <button type="button" onClick={() => setCustomPriority([])} className="text-hack-red hover:underline">clear</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

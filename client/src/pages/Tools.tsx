import React, { useState, useEffect, useCallback } from "react";
import {
  Wrench, Plus, Pencil, Trash2, Play, CheckCircle2, XCircle,
  ToggleLeft, ToggleRight, ChevronDown, ChevronUp, Terminal,
  RefreshCw, AlertTriangle, Cpu, Layers
} from "lucide-react";
import { toolsAPI } from "../lib/api";
import api from "../lib/api";
import toast from "react-hot-toast";
import { ToolReadiness } from "../components/bounty/ToolReadiness";

interface CustomTool {
  id: number;
  name: string;
  displayName: string;
  description: string;
  commandTemplate: string;
  requiredBinary: string;
  category: string;
  vulnClasses: string[];
  rateLimit: number;
  riskLevel: string;
  stealthRating: number;
  parserType: string;
  enabled: boolean;
  available?: boolean;
  path?: string;
  version?: string;
  createdAt: string;
}

const CATEGORIES = [
  "recon", "scanning", "exploitation", "fuzzing",
  "web", "credential", "network", "reporting",
];

const RISK_COLORS: Record<string, string> = {
  low: "text-green-400 bg-green-400/10 border-green-400/30",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
  high: "text-red-400 bg-red-400/10 border-red-400/30",
};

const PARSER_LABELS: Record<string, string> = {
  plain: "Plain (raw stdout)",
  lines: "Lines (split by newline)",
  json: "JSON (parse stdout)",
};

const EMPTY_FORM = {
  displayName: "",
  requiredBinary: "",
  commandTemplate: "",
  description: "",
  category: "scanning",
  vulnClassesText: "",
  rateLimit: 30,
  riskLevel: "medium",
  stealthRating: 5,
  parserType: "lines",
};

type FormState = typeof EMPTY_FORM;

export default function ToolsPage() {
  const [activeTab, setActiveTab] = useState<"builtin" | "custom">("builtin");
  const [tools, setTools] = useState<CustomTool[]>([]);
  const [loading, setLoading] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [testUrl, setTestUrl] = useState("");
  const [testOutput, setTestOutput] = useState<{ stdout: string; stderr: string } | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const fetchTools = useCallback(async () => {
    setLoading(true);
    try {
      const res = await toolsAPI.list();
      setTools(res.data.tools || []);
    } catch {
      toast.error("Failed to load custom tools");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "custom") fetchTools();
  }, [activeTab, fetchTools]);

  const openCreate = () => {
    setEditingId(null);
    setForm(EMPTY_FORM);
    setTestOutput(null);
    setShowForm(true);
  };

  const openEdit = (t: CustomTool) => {
    setEditingId(t.id);
    setForm({
      displayName: t.displayName,
      requiredBinary: t.requiredBinary,
      commandTemplate: t.commandTemplate,
      description: t.description,
      category: t.category,
      vulnClassesText: t.vulnClasses.join(", "),
      rateLimit: t.rateLimit,
      riskLevel: t.riskLevel,
      stealthRating: t.stealthRating,
      parserType: t.parserType,
    });
    setTestOutput(null);
    setShowForm(true);
    setExpandedId(null);
  };

  const cancelForm = () => {
    setShowForm(false);
    setEditingId(null);
    setForm(EMPTY_FORM);
    setTestOutput(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.displayName.trim() || !form.commandTemplate.trim() || !form.requiredBinary.trim()) {
      toast.error("Display name, binary, and command template are required");
      return;
    }
    setSubmitting(true);
    const payload = {
      displayName: form.displayName.trim(),
      commandTemplate: form.commandTemplate.trim(),
      requiredBinary: form.requiredBinary.trim(),
      description: form.description.trim(),
      category: form.category,
      vulnClasses: form.vulnClassesText.split(",").map(s => s.trim()).filter(Boolean),
      rateLimit: Number(form.rateLimit),
      riskLevel: form.riskLevel,
      stealthRating: Number(form.stealthRating),
      parserType: form.parserType,
    };
    try {
      if (editingId !== null) {
        await toolsAPI.update(editingId, payload);
        toast.success("Tool updated");
      } else {
        await toolsAPI.create(payload);
        toast.success("Tool created");
      }
      cancelForm();
      fetchTools();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error || "Failed to save tool";
      toast.error(msg);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Delete custom tool "${name}"?`)) return;
    try {
      await toolsAPI.remove(id);
      toast.success("Tool deleted");
      setTools(prev => prev.filter(t => t.id !== id));
      if (expandedId === id) setExpandedId(null);
    } catch {
      toast.error("Failed to delete tool");
    }
  };

  const handleToggle = async (t: CustomTool) => {
    try {
      await toolsAPI.update(t.id, { enabled: !t.enabled });
      setTools(prev => prev.map(x => x.id === t.id ? { ...x, enabled: !x.enabled } : x));
    } catch {
      toast.error("Failed to toggle tool");
    }
  };

  const handleTest = async () => {
    if (!editingId) return;
    if (!testUrl.trim()) { toast.error("Enter a URL to test"); return; }
    setTestLoading(true);
    setTestOutput(null);
    try {
      const res = await toolsAPI.test(editingId, testUrl.trim());
      setTestOutput(res.data);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: string } } })?.response?.data?.error || "Test failed";
      toast.error(msg);
    } finally {
      setTestLoading(false);
    }
  };

  const f = (field: keyof FormState, val: string | number) =>
    setForm(prev => ({ ...prev, [field]: val }));

  return (
    <div className="flex flex-col h-full bg-hack-bg text-hack-text font-mono overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-hack-border bg-hack-surface flex-shrink-0">
        <div className="flex items-center gap-2">
          <Wrench className="w-4 h-4 text-hack-accent" />
          <span className="text-hack-accent font-semibold text-sm tracking-wider">TOOL REGISTRY</span>
        </div>
        <div className="flex items-center gap-1">
          {/* Tabs */}
          {(["builtin", "custom"] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1 text-[11px] rounded border transition-all ${
                activeTab === tab
                  ? "border-hack-accent/50 bg-hack-accent/10 text-hack-accent"
                  : "border-hack-border text-hack-dim hover:text-hack-text"
              }`}
            >
              {tab === "builtin" ? (
                <span className="flex items-center gap-1"><Layers className="w-3 h-3" /> BUILT-IN (39)</span>
              ) : (
                <span className="flex items-center gap-1"><Cpu className="w-3 h-3" /> CUSTOM ({tools.length})</span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto">
        {activeTab === "builtin" && (
          <div className="p-4">
            <ToolReadiness />
          </div>
        )}

        {activeTab === "custom" && (
          <div className="p-4 space-y-4">
            {/* Action bar */}
            <div className="flex items-center justify-between">
              <p className="text-[11px] text-hack-dim">
                Custom tools are loaded at hunt start and participate in the scan rotation.
                Use <code className="text-hack-accent bg-hack-accent/10 px-1 rounded">{"{url}"}</code> in your command template as the target placeholder.
              </p>
              <div className="flex gap-2">
                <button
                  onClick={fetchTools}
                  disabled={loading}
                  className="flex items-center gap-1 px-2 py-1 text-[11px] border border-hack-border text-hack-dim hover:text-hack-text rounded"
                >
                  <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
                  REFRESH
                </button>
                <button
                  onClick={openCreate}
                  className="flex items-center gap-1 px-3 py-1 text-[11px] bg-hack-accent/10 border border-hack-accent/50 text-hack-accent hover:bg-hack-accent/20 rounded"
                >
                  <Plus className="w-3 h-3" /> ADD TOOL
                </button>
              </div>
            </div>

            {/* Create / Edit form */}
            {showForm && (
              <div className="border border-hack-accent/40 rounded bg-hack-panel p-4 space-y-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] text-hack-accent font-semibold">
                    {editingId ? "EDIT TOOL" : "NEW CUSTOM TOOL"}
                  </span>
                  <button onClick={cancelForm} className="text-[10px] text-hack-dim hover:text-hack-text">CANCEL</button>
                </div>

                <form onSubmit={handleSubmit} className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">DISPLAY NAME *</span>
                      <input
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.displayName}
                        onChange={e => f("displayName", e.target.value)}
                        placeholder="e.g. Custom Nuclei Scanner"
                        required
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">REQUIRED BINARY *</span>
                      <input
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.requiredBinary}
                        onChange={e => f("requiredBinary", e.target.value)}
                        placeholder="e.g. nuclei"
                        required
                      />
                    </label>
                  </div>

                  <label className="flex flex-col gap-1">
                    <span className="text-[10px] text-hack-dim">
                      COMMAND TEMPLATE * — use <code className="text-hack-accent">{"{url}"}</code> for target
                    </span>
                    <input
                      className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none font-mono"
                      value={form.commandTemplate}
                      onChange={e => f("commandTemplate", e.target.value)}
                      placeholder='nuclei -u {url} -t cves/ -silent'
                      required
                    />
                  </label>

                  <label className="flex flex-col gap-1">
                    <span className="text-[10px] text-hack-dim">DESCRIPTION</span>
                    <input
                      className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                      value={form.description}
                      onChange={e => f("description", e.target.value)}
                      placeholder="What does this tool detect?"
                    />
                  </label>

                  <div className="grid grid-cols-3 gap-3">
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">CATEGORY</span>
                      <select
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.category}
                        onChange={e => f("category", e.target.value)}
                      >
                        {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                      </select>
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">RISK LEVEL</span>
                      <select
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.riskLevel}
                        onChange={e => f("riskLevel", e.target.value)}
                      >
                        <option value="low">low</option>
                        <option value="medium">medium</option>
                        <option value="high">high</option>
                      </select>
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">OUTPUT PARSER</span>
                      <select
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.parserType}
                        onChange={e => f("parserType", e.target.value)}
                      >
                        {Object.entries(PARSER_LABELS).map(([k, v]) => (
                          <option key={k} value={k}>{v}</option>
                        ))}
                      </select>
                    </label>
                  </div>

                  <div className="grid grid-cols-3 gap-3">
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">RATE LIMIT (sec)</span>
                      <input
                        type="number" min={1} max={3600}
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.rateLimit}
                        onChange={e => f("rateLimit", parseInt(e.target.value) || 30)}
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">STEALTH RATING (1–10)</span>
                      <input
                        type="number" min={1} max={10}
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.stealthRating}
                        onChange={e => f("stealthRating", parseInt(e.target.value) || 5)}
                      />
                    </label>
                    <label className="flex flex-col gap-1">
                      <span className="text-[10px] text-hack-dim">VULN CLASSES (comma-sep)</span>
                      <input
                        className="bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none"
                        value={form.vulnClassesText}
                        onChange={e => f("vulnClassesText", e.target.value)}
                        placeholder="xss, sqli, rce"
                      />
                    </label>
                  </div>

                  {/* Test fire — only available when editing */}
                  {editingId !== null && (
                    <div className="border border-hack-border/50 rounded p-3 space-y-2">
                      <span className="text-[10px] text-hack-dim flex items-center gap-1">
                        <Terminal className="w-3 h-3" /> TEST FIRE
                      </span>
                      <div className="flex gap-2">
                        <input
                          className="flex-1 bg-hack-surface border border-hack-border rounded px-2 py-1 text-[11px] text-hack-text focus:border-hack-accent outline-none font-mono"
                          value={testUrl}
                          onChange={e => setTestUrl(e.target.value)}
                          placeholder="https://example.com"
                        />
                        <button
                          type="button"
                          onClick={handleTest}
                          disabled={testLoading}
                          className="flex items-center gap-1 px-3 py-1 text-[11px] bg-hack-accent/10 border border-hack-accent/50 text-hack-accent hover:bg-hack-accent/20 rounded disabled:opacity-50"
                        >
                          <Play className={`w-3 h-3 ${testLoading ? "animate-pulse" : ""}`} />
                          {testLoading ? "RUNNING..." : "RUN"}
                        </button>
                      </div>
                      {testOutput && (
                        <div className="space-y-1">
                          {testOutput.stdout && (
                            <pre className="bg-hack-bg border border-hack-border rounded p-2 text-[10px] text-hack-text overflow-auto max-h-40">
                              {testOutput.stdout}
                            </pre>
                          )}
                          {testOutput.stderr && (
                            <pre className="bg-hack-bg border border-red-500/30 rounded p-2 text-[10px] text-red-400 overflow-auto max-h-24">
                              {testOutput.stderr}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      type="button"
                      onClick={cancelForm}
                      className="px-3 py-1 text-[11px] border border-hack-border text-hack-dim hover:text-hack-text rounded"
                    >
                      CANCEL
                    </button>
                    <button
                      type="submit"
                      disabled={submitting}
                      className="px-4 py-1 text-[11px] bg-hack-accent/10 border border-hack-accent/50 text-hack-accent hover:bg-hack-accent/20 rounded disabled:opacity-50"
                    >
                      {submitting ? "SAVING..." : editingId ? "UPDATE TOOL" : "CREATE TOOL"}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Tool list */}
            {loading ? (
              <div className="text-center py-12 text-hack-dim text-[11px]">
                <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-hack-accent" />
                Loading custom tools...
              </div>
            ) : tools.length === 0 ? (
              <div className="text-center py-16 space-y-3">
                <Wrench className="w-10 h-10 mx-auto text-hack-dim/40" />
                <p className="text-hack-dim text-[11px]">No custom tools registered yet.</p>
                <button
                  onClick={openCreate}
                  className="inline-flex items-center gap-1 px-3 py-1 text-[11px] bg-hack-accent/10 border border-hack-accent/50 text-hack-accent hover:bg-hack-accent/20 rounded"
                >
                  <Plus className="w-3 h-3" /> Add your first tool
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                {tools.map(tool => (
                  <div
                    key={tool.id}
                    className={`border rounded bg-hack-panel transition-all ${
                      tool.enabled ? "border-hack-border" : "border-hack-border/40 opacity-60"
                    }`}
                  >
                    {/* Tool header row */}
                    <div className="flex items-center gap-3 px-4 py-2">
                      {/* Binary availability */}
                      <div title={tool.available ? `Found at ${tool.path}` : "Binary not found"}>
                        {tool.available
                          ? <CheckCircle2 className="w-3.5 h-3.5 text-hack-green flex-shrink-0" />
                          : <XCircle className="w-3.5 h-3.5 text-hack-red flex-shrink-0" />}
                      </div>

                      {/* Name */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-[12px] text-hack-text font-semibold">{tool.displayName}</span>
                          <span className="text-[10px] text-hack-dim">({tool.name})</span>
                          <span className={`text-[9px] px-1.5 py-0.5 rounded border ${RISK_COLORS[tool.riskLevel] || RISK_COLORS.medium}`}>
                            {tool.riskLevel}
                          </span>
                          <span className="text-[9px] text-hack-dim border border-hack-border/50 px-1.5 py-0.5 rounded">
                            {tool.category}
                          </span>
                          {tool.available && tool.version && (
                            <span className="text-[9px] text-hack-dim">{tool.version.slice(0, 40)}</span>
                          )}
                        </div>
                        <div className="text-[10px] text-hack-dim mt-0.5 truncate">
                          <code className="text-hack-accent/70">{tool.commandTemplate}</code>
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <button
                          onClick={() => handleToggle(tool)}
                          title={tool.enabled ? "Disable" : "Enable"}
                          className="text-hack-dim hover:text-hack-text p-1"
                        >
                          {tool.enabled
                            ? <ToggleRight className="w-4 h-4 text-hack-accent" />
                            : <ToggleLeft className="w-4 h-4" />}
                        </button>
                        <button
                          onClick={() => openEdit(tool)}
                          title="Edit"
                          className="text-hack-dim hover:text-hack-text p-1"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => handleDelete(tool.id, tool.displayName)}
                          title="Delete"
                          className="text-hack-dim hover:text-hack-red p-1"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => setExpandedId(expandedId === tool.id ? null : tool.id)}
                          className="text-hack-dim hover:text-hack-text p-1"
                        >
                          {expandedId === tool.id
                            ? <ChevronUp className="w-3.5 h-3.5" />
                            : <ChevronDown className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>

                    {/* Expanded detail */}
                    {expandedId === tool.id && (
                      <div className="border-t border-hack-border/40 px-4 py-3 grid grid-cols-4 gap-4 text-[10px]">
                        <div>
                          <span className="text-hack-dim block mb-1">BINARY</span>
                          <span className="text-hack-text font-mono">{tool.requiredBinary}</span>
                          {tool.available
                            ? <span className="block text-green-400">{tool.path}</span>
                            : <span className="block text-red-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> not found</span>}
                        </div>
                        <div>
                          <span className="text-hack-dim block mb-1">PARSER / RATE LIMIT</span>
                          <span className="text-hack-text">{PARSER_LABELS[tool.parserType] ?? tool.parserType}</span>
                          <span className="block text-hack-dim">{tool.rateLimit}s between calls</span>
                        </div>
                        <div>
                          <span className="text-hack-dim block mb-1">STEALTH / RISK</span>
                          <span className="text-hack-text">Stealth {tool.stealthRating}/10</span>
                          <span className={`block ${RISK_COLORS[tool.riskLevel]?.split(" ")[0] ?? ""}`}>
                            {tool.riskLevel} risk
                          </span>
                        </div>
                        <div>
                          <span className="text-hack-dim block mb-1">VULN CLASSES</span>
                          {tool.vulnClasses.length > 0
                            ? <div className="flex flex-wrap gap-1">
                                {tool.vulnClasses.map(vc => (
                                  <span key={vc} className="px-1 bg-hack-accent/10 text-hack-accent border border-hack-accent/20 rounded text-[9px]">{vc}</span>
                                ))}
                              </div>
                            : <span className="text-hack-dim/50 italic">none defined</span>}
                        </div>
                        {tool.description && (
                          <div className="col-span-4">
                            <span className="text-hack-dim">DESCRIPTION — </span>
                            <span className="text-hack-text">{tool.description}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

import React, { useEffect, useState } from "react";
import { FileText, Download, Copy, RefreshCw, MessageSquare, Send } from "lucide-react";
import { hunterAPI, bountyAPI } from "../lib/api";
import toast from "react-hot-toast";

interface Finding {
  id: number;
  title: string;
  severity: string;
  vulnType: string;
  reportDraft?: string;
  nucleiTemplate?: string;
  verificationStatus: string;
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export default function Reports() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [activePane, setActivePane] = useState<"reports" | "chat">("reports");

  useEffect(() => {
    setLoading(true);
    hunterAPI.getFindings().then(r => {
      setFindings(r.data || []);
    }).finally(() => setLoading(false));
  }, []);

  const selectedFinding = findings.find(f => f.id === selectedId);

  const generateAll = async () => {
    const confirmed = findings.filter(f => f.verificationStatus === "confirmed" && !f.reportDraft);
    if (confirmed.length === 0) return toast("No confirmed findings without reports");

    setGenerating(true);
    let generated = 0;
    for (const f of confirmed) {
      try {
        await hunterAPI.generateReport(f.id, { programName: "Target Program" });
        generated++;
      } catch { /* skip */ }
    }
    toast.success(`Generated ${generated} reports`);
    setGenerating(false);
    // Reload
    hunterAPI.getFindings().then(r => setFindings(r.data || []));
  };

  const copyReport = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  const downloadReport = (finding: Finding) => {
    if (!finding.reportDraft) return;
    const blob = new Blob([finding.reportDraft], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${finding.vulnType}-${finding.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const sendChat = async () => {
    if (!chatInput.trim()) return;
    const message = chatInput.trim();
    setChatInput("");
    setChatMessages(prev => [...prev, { role: "user", content: message }]);
    setChatLoading(true);

    try {
      const context = selectedFinding ? {
        currentFinding: { title: selectedFinding.title, vulnType: selectedFinding.vulnType, severity: selectedFinding.severity }
      } : undefined;
      const res = await bountyAPI.aiChat(message, context);
      setChatMessages(prev => [...prev, { role: "assistant", content: res.data.response }]);
    } catch {
      setChatMessages(prev => [...prev, { role: "assistant", content: "AI unavailable. Is Ollama running?" }]);
    } finally {
      setChatLoading(false);
    }
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-hack-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-hack-blue" />
          <span className="text-sm font-mono font-bold text-hack-blue">REPORTS & AI ASSISTANT</span>
        </div>
        <div className="flex gap-2">
          <div className="flex border border-hack-border rounded overflow-hidden">
            <button onClick={() => setActivePane("reports")}
              className={`px-3 py-1 text-[10px] font-mono transition-colors ${activePane === "reports" ? "bg-hack-accent/10 text-hack-accent" : "text-hack-dim hover:text-hack-text"}`}>
              REPORTS
            </button>
            <button onClick={() => setActivePane("chat")}
              className={`px-3 py-1 text-[10px] font-mono transition-colors ${activePane === "chat" ? "bg-hack-accent/10 text-hack-accent" : "text-hack-dim hover:text-hack-text"}`}>
              AI CHAT
            </button>
          </div>
          {activePane === "reports" && (
            <button onClick={generateAll} disabled={generating} className="hack-btn flex items-center gap-1">
              <RefreshCw className={`w-3 h-3 ${generating ? "animate-spin" : ""}`} /> GENERATE ALL
            </button>
          )}
        </div>
      </div>

      {activePane === "reports" ? (
        <div className="flex-1 flex overflow-hidden">
          {/* Left: Findings */}
          <div className="w-64 border-r border-hack-border overflow-y-auto terminal-scroll flex-shrink-0">
            {loading ? (
              <div className="p-4 text-[10px] text-hack-dim animate-pulse font-mono">Loading...</div>
            ) : findings.length === 0 ? (
              <div className="p-4 text-[10px] text-hack-dim font-mono">No findings available</div>
            ) : (
              findings.map(f => (
                <div key={f.id} onClick={() => setSelectedId(f.id)}
                  className={`p-3 border-b border-hack-border cursor-pointer hover:bg-hack-muted/30 transition-colors ${selectedId === f.id ? "bg-hack-muted/50 border-l-2 border-l-hack-accent" : ""}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-[9px] font-mono px-1 rounded border severity-${f.severity}`}>{f.severity.toUpperCase()}</span>
                    {f.reportDraft && <span className="text-[8px] text-hack-accent font-mono">✓ REPORT</span>}
                  </div>
                  <div className="text-[10px] font-mono text-hack-text truncate">{f.title}</div>
                  <div className="text-[9px] text-hack-dim font-mono mt-0.5">{f.vulnType}</div>
                </div>
              ))
            )}
          </div>

          {/* Right: Report Content */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {!selectedFinding ? (
              <div className="flex-1 flex items-center justify-center text-hack-dim">
                <div className="text-center">
                  <FileText className="w-12 h-12 mx-auto mb-3" strokeWidth={0.8} />
                  <div className="text-xs font-mono">Select a finding to view its report</div>
                </div>
              </div>
            ) : (
              <>
                <div className="p-3 border-b border-hack-border flex items-center justify-between flex-shrink-0">
                  <div className="text-[10px] font-mono text-hack-text">{selectedFinding.title}</div>
                  <div className="flex gap-2">
                    {!selectedFinding.reportDraft && (
                      <button onClick={() => hunterAPI.generateReport(selectedFinding.id, { programName: "Target Program" })
                          .then(r => {
                            setFindings(prev => prev.map(f => f.id === selectedId ? { ...f, reportDraft: r.data.reportMarkdown } : f));
                            toast.success("Report generated");
                          }).catch(() => toast.error("Failed"))}
                        className="hack-btn-primary flex items-center gap-1">
                        <FileText className="w-3 h-3" /> GENERATE
                      </button>
                    )}
                    {selectedFinding.reportDraft && (
                      <>
                        <button onClick={() => copyReport(selectedFinding.reportDraft!)} className="hack-btn flex items-center gap-1">
                          <Copy className="w-3 h-3" /> COPY
                        </button>
                        <button onClick={() => downloadReport(selectedFinding)} className="hack-btn flex items-center gap-1">
                          <Download className="w-3 h-3" /> DOWNLOAD
                        </button>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex-1 overflow-y-auto terminal-scroll p-4">
                  {selectedFinding.reportDraft ? (
                    <pre className="text-[11px] font-mono text-hack-text leading-relaxed whitespace-pre-wrap">
                      {selectedFinding.reportDraft}
                    </pre>
                  ) : (
                    <div className="text-[10px] text-hack-dim font-mono">No report generated. Click GENERATE to create a submission-ready bug bounty report.</div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      ) : (
        /* AI Chat */
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="flex-1 overflow-y-auto terminal-scroll p-4 space-y-3">
            {chatMessages.length === 0 ? (
              <div className="text-[10px] text-hack-dim font-mono space-y-2">
                <div className="text-hack-accent">AI Security Assistant</div>
                <div>Ask me about vulnerabilities, exploitation techniques, report writing, or bug bounty strategies.</div>
                <div className="mt-2 space-y-1 text-hack-dim/70">
                  <div>"How do I exploit a blind SQL injection?"</div>
                  <div>"Write me an impact statement for an SSRF finding"</div>
                  <div>"What's the CVSS score for an authenticated RCE?"</div>
                  <div>"Explain how to chain XSS with CSRF"</div>
                </div>
              </div>
            ) : (
              chatMessages.map((msg, i) => (
                <div key={i} className={`flex gap-2 ${msg.role === "user" ? "justify-end" : ""}`}>
                  {msg.role === "assistant" && (
                    <div className="w-6 h-6 rounded bg-hack-purple/20 border border-hack-purple/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <MessageSquare className="w-3 h-3 text-hack-purple" />
                    </div>
                  )}
                  <div className={`max-w-[80%] p-2.5 rounded text-[11px] font-mono leading-relaxed ${
                    msg.role === "user"
                      ? "bg-hack-accent/10 border border-hack-accent/20 text-hack-accent"
                      : "bg-hack-surface border border-hack-border text-hack-text"
                  }`}>
                    {msg.content}
                  </div>
                </div>
              ))
            )}
            {chatLoading && (
              <div className="flex gap-2">
                <div className="w-6 h-6 rounded bg-hack-purple/20 border border-hack-purple/30 flex items-center justify-center flex-shrink-0">
                  <MessageSquare className="w-3 h-3 text-hack-purple" />
                </div>
                <div className="bg-hack-surface border border-hack-border p-2.5 rounded text-[11px] font-mono text-hack-dim">
                  <span className="animate-pulse">Thinking...</span>
                </div>
              </div>
            )}
          </div>

          {/* Chat Input */}
          <div className="p-3 border-t border-hack-border flex gap-2 flex-shrink-0">
            <input
              className="hack-input flex-1"
              value={chatInput}
              onChange={e => setChatInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendChat()}
              placeholder="Ask about vulnerabilities, exploits, reports..."
            />
            <button onClick={sendChat} disabled={chatLoading || !chatInput.trim()} className="hack-btn-primary px-3 disabled:opacity-50">
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

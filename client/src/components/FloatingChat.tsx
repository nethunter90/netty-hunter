import React, { useState, useRef, useEffect } from "react";
import { MessageSquare, X, Send, Minimize2, Bot, AlertCircle, Terminal } from "lucide-react";
import api from "../lib/api";

interface StepOutput {
  command: string;
  stdout: string;
  stderr: string;
  exitCode: number;
  error?: string;
}

interface ExecutionResult {
  plan: { steps: { bin: string; args?: string[] }[]; detached: boolean; description: string };
  outputs: StepOutput[];
  pid?: number;
}

interface Message {
  role: "user" | "assistant";
  content: string;
  executed?: ExecutionResult | null;
}

export default function FloatingChat() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [modelAvailable, setModelAvailable] = useState<boolean | null>(null);
  const [activeModel, setActiveModel] = useState<string>("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    api.get<{ available: boolean; models: string[] }>("/chat/status")
      .then(r => {
        setModelAvailable(r.data.available);
        if (r.data.models[0]) setActiveModel(r.data.models[0]);
      })
      .catch(() => setModelAvailable(false));
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const send = async () => {
    const text = input.trim();
    if (!text || loading) return;

    const userMsg: Message = { role: "user", content: text };
    // Cap conversation history (~50 messages) to bound memory on long chats.
    setMessages(prev => [...prev.slice(-49), userMsg]);
    setInput("");
    setLoading(true);

    try {
      const r = await api.post<{ response: string; model: string; executed?: ExecutionResult | null }>("/chat", {
        message: text,
        history: messages.slice(-6),
      });
      setMessages(prev => [
        ...prev.slice(-49),
        { role: "assistant", content: r.data.response, executed: r.data.executed ?? null },
      ]);
      if (r.data.model && r.data.model !== "unknown") setActiveModel(r.data.model);
      setModelAvailable(true);
    } catch (err: unknown) {
      const e = err as { response?: { data?: { error?: string } } };
      const errMsg = e.response?.data?.error || "Model unavailable";
      setMessages(prev => [...prev.slice(-49), { role: "assistant", content: `⚠ ${errMsg}` }]);
      setModelAvailable(false);
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col items-end gap-2">
      {/* Chat panel */}
      {open && (
        <div className="hack-panel border-hack-accent/30 flex flex-col w-80 h-[480px] shadow-2xl shadow-black/60">
          {/* Header */}
          <div className="flex items-center justify-between px-3 py-2 border-b border-hack-border flex-shrink-0">
            <div className="flex items-center gap-2">
              <Bot className="w-3.5 h-3.5 text-hack-accent" />
              <span className="text-[11px] font-mono font-bold text-hack-accent">AI ASSISTANT</span>
              {modelAvailable === true && (
                <span className="text-[9px] font-mono text-hack-dim truncate max-w-[100px]" title={activeModel}>
                  {activeModel || "ready"}
                </span>
              )}
              {modelAvailable === false && (
                <span className="flex items-center gap-1 text-[9px] font-mono text-hack-yellow">
                  <AlertCircle className="w-2.5 h-2.5" /> no model
                </span>
              )}
            </div>
            <div className="flex items-center gap-1">
              <button onClick={() => setOpen(false)} className="text-hack-dim hover:text-hack-text p-0.5">
                <Minimize2 className="w-3 h-3" />
              </button>
              <button onClick={() => { setOpen(false); setMessages([]); }} className="text-hack-dim hover:text-hack-red p-0.5">
                <X className="w-3 h-3" />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto terminal-scroll p-3 space-y-3 text-[11px] font-mono">
            {messages.length === 0 && (
              <div className="text-hack-dim text-center mt-8 space-y-1">
                <Bot className="w-6 h-6 mx-auto text-hack-accent/40" />
                <div>Ask me anything about</div>
                <div className="text-hack-accent/60">recon · payloads · exploits · commands</div>
              </div>
            )}
            {messages.map((m, i) => (
              <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] rounded px-2.5 py-1.5 break-words ${
                  m.role === "user"
                    ? "bg-hack-accent/10 border border-hack-accent/20 text-hack-text"
                    : "bg-hack-surface border border-hack-border text-hack-text"
                }`}>
                  {m.role === "assistant" && (
                    <span className="text-hack-accent text-[9px] block mb-0.5">AI</span>
                  )}
                  <div className="whitespace-pre-wrap break-words">{m.content}</div>
                  {m.executed && (
                    <div className="mt-2 space-y-1.5">
                      <div className="text-[9px] font-mono text-hack-dim flex items-center gap-1">
                        <Terminal className="w-3 h-3" />
                        {m.executed.plan.detached
                          ? `Launched${m.executed.pid ? ` (PID ${m.executed.pid})` : ""}: ${m.executed.plan.description}`
                          : m.executed.plan.description}
                      </div>
                      {m.executed.outputs.map((out, oi) => (
                        <div key={oi} className="bg-black/50 border border-hack-border/60 rounded p-2 text-[10px] font-mono">
                          <div className="text-hack-accent mb-1">$ {out.command}</div>
                          {out.stdout && (
                            <pre className="text-hack-text whitespace-pre-wrap break-words max-h-40 overflow-y-auto">{out.stdout}</pre>
                          )}
                          {out.stderr && (
                            <pre className="text-hack-red whitespace-pre-wrap break-words max-h-24 overflow-y-auto">{out.stderr}</pre>
                          )}
                          {(out.exitCode !== 0 || out.error) && (
                            <div className="text-hack-yellow mt-0.5">{out.error ?? `exit ${out.exitCode}`}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {loading && (
              <div className="flex justify-start">
                <div className="bg-hack-surface border border-hack-border rounded px-2.5 py-1.5">
                  <span className="text-hack-accent text-[9px] block mb-0.5">AI</span>
                  <span className="text-hack-dim animate-pulse">thinking…</span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="flex-shrink-0 border-t border-hack-border p-2 flex gap-2 items-end">
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Ask anything… (Enter to send)"
              rows={1}
              className="hack-input flex-1 resize-none text-[11px] font-mono min-h-[32px] max-h-24"
              style={{ height: Math.min(96, Math.max(32, input.split("\n").length * 20)) }}
            />
            <button
              onClick={send}
              disabled={loading || !input.trim()}
              className="hack-btn-primary p-1.5 flex-shrink-0 disabled:opacity-40"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Bubble toggle button */}
      <button
        onClick={() => setOpen(o => !o)}
        className="w-12 h-12 rounded-full bg-hack-accent text-hack-bg flex items-center justify-center shadow-lg shadow-hack-accent/20 hover:bg-hack-accent/90 transition-all"
      >
        {open
          ? <X className="w-5 h-5" />
          : <MessageSquare className="w-5 h-5" />
        }
        {!open && modelAvailable === true && (
          <span className="absolute top-0 right-0 w-2.5 h-2.5 rounded-full bg-hack-green border-2 border-hack-bg" />
        )}
        {!open && modelAvailable === false && (
          <span className="absolute top-0 right-0 w-2.5 h-2.5 rounded-full bg-hack-yellow border-2 border-hack-bg" />
        )}
      </button>
    </div>
  );
}

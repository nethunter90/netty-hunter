import { useEffect, useRef, useState, useCallback } from "react";
import { Terminal as XTerm } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import { WebLinksAddon } from "xterm-addon-web-links";
import "xterm/css/xterm.css";
import { Terminal, Plus, X } from "lucide-react";
import { getSocket } from "../lib/socket";

interface Tab {
  id: string;
  termId: string | null;
  term: XTerm;
  fitAddon: FitAddon;
  title: string;
}

let tabCounter = 1;

function createXTerm(): { term: XTerm; fitAddon: FitAddon } {
  const term = new XTerm({
    theme: {
      background: "#0a0a0f",
      foreground: "#c8c8e8",
      cursor: "#00ff88",
      cursorAccent: "#0a0a0f",
      selectionBackground: "#1e1e3f",
      black: "#0a0a0f",
      red: "#ff3355",
      green: "#00ff88",
      yellow: "#ffcc00",
      blue: "#5599ff",
      magenta: "#cc66ff",
      cyan: "#00d4ff",
      white: "#c8c8e8",
      brightBlack: "#3d3d6b",
      brightRed: "#ff5577",
      brightGreen: "#33ff99",
      brightYellow: "#ffdd33",
      brightBlue: "#77aaff",
      brightMagenta: "#dd88ff",
      brightCyan: "#33ddff",
      brightWhite: "#ffffff",
    },
    fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", "Courier New", monospace',
    fontSize: 13,
    lineHeight: 1.4,
    cursorBlink: true,
    cursorStyle: "block",
    scrollback: 5000,
    allowProposedApi: true,
  });
  const fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.loadAddon(new WebLinksAddon());
  return { term, fitAddon };
}

export default function TerminalPage() {
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeTabId, setActiveTabId] = useState<string | null>(null);
  const containerRefs = useRef<Map<string, HTMLDivElement>>(new Map());
  const tabsRef = useRef<Tab[]>([]);
  const socket = getSocket();

  tabsRef.current = tabs;

  const attachTerminal = useCallback((tabId: string, el: HTMLDivElement | null) => {
    if (!el) return;
    containerRefs.current.set(tabId, el);
    const tab = tabsRef.current.find(t => t.id === tabId);
    if (!tab) return;
    if (!tab.term.element) {
      tab.term.open(el);
      setTimeout(() => {
        tab.fitAddon.fit();
        const { cols, rows } = tab.term;
        socket.emit("terminal:create", { cols, rows, cwd: "/home/user/netty-hunter" });
        socket.once("terminal:created", ({ termId }: { termId: string }) => {
          setTabs(prev => prev.map(t => t.id === tabId ? { ...t, termId } : t));

          tab.term.write(
            "\r\n\x1b[1;32m  ╔══ SENTINEL PRIMORDIAL — TERMINAL ══╗\x1b[0m\r\n" +
            "\x1b[2m  Type \x1b[0m\x1b[1;36mclaude\x1b[0m\x1b[2m to launch Claude Code\x1b[0m\r\n\r\n"
          );
        });
      }, 50);
    } else {
      setTimeout(() => tab.fitAddon.fit(), 50);
    }
  }, [socket]);

  const addTab = useCallback(() => {
    const id = `tab-${Date.now()}`;
    const title = `shell ${tabCounter++}`;
    const { term, fitAddon } = createXTerm();

    term.onData((data) => {
      const current = tabsRef.current.find(t => t.id === id);
      if (current?.termId) {
        socket.emit("terminal:input", { termId: current.termId, data });
      }
    });

    setTabs(prev => [...prev, { id, termId: null, term, fitAddon, title }]);
    setActiveTabId(id);
  }, [socket]);

  const closeTab = useCallback((tabId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const tab = tabsRef.current.find(t => t.id === tabId);
    if (tab?.termId) socket.emit("terminal:destroy", { termId: tab.termId });
    tab?.term.dispose();
    containerRefs.current.delete(tabId);

    setTabs(prev => {
      const remaining = prev.filter(t => t.id !== tabId);
      if (remaining.length === 0) {
        // Immediately open a fresh tab rather than leaving an empty page
        return prev; // addTab will be called below
      }
      return remaining;
    });

    setActiveTabId(prev => {
      if (prev !== tabId) return prev;
      const remaining = tabsRef.current.filter(t => t.id !== tabId);
      return remaining[remaining.length - 1]?.id ?? null;
    });
  }, [socket]);

  // Open first tab on mount
  useEffect(() => {
    addTab();
  }, []);

  // If all tabs closed, open a new one
  useEffect(() => {
    if (tabs.length === 0) addTab();
  }, [tabs.length]);

  // Forward terminal output from server to the right tab
  useEffect(() => {
    const onOutput = ({ termId, data }: { termId: string; data: string }) => {
      const tab = tabsRef.current.find(t => t.termId === termId);
      tab?.term.write(data);
    };
    const onExit = ({ termId }: { termId: string }) => {
      const tab = tabsRef.current.find(t => t.termId === termId);
      tab?.term.write("\r\n\x1b[31m[process exited — press Enter to start a new shell]\x1b[0m\r\n");
    };
    socket.on("terminal:output", onOutput);
    socket.on("terminal:exit", onExit);
    return () => {
      socket.off("terminal:output", onOutput);
      socket.off("terminal:exit", onExit);
    };
  }, [socket]);

  // Resize active terminal when window resizes
  useEffect(() => {
    const onResize = () => {
      const tab = tabsRef.current.find(t => t.id === activeTabId);
      if (!tab) return;
      tab.fitAddon.fit();
      if (tab.termId) {
        socket.emit("terminal:resize", { termId: tab.termId, cols: tab.term.cols, rows: tab.term.rows });
      }
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [activeTabId, socket]);

  // Clean up all PTYs on unmount
  useEffect(() => {
    return () => {
      tabsRef.current.forEach(tab => {
        if (tab.termId) socket.emit("terminal:destroy", { termId: tab.termId });
        tab.term.dispose();
      });
    };
  }, [socket]);

  return (
    <div className="h-full flex flex-col bg-hack-bg overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-hack-border flex-shrink-0 bg-hack-surface">
        <Terminal className="w-3.5 h-3.5 text-hack-accent" />
        <span className="text-[11px] font-mono font-bold text-hack-accent">TERMINAL</span>
        <div className="flex-1 flex items-center gap-0.5 overflow-x-auto ml-2">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTabId(tab.id)}
              className={`flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-mono rounded-t border transition-all flex-shrink-0 ${
                activeTabId === tab.id
                  ? "bg-hack-bg text-hack-text border-hack-accent/30 border-b-hack-bg"
                  : "bg-hack-muted text-hack-dim border-hack-border hover:text-hack-text"
              }`}
            >
              <Terminal className="w-2.5 h-2.5" />
              {tab.title}
              <span
                onClick={(e) => closeTab(tab.id, e)}
                className="ml-1 hover:text-hack-red cursor-pointer opacity-60 hover:opacity-100"
              >
                <X className="w-2.5 h-2.5" />
              </span>
            </button>
          ))}
        </div>
        <button
          onClick={addTab}
          title="New terminal"
          className="flex items-center gap-1 px-2 py-1 text-[10px] font-mono text-hack-dim hover:text-hack-accent border border-hack-border hover:border-hack-accent/40 rounded transition-all flex-shrink-0"
        >
          <Plus className="w-3 h-3" />
        </button>
      </div>

      {/* Terminal panes */}
      <div className="flex-1 relative overflow-hidden">
        {tabs.map(tab => (
          <div
            key={tab.id}
            ref={(el) => attachTerminal(tab.id, el)}
            className="absolute inset-0 p-1"
            style={{ display: activeTabId === tab.id ? "block" : "none" }}
          />
        ))}
      </div>
    </div>
  );
}

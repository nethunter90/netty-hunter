import React, { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import ActivityBar from "./components/layout/ActivityBar";
import Dashboard from "./pages/Dashboard";
import Programs from "./pages/Programs";
import HuntConsole from "./pages/HuntConsole";
import Findings from "./pages/Findings";
import Intelligence from "./pages/Intelligence";
import Reports from "./pages/Reports";
import Orchestration from "./pages/Orchestration";
import Hunter from "./pages/Hunter";
import Login from "./pages/Login";
import { authAPI } from "./lib/api";
import { SocketProvider } from './context/SocketContext';
import Bounty from './pages/Bounty';
import Missions from './pages/Missions';
import SettingsPage from './pages/Settings';
import FloatingChat from './components/FloatingChat';
import ToolsPage from './pages/Tools';
import TerminalPage from './pages/TerminalPage';
import { useHuntEvents } from './lib/huntEventBridge';
import { useOrchestrationEvents } from './lib/orchestrationEventBridge';

interface User {
  id: number;
  username: string;
  role: string;
}

// Separate component so useLocation works inside BrowserRouter
function AppLayout({ user, setUser }: { user: User; setUser: (u: User | null) => void }) {
  const location = useLocation();
  const [activeView, setActiveView] = useState<string>("dashboard");
  const isTerminal = location.pathname === "/terminal";

  // Hunt + orchestration event subscriptions live here — above the panel routing —
  // so live progress keeps streaming into their stores regardless of which panel is
  // mounted, and returning to a panel restores the full prior stream.
  useHuntEvents();
  useOrchestrationEvents();

  return (
    <div className="flex h-screen bg-hack-bg overflow-hidden">
      <ActivityBar activeView={activeView} onViewChange={setActiveView} user={user} onLogout={() => setUser(null)} />

      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="h-6 bg-hack-surface border-b border-hack-border flex items-center px-4 text-[10px] text-hack-dim font-mono flex-shrink-0">
          <span className="text-hack-accent glow-green">SENTINEL PRIMORDIAL</span>
          <span className="mx-2">|</span>
          <span>v1.0.0</span>
          <span className="mx-2">|</span>
          <span className="text-hack-green">{user.username}@hunter</span>
          <span className="mx-2">|</span>
          <span>BUG BOUNTY INTELLIGENCE PLATFORM</span>
          <div className="ml-auto flex items-center gap-3">
            <span className="flex items-center gap-1">
              <span className="status-dot status-running"></span>
              LIVE
            </span>
          </div>
        </div>

        <div className="flex-1 overflow-hidden relative">
          {/* Terminal always mounted — PTY survives panel switches */}
          <div style={{ display: isTerminal ? "flex" : "none", position: "absolute", inset: 0, flexDirection: "column" }}>
            <TerminalPage />
          </div>

          {/* All other pages via normal routing */}
          {!isTerminal && (
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/programs" element={<Programs />} />
              <Route path="/hunt" element={<HuntConsole />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/intelligence" element={<Intelligence />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/orchestration" element={<Orchestration />} />
              <Route path="/hunter" element={<Hunter />} />
              <Route path="/bounty" element={<Bounty />} />
              <Route path="/missions" element={<Missions />} />
              <Route path="/tools" element={<ToolsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          )}
        </div>
      </div>

      <Toaster position="bottom-right" toastOptions={{
        style: { background: "#141420", color: "#c8c8e8", border: "1px solid #1e1e3f", fontFamily: "monospace", fontSize: "12px" },
        success: { iconTheme: { primary: "#00ff88", secondary: "#0a0a0f" } },
        error: { iconTheme: { primary: "#ff3355", secondary: "#0a0a0f" } },
      }} />
      <FloatingChat />
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    authAPI.me()
      .then(r => setUser(r.data.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const handler = () => setUser(null);
    window.addEventListener('auth:expired', handler);
    return () => window.removeEventListener('auth:expired', handler);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-hack-bg">
        <div className="text-hack-accent font-mono text-sm animate-pulse">
          INITIALIZING SENTINEL PRIMORDIAL...
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login onLogin={setUser} />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>
        <Toaster position="bottom-right" toastOptions={{
          style: { background: "#141420", color: "#c8c8e8", border: "1px solid #1e1e3f", fontFamily: "monospace", fontSize: "12px" },
        }} />
      </BrowserRouter>
    );
  }

  return (
    <SocketProvider>
      <BrowserRouter>
        <AppLayout user={user} setUser={setUser} />
      </BrowserRouter>
    </SocketProvider>
  );
}

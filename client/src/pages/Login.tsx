import React, { useState } from "react";
import { Shield, Lock, User } from "lucide-react";
import { authAPI } from "../lib/api";
import toast from "react-hot-toast";

interface LoginProps {
  onLogin: (user: { id: number; username: string; role: string }) => void;
}

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [mode, setMode] = useState<"login" | "register">("login");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const fn = mode === "login" ? authAPI.login : authAPI.register;
      const res = await fn(username, password);
      onLogin(res.data.user);
      toast.success(mode === "login" ? "Access granted" : "Account created");
    } catch (err: unknown) {
      const error = err as { response?: { data?: { error?: string } } };
      toast.error(error.response?.data?.error || "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-hack-bg matrix-grid flex items-center justify-center p-4">
      {/* Background glow */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-hack-accent/5 rounded-full blur-3xl" />
      </div>

      <div className="w-full max-w-sm relative">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-hack-accent animate-pulse" strokeWidth={1} />
          </div>
          <h1 className="text-lg font-mono font-bold text-hack-accent glow-green tracking-widest">
            SENTINEL PRIMORDIAL
          </h1>
          <p className="text-[10px] text-hack-dim font-mono mt-1 tracking-widest">
            BUG BOUNTY INTELLIGENCE PLATFORM
          </p>
        </div>

        {/* Login form */}
        <div className="hack-panel p-6 border-glow-green">
          <div className="flex gap-1 mb-6">
            {(["login", "register"] as const).map(m => (
              <button key={m} onClick={() => setMode(m)}
                className={`flex-1 py-1.5 text-xs font-mono uppercase rounded transition-all ${mode === m ? "bg-hack-accent/10 text-hack-accent border border-hack-accent/30" : "text-hack-dim hover:text-hack-text"}`}>
                {m}
              </button>
            ))}
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="hack-label">Username</label>
              <div className="relative">
                <User className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-hack-dim" />
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  className="hack-input w-full pl-8"
                  placeholder="hunter"
                  required
                  autoComplete="username"
                />
              </div>
            </div>

            <div>
              <label className="hack-label">Password</label>
              <div className="relative">
                <Lock className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-hack-dim" />
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="hack-input w-full pl-8"
                  placeholder="••••••••"
                  required
                  autoComplete={mode === "login" ? "current-password" : "new-password"}
                />
              </div>
            </div>

            <button type="submit" disabled={loading} className="hack-btn-primary w-full py-2">
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-3 h-3 border border-hack-bg border-t-transparent rounded-full animate-spin" />
                  AUTHENTICATING...
                </span>
              ) : (
                mode === "login" ? "AUTHENTICATE" : "CREATE ACCOUNT"
              )}
            </button>
          </form>

          <div className="mt-4 text-center text-[10px] text-hack-dim font-mono">
            <span className="text-hack-accent">$</span> AUTHORIZED SECURITY RESEARCH ONLY
          </div>
        </div>
      </div>
    </div>
  );
}

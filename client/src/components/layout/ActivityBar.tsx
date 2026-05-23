import React from "react";
import { useNavigate, useLocation } from "react-router-dom";
import {
  LayoutDashboard, Target, Terminal, ShieldAlert,
  Brain, FileText, LogOut, User, Shield, Layers, Crosshair,
  DollarSign, Swords
} from "lucide-react";
import { authAPI } from "../../lib/api";
import toast from "react-hot-toast";

interface ActivityBarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  user: { username: string; role: string };
  onLogout: () => void;
}

const NAV_ITEMS = [
  { id: "dashboard", icon: LayoutDashboard, label: "Dashboard", path: "/" },
  { id: "programs", icon: Target, label: "Programs", path: "/programs" },
  { id: "hunt", icon: Terminal, label: "Hunt Console", path: "/hunt" },
  { id: "findings", icon: ShieldAlert, label: "Findings", path: "/findings" },
  { id: "intelligence", icon: Brain, label: "Intelligence", path: "/intelligence" },
  { id: "reports", icon: FileText, label: "Reports", path: "/reports" },
  { id: "orchestration", icon: Layers, label: "Orchestration", path: "/orchestration" },
  { id: "hunter", icon: Crosshair, label: "Hunter", path: "/hunter" },
  { id: "bounty", icon: DollarSign, label: "Bounty", path: "/bounty" },
  { id: "missions", icon: Swords, label: "Missions", path: "/missions" },
];

export default function ActivityBar({ activeView, onViewChange, user, onLogout }: ActivityBarProps) {
  const navigate = useNavigate();
  const location = useLocation();

  const handleNav = (item: typeof NAV_ITEMS[0]) => {
    onViewChange(item.id);
    navigate(item.path);
  };

  const handleLogout = async () => {
    await authAPI.logout().catch(() => {});
    onLogout();
    toast.success("Logged out");
  };

  const isActive = (path: string) => {
    if (path === "/") return location.pathname === "/";
    return location.pathname.startsWith(path);
  };

  return (
    <div className="w-12 bg-hack-surface border-r border-hack-border flex flex-col items-center py-2 flex-shrink-0">
      {/* Logo */}
      <div className="mb-4 p-1">
        <Shield className="w-7 h-7 text-hack-accent glow-green" strokeWidth={1.5} />
      </div>

      {/* Nav items */}
      <div className="flex-1 flex flex-col gap-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const active = isActive(item.path);
          return (
            <button
              key={item.id}
              onClick={() => handleNav(item)}
              title={item.label}
              className={`
                group relative w-10 h-10 flex items-center justify-center rounded
                transition-all duration-150
                ${active
                  ? "bg-hack-accent/10 text-hack-accent border border-hack-accent/30"
                  : "text-hack-dim hover:text-hack-text hover:bg-hack-muted"
                }
              `}
            >
              {active && (
                <div className="absolute left-0 w-0.5 h-6 bg-hack-accent rounded-r" />
              )}
              <Icon className="w-4 h-4" strokeWidth={1.5} />
              {/* Tooltip */}
              <div className="absolute left-12 bg-hack-panel border border-hack-border rounded px-2 py-1 text-[10px] font-mono text-hack-text whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                {item.label}
              </div>
            </button>
          );
        })}
      </div>

      {/* User / Logout */}
      <div className="flex flex-col gap-1 mt-2">
        <div
          title={`${user.username} (${user.role})`}
          className="w-10 h-10 flex items-center justify-center rounded text-hack-dim hover:text-hack-text hover:bg-hack-muted cursor-default group relative"
        >
          <User className="w-4 h-4" strokeWidth={1.5} />
          <div className="absolute left-12 bg-hack-panel border border-hack-border rounded px-2 py-1 text-[10px] font-mono text-hack-text whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none z-50">
            {user.username} [{user.role}]
          </div>
        </div>
        <button
          onClick={handleLogout}
          title="Logout"
          className="w-10 h-10 flex items-center justify-center rounded text-hack-dim hover:text-hack-red hover:bg-hack-red/10 transition-all"
        >
          <LogOut className="w-4 h-4" strokeWidth={1.5} />
        </button>
      </div>
    </div>
  );
}

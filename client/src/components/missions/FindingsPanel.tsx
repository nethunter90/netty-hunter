import { useMemo } from 'react';
import { Shield, AlertTriangle, Zap, Eye, Circle } from 'lucide-react';

interface Finding {
  id: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  evidence: string | null;
  timestamp: string;
}

interface FindingsPanelProps {
  findings: Finding[];
}

const severityConfig: Record<string, { color: string; bg: string; border: string; icon: typeof Shield; label: string; order: number }> = {
  critical: { color: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/30', icon: Zap, label: 'Critical', order: 0 },
  high: { color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/30', icon: AlertTriangle, label: 'High', order: 1 },
  medium: { color: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/30', icon: Eye, label: 'Medium', order: 2 },
  low: { color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/30', icon: Shield, label: 'Low', order: 3 },
  info: { color: 'text-gray-400', bg: 'bg-gray-400/10', border: 'border-gray-400/30', icon: Circle, label: 'Info', order: 4 },
};

const severityBorderLeft: Record<string, string> = {
  critical: 'border-l-red-400',
  high: 'border-l-orange-400',
  medium: 'border-l-yellow-400',
  low: 'border-l-blue-400',
  info: 'border-l-gray-400',
};

export function FindingsPanel({ findings }: FindingsPanelProps) {
  const grouped = useMemo(() => {
    if (!findings || findings.length === 0) return [];
    const groups: Record<string, Finding[]> = {};
    findings.forEach(f => {
      const sev = f.severity in severityConfig ? f.severity : 'info';
      if (!groups[sev]) groups[sev] = [];
      groups[sev].push(f);
    });
    return Object.entries(groups)
      .sort(([a], [b]) => (severityConfig[a]?.order ?? 99) - (severityConfig[b]?.order ?? 99));
  }, [findings]);

  if (!findings || findings.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-gray-500" data-testid="findings-empty">
        <Shield className="w-8 h-8 mb-2 opacity-20" />
        <p className="text-xs">No findings yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="findings-panel">
      {grouped.map(([severity, items]) => {
        const config = severityConfig[severity] || severityConfig.info;
        const Icon = config.icon;

        return (
          <div key={severity} data-testid={`findings-group-${severity}`}>
            <div className="flex items-center gap-2 mb-2">
              <Icon className={`w-3.5 h-3.5 ${config.color}`} />
              <span className={`text-xs font-semibold ${config.color}`}>{config.label}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded ${config.bg} ${config.border} border ${config.color} font-mono`}>
                {items.length}
              </span>
            </div>
            <div className="space-y-1.5">
              {items.map(finding => (
                <div
                  key={finding.id}
                  className={`bg-[#252526] border border-[#3d3d3d] border-l-2 ${severityBorderLeft[severity] || 'border-l-gray-400'} rounded p-3`}
                  data-testid={`finding-card-${finding.id}`}
                >
                  <div className="text-xs font-medium text-gray-200">{finding.title}</div>
                  <p className="text-[11px] text-gray-400 mt-1">{finding.description}</p>
                  {finding.evidence && (
                    <p className="text-[10px] text-gray-500 mt-1.5 font-mono bg-[#1e1e1e] px-2 py-1 rounded">{finding.evidence}</p>
                  )}
                  <div className="text-[9px] text-gray-600 mt-1.5">
                    {new Date(finding.timestamp).toLocaleString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

import { Zap, Shield, Eye } from 'lucide-react';

interface StealthIndicatorProps {
  stealthStatus: { mode: string; detections: number };
  compact?: boolean;
}

const modeConfigs: Record<string, { icon: typeof Zap; label: string; color: string; bg: string; border: string; description: string }> = {
  aggressive: { icon: Zap, label: 'Aggressive', color: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/30', description: 'Maximum speed, no evasion techniques applied' },
  stealth: { icon: Shield, label: 'Stealth', color: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/30', description: 'Balanced speed with basic evasion techniques' },
  ultrastealth: { icon: Eye, label: 'Ultra Stealth', color: 'text-green-400', bg: 'bg-green-400/10', border: 'border-green-400/30', description: 'Maximum evasion with timing obfuscation' },
  auto: { icon: Shield, label: 'Auto', color: 'text-cyan-400', bg: 'bg-cyan-400/10', border: 'border-cyan-400/30', description: 'Automatically adjusts based on detection risk' },
};

export function StealthIndicator({ stealthStatus, compact = true }: StealthIndicatorProps) {
  const config = modeConfigs[stealthStatus.mode] || modeConfigs.auto;
  const Icon = config.icon;

  if (compact) {
    return (
      <div className="flex items-center gap-1.5" data-testid="stealth-indicator-compact">
        <div className={`flex items-center gap-1 px-2 py-1 rounded ${config.bg} ${config.border} border`}>
          <Icon className={`w-3 h-3 ${config.color}`} />
          <span className={`text-[11px] font-medium ${config.color}`}>{config.label}</span>
        </div>
        {stealthStatus.detections > 0 && (
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-400/10 border border-red-400/30 text-red-400" data-testid="detection-count">
            {stealthStatus.detections}
          </span>
        )}
      </div>
    );
  }

  return (
    <div className={`rounded border ${config.border} bg-[#252526] p-3`} data-testid="stealth-indicator-full">
      <div className="flex items-center gap-2 mb-2">
        <Icon className={`w-4 h-4 ${config.color}`} />
        <span className={`text-sm font-semibold ${config.color}`}>{config.label}</span>
      </div>
      <p className="text-[11px] text-gray-400 mb-2">{config.description}</p>
      {stealthStatus.detections > 0 && (
        <div className="flex items-center gap-1.5 px-2 py-1.5 rounded bg-red-400/10 border border-red-400/30" data-testid="detection-warning">
          <Zap className="w-3 h-3 text-red-400" />
          <span className="text-[11px] text-red-400 font-medium">{stealthStatus.detections} detection{stealthStatus.detections !== 1 ? 's' : ''} recorded</span>
        </div>
      )}
    </div>
  );
}

import { CheckCircle, Loader2, Circle, Target } from 'lucide-react';

interface AttackStep {
  step: number;
  phase: string;
  status: 'completed' | 'active' | 'pending';
  description: string;
}

interface AttackPathVisualizerProps {
  attackPath: AttackStep[];
}

const statusConfig: Record<string, { icon: typeof CheckCircle; color: string; bg: string; border: string; lineColor: string; animate?: boolean }> = {
  completed: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-400/10', border: 'border-green-400/30', lineColor: 'bg-green-400/40' },
  active: { icon: Loader2, color: 'text-cyan-400', bg: 'bg-cyan-400/10', border: 'border-cyan-400/30', lineColor: 'bg-gray-600', animate: true },
  pending: { icon: Circle, color: 'text-gray-500', bg: 'bg-[#1e1e1e]', border: 'border-[#3d3d3d]', lineColor: 'bg-gray-600' },
};

export function AttackPathVisualizer({ attackPath }: AttackPathVisualizerProps) {
  if (!attackPath || attackPath.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-gray-500" data-testid="attack-path-empty">
        <Target className="w-8 h-8 mb-2 opacity-20" />
        <p className="text-xs">No attack path generated yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-0" data-testid="attack-path-visualizer">
      {attackPath.map((step, index) => {
        const config = statusConfig[step.status] || statusConfig.pending;
        const Icon = config.icon;
        const isLast = index === attackPath.length - 1;

        return (
          <div key={step.step} className="relative" data-testid={`attack-step-${step.step}`}>
            <div className="flex gap-3">
              <div className="flex flex-col items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center border ${config.border} ${config.bg}`}>
                  <Icon className={`w-4 h-4 ${config.color} ${config.animate ? 'animate-spin' : ''}`} />
                </div>
                {!isLast && (
                  <div className={`w-0.5 h-8 ${step.status === 'completed' ? 'bg-green-400/40' : 'bg-gray-600'}`} />
                )}
              </div>
              <div className="flex-1 pb-4">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-gray-200">{step.phase}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded capitalize ${config.color} ${config.bg} border ${config.border}`}>
                    {step.status}
                  </span>
                </div>
                <p className="text-[11px] text-gray-500 mt-0.5">{step.description}</p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

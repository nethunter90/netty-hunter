import { useState, useEffect, useCallback, useRef } from 'react';
import {
  CheckCircle, XCircle, AlertTriangle, Download,
  Loader2, Shield, Wrench, RefreshCw
} from 'lucide-react';
import { csrfFetch } from '@/services/api';

interface Tool {
  name: string;
  package: string;
  description: string;
  category: string;
  critical: boolean;
  installed: boolean;
  version: string | null;
  status: 'ready' | 'missing' | 'installing';
}

interface ToolValidatorProps {
  huntGoal: string;
  onValidationComplete: (ready: boolean) => void;
}

export function ToolValidator({ huntGoal, onValidationComplete }: ToolValidatorProps) {
  const [tools, setTools] = useState<Tool[]>([]);
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState<Record<string, number>>({});
  const [installingAll, setInstallingAll] = useState(false);
  const intervalRefs = useRef<Record<string, ReturnType<typeof setInterval>>>({});

  const fetchTools = useCallback(async () => {
    try {
      const [recRes, checkRes] = await Promise.all([
        fetch(`/api/tools/recommend/${encodeURIComponent(huntGoal)}`),
        fetch('/api/tools/check')
      ]);
      const recData = await recRes.json();
      const checkData = await checkRes.json();

      if (recData.success && checkData.success) {
        const checkMap = new Map(
          checkData.tools.map((t: any) => [t.name, t])
        );
        const recommendedNames: string[] = recData.recommendations.map((r: any) => r.name);

        const merged: Tool[] = recommendedNames.map((name) => {
          const full = checkMap.get(name) as any;
          const rec = recData.recommendations.find((r: any) => r.name === name);
          if (full) {
            return {
              name: full.name,
              package: full.package,
              description: full.description,
              category: full.category,
              critical: full.critical,
              installed: full.installed,
              version: full.version,
              status: full.installed ? 'ready' as const : 'missing' as const,
            };
          }
          return {
            name,
            package: name,
            description: rec?.description || 'External tool',
            category: rec?.category || 'unknown',
            critical: false,
            installed: rec?.installed || false,
            version: null,
            status: rec?.installed ? 'ready' as const : 'missing' as const,
          };
        });

        setTools(merged);

        const criticalMissing = merged.filter(t => t.critical && !t.installed).length;
        onValidationComplete(criticalMissing === 0);
      }
    } catch (err) {
      console.error('Failed to fetch tools:', err);
    } finally {
      setLoading(false);
    }
  }, [huntGoal, onValidationComplete]);

  useEffect(() => {
    setLoading(true);
    setTools([]);
    fetchTools();
  }, [fetchTools]);

  useEffect(() => {
    return () => {
      Object.values(intervalRefs.current).forEach((id) => clearInterval(id));
    };
  }, []);

  const simulateProgress = (key: string, onComplete: () => void) => {
    setInstalling(prev => ({ ...prev, [key]: 0 }));
    const start = Date.now();
    const duration = 5000;
    const interval = setInterval(() => {
      const elapsed = Date.now() - start;
      const progress = Math.min(100, Math.round((elapsed / duration) * 100));
      setInstalling(prev => ({ ...prev, [key]: progress }));
      if (progress >= 100) {
        clearInterval(interval);
        delete intervalRefs.current[key];
        setInstalling(prev => {
          const next = { ...prev };
          delete next[key];
          return next;
        });
        onComplete();
      }
    }, 100);
    intervalRefs.current[key] = interval;
  };

  const installTool = async (toolName: string) => {
    setTools(prev => prev.map(t =>
      t.name === toolName ? { ...t, status: 'installing' as const } : t
    ));

    simulateProgress(toolName, async () => {
      try {
        await csrfFetch(`/api/tools/install/${toolName}`, { method: 'POST' });
      } catch (err) {
        console.error(`Install ${toolName} failed:`, err);
      }
      await fetchTools();
    });
  };

  const installAllCritical = async () => {
    setInstallingAll(true);
    const criticalMissing = tools.filter(t => t.critical && !t.installed);
    criticalMissing.forEach(t => {
      setTools(prev => prev.map(tool =>
        tool.name === t.name ? { ...tool, status: 'installing' as const } : tool
      ));
    });

    simulateProgress('__all_critical__', async () => {
      try {
        await csrfFetch('/api/tools/install-critical', { method: 'POST' });
      } catch (err) {
        console.error('Install critical failed:', err);
      }
      setInstallingAll(false);
      await fetchTools();
    });
  };

  const totalTools = tools.length;
  const installedCount = tools.filter(t => t.installed).length;
  const missingCount = tools.filter(t => !t.installed).length;
  const criticalMissingCount = tools.filter(t => t.critical && !t.installed).length;
  const allCriticalInstalled = criticalMissingCount === 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8" data-testid="tool-validator-loading">
        <Loader2 className="w-6 h-6 text-cyan-400 animate-spin mr-2" />
        <span className="text-sm text-gray-400">Checking tool availability...</span>
      </div>
    );
  }

  return (
    <div className="space-y-4" data-testid="tool-validator">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-gray-100">Pre-Flight Tool Check</h3>
        </div>
        <button
          onClick={() => { setLoading(true); fetchTools(); }}
          className="p-1.5 text-gray-400 hover:bg-[#2d2d2d] rounded transition-colors"
          data-testid="button-refresh-tools"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      <div className="grid grid-cols-4 gap-2" data-testid="tool-summary">
        <div className="bg-[#252526] border border-[#3d3d3d] rounded px-3 py-2 text-center">
          <div className="text-lg font-bold font-mono text-gray-200" data-testid="text-total-tools">{totalTools}</div>
          <div className="text-[10px] text-gray-500">Total Tools</div>
        </div>
        <div className="bg-[#252526] border border-[#3d3d3d] rounded px-3 py-2 text-center">
          <div className="text-lg font-bold font-mono text-green-400" data-testid="text-installed-count">{installedCount}</div>
          <div className="text-[10px] text-gray-500">Installed</div>
        </div>
        <div className="bg-[#252526] border border-[#3d3d3d] rounded px-3 py-2 text-center">
          <div className="text-lg font-bold font-mono text-orange-400" data-testid="text-missing-count">{missingCount}</div>
          <div className="text-[10px] text-gray-500">Missing</div>
        </div>
        <div className="bg-[#252526] border border-[#3d3d3d] rounded px-3 py-2 text-center">
          <div className="text-lg font-bold font-mono text-red-400" data-testid="text-critical-missing">{criticalMissingCount}</div>
          <div className="text-[10px] text-gray-500">Critical Missing</div>
        </div>
      </div>

      <div className={`flex items-center justify-between px-3 py-2 rounded border ${
        allCriticalInstalled
          ? 'bg-green-400/10 border-green-400/30'
          : 'bg-red-400/10 border-red-400/30'
      }`} data-testid="tool-status-message">
        <div className="flex items-center gap-2">
          {allCriticalInstalled ? (
            <CheckCircle className="w-4 h-4 text-green-400" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-red-400" />
          )}
          <span className={`text-xs font-medium ${allCriticalInstalled ? 'text-green-400' : 'text-red-400'}`}>
            {allCriticalInstalled
              ? 'All critical tools installed - Ready to launch'
              : `${criticalMissingCount} critical tool${criticalMissingCount !== 1 ? 's' : ''} missing`}
          </span>
        </div>
        {!allCriticalInstalled && !installingAll && (
          <button
            onClick={installAllCritical}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-red-400/10 border border-red-400/30 text-red-400 rounded hover:bg-red-400/20 transition-colors"
            data-testid="button-install-all-critical"
          >
            <Download className="w-3 h-3" />
            Install All
          </button>
        )}
      </div>

      {'__all_critical__' in installing && (
        <div className="px-3" data-testid="progress-install-all">
          <div className="h-1.5 bg-[#1a1a1a] rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-yellow-400 to-green-400 rounded-full transition-all duration-100"
              style={{ width: `${installing['__all_critical__']}%` }}
            />
          </div>
          <div className="text-[10px] text-yellow-400 font-mono mt-1 text-right">
            {installing['__all_critical__']}%
          </div>
        </div>
      )}

      <div className="space-y-1" data-testid="tool-list">
        {tools.map((tool) => {
          const isInstalling = tool.status === 'installing' || tool.name in installing;
          return (
            <div key={tool.name}>
              <div
                className={`flex items-center gap-3 px-3 py-2 rounded border ${
                  isInstalling
                    ? 'bg-yellow-400/5 border-yellow-400/20'
                    : tool.installed
                      ? 'bg-[#252526] border-[#3d3d3d]'
                      : 'bg-[#252526] border-[#2d2d2d]'
                }`}
                data-testid={`tool-row-${tool.name}`}
              >
                <Wrench className={`w-3.5 h-3.5 shrink-0 ${
                  isInstalling ? 'text-yellow-400' : tool.installed ? 'text-green-400' : 'text-gray-500'
                }`} />

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-200 font-medium" data-testid={`text-tool-name-${tool.name}`}>
                      {tool.name}
                    </span>
                    {tool.critical && (
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-400/10 border border-red-400/30 text-red-400 font-medium" data-testid={`badge-critical-${tool.name}`}>
                        CRITICAL
                      </span>
                    )}
                    {tool.installed && tool.version && (
                      <span className="text-[10px] text-gray-500 font-mono truncate max-w-[120px]" data-testid={`text-version-${tool.name}`}>
                        {tool.version}
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-gray-500 mt-0.5">{tool.description}</div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {isInstalling ? (
                    <div className="flex items-center gap-1.5">
                      <Loader2 className="w-3 h-3 text-yellow-400 animate-spin" />
                      <span className="text-[10px] text-yellow-400 px-1.5 py-0.5 rounded bg-yellow-400/10 border border-yellow-400/30">
                        Installing
                      </span>
                    </div>
                  ) : tool.installed ? (
                    <span className="text-[10px] text-green-400 px-1.5 py-0.5 rounded bg-green-400/10 border border-green-400/30" data-testid={`status-installed-${tool.name}`}>
                      Installed
                    </span>
                  ) : (
                    <span className="text-[10px] text-red-400 px-1.5 py-0.5 rounded bg-red-400/10 border border-red-400/30" data-testid={`status-missing-${tool.name}`}>
                      Missing
                    </span>
                  )}

                  {!tool.installed && !isInstalling && (
                    <button
                      onClick={() => installTool(tool.name)}
                      className="p-1 text-gray-400 hover:text-cyan-400 hover:bg-cyan-400/10 rounded transition-colors"
                      title={`Install ${tool.name}`}
                      data-testid={`button-install-${tool.name}`}
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
              {tool.name in installing && (
                <div className="px-3 mt-0.5" data-testid={`progress-${tool.name}`}>
                  <div className="h-1 bg-[#1a1a1a] rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-yellow-400 to-green-400 rounded-full transition-all duration-100"
                      style={{ width: `${installing[tool.name]}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

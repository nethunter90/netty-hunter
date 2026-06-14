import { useState, useEffect } from 'react';
import { 
  CheckCircle, AlertCircle, Loader2, XCircle, 
  RefreshCw, Activity, Zap, Shield, Code,
  Radio, GraduationCap, Target
} from 'lucide-react';

interface FeatureStatus {
  name: string;
  status: 'fully_wired' | 'partial' | 'simulation' | 'inactive';
  endpoint?: string;
  lastChecked?: string;
  details?: string;
}

interface CategoryStatus {
  name: string;
  icon: any;
  features: FeatureStatus[];
  color: string;
}

const iconMap: Record<string, any> = {
  zap: Zap,
  activity: Activity,
  shield: Shield,
  target: Target,
  code: Code,
  'graduation-cap': GraduationCap,
  radio: Radio,
};

const colorMap: Record<string, string> = {
  cyan: 'text-cyan-400',
  purple: 'text-purple-400',
  orange: 'text-orange-400',
  green: 'text-green-400',
  yellow: 'text-yellow-400',
  blue: 'text-blue-400',
  pink: 'text-pink-400',
};

const featureDefinitions: CategoryStatus[] = [
  {
    name: 'Core Infrastructure',
    icon: Zap,
    color: 'text-cyan-400',
    features: [
      { name: 'Hunt Orchestrator', status: 'fully_wired', endpoint: '/api/bounty/hunts' },
      { name: 'WebSocket Bridge', status: 'fully_wired', endpoint: '/api/orchestration/stats/summary' },
    ]
  },
  {
    name: 'AI Integration',
    icon: Activity,
    color: 'text-purple-400',
    features: [
      { name: 'Ollama Client', status: 'fully_wired', endpoint: '/api/bounty/advisor/chat' },
      { name: 'OpenAI Fallback', status: 'partial', details: 'Requires API key configuration' },
    ]
  },
  {
    name: 'Security Tools',
    icon: Shield,
    color: 'text-orange-400',
    features: [
      { name: 'Nmap Integration', status: 'inactive', endpoint: '/api/bounty/tools/nmap', details: 'Not installed - install on Kali Linux' },
      { name: 'SQLMap Integration', status: 'inactive', endpoint: '/api/bounty/tools/sqlmap', details: 'Not installed - install on Kali Linux' },
      { name: 'Nuclei Templates', status: 'fully_wired', endpoint: '/api/bounty/nuclei/templates' },
      { name: 'Burp Suite Bridge', status: 'inactive', details: 'Not installed - install on Kali Linux' },
      { name: 'Metasploit Integration', status: 'inactive', endpoint: '/api/bounty/tools/metasploit', details: 'Not installed - install on Kali Linux' },
    ]
  },
  {
    name: 'Bug Bounty Agents',
    icon: Target,
    color: 'text-green-400',
    features: [
      { name: 'Backward Hunt', status: 'fully_wired', endpoint: '/api/bounty/hunts' },
      { name: 'Tool Readiness', status: 'fully_wired', endpoint: '/api/bounty/tools' },
      { name: 'Audit Trail', status: 'fully_wired', endpoint: '/api/bounty/audit' },
      { name: 'Scope Manager', status: 'fully_wired', endpoint: '/api/bounty/scope' },
    ]
  },
  {
    name: 'Workflow System',
    icon: Code,
    color: 'text-yellow-400',
    features: [
      { name: 'Workflow Builder', status: 'fully_wired', endpoint: '/api/bounty/workflows' },
      { name: 'Task Planning', status: 'fully_wired', endpoint: '/api/bounty/tasks' },
      { name: 'Browser Automation', status: 'partial', endpoint: '/api/bounty/browser/navigate', details: 'Playwright browser service' },
      { name: 'Analysis Engine', status: 'partial', details: 'AI analysis available via Ollama' },
    ]
  },
  {
    name: 'Reporting & Tracking',
    icon: GraduationCap,
    color: 'text-blue-400',
    features: [
      { name: 'Draft Reports', status: 'fully_wired', endpoint: '/api/bounty/reports' },
      { name: 'Submissions Tracker', status: 'fully_wired', endpoint: '/api/bounty/submissions' },
      { name: 'Deadline Manager', status: 'fully_wired', endpoint: '/api/bounty/deadlines' },
      { name: 'Platform Sync', status: 'partial', details: 'Platform API fetchers available (configure API keys for full sync)' },
    ]
  },
  {
    name: 'Utilities',
    icon: Radio,
    color: 'text-pink-400',
    features: [
      { name: 'Payload Library', status: 'fully_wired', endpoint: '/api/bounty/payloads' },
      { name: 'CVE Intel', status: 'partial', endpoint: '/api/bounty/cve/search', details: 'Database cache empty' },
      { name: 'PoC Lab', status: 'partial', endpoint: '/api/bounty/poc/test', details: 'Available (sandboxing requires local Kali setup)' },
      { name: 'AI Advisor', status: 'fully_wired', endpoint: '/api/bounty/advisor/chat' },
    ]
  },
];

export function SyncStatus() {
  const [lastChecked, setLastChecked] = useState(new Date());
  const [isChecking, setIsChecking] = useState(false);
  const [categories, setCategories] = useState<CategoryStatus[]>([]);
  const [mode, setMode] = useState<string>('web');

  useEffect(() => {
    checkAllFeatures();
    const interval = setInterval(checkAllFeatures, 15000);
    return () => clearInterval(interval);
  }, []);

  const checkAllFeatures = async () => {
    setIsChecking(true);

    try {
      const response = await fetch('/api/bounty/platform/status');
      const data = await response.json();

      if (data.success && data.categories) {
        setMode(data.mode || 'web');
        const mapped: CategoryStatus[] = data.categories.map((cat: any) => ({
          name: cat.name,
          icon: iconMap[cat.icon] || Zap,
          color: colorMap[cat.color] || 'text-gray-400',
          features: cat.features.map((f: any) => ({
            name: f.name,
            status: f.status as FeatureStatus['status'],
            endpoint: f.endpoint,
            details: f.details,
            lastChecked: f.lastChecked ? new Date(f.lastChecked).toLocaleTimeString() : undefined,
          })),
        }));
        setCategories(mapped);
        setLastChecked(new Date());
        setIsChecking(false);
        return;
      }
    } catch {
    }

    const updatedCategories = featureDefinitions.map(cat => ({
      ...cat,
      features: cat.features.map(f => ({ ...f })),
    }));

    for (const category of updatedCategories) {
      for (const feature of category.features) {
        if (feature.endpoint) {
          try {
            const response = await fetch(feature.endpoint, {
              method: 'GET',
              headers: { 'Accept': 'application/json' }
            });

            if (response.ok) {
              const data = await response.json();
              if (data.success !== false) {
                if (feature.status !== 'simulation' && feature.status !== 'partial') {
                  feature.status = 'fully_wired';
                }
              }
              feature.lastChecked = new Date().toLocaleTimeString();
            } else {
              feature.status = 'inactive';
              feature.details = `HTTP ${response.status}`;
            }
          } catch {
            feature.status = 'inactive';
            feature.details = 'Endpoint unreachable';
          }
        }
      }
    }

    setCategories(updatedCategories);
    setLastChecked(new Date());
    setIsChecking(false);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'fully_wired':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'partial':
        return <AlertCircle className="w-4 h-4 text-yellow-500" />;
      case 'simulation':
        return <Loader2 className="w-4 h-4 text-blue-500" />;
      case 'inactive':
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return <AlertCircle className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    const styles: Record<string, string> = {
      fully_wired: 'bg-green-500/20 text-green-400 border border-green-500/30',
      partial: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
      simulation: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
      inactive: 'bg-red-500/20 text-red-400 border border-red-500/30',
    };
    const labels: Record<string, string> = {
      fully_wired: 'Fully Wired',
      partial: 'Partial',
      simulation: 'Simulation',
      inactive: 'Inactive',
    };
    return (
      <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status] || 'bg-gray-500/20 text-gray-400 border border-gray-500/30'}`}>
        {labels[status] || 'Unknown'}
      </span>
    );
  };

  const getCategoryCounts = (features: FeatureStatus[]) => {
    return {
      fully_wired: features.filter(f => f.status === 'fully_wired').length,
      partial: features.filter(f => f.status === 'partial').length,
      simulation: features.filter(f => f.status === 'simulation').length,
      inactive: features.filter(f => f.status === 'inactive').length,
    };
  };

  const getCategoryStatus = (features: FeatureStatus[]): string => {
    const allWired = features.every(f => f.status === 'fully_wired');
    const someWired = features.some(f => f.status === 'fully_wired');
    const allInactive = features.every(f => f.status === 'inactive');

    if (allWired) return 'fully_wired';
    if (allInactive) return 'inactive';
    if (someWired) return 'partial';
    return 'simulation';
  };

  const totalCounts = categories.reduce((acc, cat) => {
    const counts = getCategoryCounts(cat.features);
    return {
      fully_wired: acc.fully_wired + counts.fully_wired,
      partial: acc.partial + counts.partial,
      simulation: acc.simulation + counts.simulation,
      inactive: acc.inactive + counts.inactive,
    };
  }, { fully_wired: 0, partial: 0, simulation: 0, inactive: 0 });

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6" data-testid="sync-status-panel">
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-2xl font-bold text-gray-100" data-testid="text-panel-title">Platform Wiring Status</h2>
          <button
            onClick={checkAllFeatures}
            disabled={isChecking}
            className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50 text-gray-200"
            data-testid="button-refresh-status"
          >
            <RefreshCw className={`w-4 h-4 ${isChecking ? 'animate-spin' : ''}`} />
            {isChecking ? 'Checking...' : 'Refresh'}
          </button>
        </div>
        <div className="flex items-center gap-2 text-sm text-gray-400">
          <span data-testid="text-mode">{mode === 'production' ? 'Production Mode' : 'Web Mode'}</span>
          <span>·</span>
          <span data-testid="text-last-checked">Last checked: {lastChecked.toLocaleTimeString()}</span>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg" data-testid="card-summary-wired">
          <div className="text-3xl font-bold text-green-400 mb-1">{totalCounts.fully_wired}</div>
          <div className="text-sm text-green-300">Fully Wired</div>
        </div>
        <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg" data-testid="card-summary-partial">
          <div className="text-3xl font-bold text-yellow-400 mb-1">{totalCounts.partial}</div>
          <div className="text-sm text-yellow-300">Partial</div>
        </div>
        <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-lg" data-testid="card-summary-simulation">
          <div className="text-3xl font-bold text-blue-400 mb-1">{totalCounts.simulation}</div>
          <div className="text-sm text-blue-300">Simulation</div>
        </div>
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg" data-testid="card-summary-inactive">
          <div className="text-3xl font-bold text-red-400 mb-1">{totalCounts.inactive}</div>
          <div className="text-sm text-red-300">Inactive</div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="space-y-4">
          {categories.map((category) => {
            const CategoryIcon = category.icon;
            const counts = getCategoryCounts(category.features);
            const categoryStatus = getCategoryStatus(category.features);

            return (
              <div key={category.name} className="p-4 bg-[#252526] border border-[#3d3d3d] rounded-lg" data-testid={`card-category-${category.name.toLowerCase().replace(/[^a-z]/g, '-')}`}>
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <CategoryIcon className={`w-5 h-5 ${category.color}`} />
                    <div>
                      <h3 className="font-semibold text-gray-200">{category.name}</h3>
                      <div className="text-xs text-gray-400">
                        ({category.features.length} features)
                      </div>
                    </div>
                  </div>
                  {getStatusBadge(categoryStatus)}
                </div>

                <div className="space-y-2">
                  {category.features.map((feature) => (
                    <div
                      key={feature.name}
                      className="flex items-center justify-between p-3 bg-gray-900/50 rounded-lg hover:bg-gray-900 transition-colors"
                      data-testid={`feature-row-${feature.name.toLowerCase().replace(/[^a-z]/g, '-')}`}
                    >
                      <div className="flex items-center gap-3 flex-1">
                        {getStatusIcon(feature.status)}
                        <div className="flex-1">
                          <div className="font-medium text-sm text-gray-200">{feature.name}</div>
                          {feature.details && (
                            <div className="text-xs text-gray-500 mt-1">
                              {feature.details}
                            </div>
                          )}
                          {feature.endpoint && (
                            <div className="text-xs font-mono text-gray-600 mt-1">
                              {feature.endpoint}
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {feature.lastChecked && (
                          <span className="text-xs text-gray-500">
                            {feature.lastChecked}
                          </span>
                        )}
                        {getStatusBadge(feature.status)}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="flex items-center gap-4 mt-4 pt-4 border-t border-gray-800 text-xs text-gray-500">
                  {counts.fully_wired > 0 && (
                    <span className="flex items-center gap-1">
                      <CheckCircle className="w-3 h-3 text-green-500" />
                      {counts.fully_wired} wired
                    </span>
                  )}
                  {counts.partial > 0 && (
                    <span className="flex items-center gap-1">
                      <AlertCircle className="w-3 h-3 text-yellow-500" />
                      {counts.partial} partial
                    </span>
                  )}
                  {counts.simulation > 0 && (
                    <span className="flex items-center gap-1">
                      <Loader2 className="w-3 h-3 text-blue-500" />
                      {counts.simulation} simulation
                    </span>
                  )}
                  {counts.inactive > 0 && (
                    <span className="flex items-center gap-1">
                      <XCircle className="w-3 h-3 text-red-500" />
                      {counts.inactive} inactive
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="mt-6 p-4 bg-gray-900/50 rounded-lg">
        <div className="text-xs font-semibold text-gray-400 mb-3">Status Legend</div>
        <div className="grid grid-cols-2 gap-3 text-xs text-gray-300">
          <div className="flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-green-500" />
            <span><span className="font-medium">Fully Wired:</span> All endpoints responding, fully functional</span>
          </div>
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-yellow-500" />
            <span><span className="font-medium">Partial:</span> Core working, some features missing/needs config</span>
          </div>
          <div className="flex items-center gap-2">
            <Loader2 className="w-4 h-4 text-blue-500" />
            <span><span className="font-medium">Simulation:</span> Mock/preview mode, not executing real operations</span>
          </div>
          <div className="flex items-center gap-2">
            <XCircle className="w-4 h-4 text-red-500" />
            <span><span className="font-medium">Inactive:</span> Endpoint not responding, feature disabled</span>
          </div>
        </div>
      </div>
    </div>
  );
}

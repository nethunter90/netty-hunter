import { useState, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import {
  BarChart3, Loader2, RefreshCw, Shield, Globe,
  AlertTriangle, CheckCircle, Target
} from 'lucide-react';
import { csrfFetch } from '@/services/api';

interface Hunt {
  id: string;
  target: string;
  goal: string;
  status: string;
}

interface AnalysisData {
  severity_distribution?: Record<string, number>;
  severityBreakdown?: Record<string, number>;
  vulnerabilityDistribution?: Record<string, number>;
  attack_surface?: string[];
  attackSurface?: string[];
  total_findings?: number;
  totalFindings?: number;
  recommendations?: string[];
  generatedAt?: string;
}

const SEVERITY_CONFIG: Record<string, { color: string; bg: string }> = {
  critical: { color: 'bg-red-500', bg: 'bg-red-500/20' },
  high: { color: 'bg-orange-500', bg: 'bg-orange-500/20' },
  medium: { color: 'bg-yellow-500', bg: 'bg-yellow-500/20' },
  low: { color: 'bg-blue-500', bg: 'bg-blue-500/20' },
  info: { color: 'bg-gray-500', bg: 'bg-gray-500/20' },
};

function normalizeAnalysis(raw: any): AnalysisData | null {
  if (!raw) return null;
  return {
    severity_distribution: raw.severity_distribution || raw.severityBreakdown || raw.vulnerabilityDistribution || {},
    attack_surface: raw.attack_surface || raw.attackSurface || [],
    total_findings: raw.total_findings ?? raw.totalFindings ?? 0,
    recommendations: raw.recommendations || [],
    generatedAt: raw.generatedAt,
  };
}

export function Analysis() {
  const [hunts, setHunts] = useState<Hunt[]>([]);
  const [selectedHuntId, setSelectedHuntId] = useState<string>('');
  const [analysis, setAnalysis] = useState<AnalysisData | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string>('');

  useEffect(() => {
    fetchHunts();
    const interval = setInterval(fetchHunts, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (selectedHuntId) {
      fetchAnalysis(selectedHuntId);
    } else {
      setAnalysis(null);
    }
  }, [selectedHuntId]);

  useEffect(() => {
    if (!selectedHuntId) return;
    const activeHunt = hunts.find(h => h.id === selectedHuntId);
    if (activeHunt && (activeHunt.status === 'running' || activeHunt.status === 'in_progress')) {
      const interval = setInterval(() => fetchAnalysis(selectedHuntId), 5000);
      return () => clearInterval(interval);
    }
  }, [selectedHuntId, hunts]);

  const fetchHunts = async () => {
    try {
      const response = await fetch('/api/bounty/hunts');
      const data = await response.json();
      if (data.success) {
        setHunts(data.hunts || []);
      }
    } catch (error) {
      console.error('Failed to fetch hunts:', error);
    }
  };

  const fetchAnalysis = async (huntId: string) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/bounty/analysis/${huntId}`);
      const data = await response.json();
      if (data.success && data.analysis) {
        const normalized = normalizeAnalysis(data.analysis);
        setAnalysis(normalized);
        if (normalized?.generatedAt) setLastUpdated(normalized.generatedAt);
      } else {
        setAnalysis(null);
      }
    } catch (error) {
      console.error('Failed to fetch analysis:', error);
      setAnalysis(null);
    } finally {
      setLoading(false);
    }
  };

  const generateAnalysis = async () => {
    if (!selectedHuntId) return;
    setGenerating(true);
    try {
      const response = await csrfFetch(`/api/bounty/analysis/${selectedHuntId}/generate`, {
        method: 'POST',
      });
      const data = await response.json();
      if (data.success && data.analysis) {
        const normalized = normalizeAnalysis(data.analysis);
        setAnalysis(normalized);
        if (normalized?.generatedAt) setLastUpdated(normalized.generatedAt);
      }
    } catch (error) {
      console.error('Failed to generate analysis:', error);
    } finally {
      setGenerating(false);
    }
  };

  const sevDist = analysis?.severity_distribution || {};
  const maxSeverityCount = Object.keys(sevDist).length > 0
    ? Math.max(...(Object.values(sevDist) as number[]), 1)
    : 1;
  const attackSurface = analysis?.attack_surface || [];
  const totalFindings = analysis?.total_findings ?? 0;
  const recommendations = analysis?.recommendations || [];

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#3d3d3d]">
        <div className="flex items-center gap-3">
          <BarChart3 className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">Analysis</h1>
          {selectedHuntId && hunts.find(h => h.id === selectedHuntId && (h.status === 'running' || h.status === 'in_progress')) && (
            <Badge className="bg-green-500/20 text-green-400 border-green-500/30 text-[10px] animate-pulse" data-testid="badge-live">
              LIVE
            </Badge>
          )}
          {lastUpdated && analysis && (
            <span className="text-[10px] text-gray-500" data-testid="text-last-updated">
              Updated: {new Date(lastUpdated).toLocaleTimeString()}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="w-64">
            <Select value={selectedHuntId} onValueChange={setSelectedHuntId}>
              <SelectTrigger className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-hunt">
                <SelectValue placeholder="Select a hunt..." />
              </SelectTrigger>
              <SelectContent>
                {hunts.map(h => (
                  <SelectItem key={h.id} value={h.id}>
                    {h.target} — {h.goal}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <Button
            onClick={generateAnalysis}
            disabled={!selectedHuntId || generating}
            variant="outline"
            className="bg-[#252526] border-[#3d3d3d] text-cyan-400 hover:bg-cyan-600/20"
            data-testid="button-generate-analysis"
          >
            {generating ? (
              <Loader2 className="w-4 h-4 mr-1 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4 mr-1" />
            )}
            {generating ? 'Generating...' : 'Generate Analysis'}
          </Button>
        </div>
      </div>

      <ScrollArea className="flex-1">
        {!selectedHuntId ? (
          <div className="flex flex-col items-center justify-center py-24 text-gray-500" data-testid="text-empty-state">
            <Target className="w-12 h-12 mb-4 text-gray-600" />
            <p className="text-sm">Select a hunt to view analysis</p>
          </div>
        ) : loading ? (
          <div className="flex items-center justify-center py-24">
            <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
          </div>
        ) : !analysis ? (
          <div className="flex flex-col items-center justify-center py-24 text-gray-500" data-testid="text-no-analysis">
            <BarChart3 className="w-12 h-12 mb-4 text-gray-600" />
            <p className="text-sm mb-3">No analysis data available</p>
            <Button
              onClick={generateAnalysis}
              disabled={generating}
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              data-testid="button-generate-first-analysis"
            >
              <RefreshCw className="w-4 h-4 mr-1" /> Generate Analysis
            </Button>
          </div>
        ) : (
          <div className="p-6 space-y-6">
            <div className="grid grid-cols-3 gap-4">
              <Card className="bg-[#252526] border-[#3d3d3d] p-6 text-center">
                <Shield className="w-8 h-8 text-cyan-400 mx-auto mb-2" />
                <p className="text-4xl font-bold text-gray-100" data-testid="text-total-findings">
                  {totalFindings}
                </p>
                <p className="text-xs text-gray-500 mt-1">Total Findings</p>
              </Card>
              <Card className="bg-[#252526] border-[#3d3d3d] p-6 text-center">
                <Globe className="w-8 h-8 text-purple-400 mx-auto mb-2" />
                <p className="text-4xl font-bold text-gray-100" data-testid="text-attack-surface-count">
                  {attackSurface.length}
                </p>
                <p className="text-xs text-gray-500 mt-1">Attack Surface Targets</p>
              </Card>
              <Card className="bg-[#252526] border-[#3d3d3d] p-6 text-center">
                <AlertTriangle className="w-8 h-8 text-orange-400 mx-auto mb-2" />
                <p className="text-4xl font-bold text-gray-100" data-testid="text-critical-count">
                  {(sevDist.critical || 0) + (sevDist.high || 0)}
                </p>
                <p className="text-xs text-gray-500 mt-1">Critical + High</p>
              </Card>
            </div>

            <Card className="bg-[#252526] border-[#3d3d3d] p-6">
              <h3 className="text-sm font-semibold text-gray-200 mb-4">Severity Distribution</h3>
              <div className="space-y-3">
                {Object.entries(SEVERITY_CONFIG).map(([severity, config]) => {
                  const count = sevDist[severity] || 0;
                  const width = maxSeverityCount > 0 ? (count / maxSeverityCount) * 100 : 0;
                  return (
                    <div key={severity} className="flex items-center gap-3" data-testid={`bar-severity-${severity}`}>
                      <span className="text-xs text-gray-400 w-16 capitalize">{severity}</span>
                      <div className="flex-1 h-6 bg-[#1e1e1e] rounded overflow-hidden">
                        <div
                          className={`h-full ${config.color} rounded transition-all flex items-center px-2`}
                          style={{ width: `${Math.max(width, count > 0 ? 5 : 0)}%` }}
                        >
                          {count > 0 && (
                            <span className="text-[10px] text-white font-bold">{count}</span>
                          )}
                        </div>
                      </div>
                      <span className="text-xs text-gray-500 w-8 text-right">{count}</span>
                    </div>
                  );
                })}
              </div>
            </Card>

            <div className="grid grid-cols-2 gap-4">
              <Card className="bg-[#252526] border-[#3d3d3d] p-6">
                <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-purple-400" /> Attack Surface
                </h3>
                {attackSurface.length === 0 ? (
                  <p className="text-xs text-gray-500">No targets found</p>
                ) : (
                  <div className="space-y-2">
                    {attackSurface.map((target, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-2 px-3 py-2 bg-[#1e1e1e] rounded text-xs text-gray-300"
                        data-testid={`text-attack-surface-${i}`}
                      >
                        <Target className="w-3 h-3 text-cyan-400 flex-shrink-0" />
                        <span className="truncate">{target}</span>
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card className="bg-[#252526] border-[#3d3d3d] p-6">
                <h3 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-green-400" /> Recommendations
                </h3>
                {recommendations.length === 0 ? (
                  <p className="text-xs text-gray-500">No recommendations available</p>
                ) : (
                  <div className="space-y-2">
                    {recommendations.map((rec, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-2 px-3 py-2 bg-[#1e1e1e] rounded text-xs text-gray-300"
                        data-testid={`text-recommendation-${i}`}
                      >
                        <span className="text-green-400 font-bold mt-0.5">{i + 1}.</span>
                        <span>{rec}</span>
                      </div>
                    ))}
                  </div>
                )}
              </Card>
            </div>
          </div>
        )}
      </ScrollArea>
    </div>
  );
}

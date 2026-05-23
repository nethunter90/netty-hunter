import { useState, useEffect } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Target, BarChart3, Plus, Loader2, Search,
  Globe, Shield, Clock, ChevronDown, ChevronUp,
  Crosshair, FileSearch, Trophy, AlertTriangle, X
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface CampaignEntry {
  id: string;
  domain: string;
  industry: string;
  outcome: 'success' | 'partial' | 'failure';
  findingCount: number;
  completedAt: string;
  stackHash?: string;
  wafType?: string | null;
}

interface SimilarCampaign {
  campaignId: string;
  similarity: number;
  sharedTechniques: string[];
  uniqueFindings: number;
}

const OUTCOME_STYLES: Record<string, string> = {
  success: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
  partial: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  failure: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const HUNT_GOALS = [
  'find-vulns', 'recon-only', 'specific-vuln', 'full-audit',
  'api-testing', 'auth-testing', 'injection-hunting', 'misconfig-hunting'
];

export function CampaignIntelligence() {
  const [campaigns, setCampaigns] = useState<CampaignEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [similarCampaigns, setSimilarCampaigns] = useState<SimilarCampaign[]>([]);
  const [similarLoading, setSimilarLoading] = useState(false);

  const [showForm, setShowForm] = useState(false);
  const [formDomain, setFormDomain] = useState('');
  const [formIndustry, setFormIndustry] = useState('');
  const [formGoal, setFormGoal] = useState('find-vulns');
  const [formOutcome, setFormOutcome] = useState<'success' | 'partial' | 'failure'>('success');
  const [formSubmitting, setFormSubmitting] = useState(false);

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const fetchCampaigns = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/intelligence/campaigns');
      const data = await res.json();
      if (data.success) {
        setCampaigns(data.data || []);
      }
    } catch (err) {
      console.error('Failed to fetch campaigns:', err);
    } finally {
      setLoading(false);
    }
  };

  const selectCampaign = async (campaign: CampaignEntry) => {
    if (selectedId === campaign.id) {
      setSelectedId(null);
      setSimilarCampaigns([]);
      return;
    }
    setSelectedId(campaign.id);
    setSimilarLoading(true);
    setSimilarCampaigns([]);
    try {
      const res = await csrfFetch('/api/intelligence/campaigns/similar', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetProfile: { domain: campaign.domain, industry: campaign.industry },
          huntGoal: 'find-vulns',
        }),
      });
      const data = await res.json();
      if (data.success) {
        setSimilarCampaigns(data.data || []);
      }
    } catch (err) {
      console.error('Failed to fetch similar campaigns:', err);
    } finally {
      setSimilarLoading(false);
    }
  };

  const submitCampaign = async () => {
    if (!formDomain.trim()) return;
    setFormSubmitting(true);
    try {
      const now = new Date().toISOString();
      const body = {
        id: `camp-${Date.now()}`,
        target: {
          domain: formDomain,
          industry: formIndustry || 'unknown',
          techStack: { language: null, framework: null, server: null, database: null, cdn: null, jsLibraries: [] },
          defensePosture: {
            wafType: null, wafStrictness: 'moderate',
            rateLimiting: { detected: false, threshold: null, resetWindow: null },
            errorVerbosity: 'standard',
            cspPolicy: { present: false, strictness: 'none', reportOnly: false },
            securityHeaders: { hsts: false, xFrameOptions: false, xContentType: false, referrerPolicy: null },
            cookieFlags: { httpOnly: false, secure: false, sameSite: null },
            authMechanisms: [], apiStyle: 'rest',
          },
        },
        hunt: {
          goal: formGoal,
          startedAt: now,
          completedAt: now,
          durationMinutes: 0,
          tasksExecuted: 0,
          toolsUsed: [],
        },
        techniques: [],
        findings: [],
        outcome: formOutcome,
      };
      const res = await csrfFetch('/api/intelligence/campaigns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (data.success) {
        setFormDomain('');
        setFormIndustry('');
        setFormGoal('find-vulns');
        setFormOutcome('success');
        setShowForm(false);
        await fetchCampaigns();
      }
    } catch (err) {
      console.error('Failed to record campaign:', err);
    } finally {
      setFormSubmitting(false);
    }
  };

  const totalCampaigns = campaigns.length;
  const avgFindings = totalCampaigns > 0
    ? Math.round(campaigns.reduce((sum, c) => sum + c.findingCount, 0) / totalCampaigns * 10) / 10
    : 0;
  const successRate = totalCampaigns > 0
    ? Math.round(campaigns.filter(c => c.outcome === 'success').length / totalCampaigns * 100)
    : 0;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] text-gray-300" data-testid="campaign-intelligence-panel">
      <div className="px-4 py-3 border-b border-[#3d3d3d] shrink-0">
        <div className="flex items-center gap-3">
          <Crosshair className="w-6 h-6 text-cyan-400" />
          <h1 className="text-xl font-bold text-gray-100" data-testid="text-campaign-title">Campaign Intelligence</h1>
        </div>
        <p className="text-xs text-gray-500 mt-1">Cross-campaign learning &amp; analysis</p>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        <div className="grid grid-cols-3 gap-3">
          <Card className="bg-[#252526] border-[#3d3d3d] p-3">
            <div className="flex items-center gap-2 mb-1">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <span className="text-xs text-gray-500">Total Campaigns</span>
            </div>
            <span className="text-2xl font-bold text-gray-200" data-testid="text-total-campaigns">{totalCampaigns}</span>
          </Card>
          <Card className="bg-[#252526] border-[#3d3d3d] p-3">
            <div className="flex items-center gap-2 mb-1">
              <FileSearch className="w-4 h-4 text-purple-400" />
              <span className="text-xs text-gray-500">Avg Findings</span>
            </div>
            <span className="text-2xl font-bold text-gray-200" data-testid="text-avg-findings">{avgFindings}</span>
          </Card>
          <Card className="bg-[#252526] border-[#3d3d3d] p-3">
            <div className="flex items-center gap-2 mb-1">
              <Trophy className="w-4 h-4 text-emerald-400" />
              <span className="text-xs text-gray-500">Success Rate</span>
            </div>
            <span className="text-2xl font-bold text-gray-200" data-testid="text-success-rate">{successRate}%</span>
          </Card>
        </div>

        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-200">Campaigns</h2>
          <Button
            size="sm"
            onClick={() => setShowForm(!showForm)}
            className="bg-purple-600 hover:bg-purple-700 text-white h-7 text-xs"
            data-testid="button-toggle-form"
          >
            {showForm ? <X className="w-3.5 h-3.5 mr-1" /> : <Plus className="w-3.5 h-3.5 mr-1" />}
            {showForm ? 'Cancel' : 'Record Campaign'}
          </Button>
        </div>

        {showForm && (
          <Card className="bg-[#252526] border-[#3d3d3d] p-4 space-y-3" data-testid="card-campaign-form">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Plus className="w-4 h-4 text-orange-400" />
              Record New Campaign
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Domain *</label>
                <Input
                  value={formDomain}
                  onChange={(e) => setFormDomain(e.target.value)}
                  placeholder="e.g., example.com"
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                  data-testid="input-campaign-domain"
                />
              </div>
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Industry</label>
                <Input
                  value={formIndustry}
                  onChange={(e) => setFormIndustry(e.target.value)}
                  placeholder="e.g., fintech, healthcare"
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                  data-testid="input-campaign-industry"
                />
              </div>
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Hunt Goal</label>
                <select
                  value={formGoal}
                  onChange={(e) => setFormGoal(e.target.value)}
                  className="w-full bg-[#1e1e1e] border border-[#3d3d3d] text-gray-200 h-8 text-xs rounded px-2"
                  data-testid="select-campaign-goal"
                >
                  {HUNT_GOALS.map(g => (
                    <option key={g} value={g}>{g}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs text-gray-500 mb-1 block">Outcome</label>
                <select
                  value={formOutcome}
                  onChange={(e) => setFormOutcome(e.target.value as 'success' | 'partial' | 'failure')}
                  className="w-full bg-[#1e1e1e] border border-[#3d3d3d] text-gray-200 h-8 text-xs rounded px-2"
                  data-testid="select-campaign-outcome"
                >
                  <option value="success">Success</option>
                  <option value="partial">Partial</option>
                  <option value="failure">Failure</option>
                </select>
              </div>
            </div>
            <Button
              onClick={submitCampaign}
              disabled={formSubmitting || !formDomain.trim()}
              className="bg-cyan-600 hover:bg-cyan-700 text-white h-8 text-xs w-full"
              data-testid="button-submit-campaign"
            >
              {formSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Plus className="w-3.5 h-3.5 mr-1" />}
              Record Campaign
            </Button>
          </Card>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-12" data-testid="loading-campaigns">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            <span className="ml-2 text-sm text-gray-500">Loading campaigns...</span>
          </div>
        ) : campaigns.length === 0 ? (
          <Card className="bg-[#252526] border-[#3d3d3d] p-8 text-center" data-testid="empty-campaigns">
            <Target className="w-8 h-8 text-gray-500 mx-auto mb-2" />
            <p className="text-sm text-gray-500">No campaigns recorded yet</p>
            <p className="text-xs text-gray-600 mt-1">Record your first campaign to start learning</p>
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-2">
            {campaigns.map((campaign) => {
              const isSelected = selectedId === campaign.id;
              return (
                <div key={campaign.id}>
                  <Card
                    className={cn(
                      'bg-[#252526] border-[#3d3d3d] p-3 cursor-pointer transition-colors hover:border-cyan-400/30',
                      isSelected && 'border-cyan-400/60'
                    )}
                    onClick={() => selectCampaign(campaign)}
                    data-testid={`card-campaign-${campaign.id}`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 min-w-0">
                        <Globe className="w-4 h-4 text-cyan-400 shrink-0" />
                        <span className="text-sm font-medium text-gray-200 truncate" data-testid={`text-domain-${campaign.id}`}>
                          {campaign.domain}
                        </span>
                        <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-[#3d3d3d] text-gray-400">
                          {campaign.industry}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <Badge
                          variant="outline"
                          className={cn('text-[10px] px-1.5 py-0', OUTCOME_STYLES[campaign.outcome])}
                          data-testid={`badge-outcome-${campaign.id}`}
                        >
                          {campaign.outcome}
                        </Badge>
                        {isSelected ? <ChevronUp className="w-3.5 h-3.5 text-gray-500" /> : <ChevronDown className="w-3.5 h-3.5 text-gray-500" />}
                      </div>
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                      <span className="flex items-center gap-1" data-testid={`text-findings-${campaign.id}`}>
                        <Shield className="w-3 h-3" />
                        {campaign.findingCount} findings
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {campaign.completedAt ? new Date(campaign.completedAt).toLocaleDateString() : 'N/A'}
                      </span>
                    </div>
                  </Card>

                  {isSelected && (
                    <Card className="bg-[#252526] border-[#3d3d3d] border-t-0 rounded-t-none p-3 space-y-3" data-testid={`card-similar-${campaign.id}`}>
                      <div className="flex items-center gap-2">
                        <Search className="w-4 h-4 text-purple-400" />
                        <span className="text-xs font-semibold text-gray-200">Similar Campaigns</span>
                      </div>
                      {similarLoading ? (
                        <div className="flex items-center gap-2 py-3" data-testid="loading-similar">
                          <Loader2 className="w-4 h-4 animate-spin text-purple-400" />
                          <span className="text-xs text-gray-500">Finding similar campaigns...</span>
                        </div>
                      ) : similarCampaigns.length === 0 ? (
                        <div className="py-3 text-center" data-testid="empty-similar">
                          <AlertTriangle className="w-4 h-4 text-gray-500 mx-auto mb-1" />
                          <p className="text-xs text-gray-500">No similar campaigns found</p>
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {similarCampaigns.map((sc, idx) => (
                            <div
                              key={sc.campaignId}
                              className="bg-[#1e1e1e] border border-[#3d3d3d] rounded p-2 space-y-2"
                              data-testid={`card-similar-item-${idx}`}
                            >
                              <div className="flex items-center justify-between">
                                <span className="text-xs font-medium text-gray-300 truncate">{sc.campaignId}</span>
                                <span className="text-xs font-bold text-cyan-400" data-testid={`text-similarity-${idx}`}>
                                  {sc.similarity}%
                                </span>
                              </div>
                              <div className="w-full bg-[#3d3d3d] rounded-full h-1.5">
                                <div
                                  className="bg-cyan-400 h-1.5 rounded-full transition-all"
                                  style={{ width: `${sc.similarity}%` }}
                                  data-testid={`progress-similarity-${idx}`}
                                />
                              </div>
                              {sc.sharedTechniques.length > 0 && (
                                <div className="flex flex-wrap gap-1">
                                  {sc.sharedTechniques.map((t, ti) => (
                                    <Badge
                                      key={ti}
                                      variant="outline"
                                      className="text-[9px] px-1 py-0 bg-purple-500/10 text-purple-400 border-purple-500/20"
                                      data-testid={`badge-technique-${idx}-${ti}`}
                                    >
                                      {t}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                              <span className="text-[10px] text-orange-400" data-testid={`text-unique-findings-${idx}`}>
                                {sc.uniqueFindings} unique findings
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </Card>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

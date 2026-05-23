import { useState, useEffect } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { FileText, Plus, Save, Trash2, Download, Send, DollarSign, TrendingUp, ArrowRight, Loader2, ChevronDown, ChevronUp } from 'lucide-react';

interface Report {
  id: string;
  title: string;
  severity: string;
  status: string;
  content: string;
  huntId?: string;
  createdAt: string;
  updatedAt?: string;
  savedOnce?: boolean;
}

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const VALID_STATUSES = ['draft', 'review', 'submitted'];

function sanitizeReport(raw: any): Report {
  return {
    id: String(raw?.id || `report_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`),
    title: String(raw?.title || 'Untitled Report'),
    severity: VALID_SEVERITIES.includes(raw?.severity) ? raw.severity : 'medium',
    status: VALID_STATUSES.includes(raw?.status) ? raw.status : 'draft',
    content: String(raw?.content || ''),
    huntId: raw?.huntId ? String(raw.huntId) : undefined,
    createdAt: raw?.createdAt || new Date().toISOString(),
    updatedAt: raw?.updatedAt || undefined,
    savedOnce: !!raw?.savedOnce,
  };
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

function getStatusColor(status: string) {
  switch (status) {
    case 'draft': return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    case 'review': return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'submitted': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return 'Unknown';
  try {
    const d = new Date(dateStr);
    return isNaN(d.getTime()) ? 'Unknown' : d.toLocaleDateString();
  } catch {
    return 'Unknown';
  }
}

function detectVulnType(title: string): string {
  const t = (title || '').toLowerCase();
  if (t.includes('xss')) return 'xss';
  if (t.includes('sql')) return 'sqli';
  if (t.includes('ssrf')) return 'ssrf';
  if (t.includes('idor')) return 'idor';
  if (t.includes('rce')) return 'rce';
  return 'xss';
}

export function DraftReports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [payoutData, setPayoutData] = useState<any>(null);
  const [payoutLoading, setPayoutLoading] = useState(false);
  const [showPayoutPanel, setShowPayoutPanel] = useState(false);

  useEffect(() => {
    fetchReports();
    const interval = setInterval(fetchReports, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchReports = async () => {
    try {
      const response = await fetch('/api/bounty/reports');
      if (!response.ok) {
        console.error('Failed to fetch reports:', response.status);
        return;
      }
      const data = await response.json();
      const rawList = Array.isArray(data?.reports) ? data.reports :
                      Array.isArray(data) ? data : [];
      setReports(rawList.map(sanitizeReport));
    } catch (error) {
      console.error('Failed to fetch reports:', error);
    }
  };

  const fetchPayoutTips = async (vulnType: string, severity: string) => {
    setPayoutLoading(true);
    try {
      const [framingRes, escalationRes, estimateRes] = await Promise.all([
        fetch(`/api/intelligence/payout/framing?vulnType=${encodeURIComponent(vulnType)}`),
        fetch(`/api/intelligence/payout/escalations?vulnType=${encodeURIComponent(vulnType)}`),
        fetch(`/api/intelligence/payout/estimate?program=${encodeURIComponent('default')}&severity=${encodeURIComponent(severity)}&impactType=${encodeURIComponent(vulnType)}`),
      ]);
      const [framing, escalation, estimate] = await Promise.all([
        framingRes.json(), escalationRes.json(), estimateRes.json(),
      ]);
      const framingItem = Array.isArray(framing?.data) ? framing.data[0] : framing?.data;
      const escalationItem = Array.isArray(escalation?.data) ? escalation.data[0] : escalation?.data;
      const estimateItem = estimate?.data || null;
      setPayoutData({
        framing: framing?.success ? framingItem : null,
        escalation: escalation?.success ? escalationItem : null,
        estimate: estimate?.success ? estimateItem : null,
      });
    } catch (err) {
      console.error('Failed to fetch payout tips:', err);
    } finally {
      setPayoutLoading(false);
    }
  };

  const selectedReport = reports.find(r => r.id === selectedId);

  useEffect(() => {
    if (selectedReport) {
      const vulnType = detectVulnType(selectedReport.title);
      fetchPayoutTips(vulnType, selectedReport.severity);
    }
  }, [selectedId]);

  const createNewReport = () => {
    const newReport: Report = {
      id: `report_${Date.now()}`,
      title: 'Untitled Report',
      severity: 'medium',
      status: 'draft',
      content: '',
      createdAt: new Date().toISOString(),
    };
    setReports(prev => [newReport, ...prev]);
    setSelectedId(newReport.id);
  };

  const updateReport = (field: keyof Report, value: string) => {
    setReports(prev => prev.map(r => {
      if (r.id !== selectedId) return r;
      return { ...r, [field]: value, updatedAt: new Date().toISOString() };
    }));
  };

  const saveReport = async () => {
    if (!selectedReport) return;
    setSaving(true);
    try {
      const isNew = !selectedReport.savedOnce;
      const url = isNew ? '/api/bounty/reports' : `/api/bounty/reports/${selectedReport.id}`;
      const method = isNew ? 'POST' : 'PUT';
      await csrfFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(selectedReport),
      });
    } catch (error) {
      console.error('Failed to save report:', error);
    } finally {
      setSaving(false);
    }
  };

  const exportReport = async (format: 'markdown' | 'json') => {
    if (!selectedReport) return;
    try {
      const response = await fetch(`/api/bounty/reports/${selectedReport.id}/export?format=${format}`);
      const data = await response.json();
      if (data.exported) {
        const blob = new Blob([typeof data.exported === 'string' ? data.exported : JSON.stringify(data.exported, null, 2)], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${(selectedReport.title || 'report').replace(/\s+/g, '-')}.${format === 'markdown' ? 'md' : 'json'}`;
        a.click();
        URL.revokeObjectURL(a.href);
      }
    } catch (error) {
      console.error('Export failed:', error);
    }
  };

  const exportPlatform = async (platform: 'hackerone' | 'bugcrowd' | 'intigriti') => {
    if (!selectedReport) return;
    try {
      const finding = {
        id: selectedReport.id,
        title: selectedReport.title,
        type: 'xss',
        severity: selectedReport.severity as any,
        description: selectedReport.content,
        stepsToReproduce: (selectedReport.content || '').split('\n').filter((l: string) => l.trim().startsWith('-') || l.trim().match(/^\d+\./)),
        impact: 'See report content',
        affectedEndpoint: selectedReport.huntId || 'N/A',
      };
      const response = await csrfFetch('/api/report-export/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding, options: { format: platform, includeRemediation: true } }),
      });
      const data = await response.json();
      if (data.success && data.data) {
        const content = typeof data.data === 'string' ? data.data : JSON.stringify(data.data, null, 2);
        const blob = new Blob([content], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${(selectedReport.title || 'report').replace(/\s+/g, '-')}-${platform}.json`;
        a.click();
        URL.revokeObjectURL(a.href);
      }
    } catch (error) {
      console.error('Platform export failed:', error);
    }
  };

  const deleteReport = (id: string) => {
    if (deleteConfirm === id) {
      setReports(prev => prev.filter(r => r.id !== id));
      if (selectedId === id) setSelectedId(null);
      setDeleteConfirm(null);
    } else {
      setDeleteConfirm(id);
      setTimeout(() => setDeleteConfirm(null), 3000);
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6">
      <div className="mb-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3 mb-2">
            <FileText className="w-6 h-6 text-cyan-400" />
            <h1 className="text-2xl font-bold text-gray-100">Draft Reports</h1>
          </div>
          <Button
            onClick={createNewReport}
            className="bg-cyan-600 hover:bg-cyan-700 text-white"
            data-testid="button-new-report"
          >
            <Plus className="w-4 h-4 mr-1" /> New Report
          </Button>
        </div>
        <p className="text-sm text-gray-400">Bug bounty report drafting interface</p>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        <Card className="bg-[#252526] border-[#3d3d3d] w-64 flex-shrink-0 flex flex-col">
          <ScrollArea className="flex-1">
            <div className="p-2 space-y-1">
              {reports.length === 0 ? (
                <p className="text-xs text-gray-500 p-3">No reports yet. Create one to get started.</p>
              ) : (
                reports.map(report => (
                  <button
                    key={report.id}
                    onClick={() => setSelectedId(report.id)}
                    className={`w-full text-left p-3 rounded transition-colors ${
                      selectedId === report.id
                        ? 'bg-cyan-600/20 border border-cyan-500/30'
                        : 'hover:bg-[#333] border border-transparent'
                    }`}
                    data-testid={`button-report-${report.id}`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <span className="text-sm text-gray-200 font-medium truncate">{report.title}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className={`text-[10px] ${getSeverityColor(report.severity)}`}>
                        {report.severity}
                      </Badge>
                      <Badge className={`text-[10px] ${getStatusColor(report.status)}`}>
                        {report.status}
                      </Badge>
                    </div>
                    <p className="text-[10px] text-gray-500 mt-1">
                      {formatDate(report.updatedAt || report.createdAt)}
                    </p>
                  </button>
                ))
              )}
            </div>
          </ScrollArea>
        </Card>

        <div className="flex-1 flex flex-col min-h-0">
          {!selectedReport ? (
            <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
              Select or create a report to start editing
            </div>
          ) : (
            <>
              <Card className="bg-[#252526] border-[#3d3d3d] p-4 mb-3 space-y-4">
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Title</Label>
                  <Input
                    value={selectedReport.title}
                    onChange={(e) => updateReport('title', e.target.value)}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-report-title"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs text-gray-400 mb-1 block">Severity</Label>
                    <Select value={selectedReport.severity || 'medium'} onValueChange={(v) => updateReport('severity', v)}>
                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-report-severity">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs text-gray-400 mb-1 block">Status</Label>
                    <Select value={selectedReport.status || 'draft'} onValueChange={(v) => updateReport('status', v)}>
                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-report-status">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="draft">Draft</SelectItem>
                        <SelectItem value="review">Review</SelectItem>
                        <SelectItem value="submitted">Submitted</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {selectedReport.huntId && (
                  <div className="flex items-center gap-2 text-xs text-cyan-400">
                    <span>Linked to hunt: {selectedReport.huntId}</span>
                  </div>
                )}
              </Card>

              <div className="flex-1 min-h-0 mb-3">
                <textarea
                  value={selectedReport.content}
                  onChange={(e) => updateReport('content', e.target.value)}
                  placeholder="Write your vulnerability report here...&#10;&#10;## Summary&#10;&#10;## Steps to Reproduce&#10;&#10;## Impact&#10;&#10;## Remediation"
                  className="w-full h-full bg-[#252526] border border-[#3d3d3d] rounded-md p-4 text-sm text-gray-200 font-mono resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 placeholder:text-gray-600"
                  data-testid="textarea-report-content"
                />
              </div>

              <div data-testid="payout-intelligence-panel" className="mb-3">
                <button
                  onClick={() => setShowPayoutPanel(!showPayoutPanel)}
                  className="w-full flex items-center justify-between p-3 bg-gray-800/50 border border-gray-700 rounded-md hover:bg-gray-800/70 transition-colors"
                  data-testid="button-toggle-payout-panel"
                >
                  <div className="flex items-center gap-2">
                    <DollarSign className="w-4 h-4 text-green-400" />
                    <span className="text-sm font-medium text-gray-200">Payout Intelligence</span>
                  </div>
                  {showPayoutPanel ? (
                    <ChevronUp className="w-4 h-4 text-gray-400" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-gray-400" />
                  )}
                </button>

                {showPayoutPanel && (
                  <div className="mt-2 space-y-3">
                    {payoutLoading ? (
                      <div className="flex items-center justify-center p-6 bg-gray-800/50 border border-gray-700 rounded-md">
                        <Loader2 className="w-5 h-5 text-cyan-400 animate-spin mr-2" />
                        <span className="text-sm text-gray-400">Loading payout intelligence...</span>
                      </div>
                    ) : (
                      <>
                        <Card className="bg-gray-800/50 border-gray-700 p-4" data-testid="payout-estimate">
                          <div className="flex items-center gap-2 mb-3">
                            <TrendingUp className="w-4 h-4 text-green-400" />
                            <span className="text-sm font-medium text-gray-200">Estimated Payout</span>
                          </div>
                          {payoutData?.estimate ? (
                            <div className="grid grid-cols-3 gap-3">
                              <div className="bg-[#1e1e1e] rounded-md p-3 text-center">
                                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Median</p>
                                <p className="text-lg font-bold text-green-400">${payoutData.estimate.median ?? payoutData.estimate.estimatedPayout?.median ?? 'N/A'}</p>
                              </div>
                              <div className="bg-[#1e1e1e] rounded-md p-3 text-center">
                                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">P75</p>
                                <p className="text-lg font-bold text-yellow-400">${payoutData.estimate.p75 ?? payoutData.estimate.estimatedPayout?.p75 ?? 'N/A'}</p>
                              </div>
                              <div className="bg-[#1e1e1e] rounded-md p-3 text-center">
                                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">P95</p>
                                <p className="text-lg font-bold text-red-400">${payoutData.estimate.p95 ?? payoutData.estimate.estimatedPayout?.p95 ?? 'N/A'}</p>
                              </div>
                            </div>
                          ) : (
                            <p className="text-xs text-gray-500">No estimate data available</p>
                          )}
                        </Card>

                        <Card className="bg-gray-800/50 border-gray-700 p-4">
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-2">
                              <DollarSign className="w-4 h-4 text-yellow-400" />
                              <span className="text-sm font-medium text-gray-200">Impact Framing</span>
                            </div>
                            {payoutData?.framing?.highValueFraming && (
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs bg-[#1e1e1e] border-gray-600 text-gray-300 hover:bg-gray-700"
                                onClick={() => navigator.clipboard.writeText(payoutData.framing.highValueFraming)}
                                data-testid="button-copy-framing"
                              >
                                Copy Framing
                              </Button>
                            )}
                          </div>
                          {payoutData?.framing?.highValueFraming ? (
                            <p className="text-sm text-gray-300 bg-[#1e1e1e] rounded-md p-3 leading-relaxed">
                              {payoutData.framing.highValueFraming}
                            </p>
                          ) : (
                            <p className="text-xs text-gray-500">No framing data available</p>
                          )}
                        </Card>

                        <Card className="bg-gray-800/50 border-gray-700 p-4">
                          <div className="flex items-center gap-2 mb-3">
                            <ArrowRight className="w-4 h-4 text-cyan-400" />
                            <span className="text-sm font-medium text-gray-200">Escalation Chain</span>
                          </div>
                          {payoutData?.escalation?.chain && payoutData.escalation.chain.length > 0 ? (
                            <div className="space-y-2">
                              <div className="flex items-center flex-wrap gap-1">
                                {payoutData.escalation.chain.map((step: any, idx: number) => (
                                  <div key={idx} className="flex items-center gap-1">
                                    <span className="text-xs bg-[#1e1e1e] border border-gray-600 rounded px-2 py-1 text-gray-300">
                                      {typeof step === 'string' ? step : step?.step || step?.action || JSON.stringify(step)}
                                    </span>
                                    {idx < payoutData.escalation.chain.length - 1 && (
                                      <ArrowRight className="w-3 h-3 text-gray-500" />
                                    )}
                                  </div>
                                ))}
                              </div>
                              <div className="flex items-center gap-3 mt-2">
                                {payoutData.escalation.difficulty && (
                                  <Badge className={`text-[10px] ${
                                    payoutData.escalation.difficulty === 'hard' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                    payoutData.escalation.difficulty === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                                    'bg-green-500/20 text-green-400 border-green-500/30'
                                  }`}>
                                    {payoutData.escalation.difficulty}
                                  </Badge>
                                )}
                                {payoutData.escalation.payoutMultiplier && (
                                  <span className="text-xs text-green-400 font-medium">
                                    {payoutData.escalation.payoutMultiplier}x payout multiplier
                                  </span>
                                )}
                              </div>
                            </div>
                          ) : (
                            <p className="text-xs text-gray-500">No escalation chain available</p>
                          )}
                        </Card>
                      </>
                    )}
                  </div>
                )}
              </div>

              <div className="flex items-center justify-between">
                <div className="flex gap-2">
                  <Button
                    onClick={saveReport}
                    disabled={saving}
                    className="bg-cyan-600 hover:bg-cyan-700 text-white"
                    data-testid="button-save-report"
                  >
                    <Save className="w-4 h-4 mr-1" />
                    {saving ? 'Saving...' : 'Save'}
                  </Button>
                  <Button
                    onClick={() => exportReport('markdown')}
                    variant="outline"
                    className="bg-[#252526] border-[#3d3d3d] text-gray-300 hover:bg-[#333]"
                    data-testid="button-export-markdown"
                  >
                    <Download className="w-4 h-4 mr-1" /> Markdown
                  </Button>
                  <Button
                    onClick={() => exportReport('json')}
                    variant="outline"
                    className="bg-[#252526] border-[#3d3d3d] text-gray-300 hover:bg-[#333]"
                    data-testid="button-export-json"
                  >
                    <Download className="w-4 h-4 mr-1" /> JSON
                  </Button>
                  <Button
                    onClick={() => exportPlatform('hackerone')}
                    variant="outline"
                    className="bg-[#252526] border-[#3d3d3d] text-emerald-400 hover:bg-emerald-600/20"
                    data-testid="button-export-hackerone"
                  >
                    <Send className="w-4 h-4 mr-1" /> H1
                  </Button>
                  <Button
                    onClick={() => exportPlatform('bugcrowd')}
                    variant="outline"
                    className="bg-[#252526] border-[#3d3d3d] text-orange-400 hover:bg-orange-600/20"
                    data-testid="button-export-bugcrowd"
                  >
                    <Send className="w-4 h-4 mr-1" /> BC
                  </Button>
                  <Button
                    onClick={() => exportPlatform('intigriti')}
                    variant="outline"
                    className="bg-[#252526] border-[#3d3d3d] text-blue-400 hover:bg-blue-600/20"
                    data-testid="button-export-intigriti"
                  >
                    <Send className="w-4 h-4 mr-1" /> IG
                  </Button>
                </div>
                <Button
                  onClick={() => selectedReport && deleteReport(selectedReport.id)}
                  variant="ghost"
                  className={`text-red-400 hover:bg-red-600/20 ${deleteConfirm === selectedReport.id ? 'bg-red-600/30' : ''}`}
                  data-testid="button-delete-report"
                >
                  <Trash2 className="w-4 h-4 mr-1" />
                  {deleteConfirm === selectedReport.id ? 'Confirm Delete' : 'Delete'}
                </Button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

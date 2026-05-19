import { useState, useEffect } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Plus, Trash2, Edit3, X, Send, DollarSign, FileText, TrendingUp, CheckCircle, Clock } from 'lucide-react';

interface Submission {
  id: string;
  hunt_id?: string;
  platform: string;
  title: string;
  severity: string;
  status: string;
  payout: number;
  description: string;
  resolution?: string;
  createdAt: string;
}

const PLATFORMS = ['HackerOne', 'Bugcrowd', 'Intigriti', 'YesWeHack', 'Other'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const STATUSES = ['draft', 'submitted', 'triaged', 'accepted', 'resolved', 'duplicate', 'informative'];

function getPlatformColor(platform: string): string {
  switch (platform.toLowerCase()) {
    case 'hackerone': return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'bugcrowd': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'intigriti': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'yeswehack': return 'bg-green-500/20 text-green-400 border-green-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'info': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

function getStatusColor(status: string): string {
  switch (status) {
    case 'draft': return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    case 'submitted': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'triaged': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'accepted': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'resolved': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
    case 'duplicate': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'informative': return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

export function Submissions() {
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [formData, setFormData] = useState({
    hunt_id: '',
    platform: 'HackerOne',
    title: '',
    severity: 'medium',
    payout: 0,
    description: '',
  });
  const [editData, setEditData] = useState({
    status: '',
    payout: 0,
    resolution: '',
  });
  const [triageEstimates, setTriageEstimates] = useState<Record<string, { estimatedDays: number; confidence: number }>>({});

  useEffect(() => {
    fetchSubmissions();
  }, []);

  const fetchTriageEstimate = async (submission: Submission) => {
    try {
      const res = await fetch(`/api/intelligence/triage/predict?program=${encodeURIComponent(submission.platform.toLowerCase())}&severity=${encodeURIComponent(submission.severity)}&quality=${encodeURIComponent('0.7')}`);
      const data = await res.json();
      if (data.success && data.data) {
        setTriageEstimates(prev => ({
          ...prev,
          [submission.id]: { estimatedDays: data.data.estimatedDays, confidence: data.data.confidence },
        }));
      }
    } catch (err) {
      console.error('Failed to fetch triage estimate:', err);
    }
  };

  useEffect(() => {
    submissions
      .filter(s => s.status === 'submitted' || s.status === 'triaged')
      .forEach(s => {
        if (!triageEstimates[s.id]) fetchTriageEstimate(s);
      });
  }, [submissions]);

  const fetchSubmissions = async () => {
    try {
      const response = await fetch('/api/bounty/submissions');
      const data = await response.json();
      if (data.success) {
        setSubmissions(data.submissions || []);
      }
    } catch (error) {
      console.error('Failed to fetch submissions:', error);
    }
  };

  const createSubmission = async () => {
    if (!formData.title || !formData.platform) return;
    try {
      const response = await csrfFetch('/api/bounty/submissions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (data.success) {
        setShowForm(false);
        setFormData({ hunt_id: '', platform: 'HackerOne', title: '', severity: 'medium', payout: 0, description: '' });
        fetchSubmissions();
      }
    } catch (error) {
      console.error('Failed to create submission:', error);
    }
  };

  const updateSubmission = async (id: string) => {
    try {
      const response = await csrfFetch(`/api/bounty/submissions/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editData),
      });
      const data = await response.json();
      if (data.success) {
        setEditingId(null);
        fetchSubmissions();
      }
    } catch (error) {
      console.error('Failed to update submission:', error);
    }
  };

  const deleteSubmission = async (id: string) => {
    try {
      const response = await csrfFetch(`/api/bounty/submissions/${id}`, { method: 'DELETE' });
      const data = await response.json();
      if (data.success) {
        setDeleteConfirmId(null);
        fetchSubmissions();
      }
    } catch (error) {
      console.error('Failed to delete submission:', error);
    }
  };

  const totalSubmissions = submissions.length;
  const acceptedCount = submissions.filter(s => s.status === 'accepted' || s.status === 'resolved').length;
  const totalPayouts = submissions.reduce((sum, s) => sum + (s.payout || 0), 0);
  const avgPayout = totalSubmissions > 0 ? totalPayouts / totalSubmissions : 0;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <ScrollArea className="flex-1">
        <div className="p-6">
          <div className="mb-6">
            <div className="flex items-center gap-3 mb-2">
              <Send className="w-6 h-6 text-cyan-400" />
              <h1 className="text-2xl font-bold text-gray-100">Submissions</h1>
            </div>
            <p className="text-sm text-gray-400">Track bug bounty submissions across platforms</p>
          </div>

          <div className="grid grid-cols-4 gap-3 mb-6">
            <Card className="bg-[#252526] border-[#3d3d3d] p-4">
              <div className="flex items-center gap-2 mb-1">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span className="text-xs text-gray-400">Total</span>
              </div>
              <span className="text-2xl font-bold text-gray-200" data-testid="text-total-submissions">{totalSubmissions}</span>
            </Card>
            <Card className="bg-[#252526] border-[#3d3d3d] p-4">
              <div className="flex items-center gap-2 mb-1">
                <CheckCircle className="w-4 h-4 text-green-400" />
                <span className="text-xs text-gray-400">Accepted</span>
              </div>
              <span className="text-2xl font-bold text-gray-200" data-testid="text-accepted-count">{acceptedCount}</span>
            </Card>
            <Card className="bg-[#252526] border-[#3d3d3d] p-4">
              <div className="flex items-center gap-2 mb-1">
                <DollarSign className="w-4 h-4 text-green-400" />
                <span className="text-xs text-gray-400">Total Payouts</span>
              </div>
              <span className="text-2xl font-bold text-gray-200" data-testid="text-total-payouts">${totalPayouts.toLocaleString()}</span>
            </Card>
            <Card className="bg-[#252526] border-[#3d3d3d] p-4">
              <div className="flex items-center gap-2 mb-1">
                <TrendingUp className="w-4 h-4 text-purple-400" />
                <span className="text-xs text-gray-400">Avg Payout</span>
              </div>
              <span className="text-2xl font-bold text-gray-200" data-testid="text-avg-payout">${avgPayout.toFixed(0)}</span>
            </Card>
          </div>

          <div className="flex justify-end mb-4">
            <Button
              onClick={() => setShowForm(!showForm)}
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              data-testid="button-new-submission"
            >
              {showForm ? <X className="w-4 h-4 mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
              {showForm ? 'Cancel' : 'New Submission'}
            </Button>
          </div>

          {showForm && (
            <Card className="bg-[#252526] border-[#3d3d3d] p-6 mb-6">
              <h3 className="text-sm font-semibold text-gray-200 mb-4">New Submission</h3>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs text-gray-400 mb-2">Platform</Label>
                    <Select value={formData.platform} onValueChange={(v) => setFormData({ ...formData, platform: v })}>
                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10" data-testid="select-platform">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {PLATFORMS.map(p => (
                          <SelectItem key={p} value={p}>{p}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs text-gray-400 mb-2">Severity</Label>
                    <Select value={formData.severity} onValueChange={(v) => setFormData({ ...formData, severity: v })}>
                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10" data-testid="select-severity">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITIES.map(s => (
                          <SelectItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Title</Label>
                  <Input
                    placeholder="Submission title..."
                    value={formData.title}
                    onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                    data-testid="input-title"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Description</Label>
                  <Textarea
                    placeholder="Describe the vulnerability..."
                    value={formData.description}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 min-h-[100px]"
                    data-testid="input-description"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Payout ($)</Label>
                  <Input
                    type="number"
                    placeholder="0"
                    value={formData.payout || ''}
                    onChange={(e) => setFormData({ ...formData, payout: Number(e.target.value) })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                    data-testid="input-payout"
                  />
                </div>
                <Button
                  onClick={createSubmission}
                  disabled={!formData.title}
                  className="w-full bg-cyan-600 hover:bg-cyan-700 text-white h-10"
                  data-testid="button-submit-new"
                >
                  <Send className="w-4 h-4 mr-2" />
                  Create Submission
                </Button>
              </div>
            </Card>
          )}

          <div className="space-y-3">
            {submissions.length === 0 ? (
              <div className="text-center py-16 text-gray-500 text-sm" data-testid="text-no-submissions">
                No submissions yet. Create your first submission above.
              </div>
            ) : (
              submissions.map(sub => (
                <Card
                  key={sub.id}
                  className="bg-[#252526] border-[#3d3d3d] p-4"
                  data-testid={`card-submission-${sub.id}`}
                >
                  {editingId === sub.id ? (
                    <div className="space-y-3">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-semibold text-gray-200">{sub.title}</h4>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setEditingId(null)}
                          className="text-gray-400 hover:text-gray-200"
                          data-testid={`button-cancel-edit-${sub.id}`}
                        >
                          <X className="w-4 h-4" />
                        </Button>
                      </div>
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <Label className="text-xs text-gray-400 mb-1">Status</Label>
                          <Select value={editData.status} onValueChange={(v) => setEditData({ ...editData, status: v })}>
                            <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid={`select-edit-status-${sub.id}`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {STATUSES.map(s => (
                                <SelectItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <div>
                          <Label className="text-xs text-gray-400 mb-1">Payout ($)</Label>
                          <Input
                            type="number"
                            value={editData.payout || ''}
                            onChange={(e) => setEditData({ ...editData, payout: Number(e.target.value) })}
                            className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                            data-testid={`input-edit-payout-${sub.id}`}
                          />
                        </div>
                      </div>
                      <div>
                        <Label className="text-xs text-gray-400 mb-1">Resolution</Label>
                        <Input
                          placeholder="Resolution notes..."
                          value={editData.resolution}
                          onChange={(e) => setEditData({ ...editData, resolution: e.target.value })}
                          className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                          data-testid={`input-edit-resolution-${sub.id}`}
                        />
                      </div>
                      <Button
                        onClick={() => updateSubmission(sub.id)}
                        className="bg-cyan-600 hover:bg-cyan-700 text-white h-9"
                        data-testid={`button-save-edit-${sub.id}`}
                      >
                        Save Changes
                      </Button>
                    </div>
                  ) : (
                    <div>
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex-1">
                          <h4 className="font-semibold text-gray-200 mb-1">{sub.title}</h4>
                          {sub.description && (
                            <p className="text-xs text-gray-400 mb-2 line-clamp-2">{sub.description}</p>
                          )}
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge className={getPlatformColor(sub.platform)}>{sub.platform}</Badge>
                            <Badge className={getSeverityColor(sub.severity)}>{sub.severity}</Badge>
                            <Badge className={getStatusColor(sub.status)}>{sub.status}</Badge>
                            {triageEstimates[sub.id] && (
                              <div className="flex items-center gap-1 text-xs text-gray-400" data-testid={`triage-estimate-${sub.id}`}>
                                <span className={`w-2 h-2 rounded-full ${triageEstimates[sub.id].estimatedDays <= 3 ? 'bg-green-400' : triageEstimates[sub.id].estimatedDays <= 7 ? 'bg-yellow-400' : 'bg-red-400'}`} />
                                <Clock className="w-3 h-3" />
                                <span>~{triageEstimates[sub.id].estimatedDays}d triage</span>
                                <span className="text-gray-500">({Math.round(triageEstimates[sub.id].confidence * 100)}%)</span>
                              </div>
                            )}
                            {sub.payout > 0 && (
                              <span className="text-sm font-semibold text-green-400" data-testid={`text-payout-${sub.id}`}>
                                ${sub.payout.toLocaleString()}
                              </span>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-1 ml-3">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setEditingId(sub.id);
                              setEditData({ status: sub.status, payout: sub.payout, resolution: sub.resolution || '' });
                            }}
                            className="text-gray-400 hover:text-cyan-400 h-8 w-8 p-0"
                            data-testid={`button-edit-${sub.id}`}
                          >
                            <Edit3 className="w-4 h-4" />
                          </Button>
                          {deleteConfirmId === sub.id ? (
                            <div className="flex items-center gap-1">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => deleteSubmission(sub.id)}
                                className="text-red-400 hover:text-red-300 h-8 px-2 text-xs"
                                data-testid={`button-confirm-delete-${sub.id}`}
                              >
                                Confirm
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => setDeleteConfirmId(null)}
                                className="text-gray-400 hover:text-gray-200 h-8 w-8 p-0"
                                data-testid={`button-cancel-delete-${sub.id}`}
                              >
                                <X className="w-4 h-4" />
                              </Button>
                            </div>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setDeleteConfirmId(sub.id)}
                              className="text-gray-400 hover:text-red-400 h-8 w-8 p-0"
                              data-testid={`button-delete-${sub.id}`}
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          )}
                        </div>
                      </div>
                      <div className="text-xs text-gray-500 mt-2">
                        {new Date(sub.createdAt).toLocaleDateString()} {new Date(sub.createdAt).toLocaleTimeString()}
                      </div>
                    </div>
                  )}
                </Card>
              ))
            )}
          </div>
        </div>
      </ScrollArea>
    </div>
  );
}
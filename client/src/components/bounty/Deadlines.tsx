import { useState, useEffect } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Plus, Trash2, X, Clock, CheckCircle, AlertTriangle, ChevronDown, ChevronUp, Calendar } from 'lucide-react';

interface Deadline {
  id: string;
  huntId?: string;
  title: string;
  deadline: string;
  reminderHours: number;
  status: string;
  createdAt: string;
}

function getTimeRemaining(deadline: string): { days: number; hours: number; minutes: number; total: number } {
  const diff = new Date(deadline).getTime() - Date.now();
  if (diff <= 0) return { days: 0, hours: 0, minutes: 0, total: 0 };
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  return { days, hours, minutes, total: diff };
}

function getProgress(createdAt: string, deadline: string): number {
  const start = new Date(createdAt).getTime();
  const end = new Date(deadline).getTime();
  const now = Date.now();
  const total = end - start;
  if (total <= 0) return 100;
  const elapsed = now - start;
  return Math.min(100, Math.max(0, (elapsed / total) * 100));
}

function getUrgencyClass(deadline: string, status: string): string {
  if (status === 'completed' || status === 'expired') return '';
  const diff = new Date(deadline).getTime() - Date.now();
  if (diff <= 0) return '';
  if (diff < 24 * 60 * 60 * 1000) return 'ring-1 ring-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.2)]';
  if (diff < 72 * 60 * 60 * 1000) return 'ring-1 ring-orange-500/30 shadow-[0_0_10px_rgba(249,115,22,0.15)]';
  return '';
}

function getStatusBadge(status: string): { color: string; label: string } {
  switch (status) {
    case 'active': return { color: 'bg-green-500/20 text-green-400 border-green-500/30', label: 'Active' };
    case 'expired': return { color: 'bg-red-500/20 text-red-400 border-red-500/30', label: 'Expired' };
    case 'completed': return { color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', label: 'Completed' };
    default: return { color: 'bg-gray-500/20 text-gray-400 border-gray-500/30', label: status };
  }
}

export function Deadlines() {
  const [deadlines, setDeadlines] = useState<Deadline[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [showExpired, setShowExpired] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [, setTick] = useState(0);
  const [formData, setFormData] = useState({
    title: '',
    deadline: '',
    reminderHours: 24,
    hunt_id: '',
  });

  useEffect(() => {
    fetchDeadlines();
  }, []);

  useEffect(() => {
    const interval = setInterval(() => setTick(t => t + 1), 60000);
    return () => clearInterval(interval);
  }, []);

  const fetchDeadlines = async () => {
    try {
      const response = await fetch('/api/bounty/deadlines');
      const data = await response.json();
      if (data.success) {
        setDeadlines(data.deadlines || []);
      }
    } catch (error) {
      console.error('Failed to fetch deadlines:', error);
    }
  };

  const createDeadline = async () => {
    if (!formData.title || !formData.deadline) return;
    try {
      const response = await csrfFetch('/api/bounty/deadlines', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (data.success) {
        setShowForm(false);
        setFormData({ title: '', deadline: '', reminderHours: 24, hunt_id: '' });
        fetchDeadlines();
      }
    } catch (error) {
      console.error('Failed to create deadline:', error);
    }
  };

  const markComplete = async (id: string) => {
    try {
      const response = await csrfFetch(`/api/bounty/deadlines/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'completed' }),
      });
      const data = await response.json();
      if (data.success) {
        fetchDeadlines();
      }
    } catch (error) {
      console.error('Failed to mark complete:', error);
    }
  };

  const deleteDeadline = async (id: string) => {
    try {
      const response = await csrfFetch(`/api/bounty/deadlines/${id}`, { method: 'DELETE' });
      const data = await response.json();
      if (data.success) {
        setDeleteConfirmId(null);
        fetchDeadlines();
      }
    } catch (error) {
      console.error('Failed to delete deadline:', error);
    }
  };

  const activeDeadlines = deadlines
    .filter(d => d.status === 'active')
    .sort((a, b) => new Date(a.deadline).getTime() - new Date(b.deadline).getTime());

  const expiredDeadlines = deadlines.filter(d => d.status === 'expired' || d.status === 'completed');

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <ScrollArea className="flex-1">
        <div className="p-6">
          <div className="mb-6">
            <div className="flex items-center gap-3 mb-2">
              <Calendar className="w-6 h-6 text-cyan-400" />
              <h1 className="text-2xl font-bold text-gray-100">Deadlines</h1>
            </div>
            <p className="text-sm text-gray-400">Track bounty deadlines with countdown timers</p>
          </div>

          <div className="flex justify-end mb-4">
            <Button
              onClick={() => setShowForm(!showForm)}
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              data-testid="button-add-deadline"
            >
              {showForm ? <X className="w-4 h-4 mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
              {showForm ? 'Cancel' : 'Add Deadline'}
            </Button>
          </div>

          {showForm && (
            <Card className="bg-[#252526] border-[#3d3d3d] p-6 mb-6">
              <h3 className="text-sm font-semibold text-gray-200 mb-4">New Deadline</h3>
              <div className="space-y-4">
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Title</Label>
                  <Input
                    placeholder="Deadline title..."
                    value={formData.title}
                    onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                    data-testid="input-deadline-title"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Deadline</Label>
                  <Input
                    type="datetime-local"
                    value={formData.deadline}
                    onChange={(e) => setFormData({ ...formData, deadline: e.target.value })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                    data-testid="input-deadline-date"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-2">Reminder (hours before)</Label>
                  <Input
                    type="number"
                    value={formData.reminderHours}
                    onChange={(e) => setFormData({ ...formData, reminderHours: Number(e.target.value) })}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-10"
                    data-testid="input-reminder-hours"
                  />
                </div>
                <Button
                  onClick={createDeadline}
                  disabled={!formData.title || !formData.deadline}
                  className="w-full bg-cyan-600 hover:bg-cyan-700 text-white h-10"
                  data-testid="button-submit-deadline"
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Create Deadline
                </Button>
              </div>
            </Card>
          )}

          <div className="space-y-3 mb-6">
            {activeDeadlines.length === 0 && expiredDeadlines.length === 0 ? (
              <div className="text-center py-16 text-gray-500 text-sm" data-testid="text-no-deadlines">
                No deadlines set. Add one above to start tracking.
              </div>
            ) : (
              activeDeadlines.map(dl => {
                const remaining = getTimeRemaining(dl.deadline);
                const progress = getProgress(dl.createdAt, dl.deadline);
                const statusInfo = getStatusBadge(dl.status);
                const urgencyClass = getUrgencyClass(dl.deadline, dl.status);

                return (
                  <Card
                    key={dl.id}
                    className={`bg-[#252526] border-[#3d3d3d] p-4 ${urgencyClass}`}
                    data-testid={`card-deadline-${dl.id}`}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h4 className="font-semibold text-gray-200 mb-1">{dl.title}</h4>
                        {dl.huntId && (
                          <span className="text-xs text-cyan-400">Hunt: {dl.huntId}</span>
                        )}
                      </div>
                      <Badge className={statusInfo.color}>{statusInfo.label}</Badge>
                    </div>

                    <div className="flex items-center gap-4 mb-3">
                      <div className="flex items-center gap-6 bg-[#1e1e1e] rounded px-4 py-2 border border-[#3d3d3d]">
                        <div className="text-center">
                          <span className={`text-2xl font-bold ${remaining.total < 24 * 60 * 60 * 1000 ? 'text-red-400' : remaining.total < 72 * 60 * 60 * 1000 ? 'text-orange-400' : 'text-cyan-400'}`} data-testid={`text-days-${dl.id}`}>
                            {remaining.days}
                          </span>
                          <p className="text-[10px] text-gray-500">DAYS</p>
                        </div>
                        <div className="text-center">
                          <span className={`text-2xl font-bold ${remaining.total < 24 * 60 * 60 * 1000 ? 'text-red-400' : remaining.total < 72 * 60 * 60 * 1000 ? 'text-orange-400' : 'text-cyan-400'}`} data-testid={`text-hours-${dl.id}`}>
                            {remaining.hours}
                          </span>
                          <p className="text-[10px] text-gray-500">HRS</p>
                        </div>
                        <div className="text-center">
                          <span className={`text-2xl font-bold ${remaining.total < 24 * 60 * 60 * 1000 ? 'text-red-400' : remaining.total < 72 * 60 * 60 * 1000 ? 'text-orange-400' : 'text-cyan-400'}`} data-testid={`text-minutes-${dl.id}`}>
                            {remaining.minutes}
                          </span>
                          <p className="text-[10px] text-gray-500">MIN</p>
                        </div>
                      </div>
                    </div>

                    <div className="mb-3">
                      <div className="flex items-center justify-between text-xs text-gray-500 mb-1">
                        <span>Progress</span>
                        <span>{progress.toFixed(0)}% elapsed</span>
                      </div>
                      <div className="w-full h-2 bg-[#1e1e1e] rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all ${
                            progress > 90 ? 'bg-red-400' : progress > 75 ? 'bg-orange-400' : 'bg-cyan-400'
                          }`}
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => markComplete(dl.id)}
                        className="bg-[#1e1e1e] border-[#3d3d3d] text-green-400 hover:text-green-300 hover:bg-[#333] h-8 text-xs"
                        data-testid={`button-complete-${dl.id}`}
                      >
                        <CheckCircle className="w-3.5 h-3.5 mr-1" />
                        Mark Complete
                      </Button>
                      {deleteConfirmId === dl.id ? (
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteDeadline(dl.id)}
                            className="text-red-400 hover:text-red-300 h-8 px-2 text-xs"
                            data-testid={`button-confirm-delete-${dl.id}`}
                          >
                            Confirm Delete
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setDeleteConfirmId(null)}
                            className="text-gray-400 hover:text-gray-200 h-8 w-8 p-0"
                            data-testid={`button-cancel-delete-${dl.id}`}
                          >
                            <X className="w-4 h-4" />
                          </Button>
                        </div>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setDeleteConfirmId(dl.id)}
                          className="text-gray-400 hover:text-red-400 h-8 w-8 p-0"
                          data-testid={`button-delete-${dl.id}`}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      )}
                      <span className="text-xs text-gray-500 ml-auto">
                        Due: {new Date(dl.deadline).toLocaleString()}
                      </span>
                    </div>
                  </Card>
                );
              })
            )}
          </div>

          {expiredDeadlines.length > 0 && (
            <div>
              <button
                onClick={() => setShowExpired(!showExpired)}
                className="flex items-center gap-2 text-sm text-gray-400 hover:text-gray-300 mb-3 w-full"
                data-testid="button-toggle-expired"
              >
                {showExpired ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                <span>Expired / Completed ({expiredDeadlines.length})</span>
              </button>
              {showExpired && (
                <div className="space-y-3 opacity-60">
                  {expiredDeadlines.map(dl => {
                    const statusInfo = getStatusBadge(dl.status);
                    return (
                      <Card
                        key={dl.id}
                        className="bg-[#252526] border-[#3d3d3d] p-4"
                        data-testid={`card-deadline-expired-${dl.id}`}
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <h4 className="font-semibold text-gray-400">{dl.title}</h4>
                            <span className="text-xs text-gray-500">
                              {dl.status === 'completed' ? 'Completed' : 'Expired'}: {new Date(dl.deadline).toLocaleDateString()}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge className={statusInfo.color}>{statusInfo.label}</Badge>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => deleteDeadline(dl.id)}
                              className="text-gray-500 hover:text-red-400 h-8 w-8 p-0"
                              data-testid={`button-delete-expired-${dl.id}`}
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>
                      </Card>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
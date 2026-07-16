import { useState, useEffect, useCallback } from 'react';
import { csrfFetch } from '@/services/api';
import { bountyAPI } from '../../lib/api';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Shield, RefreshCw, ExternalLink, CheckCircle2, XCircle, Clock,
  DollarSign, Timer, ThumbsUp, ThumbsDown, AlertTriangle, Link2Off, X,
} from 'lucide-react';
import toast from 'react-hot-toast';

// Same Program shape Programs.tsx uses — this panel reads from the same
// DB-backed /api/bounty/programs endpoint ScopeGuard/hunts actually use,
// not the disconnected file-based bounty-intelligence.ts program store.
interface Program {
  id: number;
  name: string;
  platform: string;
  programHandle?: string;
  scope: string[];
  outOfScope: string[];
  maxPayout: number;
  avgPayout: number;
  responseTime: number;
  roiScore: number;
  active: boolean;
  lastHunted?: string | null;
}

interface Submission {
  id: string;
  platform: string;
  title: string;
  severity: string;
  status: string;
  description?: string;
  createdAt: string;
  targetUrl?: string;
  programHandle?: string;
  reportUrl?: string;
  reportId?: string;
  error?: string;
}

// Matches server/src/intelligence/TargetSelection.ts's ProgramScore
interface ProgramScore {
  programId: number;
  name: string;
  platform: string;
  roiScore: number;
  avgPayout: number;
  responseTime: number;
  competitionLevel: 'low' | 'medium' | 'high';
  rank: number;
  notes: string[];
}

interface SyncResult {
  total: number;
  added: string[];
  alreadyTracked: number;
  skippedNoRealScope: string[];
  failed: string[];
  disabled?: boolean;
}

function isHackerOne(platform: string): boolean {
  return platform.toLowerCase() === 'hackerone';
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

function getStatusColor(status: string): string {
  switch (status) {
    case 'pending_review': return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    case 'submitted': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'accepted': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'rejected': return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    case 'failed': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

export function HackerOneDashboard() {
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [programs, setPrograms] = useState<Program[]>([]);
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [rankings, setRankings] = useState<ProgramScore[]>([]);
  const [rankingLoading, setRankingLoading] = useState(false);
  const [reviewingId, setReviewingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [settingsRes, programsRes, submissionsRes] = await Promise.all([
        csrfFetch('/api/settings').then(r => r.json()),
        bountyAPI.getPrograms(),
        csrfFetch('/api/bounty/submissions').then(r => r.json()),
      ]);
      setSettings(settingsRes || {});
      setPrograms((programsRes.data as Program[]).filter(p => isHackerOne(p.platform)));
      setSubmissions(((submissionsRes.submissions || []) as Submission[]).filter(s => isHackerOne(s.platform)));
    } catch {
      toast.error('Failed to load HackerOne data');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRankings = useCallback(async () => {
    setRankingLoading(true);
    try {
      const res = await bountyAPI.rankPrograms();
      setRankings((res.data as ProgramScore[]).filter(s => isHackerOne(s.platform)));
    } catch {
      toast.error('Failed to load recommendations');
    } finally {
      setRankingLoading(false);
    }
  }, []);

  useEffect(() => { load(); loadRankings(); }, [load, loadRankings]);

  const connected = settings['HACKERONE_ENABLED'] !== 'false';
  // Non-secret settings are returned verbatim, secrets masked to "****1234"
  // (or blank when unset) — either shape means SOMETHING is configured.
  const hasCredentials = Boolean(settings['HACKERONE_USERNAME']) && Boolean(settings['HACKERONE_TOKEN']);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const res = await bountyAPI.syncHackerOne();
      const result = res.data as SyncResult;
      const skipped = result.skippedNoRealScope?.length ?? 0;
      let skipToastShown = false;
      if (result.disabled) {
        toast.error('HackerOne is disconnected — reconnect it in Settings first');
      } else if (result.added.length > 0) {
        toast.success(`Synced ${result.added.length} new program(s) from your HackerOne account`);
      } else if (result.total === 0) {
        toast('No accessible programs found — check your HackerOne credentials', { icon: 'ℹ️' });
      } else if (skipped > 0 && result.alreadyTracked === 0) {
        // Nothing added AND nothing was already tracked — every newly-
        // discovered program was skipped for lacking real scope. Calling
        // this "up to date" would be misleading, since nothing synced.
        toast.error(`Sync found ${skipped} new program(s) but none had real scope data — check your HackerOne credentials`);
        skipToastShown = true;
      } else {
        toast.success(`Up to date — ${result.alreadyTracked} program(s) already tracked`);
      }
      if (skipped > 0 && !skipToastShown) {
        toast(`Skipped ${skipped} program(s) — no real scope data returned by HackerOne (check credentials, try again later)`, { icon: '⚠️' });
      }
      if (result.failed.length > 0) {
        toast.error(`Failed to fetch scope for: ${result.failed.join(', ')}`);
      }
      await load();
    } catch {
      toast.error('Sync failed');
    } finally {
      setSyncing(false);
    }
  };

  const approveSubmission = async (id: string) => {
    try {
      const res = await csrfFetch(`/api/bounty/submissions/${id}/approve`, { method: 'POST' });
      const data = await res.json();
      if (!data.success) toast.error(data.result?.error || data.error || 'Submission failed');
      else toast.success('Report sent to HackerOne');
    } catch {
      toast.error('Failed to approve submission');
    } finally {
      setReviewingId(null);
      load();
    }
  };

  const rejectSubmission = async (id: string) => {
    try {
      await csrfFetch(`/api/bounty/submissions/${id}/reject`, { method: 'POST' });
    } catch {
      toast.error('Failed to reject submission');
    } finally {
      load();
    }
  };

  const pendingReview = submissions.filter(s => s.status === 'pending_review');
  const otherSubmissions = submissions.filter(s => s.status !== 'pending_review').slice(0, 15);

  if (loading) {
    return <div className="p-6 text-gray-400 text-sm">Loading HackerOne data…</div>;
  }

  return (
    <div className="p-6 space-y-6 overflow-auto h-full">
      {/* Connection status */}
      <Card className="p-4">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <Shield className={`w-5 h-5 ${connected && hasCredentials ? 'text-green-400' : 'text-gray-500'}`} />
            <div>
              <div className="text-sm font-semibold text-gray-200">HackerOne</div>
              <div className="text-xs text-gray-500">
                {!hasCredentials
                  ? 'No credentials configured — add HACKERONE_USERNAME/TOKEN in Settings'
                  : !connected
                    ? 'Disconnected — scope sync and report submission are both paused'
                    : `Connected · ${programs.length} program(s) tracked`}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {!connected && hasCredentials && (
              <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                <Link2Off className="w-3 h-3 mr-1 inline" /> Disconnected
              </Badge>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={handleSync}
              disabled={syncing || !hasCredentials || !connected}
              className="text-xs"
              title={!hasCredentials ? 'Configure HackerOne credentials in Settings first' : undefined}
            >
              <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${syncing ? 'animate-spin' : ''}`} />
              {syncing ? 'Syncing…' : 'Sync Programs'}
            </Button>
          </div>
        </div>
      </Card>

      {/* Recommended — ranked by real scope/rules/payout data where available,
          never excluding a program just because it can't yield an RCE chain;
          asset testability is one weighted factor among several, not a gate. */}
      <div>
        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
          Recommended for your next hunt
        </div>
        {rankingLoading ? (
          <Card className="p-4 text-sm text-gray-500">Scoring programs…</Card>
        ) : rankings.length === 0 ? (
          <Card className="p-4 text-sm text-gray-500">No HackerOne programs to rank yet.</Card>
        ) : (
          <div className="space-y-2">
            {rankings.slice(0, 5).map(s => (
              <Card key={s.programId} className="p-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-gray-500">#{s.rank}</span>
                    <span className="text-sm font-semibold text-gray-200">{s.name}</span>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Badge className={
                      s.competitionLevel === 'low' ? 'bg-green-500/20 text-green-400 border-green-500/30'
                        : s.competitionLevel === 'medium' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
                        : 'bg-red-500/20 text-red-400 border-red-500/30'
                    }>
                      {s.competitionLevel} competition
                    </Badge>
                    <span className="text-xs font-mono text-gray-400">score {s.roiScore.toFixed(2)}</span>
                  </div>
                </div>
                {s.notes.length > 0 && (
                  <ul className="mt-2 space-y-0.5">
                    {s.notes.map((n, i) => (
                      <li key={i} className="text-xs text-gray-500 flex items-start gap-1.5">
                        <span className="text-gray-600">·</span> {n}
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Pending review queue */}
      {pendingReview.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-amber-400 uppercase tracking-wide mb-2 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" /> Awaiting review ({pendingReview.length})
          </div>
          <div className="space-y-2">
            {pendingReview.map(sub => (
              <Card key={sub.id} className="p-3 border-amber-500/30 bg-amber-500/5">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-gray-200 font-medium truncate">{sub.title}</div>
                    <div className="flex items-center gap-2 mt-1 flex-wrap">
                      <Badge className={getSeverityColor(sub.severity)}>{sub.severity}</Badge>
                      {sub.programHandle && <span className="text-xs text-gray-500">{sub.programHandle}</span>}
                    </div>
                  </div>
                  {reviewingId === sub.id ? (
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <Button variant="ghost" size="sm" onClick={() => approveSubmission(sub.id)} className="text-green-400 hover:text-green-300 h-8 px-2 text-xs">
                        Confirm send
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => setReviewingId(null)} className="text-gray-400 h-8 w-8 p-0">
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <Button variant="ghost" size="sm" onClick={() => setReviewingId(sub.id)} title="Approve and send" className="text-green-400 hover:text-green-300 h-8 w-8 p-0">
                        <ThumbsUp className="w-4 h-4" />
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => rejectSubmission(sub.id)} title="Reject — never send" className="text-gray-400 hover:text-red-400 h-8 w-8 p-0">
                        <ThumbsDown className="w-4 h-4" />
                      </Button>
                    </div>
                  )}
                </div>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Programs */}
      <div>
        <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
          Programs ({programs.length})
        </div>
        {programs.length === 0 ? (
          <Card className="p-4 text-sm text-gray-500">
            No HackerOne programs tracked yet — add one manually in Programs, or sync your account above.
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {programs.map(p => (
              <Card key={p.id} className="p-3">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <div className="text-sm font-semibold text-gray-200">{p.name}</div>
                    {p.programHandle && (
                      <a
                        href={`https://hackerone.com/${p.programHandle}`}
                        target="_blank" rel="noreferrer"
                        className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                      >
                        {p.programHandle} <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                  {p.active
                    ? <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Active</Badge>
                    : <Badge className="bg-gray-500/20 text-gray-400 border-gray-500/30">Inactive</Badge>}
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs text-gray-400">
                  <div className="flex items-center gap-1"><DollarSign className="w-3 h-3" /> ${p.maxPayout}</div>
                  <div className="flex items-center gap-1"><Timer className="w-3 h-3" /> {p.responseTime}h</div>
                  <div>ROI {p.roiScore?.toFixed?.(2) ?? p.roiScore}</div>
                </div>
                <div className="text-xs text-gray-500 mt-2">
                  {p.scope.length} in-scope · {p.outOfScope.length} out-of-scope
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Recent submission history */}
      {otherSubmissions.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">Recent activity</div>
          <div className="space-y-1.5">
            {otherSubmissions.map(sub => (
              <div key={sub.id} className="flex items-center gap-3 px-3 py-2 rounded border border-gray-800 text-xs">
                {sub.status === 'submitted' && <CheckCircle2 className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />}
                {sub.status === 'failed' && <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
                {sub.status === 'rejected' && <Clock className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />}
                <span className="text-gray-300 truncate flex-1">{sub.title}</span>
                <Badge className={getStatusColor(sub.status)}>{sub.status}</Badge>
                {sub.reportUrl && (
                  <a href={sub.reportUrl} target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline flex-shrink-0">
                    view
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

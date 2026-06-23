import { useState, useEffect, useCallback } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  Import, Loader2, CheckCircle, XCircle,
  ChevronDown, ChevronRight, Activity,
  Globe, Lock, Gauge, Zap, AlertTriangle,
  RefreshCw, Target, Search
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ProgramScope {
  inScope: string[];
  outOfScope: string[];
  restrictions?: string[];
}

interface Program {
  id: string;
  name: string;
  platform: string;
  stealthProfile: string;
  noveltyFloor: number;
  maxScanRate: number;
  scope: ProgramScope;
  status: string;
  domainCount?: number;
}

interface ScopeGuardStats {
  totalChecks: number;
  blocked: number;
  allowed: number;
  blockRate: number;
}

interface AuditEntry {
  timestamp: string;
  target: string;
  action: string;
  reason: string;
}

interface ValidationResult {
  allowed: boolean;
  reason: string;
}

const PLATFORMS = [
  { value: 'hackerone', label: 'HackerOne', color: 'bg-emerald-600/20 text-emerald-400' },
  { value: 'bugcrowd', label: 'Bugcrowd', color: 'bg-orange-600/20 text-orange-400' },
  { value: 'intigriti', label: 'Intigriti', color: 'bg-blue-600/20 text-blue-400' },
  { value: 'synack', label: 'Synack', color: 'bg-red-600/20 text-red-400' },
  { value: 'yeswehack', label: 'YesWeHack', color: 'bg-violet-600/20 text-violet-400' },
  { value: 'custom', label: 'Custom', color: 'bg-gray-600/20 text-gray-400' },
];
const STEALTH_PROFILES = ['aggressive', 'balanced', 'stealth', 'ultrastealth'];
const getPlatformInfo = (value: string) => PLATFORMS.find(p => p.value === value) || PLATFORMS[5];

export function ScopeManager() {
  const { toast } = useToast();

  const [handle, setHandle] = useState('');
  const [platform, setPlatform] = useState('hackerone');
  const [stealthProfile, setStealthProfile] = useState('balanced');
  const [noveltyFloor, setNoveltyFloor] = useState('');
  const [maxScanRate, setMaxScanRate] = useState('');
  const [scopeText, setScopeText] = useState('');
  const [outOfScopeText, setOutOfScopeText] = useState('');
  const [importing, setImporting] = useState(false);

  const [programs, setPrograms] = useState<Program[]>([]);
  const [loadingPrograms, setLoadingPrograms] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activatingId, setActivatingId] = useState<string | null>(null);

  const [editNovelty, setEditNovelty] = useState<Record<string, string>>({});
  const [editStealth, setEditStealth] = useState<Record<string, string>>({});

  const [guardStats, setGuardStats] = useState<ScopeGuardStats | null>(null);
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);

  const [validateInput, setValidateInput] = useState('');
  const [validating, setValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<ValidationResult | null>(null);

  const fetchPrograms = useCallback(async () => {
    setLoadingPrograms(true);
    try {
      const res = await fetch('/api/bounty/programs/list');
      const data = await res.json();
      if (Array.isArray(data)) {
        setPrograms(data);
      } else if (data.programs) {
        setPrograms(data.programs);
      }
    } catch {
      setPrograms([]);
    } finally {
      setLoadingPrograms(false);
    }
  }, []);

  const fetchGuardStats = useCallback(async () => {
    try {
      const [statsRes, auditRes] = await Promise.all([
        fetch('/api/bounty/scope-guard/stats'),
        fetch('/api/bounty/scope-guard/audit?limit=10'),
      ]);
      const statsData = await statsRes.json();
      const auditData = await auditRes.json();
      if (statsData) setGuardStats(statsData.stats || statsData);
      if (Array.isArray(auditData)) setAuditEntries(auditData);
      else if (auditData.entries) setAuditEntries(auditData.entries);
      else if (auditData.audit) setAuditEntries(auditData.audit);
    } catch {
      // silently fail
    }
  }, []);

  useEffect(() => {
    fetchPrograms();
    fetchGuardStats();
  }, [fetchPrograms, fetchGuardStats]);

  useEffect(() => {
    const interval = setInterval(fetchGuardStats, 10000);
    return () => clearInterval(interval);
  }, [fetchGuardStats]);

  const handleImport = async () => {
    if (!handle.trim()) return;
    setImporting(true);
    try {
      const res = await csrfFetch('/api/bounty/programs/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          handle: handle.trim(),
          platform,
          stealthProfile,
          noveltyFloor: noveltyFloor ? parseFloat(noveltyFloor) : undefined,
          maxScanRate: maxScanRate ? parseInt(maxScanRate, 10) : undefined,
          scope: scopeText,
          outOfScope: outOfScopeText,
        }),
      });
      const data = await res.json();
      if (res.ok) {
        toast({ title: 'Program Imported', description: data.message || `Successfully imported ${handle}` });
        if (data.warnings?.length) {
          toast({ title: 'Scope Warning', description: data.warnings[0], variant: 'destructive' });
        }
        setHandle('');
        setNoveltyFloor('');
        setMaxScanRate('');
        setScopeText('');
        setOutOfScopeText('');
        fetchPrograms();
      } else {
        toast({ title: 'Import Failed', description: data.error || 'Failed to import program', variant: 'destructive' });
      }
    } catch {
      toast({ title: 'Import Error', description: 'Network error during import', variant: 'destructive' });
    } finally {
      setImporting(false);
    }
  };

  const handleActivate = async (id: string) => {
    setActivatingId(id);
    try {
      const res = await csrfFetch(`/api/bounty/programs/${id}/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.ok) {
        toast({ title: 'Program Activated', description: 'Program is now active' });
        fetchPrograms();
      }
    } catch {
      toast({ title: 'Activation Failed', description: 'Could not activate program', variant: 'destructive' });
    } finally {
      setActivatingId(null);
    }
  };

  const handleValidate = async () => {
    if (!validateInput.trim()) return;
    setValidating(true);
    setValidationResult(null);
    try {
      const res = await csrfFetch('/api/bounty/programs/validate-target', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: validateInput.trim() }),
      });
      const data = await res.json();
      setValidationResult({
        allowed: data.allowed ?? data.valid ?? true,
        reason: data.reason || data.message || (data.allowed ? 'Target is in scope' : 'Target is out of scope'),
      });
    } catch {
      setValidationResult({ allowed: false, reason: 'Validation request failed' });
    } finally {
      setValidating(false);
    }
  };

  const handleUpdateProgram = async (id: string) => {
    try {
      const body: Record<string, unknown> = {};
      if (editNovelty[id] !== undefined) body.noveltyFloor = parseFloat(editNovelty[id]);
      if (editStealth[id] !== undefined) body.stealthProfile = editStealth[id];
      await csrfFetch(`/api/bounty/programs/${id}/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      toast({ title: 'Updated', description: 'Program settings updated' });
      fetchPrograms();
    } catch {
      toast({ title: 'Update Failed', description: 'Could not update program', variant: 'destructive' });
    }
  };

  const blockRate = guardStats ? (guardStats.totalChecks > 0 ? Math.round((guardStats.blocked / guardStats.totalChecks) * 100) : 0) : 0;
  const allowRate = 100 - blockRate;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6 overflow-hidden">
      <div className="mb-4">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100" data-testid="text-program-manager-title">Program Manager</h1>
        </div>
        <p className="text-sm text-gray-400">Import and manage bug bounty programs with ScopeGuard protection</p>
      </div>

      <ScrollArea className="flex-1">
        <div className="space-y-4 pr-2">
          <Card className="bg-[#252526] border-[#3d3d3d] p-4">
            <div className="flex items-center gap-2 mb-3">
              <Import className="w-4 h-4 text-cyan-400" />
              <Label className="text-sm font-semibold text-gray-200">Import Program</Label>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Program Handle</Label>
                <Input
                  placeholder={
                    platform === 'hackerone' ? 'e.g. security' :
                    platform === 'bugcrowd' ? 'e.g. tesla' :
                    platform === 'intigriti' ? 'e.g. intigriti' :
                    platform === 'synack' ? 'e.g. target-codename' :
                    platform === 'yeswehack' ? 'e.g. yes-we-hack' :
                    'e.g. my-program'
                  }
                  value={handle}
                  onChange={(e) => setHandle(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleImport()}
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                  data-testid="input-program-handle"
                />
              </div>
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Platform</Label>
                <select
                  value={platform}
                  onChange={(e) => setPlatform(e.target.value)}
                  className="w-full h-9 rounded-md bg-[#1e1e1e] border border-[#3d3d3d] text-gray-200 px-3 text-sm"
                  data-testid="select-platform"
                >
                  {PLATFORMS.map(p => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3 mb-3">
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Stealth Profile</Label>
                <select
                  value={stealthProfile}
                  onChange={(e) => setStealthProfile(e.target.value)}
                  className="w-full h-9 rounded-md bg-[#1e1e1e] border border-[#3d3d3d] text-gray-200 px-3 text-sm"
                  data-testid="select-stealth-profile"
                >
                  {STEALTH_PROFILES.map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Novelty Floor (0-1)</Label>
                <Input
                  type="number"
                  min="0"
                  max="1"
                  step="0.1"
                  placeholder="0.5"
                  value={noveltyFloor}
                  onChange={(e) => setNoveltyFloor(e.target.value)}
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                  data-testid="input-novelty-floor"
                />
              </div>
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Max Scan Rate</Label>
                <Input
                  type="number"
                  min="1"
                  placeholder="10"
                  value={maxScanRate}
                  onChange={(e) => setMaxScanRate(e.target.value)}
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                  data-testid="input-max-scan-rate"
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 mb-3">
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">In-Scope (one host per line)</Label>
                <textarea
                  placeholder={"example.com\n*.example.com\napi.example.com"}
                  value={scopeText}
                  onChange={(e) => setScopeText(e.target.value)}
                  rows={4}
                  className="w-full rounded-md bg-[#1e1e1e] border border-[#3d3d3d] text-gray-200 px-3 py-2 text-sm font-mono resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  data-testid="textarea-scope"
                />
              </div>
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Out-of-Scope (one host per line)</Label>
                <textarea
                  placeholder={"staging.example.com\ndev.example.com"}
                  value={outOfScopeText}
                  onChange={(e) => setOutOfScopeText(e.target.value)}
                  rows={4}
                  className="w-full rounded-md bg-[#1e1e1e] border border-[#3d3d3d] text-gray-200 px-3 py-2 text-sm font-mono resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  data-testid="textarea-out-of-scope"
                />
                <p className="text-xs text-gray-500 mt-1">Host patterns only — paths rejected</p>
              </div>
            </div>
            <Button
              onClick={handleImport}
              disabled={!handle.trim() || importing}
              className="bg-cyan-600 hover:bg-cyan-700 text-white"
              data-testid="button-import-program"
            >
              {importing ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Import className="w-4 h-4 mr-2" />}
              {importing ? 'Importing...' : 'Import'}
            </Button>
          </Card>

          <Card className="bg-[#252526] border-[#3d3d3d] p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-cyan-400" />
                <Label className="text-sm font-semibold text-gray-200">Active Programs</Label>
              </div>
              <Button
                onClick={fetchPrograms}
                variant="ghost"
                size="sm"
                className="text-gray-400 hover:text-gray-200 h-7"
                data-testid="button-refresh-programs"
              >
                <RefreshCw className={`w-3 h-3 ${loadingPrograms ? 'animate-spin' : ''}`} />
              </Button>
            </div>

            {loadingPrograms && programs.length === 0 ? (
              <div className="flex items-center justify-center py-8 text-gray-500">
                <Loader2 className="w-5 h-5 animate-spin mr-2" />
                Loading programs...
              </div>
            ) : programs.length === 0 ? (
              <div className="text-center py-8 text-gray-500 text-sm" data-testid="text-no-programs">
                No programs imported yet. Import a program above to get started.
              </div>
            ) : (
              <div className="space-y-2">
                {programs.map(prog => {
                  const isExpanded = expandedId === prog.id;
                  const isActive = prog.status === 'active';
                  const domainCount = prog.domainCount ?? (prog.scope?.inScope?.length || 0);
                  return (
                    <div
                      key={prog.id}
                      className={`rounded-lg border transition-colors ${
                        isActive ? 'border-green-500/50 bg-green-500/5' : 'border-[#3d3d3d] bg-[#1e1e1e]'
                      }`}
                      data-testid={`card-program-${prog.id}`}
                    >
                      <div
                        className="flex items-center justify-between p-3 cursor-pointer"
                        onClick={() => setExpandedId(isExpanded ? null : prog.id)}
                        data-testid={`button-expand-program-${prog.id}`}
                      >
                        <div className="flex items-center gap-3">
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-gray-400" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-gray-400" />
                          )}
                          <span className="text-sm font-medium text-gray-200" data-testid={`text-program-name-${prog.id}`}>
                            {prog.name}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${getPlatformInfo(prog.platform).color}`} data-testid={`badge-platform-${prog.id}`}>
                            {getPlatformInfo(prog.platform).label}
                          </span>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${
                            prog.stealthProfile === 'ultrastealth' ? 'bg-purple-600/20 text-purple-400' :
                            prog.stealthProfile === 'stealth' ? 'bg-blue-600/20 text-blue-400' :
                            prog.stealthProfile === 'balanced' ? 'bg-yellow-600/20 text-yellow-400' :
                            'bg-red-600/20 text-red-400'
                          }`} data-testid={`badge-stealth-${prog.id}`}>
                            {prog.stealthProfile}
                          </span>
                          <span className="text-xs text-gray-500">
                            {domainCount} domains
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-xs px-2 py-0.5 rounded-full ${
                            isActive ? 'bg-green-600/20 text-green-400' : 'bg-gray-600/20 text-gray-400'
                          }`} data-testid={`badge-status-${prog.id}`}>
                            {isActive ? 'active' : 'inactive'}
                          </span>
                          {!isActive && (
                            <Button
                              onClick={(e) => { e.stopPropagation(); handleActivate(prog.id); }}
                              disabled={activatingId === prog.id}
                              size="sm"
                              className="bg-green-600 hover:bg-green-700 text-white h-7 px-3 text-xs"
                              data-testid={`button-activate-${prog.id}`}
                            >
                              {activatingId === prog.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3 mr-1" />}
                              Activate
                            </Button>
                          )}
                        </div>
                      </div>

                      {isExpanded && (
                        <div className="border-t border-[#3d3d3d] p-4 space-y-4">
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <div className="flex items-center gap-2 mb-2">
                                <ShieldCheck className="w-4 h-4 text-green-400" />
                                <Label className="text-xs font-semibold text-green-400">In-Scope Domains</Label>
                              </div>
                              <div className="space-y-1">
                                {(prog.scope?.inScope || []).length === 0 ? (
                                  <p className="text-xs text-gray-500">No in-scope domains</p>
                                ) : (
                                  prog.scope.inScope.map((domain, idx) => (
                                    <div key={idx} className="flex items-center gap-2 px-2 py-1 bg-green-500/5 rounded text-xs text-gray-300" data-testid={`item-inscope-${prog.id}-${idx}`}>
                                      <ShieldCheck className="w-3 h-3 text-green-400 flex-shrink-0" />
                                      <span className="truncate">{domain}</span>
                                    </div>
                                  ))
                                )}
                              </div>
                            </div>
                            <div>
                              <div className="flex items-center gap-2 mb-2">
                                <ShieldX className="w-4 h-4 text-red-400" />
                                <Label className="text-xs font-semibold text-red-400">Out-of-Scope Domains</Label>
                              </div>
                              <div className="space-y-1">
                                {(prog.scope?.outOfScope || []).length === 0 ? (
                                  <p className="text-xs text-gray-500">No out-of-scope domains</p>
                                ) : (
                                  prog.scope.outOfScope.map((domain, idx) => (
                                    <div key={idx} className="flex items-center gap-2 px-2 py-1 bg-red-500/5 rounded text-xs text-gray-300" data-testid={`item-outscope-${prog.id}-${idx}`}>
                                      <ShieldX className="w-3 h-3 text-red-400 flex-shrink-0" />
                                      <span className="truncate">{domain}</span>
                                    </div>
                                  ))
                                )}
                              </div>
                            </div>
                          </div>

                          {prog.scope?.restrictions && prog.scope.restrictions.length > 0 && (
                            <div>
                              <div className="flex items-center gap-2 mb-2">
                                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                                <Label className="text-xs font-semibold text-yellow-400">Testing Restrictions</Label>
                              </div>
                              <div className="space-y-1">
                                {prog.scope.restrictions.map((restriction, idx) => (
                                  <div key={idx} className="flex items-center gap-2 px-2 py-1 bg-yellow-500/5 rounded text-xs text-gray-300" data-testid={`item-restriction-${prog.id}-${idx}`}>
                                    <Lock className="w-3 h-3 text-yellow-400 flex-shrink-0" />
                                    <span>{restriction}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          <div className="grid grid-cols-2 gap-4">
                            <div className="flex items-center gap-2 px-3 py-2 bg-[#1e1e1e] rounded">
                              <Gauge className="w-4 h-4 text-cyan-400" />
                              <span className="text-xs text-gray-400">Novelty Floor:</span>
                              <span className="text-xs text-gray-200 font-mono" data-testid={`text-novelty-${prog.id}`}>{prog.noveltyFloor}</span>
                            </div>
                            <div className="flex items-center gap-2 px-3 py-2 bg-[#1e1e1e] rounded">
                              <Activity className="w-4 h-4 text-cyan-400" />
                              <span className="text-xs text-gray-400">Max Scan Rate:</span>
                              <span className="text-xs text-gray-200 font-mono" data-testid={`text-scanrate-${prog.id}`}>{prog.maxScanRate}/s</span>
                            </div>
                          </div>

                          <div className="border-t border-[#3d3d3d] pt-3">
                            <Label className="text-xs text-gray-400 mb-2 block">Update Settings</Label>
                            <div className="flex items-end gap-3">
                              <div className="flex-1">
                                <Label className="text-xs text-gray-500 mb-1 block">Novelty Floor</Label>
                                <Input
                                  type="number"
                                  min="0"
                                  max="1"
                                  step="0.1"
                                  placeholder={String(prog.noveltyFloor)}
                                  value={editNovelty[prog.id] ?? ''}
                                  onChange={(e) => setEditNovelty(prev => ({ ...prev, [prog.id]: e.target.value }))}
                                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                                  data-testid={`input-edit-novelty-${prog.id}`}
                                />
                              </div>
                              <div className="flex-1">
                                <Label className="text-xs text-gray-500 mb-1 block">Stealth Profile</Label>
                                <select
                                  value={editStealth[prog.id] ?? prog.stealthProfile}
                                  onChange={(e) => setEditStealth(prev => ({ ...prev, [prog.id]: e.target.value }))}
                                  className="w-full h-8 rounded-md bg-[#1e1e1e] border border-[#3d3d3d] text-gray-200 px-2 text-xs"
                                  data-testid={`select-edit-stealth-${prog.id}`}
                                >
                                  {STEALTH_PROFILES.map(s => (
                                    <option key={s} value={s}>{s}</option>
                                  ))}
                                </select>
                              </div>
                              <Button
                                onClick={() => handleUpdateProgram(prog.id)}
                                size="sm"
                                className="bg-cyan-600 hover:bg-cyan-700 text-white h-8 px-3 text-xs"
                                data-testid={`button-update-${prog.id}`}
                              >
                                Save
                              </Button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </Card>

          <Card className="bg-[#252526] border-[#3d3d3d] p-4">
            <div className="flex items-center gap-2 mb-3">
              <Target className="w-4 h-4 text-cyan-400" />
              <Label className="text-sm font-semibold text-gray-200">Target Validator</Label>
            </div>
            <div className="flex gap-2 mb-3">
              <Input
                placeholder="Enter target URL or command to validate..."
                value={validateInput}
                onChange={(e) => setValidateInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleValidate()}
                className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                data-testid="input-validate-target"
              />
              <Button
                onClick={handleValidate}
                disabled={!validateInput.trim() || validating}
                className="bg-cyan-600 hover:bg-cyan-700 text-white h-9"
                data-testid="button-validate-target"
              >
                {validating ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Search className="w-4 h-4 mr-2" />}
                Validate
              </Button>
            </div>
            {validationResult && (
              <div
                className={`flex items-center gap-2 px-3 py-2 rounded ${
                  validationResult.allowed
                    ? 'bg-green-500/10 border border-green-500/30'
                    : 'bg-red-500/10 border border-red-500/30'
                }`}
                data-testid="text-validation-result"
              >
                {validationResult.allowed ? (
                  <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                ) : (
                  <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                )}
                <span className={`text-sm ${validationResult.allowed ? 'text-green-400' : 'text-red-400'}`}>
                  {validationResult.reason}
                </span>
              </div>
            )}
          </Card>

          <Card className="bg-[#252526] border-[#3d3d3d] p-4">
            <div className="flex items-center gap-2 mb-3">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <Label className="text-sm font-semibold text-gray-200">Scope Guard Dashboard</Label>
              <span className="text-xs text-gray-500 ml-auto">Auto-refreshes every 10s</span>
            </div>

            {guardStats ? (
              <>
                <div className="grid grid-cols-4 gap-3 mb-4">
                  <div className="bg-[#1e1e1e] rounded p-3 text-center">
                    <div className="text-lg font-bold text-gray-200" data-testid="text-total-checks">{guardStats.totalChecks}</div>
                    <div className="text-xs text-gray-500">Total Checks</div>
                  </div>
                  <div className="bg-[#1e1e1e] rounded p-3 text-center">
                    <div className="text-lg font-bold text-green-400" data-testid="text-allowed-count">{guardStats.allowed}</div>
                    <div className="text-xs text-gray-500">Allowed</div>
                  </div>
                  <div className="bg-[#1e1e1e] rounded p-3 text-center">
                    <div className="text-lg font-bold text-red-400" data-testid="text-blocked-count">{guardStats.blocked}</div>
                    <div className="text-xs text-gray-500">Blocked</div>
                  </div>
                  <div className="bg-[#1e1e1e] rounded p-3 text-center">
                    <div className="text-lg font-bold text-yellow-400" data-testid="text-block-rate">{blockRate}%</div>
                    <div className="text-xs text-gray-500">Block Rate</div>
                  </div>
                </div>

                <div className="mb-4">
                  <div className="flex h-3 rounded-full overflow-hidden bg-[#1e1e1e]" data-testid="progress-scope-guard">
                    <div
                      className="bg-green-500 transition-all duration-500"
                      style={{ width: `${allowRate}%` }}
                    />
                    <div
                      className="bg-red-500 transition-all duration-500"
                      style={{ width: `${blockRate}%` }}
                    />
                  </div>
                  <div className="flex justify-between mt-1">
                    <span className="text-xs text-green-400">Allowed {allowRate}%</span>
                    <span className="text-xs text-red-400">Blocked {blockRate}%</span>
                  </div>
                </div>
              </>
            ) : (
              <div className="text-center py-4 text-gray-500 text-sm" data-testid="text-no-guard-stats">
                No Scope Guard stats available
              </div>
            )}

            {auditEntries.length > 0 && (
              <div>
                <Label className="text-xs text-gray-400 mb-2 block">Recent Blocks</Label>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {auditEntries.map((entry, idx) => (
                    <div
                      key={idx}
                      className="flex items-center gap-2 px-2 py-1.5 bg-red-500/5 rounded text-xs border border-red-500/10"
                      data-testid={`item-audit-${idx}`}
                    >
                      <ShieldX className="w-3 h-3 text-red-400 flex-shrink-0" />
                      <span className="text-gray-400 flex-shrink-0">
                        {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString() : ''}
                      </span>
                      <span className="text-gray-300 truncate font-mono">{entry.target}</span>
                      <span className="text-red-400 ml-auto flex-shrink-0">{entry.action}</span>
                      <span className="text-gray-500 truncate max-w-[200px]">{entry.reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        </div>
      </ScrollArea>
    </div>
  );
}

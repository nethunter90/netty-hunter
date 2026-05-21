import { useState, useEffect, useCallback } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { csrfFetch } from '@/services/api';

interface Challenge {
  id: string;
  name: string;
  difficulty: 'easy' | 'medium' | 'hard';
  category: string;
  description: string;
  endpoint: string;
  method: string;
  points: number;
  cweId: string;
  expectedVulnType: string;
  hints: string[];
}

interface ChallengeResult {
  challengeId: string;
  challengeName: string;
  difficulty: string;
  category: string;
  status: 'passed' | 'failed' | 'skipped' | 'error' | 'running';
  score: number;
  maxScore: number;
  findings: string[];
  executionTimeMs: number;
  scanResults: { tool: string; output: string; vulnDetected: boolean; confidence: number }[];
  error?: string;
}

interface BenchmarkRun {
  id: string;
  status: 'idle' | 'running' | 'completed' | 'aborted';
  startedAt: string;
  completedAt?: string;
  results: ChallengeResult[];
  totalScore: number;
  maxPossibleScore: number;
  passRate: number;
  byDifficulty: Record<string, { passed: number; total: number; score: number; maxScore: number }>;
  challengeCount: number;
  passedCount: number;
  failedCount: number;
}

interface Stats {
  total: number;
  byDifficulty: { easy: number; medium: number; hard: number };
  byCategory: Record<string, number>;
  maxPoints: number;
}

interface JSChallenge {
  id: string;
  juiceShopKey: string;
  name: string;
  difficulty: number;
  category: string;
  description: string;
  points: number;
}

interface JSScanResult {
  detected: boolean;
  confidence: number;
  technique: string;
  evidence: string;
  request?: string;
  response?: string;
  executionTimeMs: number;
}

interface AdaptiveTrace {
  phase: string;
  action: string;
  result: string;
  durationMs: number;
}

interface PayloadAttempt {
  payload: string;
  method: string;
  url: string;
  reasoning: string;
  result: { status: number; body: string } | null;
}

interface AdaptiveScanResult extends JSScanResult {
  adaptive: true;
  reasoningTrace: AdaptiveTrace[];
  payloadAttempts: PayloadAttempt[];
  modelUsed: string;
  totalLLMCalls: number;
  llmTimeMs: number;
}

interface JSResult {
  challengeId: string;
  challengeName: string;
  juiceShopKey: string;
  difficulty: number;
  category: string;
  status: 'passed' | 'failed' | 'error' | 'running' | 'skipped';
  score: number;
  maxScore: number;
  scanResult: JSScanResult | null;
  adaptiveScanResult?: AdaptiveScanResult | null;
  scanMode?: 'hardcoded' | 'adaptive' | 'hybrid';
  error?: string;
}

interface JSBenchmarkRun {
  id: string;
  status: 'idle' | 'running' | 'completed' | 'aborted';
  targetUrl: string;
  scanMode: 'hardcoded' | 'adaptive' | 'hybrid';
  ollamaAvailable: boolean;
  startedAt: string;
  completedAt?: string;
  results: JSResult[];
  totalScore: number;
  maxPossibleScore: number;
  passRate: number;
  byDifficulty: Record<number, { passed: number; total: number; score: number; maxScore: number }>;
  byCategory: Record<string, { passed: number; total: number; score: number; maxScore: number }>;
  challengeCount: number;
  passedCount: number;
  failedCount: number;
  adaptivePassedCount: number;
  totalExecutionTimeMs: number;
  totalLLMCalls: number;
  totalLLMTimeMs: number;
}

interface FindingVerification {
  status: 'confirmed' | 'unverified' | 'rejected' | 'duplicate';
  verifiedConfidence: number;
  evidenceVerified: boolean;
  isDuplicate: boolean;
  replayConfirmed?: boolean;
  rejectionReason?: string;
  fingerprint: string;
}

interface VerificationStats {
  total: number;
  confirmed: number;
  unverified: number;
  rejected: number;
  duplicate: number;
  evidenceVerifiedCount: number;
  replayTestedCount: number;
  replayConfirmedCount: number;
  avgConfidence: number;
  avgVerifiedConfidence: number;
}

interface GenericScanResult {
  targetUrl: string;
  findings: Array<{
    endpoint: string;
    vulnerability: string;
    severity: string;
    confidence: number;
    evidence: string;
    technique: string;
    trace: AdaptiveTrace[];
    verification?: FindingVerification;
    browserVerification?: {
      status: 'verified' | 'false_positive' | 'error';
      confidence: number;
      domChangedSignificantly: boolean;
      visualChangedSignificantly: boolean;
      evidenceAttachments: Array<{
        id: string;
        type: string;
        path: string;
        mimeType: string;
        sizeBytes: number;
        capturedAt: string;
        label?: string;
      }>;
      traceZipPath: string | null;
      domHashBefore?: string;
      domHashAfter?: string;
      screenshotHashBefore?: string;
      screenshotHashAfter?: string;
      durationMs: number;
      verifiedAt: string;
      errorMessage?: string;
    };
  }>;
  verificationStats?: VerificationStats;
  totalEndpointsScanned: number;
  totalLLMCalls: number;
  totalTimeMs: number;
  modelUsed: string;
}

const VERIFICATION_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  confirmed: { bg: 'bg-green-900/30', text: 'text-green-400', label: 'CONFIRMED' },
  unverified: { bg: 'bg-yellow-900/30', text: 'text-yellow-400', label: 'UNVERIFIED' },
  rejected: { bg: 'bg-red-900/30', text: 'text-red-400', label: 'REJECTED' },
  duplicate: { bg: 'bg-gray-700/30', text: 'text-gray-400', label: 'DUPLICATE' },
};

const DIFFICULTY_COLORS: Record<string, string> = {
  easy: '#22c55e',
  medium: '#f59e0b',
  hard: '#ef4444',
  '1': '#22c55e',
  '2': '#3b82f6',
  '3': '#f59e0b',
  '4': '#f97316',
  '5': '#ef4444',
  '6': '#dc2626',
};

const STATUS_COLORS: Record<string, string> = {
  passed: '#22c55e',
  failed: '#ef4444',
  error: '#f59e0b',
  running: '#3b82f6',
  skipped: '#6b7280',
};

function DiffLabel({ diff }: { diff: string | number }) {
  const d = String(diff);
  const label = d === '1' ? 'D1' : d === '2' ? 'D2' : d === '3' ? 'D3' : d === '4' ? 'D4' : d === '5' ? 'D5' : d === '6' ? 'D6' : d;
  return (
    <span
      className="px-1.5 py-0.5 text-[10px] font-bold rounded uppercase"
      style={{ backgroundColor: `${DIFFICULTY_COLORS[d] || '#6b7280'}20`, color: DIFFICULTY_COLORS[d] || '#6b7280' }}
    >
      {label}
    </span>
  );
}

const SCAN_MODE_LABELS: Record<string, string> = {
  hardcoded: 'Pattern',
  adaptive: 'AI',
  hybrid: 'Hybrid',
};

const SCAN_MODE_COLORS: Record<string, string> = {
  hardcoded: '#3b82f6',
  adaptive: '#a855f7',
  hybrid: '#f59e0b',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#3b82f6',
};

interface XBOWChallenge {
  id: string;
  name: string;
  description: string;
  level: 1 | 2 | 3;
  winCondition: string;
  tags: string[];
  points: number;
}

interface XBOWChallengeResult {
  challengeId: string;
  challengeName: string;
  level: number;
  tags: string[];
  status: 'passed' | 'failed' | 'error' | 'skipped' | 'docker_unavailable';
  score: number;
  maxScore: number;
  flagFound: string | null;
  expectedFlag: string;
  executionTimeMs: number;
  scanResult: any | null;
  containerInfo: {
    imagePulled: boolean;
    containerStarted: boolean;
    healthCheckPassed: boolean;
    port: number | null;
    containerId: string | null;
  };
  error?: string;
}

interface XBOWBenchmarkRun {
  id: string;
  status: 'running' | 'completed' | 'aborted' | 'error';
  startedAt: string;
  completedAt: string | null;
  challengeCount: number;
  passedCount: number;
  failedCount: number;
  errorCount: number;
  skippedCount: number;
  passRate: number;
  totalScore: number;
  maxPossibleScore: number;
  totalExecutionTimeMs: number;
  dockerAvailable: boolean;
  ollamaAvailable: boolean;
  modelUsed: string;
  totalLLMCalls: number;
  totalLLMTimeMs: number;
  results: XBOWChallengeResult[];
  repoCloned: boolean;
  repoPath: string | null;
}

interface XBOWStatus {
  dockerAvailable: boolean;
  repoAvailable: boolean;
  repoPath: string | null;
  ollamaAvailable: boolean;
}

export function CTFBenchmark() {
  const [mode, setMode] = useState<'synthetic' | 'juiceshop' | 'xbow' | 'adaptive'>('synthetic');
  const [challenges, setChallenges] = useState<Challenge[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [currentRun, setCurrentRun] = useState<BenchmarkRun | null>(null);
  const [history, setHistory] = useState<BenchmarkRun[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [selectedDifficulty, setSelectedDifficulty] = useState<string>('all');
  const [expandedResult, setExpandedResult] = useState<string | null>(null);
  const [tab, setTab] = useState<'challenges' | 'results' | 'history'>('challenges');

  const [jsChallenges, setJsChallenges] = useState<JSChallenge[]>([]);
  const [jsStats, setJsStats] = useState<any>(null);
  const [jsCurrentRun, setJsCurrentRun] = useState<JSBenchmarkRun | null>(null);
  const [jsHistory, setJsHistory] = useState<JSBenchmarkRun[]>([]);
  const [jsRunning, setJsRunning] = useState(false);
  const [jsStatus, setJsStatus] = useState<{ running: boolean; total: number; solved: number } | null>(null);
  const [jsSpawning, setJsSpawning] = useState(false);
  const [jsScanMode, setJsScanMode] = useState<'hardcoded' | 'adaptive' | 'hybrid'>('hybrid');
  const [ollamaAvailable, setOllamaAvailable] = useState(false);

  const [genericTarget, setGenericTarget] = useState('');
  const [genericScanning, setGenericScanning] = useState(false);
  const [genericResult, setGenericResult] = useState<GenericScanResult | null>(null);

  const [xbowChallenges, setXbowChallenges] = useState<XBOWChallenge[]>([]);
  const [xbowStats, setXbowStats] = useState<any>(null);
  const [xbowStatus, setXbowStatus] = useState<XBOWStatus | null>(null);
  const [xbowCurrentRun, setXbowCurrentRun] = useState<XBOWBenchmarkRun | null>(null);
  const [xbowHistory, setXbowHistory] = useState<XBOWBenchmarkRun[]>([]);
  const [xbowRunning, setXbowRunning] = useState(false);
  const [xbowCloning, setXbowCloning] = useState(false);
  const [xbowSelectedLevel, setXbowSelectedLevel] = useState<string>('all');
  const [xbowSelectedTag, setXbowSelectedTag] = useState<string>('all');
  const [xbowMaxChallenges, setXbowMaxChallenges] = useState<string>('');

  const [evidenceStats, setEvidenceStats] = useState<{ totalMissions: number; totalFindings: number; totalArtifacts: number; totalSizeBytes: number } | null>(null);
  const [browserVerifying, setBrowserVerifying] = useState<number | null>(null);

  const loadChallenges = useCallback(async () => {
    try {
      const resp = await fetch('/api/ctf/challenges');
      const data = await resp.json();
      setChallenges(data.challenges || []);
      setStats(data.stats || null);
    } catch {}
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const resp = await fetch('/api/ctf/benchmark/history');
      const data = await resp.json();
      setHistory(data.runs || []);
    } catch {}
  }, []);

  const checkCurrent = useCallback(async () => {
    try {
      const resp = await fetch('/api/ctf/benchmark/current');
      const data = await resp.json();
      if (data.running) {
        setIsRunning(true);
        setCurrentRun(data.run);
      }
    } catch {}
  }, []);

  const loadJSData = useCallback(async () => {
    try {
      const [challResp, statusResp, histResp, ollamaResp] = await Promise.all([
        fetch('/api/juiceshop/challenges'),
        fetch('/api/juiceshop/status'),
        fetch('/api/juiceshop/benchmark/history'),
        fetch('/api/adaptive-scan/ollama-status'),
      ]);
      const challData = await challResp.json();
      const statusData = await statusResp.json();
      const histData = await histResp.json();
      const ollamaData = await ollamaResp.json();
      setJsChallenges(challData.challenges || []);
      setJsStats(challData.stats || null);
      setJsStatus(statusData);
      setJsHistory(histData || []);
      setOllamaAvailable(ollamaData.available || false);
    } catch {}
  }, []);

  const loadXBOWData = useCallback(async () => {
    try {
      const [challResp, statusResp, histResp] = await Promise.all([
        fetch('/api/xbow/challenges'),
        fetch('/api/xbow/status'),
        fetch('/api/xbow/benchmark/history'),
      ]);
      const challData = await challResp.json();
      const statusData = await statusResp.json();
      const histData = await histResp.json();
      setXbowChallenges(challData.challenges || []);
      setXbowStats(challData.stats || null);
      setXbowStatus(statusData);
      setXbowHistory(Array.isArray(histData) ? histData : []);
    } catch {}
  }, []);

  const loadEvidenceStats = useCallback(async () => {
    try {
      const resp = await fetch('/api/evidence/stats');
      const data = await resp.json();
      setEvidenceStats(data);
    } catch {}
  }, []);

  useEffect(() => {
    loadChallenges();
    loadHistory();
    checkCurrent();
    loadJSData();
    loadXBOWData();
    loadEvidenceStats();
  }, [loadChallenges, loadHistory, checkCurrent, loadJSData, loadXBOWData, loadEvidenceStats]);

  const startBenchmark = async () => {
    setIsRunning(true);
    setTab('results');
    setCurrentRun(null);
    try {
      const body: any = {};
      if (selectedDifficulty !== 'all') body.difficulty = selectedDifficulty;
      const resp = await csrfFetch('/api/ctf/benchmark/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      setCurrentRun(data);
      setIsRunning(false);
      loadHistory();
    } catch {
      setIsRunning(false);
    }
  };

  const abortRun = async () => {
    try {
      await csrfFetch('/api/ctf/benchmark/abort', { method: 'POST' });
      setIsRunning(false);
    } catch {}
  };

  const startJSBenchmark = async (scanMode?: 'hardcoded' | 'adaptive' | 'hybrid') => {
    setJsRunning(true);
    setTab('results');
    setJsCurrentRun(null);
    try {
      const body: any = { mode: scanMode || jsScanMode };
      if (selectedDifficulty !== 'all') body.difficulty = parseInt(selectedDifficulty);
      const resp = await csrfFetch('/api/juiceshop/benchmark/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      setJsCurrentRun(data);
      setJsRunning(false);
      loadJSData();
    } catch {
      setJsRunning(false);
    }
  };

  const startGenericScan = async () => {
    if (!genericTarget) return;
    setGenericScanning(true);
    setGenericResult(null);
    setTab('results');
    try {
      const resp = await csrfFetch('/api/adaptive-scan/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl: genericTarget }),
      });
      const data = await resp.json();
      setGenericResult(data);
    } catch {}
    setGenericScanning(false);
  };

  const browserVerifyFinding = async (findingIndex: number) => {
    if (!genericResult) return;
    const f = genericResult.findings[findingIndex];
    setBrowserVerifying(findingIndex);
    try {
      const resp = await csrfFetch('/api/findings/verify-browser', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          endpoint: f.endpoint,
          vulnerability: f.vulnerability,
          severity: f.severity,
          confidence: f.confidence,
          evidence: f.evidence,
          technique: f.technique,
          benchmarkMode: 'adaptive',
          runId: `adaptive-${Date.now()}`,
        }),
      });
      const data = await resp.json();
      const updatedFindings = [...genericResult.findings];
      updatedFindings[findingIndex] = {
        ...updatedFindings[findingIndex],
        browserVerification: data.browserVerification,
      };
      setGenericResult({ ...genericResult, findings: updatedFindings });
      loadEvidenceStats();
    } catch {}
    setBrowserVerifying(null);
  };

  const abortJSRun = async () => {
    try {
      await csrfFetch('/api/juiceshop/benchmark/abort', { method: 'POST' });
      setJsRunning(false);
    } catch {}
  };

  const spawnJuiceShop = async () => {
    setJsSpawning(true);
    try { await csrfFetch('/api/juiceshop/spawn', { method: 'POST' }); loadJSData(); }
    finally { setJsSpawning(false); }
  };

  const stopJuiceShop = async () => {
    try { await csrfFetch('/api/juiceshop/stop', { method: 'POST' }); } catch {}
    loadJSData();
  };

  const cloneXBOWRepo = async () => {
    setXbowCloning(true);
    try {
      const resp = await csrfFetch('/api/xbow/clone-repo', { method: 'POST' });
      const data = await resp.json();
      if (!resp.ok) {
        alert(`Clone failed: ${data.error || 'Unknown error'}.\n\nXBOW Docker benchmarks require running this app locally on a machine with Docker installed.`);
      } else {
        await loadXBOWData();
      }
    } catch (err: any) {
      alert(`Clone failed: ${err.message || 'Network error'}.\n\nXBOW Docker benchmarks require running this app locally on a machine with Docker installed.`);
    }
    setXbowCloning(false);
  };

  const startXBOWBenchmark = async () => {
    setXbowRunning(true);
    setTab('results');
    setXbowCurrentRun(null);
    try {
      const body: any = {};
      if (xbowSelectedLevel !== 'all') body.levels = [parseInt(xbowSelectedLevel)];
      if (xbowSelectedTag !== 'all') body.tags = [xbowSelectedTag];
      if (xbowMaxChallenges) body.maxChallenges = parseInt(xbowMaxChallenges);
      const resp = await csrfFetch('/api/xbow/benchmark/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      setXbowCurrentRun(data);
      setXbowRunning(false);
      loadXBOWData();
    } catch {
      setXbowRunning(false);
    }
  };

  const abortXBOWRun = async () => {
    try {
      await csrfFetch('/api/xbow/benchmark/abort', { method: 'POST' });
      setXbowRunning(false);
    } catch {}
  };

  const filteredChallenges = selectedDifficulty === 'all'
    ? challenges
    : challenges.filter(c => c.difficulty === selectedDifficulty);

  const filteredJSChallenges = selectedDifficulty === 'all'
    ? jsChallenges
    : jsChallenges.filter(c => String(c.difficulty) === selectedDifficulty);

  const filteredXBOWChallenges = xbowChallenges.filter(c => {
    if (xbowSelectedLevel !== 'all' && String(c.level) !== xbowSelectedLevel) return false;
    if (xbowSelectedTag !== 'all' && !c.tags.includes(xbowSelectedTag)) return false;
    return true;
  });

  const xbowTagList = Array.from(new Set(xbowChallenges.flatMap(c => c.tags))).sort();

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] text-gray-200">
      <div className="px-4 py-3 border-b border-[#2d2d2d] flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold text-cyan-400" data-testid="ctf-title">
            {mode === 'synthetic' ? 'CTF Benchmark Suite' : mode === 'juiceshop' ? 'Juice Shop Benchmark' : mode === 'xbow' ? 'XBOW Challenges' : 'Adaptive Scanner'}
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">
            {mode === 'synthetic'
              ? stats ? `${stats.total} challenges | ${stats.maxPoints} max points` : 'Loading...'
              : mode === 'juiceshop'
              ? jsStats ? `${jsStats.total} challenges | ${jsStats.maxPoints} max points${jsStatus?.running ? ` | JS: ${jsStatus.solved}/${jsStatus.total} solved` : ' | JS: offline'}` : 'Loading...'
              : mode === 'xbow'
              ? xbowStats ? `${xbowStats.total} challenges | Docker: ${xbowStatus?.dockerAvailable ? 'Ready' : 'Unavailable'} | Repo: ${xbowStatus?.repoAvailable ? 'Cloned' : 'Not cloned'}` : 'Loading...'
              : ollamaAvailable ? 'LLM-powered autonomous vulnerability scanner' : 'Ollama offline - start Ollama to enable AI scanning'
            }
          </p>
        </div>
        <div className="flex items-center gap-2">
          {mode === 'synthetic' ? (
            isRunning ? (
              <button onClick={abortRun} data-testid="button-abort-benchmark" className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded font-medium">Abort</button>
            ) : (
              <button onClick={startBenchmark} data-testid="button-run-benchmark" className="px-3 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-700 text-white rounded font-medium">Run Benchmark</button>
            )
          ) : mode === 'juiceshop' ? (
            jsRunning ? (
              <button onClick={abortJSRun} data-testid="button-abort-js" className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded font-medium">Abort</button>
            ) : (
              <div className="flex items-center gap-1.5">
                {!jsStatus?.running && (
                  <button
                    onClick={spawnJuiceShop}
                    disabled={jsSpawning}
                    data-testid="button-start-lab"
                    className="px-3 py-1.5 text-xs bg-green-700 hover:bg-green-600 disabled:bg-gray-700 text-white rounded font-medium"
                  >
                    {jsSpawning ? 'Starting...' : 'Start Lab'}
                  </button>
                )}
                {jsStatus?.running && !jsRunning && (
                  <button
                    onClick={stopJuiceShop}
                    data-testid="button-stop-lab"
                    className="px-3 py-1.5 text-xs bg-gray-600 hover:bg-gray-700 text-white rounded font-medium"
                  >
                    Stop Lab
                  </button>
                )}
                <select
                  value={jsScanMode}
                  onChange={e => setJsScanMode(e.target.value as any)}
                  data-testid="select-scan-mode"
                  className="px-1.5 py-1 text-[10px] bg-[#252526] text-gray-300 border border-[#404040] rounded"
                >
                  <option value="hardcoded">Pattern Only</option>
                  <option value="hybrid">Hybrid (Pattern + AI)</option>
                  <option value="adaptive">AI Only</option>
                </select>
                <button
                  onClick={() => startJSBenchmark()}
                  data-testid="button-run-js-benchmark"
                  className="px-3 py-1.5 text-xs bg-orange-600 hover:bg-orange-700 text-white rounded font-medium"
                  disabled={!jsStatus?.running}
                  title={jsStatus?.running ? 'Run live scan against Juice Shop' : 'Juice Shop is not running'}
                >
                  Scan
                </button>
              </div>
            )
          ) : mode === 'xbow' ? (
            xbowRunning ? (
              <button onClick={abortXBOWRun} data-testid="button-abort-xbow" className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded font-medium">Abort</button>
            ) : (
              <div className="flex items-center gap-1.5">
                {!xbowStatus?.repoAvailable && (
                  <button
                    onClick={cloneXBOWRepo}
                    disabled={xbowCloning}
                    data-testid="button-clone-xbow"
                    className="px-3 py-1.5 text-xs bg-gray-600 hover:bg-gray-700 disabled:bg-gray-800 text-white rounded font-medium"
                  >
                    {xbowCloning ? 'Cloning...' : 'Clone Repo'}
                  </button>
                )}
                <input
                  type="number"
                  value={xbowMaxChallenges}
                  onChange={e => setXbowMaxChallenges(e.target.value)}
                  placeholder="Max"
                  data-testid="input-xbow-max"
                  className="w-14 px-1.5 py-1 text-[10px] bg-[#252526] text-gray-300 border border-[#404040] rounded text-center"
                />
                <button
                  onClick={startXBOWBenchmark}
                  disabled={!xbowStatus?.dockerAvailable || !xbowStatus?.repoAvailable}
                  data-testid="button-run-xbow"
                  className="px-3 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded font-medium"
                  title={!xbowStatus?.dockerAvailable ? 'Docker not available' : !xbowStatus?.repoAvailable ? 'Clone XBOW repo first' : 'Run XBOW benchmark'}
                >
                  Run XBOW
                </button>
              </div>
            )
          ) : (
            <div className="flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full inline-block ${ollamaAvailable ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-[10px] text-gray-500">{ollamaAvailable ? 'Ollama' : 'Offline'}</span>
            </div>
          )}
        </div>
      </div>

      <div className="flex border-b border-[#2d2d2d]">
        <button
          onClick={() => setMode('synthetic')}
          data-testid="mode-synthetic"
          className={`px-3 py-1.5 text-[11px] font-medium ${mode === 'synthetic' ? 'text-cyan-400 bg-[#252526] border-b-2 border-cyan-400' : 'text-gray-500 hover:text-gray-300'}`}
        >
          Synthetic ({stats?.total || 0})
        </button>
        <button
          onClick={() => setMode('juiceshop')}
          data-testid="mode-juiceshop"
          className={`px-3 py-1.5 text-[11px] font-medium flex items-center gap-1.5 ${mode === 'juiceshop' ? 'text-orange-400 bg-[#252526] border-b-2 border-orange-400' : 'text-gray-500 hover:text-gray-300'}`}
        >
          Juice Shop ({jsStats?.total || 0})
          {jsStatus?.running && <span className="w-1.5 h-1.5 rounded-full bg-green-500 inline-block" />}
          {jsStatus && !jsStatus.running && <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" />}
        </button>
        <button
          onClick={() => setMode('xbow')}
          data-testid="mode-xbow"
          className={`px-3 py-1.5 text-[11px] font-medium flex items-center gap-1.5 ${mode === 'xbow' ? 'text-emerald-400 bg-[#252526] border-b-2 border-emerald-400' : 'text-gray-500 hover:text-gray-300'}`}
        >
          XBOW ({xbowStats?.total || 0})
          <span className={`w-1.5 h-1.5 rounded-full inline-block ${xbowStatus?.dockerAvailable ? 'bg-green-500' : 'bg-red-500'}`} />
        </button>
        <button
          onClick={() => setMode('adaptive')}
          data-testid="mode-adaptive"
          className={`px-3 py-1.5 text-[11px] font-medium flex items-center gap-1.5 ${mode === 'adaptive' ? 'text-purple-400 bg-[#252526] border-b-2 border-purple-400' : 'text-gray-500 hover:text-gray-300'}`}
        >
          Adaptive Scanner
          <span className={`w-1.5 h-1.5 rounded-full inline-block ${ollamaAvailable ? 'bg-green-500' : 'bg-red-500'}`} />
        </button>
      </div>

      <div className="flex border-b border-[#2d2d2d]">
        {(['challenges', 'results', 'history'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            data-testid={`tab-${t}`}
            className={`px-4 py-2 text-xs font-medium transition-colors ${
              tab === t
                ? `${mode === 'juiceshop' ? 'text-orange-400 border-b-2 border-orange-400' : 'text-cyan-400 border-b-2 border-cyan-400'} bg-[#252526]`
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {t === 'challenges'
              ? `Challenges (${mode === 'synthetic' ? stats?.total || 0 : mode === 'xbow' ? xbowStats?.total || 0 : jsStats?.total || 0})`
              : t === 'results'
              ? 'Results'
              : `History (${mode === 'synthetic' ? history.length : mode === 'xbow' ? xbowHistory.length : jsHistory.length})`
            }
          </button>
        ))}
      </div>

      {mode === 'xbow' && <div className="flex items-center gap-2 px-4 py-2 border-b border-[#2d2d2d] flex-wrap">
        <span className="text-xs text-gray-500">Level:</span>
        {['all', '1', '2', '3'].map(d => (
          <button
            key={d}
            onClick={() => setXbowSelectedLevel(d)}
            data-testid={`xbow-filter-level-${d}`}
            className={`px-2 py-0.5 text-xs rounded ${xbowSelectedLevel === d ? 'bg-emerald-600 text-white' : 'bg-[#2d2d2d] text-gray-400 hover:text-gray-200'}`}
          >
            {d === 'all' ? 'All' : `L${d}`}
          </button>
        ))}
        <span className="text-xs text-gray-500 ml-2">Tag:</span>
        <select
          value={xbowSelectedTag}
          onChange={e => setXbowSelectedTag(e.target.value)}
          data-testid="xbow-filter-tag"
          className="px-1.5 py-0.5 text-[10px] bg-[#252526] text-gray-300 border border-[#404040] rounded"
        >
          <option value="all">All Tags</option>
          {xbowTagList.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>}
      {mode !== 'adaptive' && mode !== 'xbow' && <div className="flex items-center gap-2 px-4 py-2 border-b border-[#2d2d2d]">
        <span className="text-xs text-gray-500">Filter:</span>
        {(mode === 'synthetic' ? ['all', 'easy', 'medium', 'hard'] : ['all', '1', '2', '3', '4', '5', '6']).map(d => (
          <button
            key={d}
            onClick={() => setSelectedDifficulty(d)}
            data-testid={`filter-${d}`}
            className={`px-2 py-0.5 text-xs rounded ${
              selectedDifficulty === d
                ? `${mode === 'juiceshop' ? 'bg-orange-600' : 'bg-cyan-600'} text-white`
                : 'bg-[#2d2d2d] text-gray-400 hover:text-gray-200'
            }`}
          >
            {mode === 'synthetic' ? d.charAt(0).toUpperCase() + d.slice(1) : d === 'all' ? 'All' : `D${d}`}
          </button>
        ))}
      </div>}

      <ScrollArea className="flex-1">
        {mode === 'synthetic' && tab === 'challenges' && (
          <div className="p-4 space-y-2">
            {filteredChallenges.map(c => (
              <div key={c.id} data-testid={`challenge-${c.id}`} className="p-3 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-200">{c.name}</span>
                  <div className="flex items-center gap-2">
                    <DiffLabel diff={c.difficulty} />
                    <span className="text-xs text-yellow-400 font-mono">{c.points}pts</span>
                  </div>
                </div>
                <p className="text-xs text-gray-400 mb-1">{c.description}</p>
                <div className="flex items-center gap-3 text-[10px] text-gray-500">
                  <span>{c.cweId}</span>
                  <span>{c.expectedVulnType}</span>
                  <span className="font-mono">{c.method} {c.endpoint}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {mode === 'juiceshop' && tab === 'challenges' && (
          <div className="p-4 space-y-2">
            {!jsStatus?.running && (
              <div className="p-3 bg-red-900/20 border border-red-800 rounded mb-3">
                <p className="text-xs text-red-300">Juice Shop is not running on localhost:3000. Start it to enable live scanning.</p>
              </div>
            )}
            {filteredJSChallenges.map(c => (
              <div key={c.id} data-testid={`js-challenge-${c.id}`} className="p-3 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-200">{c.name}</span>
                  <div className="flex items-center gap-2">
                    <DiffLabel diff={c.difficulty} />
                    <span className="text-xs text-orange-400 font-mono">{c.points}pts</span>
                  </div>
                </div>
                <p className="text-xs text-gray-400 mb-1">{c.description}</p>
                <div className="flex items-center gap-3 text-[10px] text-gray-500">
                  <span className="px-1 py-0.5 bg-[#1e1e1e] rounded text-orange-300">{c.category}</span>
                  <span className="font-mono text-gray-600">{c.juiceShopKey}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {mode === 'synthetic' && tab === 'results' && (
          <div className="p-4">
            {currentRun ? (
              <>
                <div className="mb-4 p-3 bg-[#252526] rounded border border-[#2d2d2d]">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-bold" style={{ color: currentRun.status === 'completed' ? (currentRun.passRate >= 80 ? '#22c55e' : currentRun.passRate >= 50 ? '#f59e0b' : '#ef4444') : '#3b82f6' }}>
                      {currentRun.status === 'running' ? 'Running...' : `${currentRun.passRate}% Pass Rate`}
                    </span>
                    <span className="text-xs text-gray-400">{currentRun.id}</span>
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    <div><div className="text-lg font-bold text-cyan-400" data-testid="text-total-score">{currentRun.totalScore}</div><div className="text-[10px] text-gray-500">Score</div></div>
                    <div><div className="text-lg font-bold text-green-400" data-testid="text-passed-count">{currentRun.passedCount}</div><div className="text-[10px] text-gray-500">Passed</div></div>
                    <div><div className="text-lg font-bold text-red-400" data-testid="text-failed-count">{currentRun.failedCount}</div><div className="text-[10px] text-gray-500">Failed</div></div>
                    <div><div className="text-lg font-bold text-yellow-400">{currentRun.maxPossibleScore}</div><div className="text-[10px] text-gray-500">Max</div></div>
                  </div>
                  {currentRun.byDifficulty && (
                    <div className="mt-2 flex gap-2">
                      {Object.entries(currentRun.byDifficulty).map(([diff, d]) => {
                        const dd = d as any;
                        return (
                        <div key={diff} className="flex-1 p-1.5 bg-[#1e1e1e] rounded text-center">
                          <div className="text-[10px] font-bold uppercase" style={{ color: DIFFICULTY_COLORS[diff] }}>{diff}</div>
                          <div className="text-xs text-gray-300">{dd.passed}/{dd.total}</div>
                          <div className="text-[10px] text-gray-500">{dd.score}/{dd.maxScore}pts</div>
                        </div>
                        );
                      })}
                    </div>
                  )}
                </div>
                <div className="space-y-1.5">
                  {currentRun.results.map(r => (
                    <div key={r.challengeId}>
                      <button
                        onClick={() => setExpandedResult(expandedResult === r.challengeId ? null : r.challengeId)}
                        data-testid={`result-${r.challengeId}`}
                        className="w-full p-2 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040] text-left"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: STATUS_COLORS[r.status] }} />
                            <span className="text-xs text-gray-200">{r.challengeName}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <DiffLabel diff={r.difficulty} />
                            <span className="text-xs font-mono text-yellow-400">{r.score}/{r.maxScore}</span>
                            <span className="text-[10px] text-gray-500">{r.executionTimeMs}ms</span>
                          </div>
                        </div>
                      </button>
                      {expandedResult === r.challengeId && (
                        <div className="ml-4 mt-1 p-2 bg-[#1e1e1e] rounded border border-[#333] text-xs space-y-1">
                          {r.findings.length > 0 && (
                            <div>
                              <span className="text-green-400 font-bold">Findings:</span>
                              {r.findings.map((f, i) => <div key={i} className="text-gray-300 ml-2">{f}</div>)}
                            </div>
                          )}
                          {r.scanResults.map((s, i) => (
                            <div key={i} className="border-t border-[#333] pt-1 mt-1">
                              <div className="flex items-center gap-2">
                                <span className="text-cyan-400 font-mono">[{s.tool}]</span>
                                <span className={s.vulnDetected ? 'text-green-400' : 'text-gray-500'}>{s.vulnDetected ? 'DETECTED' : 'NOT DETECTED'}</span>
                                {s.confidence > 0 && <span className="text-yellow-400">{Math.round(s.confidence * 100)}% conf</span>}
                              </div>
                              <div className="text-gray-400 mt-0.5 break-all">{s.output}</div>
                            </div>
                          ))}
                          {r.error && <div className="text-red-400">Error: {r.error}</div>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <p className="text-gray-500 text-sm">No benchmark results yet</p>
                <p className="text-gray-600 text-xs mt-1">Click "Run Benchmark" to test autonomous vulnerability detection</p>
              </div>
            )}
          </div>
        )}

        {mode === 'juiceshop' && tab === 'results' && (
          <div className="p-4">
            {jsCurrentRun ? (
              <>
                <div className="mb-4 p-3 bg-[#252526] rounded border border-[#2d2d2d]">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-bold" style={{ color: jsCurrentRun.status === 'completed' ? (jsCurrentRun.passRate >= 80 ? '#22c55e' : jsCurrentRun.passRate >= 50 ? '#f59e0b' : '#ef4444') : '#3b82f6' }}>
                        {jsCurrentRun.status === 'running' ? 'Scanning...' : `${jsCurrentRun.passRate}% Detection Rate`}
                      </span>
                      {jsCurrentRun.scanMode && (
                        <span className="px-1.5 py-0.5 text-[9px] font-bold rounded" style={{ backgroundColor: `${SCAN_MODE_COLORS[jsCurrentRun.scanMode] || '#666'}20`, color: SCAN_MODE_COLORS[jsCurrentRun.scanMode] || '#666' }}>
                          {SCAN_MODE_LABELS[jsCurrentRun.scanMode] || jsCurrentRun.scanMode}
                        </span>
                      )}
                    </div>
                    <span className="text-xs text-gray-400">{jsCurrentRun.totalExecutionTimeMs ? `${(jsCurrentRun.totalExecutionTimeMs / 1000).toFixed(1)}s` : ''}</span>
                  </div>
                  <div className="grid grid-cols-5 gap-2 text-center">
                    <div><div className="text-lg font-bold text-orange-400" data-testid="text-js-score">{jsCurrentRun.totalScore}</div><div className="text-[10px] text-gray-500">Score</div></div>
                    <div><div className="text-lg font-bold text-green-400" data-testid="text-js-passed">{jsCurrentRun.passedCount}</div><div className="text-[10px] text-gray-500">Detected</div></div>
                    <div><div className="text-lg font-bold text-red-400" data-testid="text-js-failed">{jsCurrentRun.failedCount}</div><div className="text-[10px] text-gray-500">Missed</div></div>
                    <div><div className="text-lg font-bold text-purple-400" data-testid="text-js-adaptive">{jsCurrentRun.adaptivePassedCount || 0}</div><div className="text-[10px] text-gray-500">AI Finds</div></div>
                    <div><div className="text-lg font-bold text-yellow-400">{jsCurrentRun.maxPossibleScore}</div><div className="text-[10px] text-gray-500">Max</div></div>
                  </div>
                  {jsCurrentRun.totalLLMCalls > 0 && (
                    <div className="mt-2 flex items-center gap-3 text-[10px] text-gray-500 border-t border-[#333] pt-1.5">
                      <span>LLM: {jsCurrentRun.totalLLMCalls} calls</span>
                      <span>{(jsCurrentRun.totalLLMTimeMs / 1000).toFixed(1)}s reasoning</span>
                      <span>Model: {jsCurrentRun.ollamaAvailable ? 'Ollama' : 'Offline'}</span>
                    </div>
                  )}
                  {jsCurrentRun.byCategory && Object.keys(jsCurrentRun.byCategory).length > 0 && (
                    <div className="mt-2 grid grid-cols-3 gap-1">
                      {Object.entries(jsCurrentRun.byCategory).map(([cat, d]) => {
                        const dd = d as any;
                        return (
                        <div key={cat} className="p-1 bg-[#1e1e1e] rounded text-center">
                          <div className="text-[9px] text-orange-300 truncate">{cat}</div>
                          <div className="text-[10px] text-gray-300">{dd.passed}/{dd.total}</div>
                        </div>
                        );
                      })}
                    </div>
                  )}
                </div>
                <div className="space-y-1.5">
                  {jsCurrentRun.results.map(r => (
                    <div key={r.challengeId}>
                      <button
                        onClick={() => setExpandedResult(expandedResult === r.challengeId ? null : r.challengeId)}
                        data-testid={`js-result-${r.challengeId}`}
                        className="w-full p-2 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040] text-left"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: STATUS_COLORS[r.status] }} />
                            <span className="text-xs text-gray-200">{r.challengeName}</span>
                            {r.scanMode && r.scanMode !== 'hardcoded' && (
                              <span className="px-1 py-0.5 text-[8px] font-bold rounded" style={{ backgroundColor: `${SCAN_MODE_COLORS[r.scanMode]}20`, color: SCAN_MODE_COLORS[r.scanMode] }}>
                                {SCAN_MODE_LABELS[r.scanMode]}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <DiffLabel diff={r.difficulty} />
                            <span className="text-[10px] text-gray-500">{r.category}</span>
                            <span className="text-xs font-mono text-orange-400">{r.score}/{r.maxScore}</span>
                          </div>
                        </div>
                      </button>
                      {expandedResult === r.challengeId && (
                        <div className="ml-4 mt-1 p-2 bg-[#1e1e1e] rounded border border-[#333] text-xs space-y-1.5">
                          {r.scanResult && (
                            <>
                              <div className="flex items-center gap-2">
                                <span className={r.scanResult.detected ? 'text-green-400 font-bold' : 'text-red-400 font-bold'}>
                                  {r.scanResult.detected ? 'VULNERABILITY DETECTED' : 'NOT DETECTED'}
                                </span>
                                <span className="text-yellow-400">{Math.round(r.scanResult.confidence * 100)}% confidence</span>
                                <span className="text-gray-500">{r.scanResult.executionTimeMs}ms</span>
                              </div>
                              <div>
                                <span className="text-cyan-400">Technique:</span>
                                <span className="text-gray-300 ml-1">{r.scanResult.technique}</span>
                              </div>
                              <div>
                                <span className="text-cyan-400">Evidence:</span>
                                <div className="text-gray-300 mt-0.5 break-all bg-[#0d0d0d] p-1.5 rounded font-mono text-[11px]">{r.scanResult.evidence}</div>
                              </div>
                              {r.scanResult.request && (
                                <div>
                                  <span className="text-cyan-400">Request:</span>
                                  <div className="text-gray-500 font-mono text-[10px]">{r.scanResult.request}</div>
                                </div>
                              )}
                            </>
                          )}
                          {r.adaptiveScanResult && (
                            <div className="border-t border-[#333] pt-1.5 mt-1.5">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-purple-400 font-bold text-[10px]">ADAPTIVE SCAN</span>
                                <span className="text-gray-500 text-[10px]">{r.adaptiveScanResult.modelUsed}</span>
                                <span className="text-gray-500 text-[10px]">{r.adaptiveScanResult.totalLLMCalls} LLM calls</span>
                                <span className="text-gray-500 text-[10px]">{(r.adaptiveScanResult.llmTimeMs / 1000).toFixed(1)}s</span>
                              </div>
                              {r.adaptiveScanResult.reasoningTrace.map((t, i) => (
                                <div key={i} className="flex items-start gap-1.5 text-[10px] ml-2">
                                  <span className="text-purple-300 font-mono shrink-0">[{t.phase}]</span>
                                  <span className="text-gray-400">{t.action}</span>
                                  <span className="text-gray-500">-</span>
                                  <span className="text-gray-300">{t.result}</span>
                                  <span className="text-gray-600 shrink-0">{t.durationMs}ms</span>
                                </div>
                              ))}
                              {r.adaptiveScanResult.payloadAttempts.length > 0 && (
                                <div className="mt-1 border-t border-[#333] pt-1">
                                  <span className="text-[10px] text-purple-300">Payloads ({r.adaptiveScanResult.payloadAttempts.length}):</span>
                                  {r.adaptiveScanResult.payloadAttempts.map((p, i) => (
                                    <div key={i} className="ml-2 text-[10px] mt-0.5">
                                      <span className="text-cyan-400 font-mono">{p.method} {p.url.slice(0, 80)}</span>
                                      <span className="text-gray-500 ml-1">-&gt; {p.result?.status || '?'}</span>
                                      {p.reasoning && <div className="text-gray-500 ml-4 italic">{p.reasoning.slice(0, 120)}</div>}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          )}
                          {r.error && <div className="text-red-400">Error: {r.error}</div>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <p className="text-gray-500 text-sm">No Juice Shop scan results yet</p>
                <p className="text-gray-600 text-xs mt-1">Click "Scan Juice Shop" to run real vulnerability detection against OWASP Juice Shop</p>
                {jsStatus?.running && (
                  <p className="text-green-400 text-xs mt-2">Juice Shop is running at localhost:3000 ({jsStatus.total} challenges)</p>
                )}
              </div>
            )}
          </div>
        )}

        {mode === 'synthetic' && tab === 'history' && (
          <div className="p-4 space-y-2">
            {history.length === 0 ? (
              <p className="text-center text-gray-500 text-sm py-8">No previous runs</p>
            ) : (
              history.map(run => (
                <button
                  key={run.id}
                  onClick={() => { setCurrentRun(run); setTab('results'); }}
                  data-testid={`history-${run.id}`}
                  className="w-full p-3 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040] text-left"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-gray-400">{run.id}</span>
                    <span className="text-xs font-bold" style={{ color: run.passRate >= 80 ? '#22c55e' : run.passRate >= 50 ? '#f59e0b' : '#ef4444' }}>
                      {run.passRate}% ({run.passedCount}/{run.challengeCount})
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-500">{new Date(run.startedAt).toLocaleString()}</span>
                    <span className="text-xs text-yellow-400 font-mono">{run.totalScore}/{run.maxPossibleScore}pts</span>
                  </div>
                </button>
              ))
            )}
          </div>
        )}

        {mode === 'juiceshop' && tab === 'history' && (
          <div className="p-4 space-y-2">
            {jsHistory.length === 0 ? (
              <p className="text-center text-gray-500 text-sm py-8">No previous Juice Shop scans</p>
            ) : (
              jsHistory.map(run => (
                <button
                  key={run.id}
                  onClick={() => { setJsCurrentRun(run); setTab('results'); }}
                  data-testid={`js-history-${run.id}`}
                  className="w-full p-3 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040] text-left"
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-gray-400">{run.id}</span>
                      {run.scanMode && (
                        <span className="px-1 py-0.5 text-[8px] font-bold rounded" style={{ backgroundColor: `${SCAN_MODE_COLORS[run.scanMode]}20`, color: SCAN_MODE_COLORS[run.scanMode] }}>
                          {SCAN_MODE_LABELS[run.scanMode]}
                        </span>
                      )}
                    </div>
                    <span className="text-xs font-bold" style={{ color: run.passRate >= 80 ? '#22c55e' : run.passRate >= 50 ? '#f59e0b' : '#ef4444' }}>
                      {run.passRate}% ({run.passedCount}/{run.challengeCount})
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-500">{new Date(run.startedAt).toLocaleString()}</span>
                    <div className="flex items-center gap-2">
                      {(run.adaptivePassedCount || 0) > 0 && <span className="text-[10px] text-purple-400">{run.adaptivePassedCount} AI</span>}
                      <span className="text-xs text-orange-400 font-mono">{run.totalScore}/{run.maxPossibleScore}pts</span>
                      <span className="text-[10px] text-gray-500">{(run.totalExecutionTimeMs / 1000).toFixed(1)}s</span>
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        )}

        {mode === 'xbow' && tab === 'challenges' && (
          <div className="p-4 space-y-2">
            {!xbowStatus?.dockerAvailable && (
              <div className="p-3 bg-red-900/20 border border-red-800 rounded mb-3">
                <p className="text-xs text-red-300 font-medium">Docker is not available on this server.</p>
                <p className="text-[10px] text-red-400 mt-1">XBOW benchmarks spin up Docker containers for each challenge. To use this feature, run the app locally on your Kali desktop where Docker is installed: <code className="bg-red-900/40 px-1 rounded">git clone &lt;repo&gt; && npm install && npm run dev</code></p>
              </div>
            )}
            {xbowStatus?.dockerAvailable && !xbowStatus?.repoAvailable && (
              <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded mb-3">
                <p className="text-xs text-yellow-300">XBOW benchmark repo not cloned. Click "Clone Repo" to download the 104 challenge containers.</p>
              </div>
            )}
            {xbowStats && (
              <div className="p-3 bg-[#252526] rounded border border-[#2d2d2d] mb-3">
                <div className="grid grid-cols-4 gap-3 text-center">
                  <div><div className="text-lg font-bold text-emerald-400">{xbowStats.total}</div><div className="text-[10px] text-gray-500">Total</div></div>
                  <div><div className="text-lg font-bold text-green-400">{xbowStats.byLevel?.['1']?.count ?? xbowStats.byLevel?.['1'] ?? 0}</div><div className="text-[10px] text-gray-500">Easy</div></div>
                  <div><div className="text-lg font-bold text-yellow-400">{xbowStats.byLevel?.['2']?.count ?? xbowStats.byLevel?.['2'] ?? 0}</div><div className="text-[10px] text-gray-500">Medium</div></div>
                  <div><div className="text-lg font-bold text-red-400">{xbowStats.byLevel?.['3']?.count ?? xbowStats.byLevel?.['3'] ?? 0}</div><div className="text-[10px] text-gray-500">Hard</div></div>
                </div>
                {xbowStats.byTag && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {Object.entries(xbowStats.byTag as Record<string, any>).sort((a, b) => (b[1]?.count ?? b[1]) - (a[1]?.count ?? a[1])).map(([tag, val]) => (
                      <span key={tag} className="px-1.5 py-0.5 text-[9px] bg-[#1e1e1e] rounded text-emerald-300 cursor-pointer hover:bg-[#333]" onClick={() => setXbowSelectedTag(tag)}>
                        {tag}: {val?.count ?? val}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
            {filteredXBOWChallenges.map(c => (
              <div key={c.id} data-testid={`xbow-challenge-${c.id}`} className="p-3 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-200">{c.name}</span>
                  <div className="flex items-center gap-2">
                    <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${c.level === 1 ? 'bg-green-900/30 text-green-400' : c.level === 2 ? 'bg-yellow-900/30 text-yellow-400' : 'bg-red-900/30 text-red-400'}`}>
                      L{c.level}
                    </span>
                    <span className="text-xs text-emerald-400 font-mono">{c.points}pts</span>
                  </div>
                </div>
                <p className="text-xs text-gray-400 mb-1">{c.description}</p>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {c.tags.map(t => (
                    <span key={t} className="px-1 py-0.5 text-[9px] bg-[#1e1e1e] rounded text-emerald-300">{t}</span>
                  ))}
                  <span className="text-[9px] text-gray-600 font-mono ml-auto">{c.id}</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {mode === 'xbow' && tab === 'results' && (
          <div className="p-4">
            {xbowCurrentRun ? (
              <>
                <div className="mb-4 p-3 bg-[#252526] rounded border border-[#2d2d2d]">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-bold" style={{ color: xbowCurrentRun.status === 'completed' ? (xbowCurrentRun.passRate >= 80 ? '#22c55e' : xbowCurrentRun.passRate >= 50 ? '#f59e0b' : '#ef4444') : '#3b82f6' }}>
                      {xbowCurrentRun.status === 'running' ? 'Running...' : `${xbowCurrentRun.passRate}% Pass Rate`}
                    </span>
                    <span className="text-xs text-gray-400">{(xbowCurrentRun.totalExecutionTimeMs / 1000).toFixed(1)}s</span>
                  </div>
                  <div className="grid grid-cols-6 gap-2 text-center">
                    <div><div className="text-lg font-bold text-emerald-400" data-testid="text-xbow-score">{xbowCurrentRun.totalScore}</div><div className="text-[10px] text-gray-500">Score</div></div>
                    <div><div className="text-lg font-bold text-green-400" data-testid="text-xbow-passed">{xbowCurrentRun.passedCount}</div><div className="text-[10px] text-gray-500">Passed</div></div>
                    <div><div className="text-lg font-bold text-red-400" data-testid="text-xbow-failed">{xbowCurrentRun.failedCount}</div><div className="text-[10px] text-gray-500">Failed</div></div>
                    <div><div className="text-lg font-bold text-yellow-400">{xbowCurrentRun.errorCount}</div><div className="text-[10px] text-gray-500">Errors</div></div>
                    <div><div className="text-lg font-bold text-gray-400">{xbowCurrentRun.skippedCount}</div><div className="text-[10px] text-gray-500">Skipped</div></div>
                    <div><div className="text-lg font-bold text-cyan-400">{xbowCurrentRun.maxPossibleScore}</div><div className="text-[10px] text-gray-500">Max</div></div>
                  </div>
                  {xbowCurrentRun.totalLLMCalls > 0 && (
                    <div className="mt-2 flex items-center gap-3 text-[10px] text-gray-500 border-t border-[#333] pt-1.5">
                      <span>LLM: {xbowCurrentRun.totalLLMCalls} calls</span>
                      <span>{(xbowCurrentRun.totalLLMTimeMs / 1000).toFixed(1)}s reasoning</span>
                      <span>Model: {xbowCurrentRun.modelUsed || 'N/A'}</span>
                      <span>Docker: {xbowCurrentRun.dockerAvailable ? 'Yes' : 'No'}</span>
                    </div>
                  )}
                </div>
                <div className="space-y-1.5">
                  {xbowCurrentRun.results.map(r => (
                    <div key={r.challengeId}>
                      <button
                        onClick={() => setExpandedResult(expandedResult === r.challengeId ? null : r.challengeId)}
                        data-testid={`xbow-result-${r.challengeId}`}
                        className="w-full p-2 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040] text-left"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full inline-block" style={{ backgroundColor: r.status === 'passed' ? '#22c55e' : r.status === 'failed' ? '#ef4444' : r.status === 'error' ? '#f59e0b' : r.status === 'docker_unavailable' ? '#6b7280' : '#6b7280' }} />
                            <span className="text-xs text-gray-200">{r.challengeName}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`px-1 py-0.5 text-[9px] font-bold rounded ${r.level === 1 ? 'bg-green-900/30 text-green-400' : r.level === 2 ? 'bg-yellow-900/30 text-yellow-400' : 'bg-red-900/30 text-red-400'}`}>
                              L{r.level}
                            </span>
                            <span className="text-xs font-mono text-emerald-400">{r.score}/{r.maxScore}</span>
                            <span className="text-[10px] text-gray-500">{(r.executionTimeMs / 1000).toFixed(1)}s</span>
                          </div>
                        </div>
                      </button>
                      {expandedResult === r.challengeId && (
                        <div className="ml-4 mt-1 p-2 bg-[#1e1e1e] rounded border border-[#333] text-xs space-y-1.5">
                          <div className="flex items-center gap-2 text-[10px]">
                            <span className="text-gray-500">Tags:</span>
                            {r.tags.map(t => <span key={t} className="px-1 py-0.5 bg-[#252526] rounded text-emerald-300">{t}</span>)}
                          </div>
                          <div className="flex items-center gap-3 text-[10px]">
                            <span className="text-gray-500">Container:</span>
                            <span className={r.containerInfo.imagePulled ? 'text-green-400' : 'text-red-400'}>Build: {r.containerInfo.imagePulled ? 'OK' : 'FAIL'}</span>
                            <span className={r.containerInfo.containerStarted ? 'text-green-400' : 'text-red-400'}>Start: {r.containerInfo.containerStarted ? 'OK' : 'FAIL'}</span>
                            <span className={r.containerInfo.healthCheckPassed ? 'text-green-400' : 'text-red-400'}>Health: {r.containerInfo.healthCheckPassed ? 'OK' : 'FAIL'}</span>
                            {r.containerInfo.port && <span className="text-cyan-400">Port: {r.containerInfo.port}</span>}
                          </div>
                          {r.flagFound && (
                            <div>
                              <span className="text-green-400 font-bold">Flag Found:</span>
                              <span className="text-gray-300 ml-1 font-mono">{r.flagFound}</span>
                            </div>
                          )}
                          {r.status === 'passed' && (
                            <div className="text-green-400 font-bold">FLAG CAPTURED - Challenge solved!</div>
                          )}
                          {r.error && <div className="text-red-400">Error: {r.error}</div>}
                          {r.scanResult && (
                            <div className="border-t border-[#333] pt-1.5">
                              <span className="text-[10px] text-purple-400 font-bold">Adaptive Scan Result</span>
                              {r.scanResult.evidence && (
                                <div className="mt-1 bg-[#0d0d0d] p-1.5 rounded font-mono text-[10px] text-gray-300 break-all max-h-32 overflow-y-auto">
                                  {r.scanResult.evidence}
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="text-center py-12">
                <p className="text-gray-500 text-sm">No XBOW benchmark results yet</p>
                <p className="text-gray-600 text-xs mt-1">Click "Run XBOW" to test against real Docker CTF challenges</p>
                {!xbowStatus?.dockerAvailable && <p className="text-red-400 text-xs mt-2">Docker is required for XBOW challenges. Run this app on your Kali desktop to use Docker.</p>}
                {xbowStatus?.dockerAvailable && !xbowStatus?.repoAvailable && <p className="text-yellow-400 text-xs mt-2">Clone the XBOW repo first</p>}
              </div>
            )}
          </div>
        )}

        {mode === 'xbow' && tab === 'history' && (
          <div className="p-4 space-y-2">
            {xbowHistory.length === 0 ? (
              <p className="text-center text-gray-500 text-sm py-8">No previous XBOW runs</p>
            ) : (
              xbowHistory.map(run => (
                <button
                  key={run.id}
                  onClick={() => { setXbowCurrentRun(run); setTab('results'); }}
                  data-testid={`xbow-history-${run.id}`}
                  className="w-full p-3 bg-[#252526] rounded border border-[#2d2d2d] hover:border-[#404040] text-left"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-gray-400">{run.id}</span>
                    <span className="text-xs font-bold" style={{ color: run.passRate >= 80 ? '#22c55e' : run.passRate >= 50 ? '#f59e0b' : '#ef4444' }}>
                      {run.passRate}% ({run.passedCount}/{run.challengeCount})
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-gray-500">{new Date(run.startedAt).toLocaleString()}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-emerald-400 font-mono">{run.totalScore}/{run.maxPossibleScore}pts</span>
                      <span className="text-[10px] text-gray-500">{(run.totalExecutionTimeMs / 1000).toFixed(1)}s</span>
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        )}

        {mode === 'adaptive' && (
          <div className="p-4 space-y-4">
            <div className="p-3 bg-[#252526] rounded border border-[#2d2d2d]">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-bold text-purple-400">Autonomous Target Scanner</span>
                <span className={`px-1.5 py-0.5 text-[9px] rounded ${ollamaAvailable ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
                  {ollamaAvailable ? 'Ollama Ready' : 'Ollama Offline'}
                </span>
              </div>
              <p className="text-[11px] text-gray-400 mb-3">
                Point the AI scanner at any web application. It will autonomously probe endpoints, analyze responses,
                generate exploit payloads, and iterate until it finds vulnerabilities or exhausts its attempts.
              </p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={genericTarget}
                  onChange={e => setGenericTarget(e.target.value)}
                  placeholder="http://localhost:3000"
                  data-testid="input-generic-target"
                  className="flex-1 px-3 py-1.5 text-xs bg-[#1e1e1e] border border-[#404040] rounded text-gray-200 placeholder-gray-600 focus:border-purple-500 outline-none"
                />
                <button
                  onClick={startGenericScan}
                  disabled={genericScanning || !ollamaAvailable || !genericTarget}
                  data-testid="button-start-generic-scan"
                  className="px-4 py-1.5 text-xs bg-purple-600 hover:bg-purple-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded font-medium"
                >
                  {genericScanning ? 'Scanning...' : 'Scan Target'}
                </button>
              </div>
            </div>

            {genericScanning && (
              <div className="p-4 text-center">
                <div className="inline-block w-6 h-6 border-2 border-purple-400 border-t-transparent rounded-full animate-spin mb-2" />
                <p className="text-xs text-purple-300">AI is probing, analyzing, and exploiting...</p>
                <p className="text-[10px] text-gray-500 mt-1">This may take 30-120 seconds depending on model speed</p>
              </div>
            )}

            {genericResult && !genericScanning && (
              <div className="space-y-3">
                <div className="p-3 bg-[#252526] rounded border border-[#2d2d2d]">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-bold text-purple-400">Scan Results: {genericResult.targetUrl}</span>
                    <span className="text-xs text-gray-400">{(genericResult.totalTimeMs / 1000).toFixed(1)}s</span>
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    <div><div className="text-lg font-bold text-purple-400">{genericResult.findings.length}</div><div className="text-[10px] text-gray-500">Vulns Found</div></div>
                    <div><div className="text-lg font-bold text-cyan-400">{genericResult.totalEndpointsScanned}</div><div className="text-[10px] text-gray-500">Endpoints</div></div>
                    <div><div className="text-lg font-bold text-yellow-400">{genericResult.totalLLMCalls}</div><div className="text-[10px] text-gray-500">LLM Calls</div></div>
                    <div><div className="text-xs font-mono text-gray-400 mt-1">{genericResult.modelUsed}</div><div className="text-[10px] text-gray-500">Model</div></div>
                  </div>
                </div>

                {genericResult.verificationStats && (
                  <div className="p-3 bg-[#252526] rounded border border-[#2d2d2d]" data-testid="verification-stats-panel">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-bold text-emerald-400">Verification Pipeline</span>
                      <span className="text-[9px] text-gray-500">4-layer anti-hallucination</span>
                    </div>
                    <div className="grid grid-cols-5 gap-2 text-center">
                      <div><div className="text-lg font-bold text-green-400" data-testid="text-verified-confirmed">{genericResult.verificationStats.confirmed}</div><div className="text-[10px] text-gray-500">Confirmed</div></div>
                      <div><div className="text-lg font-bold text-yellow-400" data-testid="text-verified-unverified">{genericResult.verificationStats.unverified}</div><div className="text-[10px] text-gray-500">Unverified</div></div>
                      <div><div className="text-lg font-bold text-red-400" data-testid="text-verified-rejected">{genericResult.verificationStats.rejected}</div><div className="text-[10px] text-gray-500">Rejected</div></div>
                      <div><div className="text-lg font-bold text-gray-400" data-testid="text-verified-duplicate">{genericResult.verificationStats.duplicate}</div><div className="text-[10px] text-gray-500">Duplicate</div></div>
                      <div><div className="text-lg font-bold text-cyan-400">{genericResult.verificationStats.evidenceVerifiedCount}</div><div className="text-[10px] text-gray-500">Evidence OK</div></div>
                    </div>
                    <div className="mt-2 flex items-center gap-4 text-[10px] text-gray-500 border-t border-[#333] pt-1.5">
                      <span>Avg Confidence: <span className="text-yellow-300">{(genericResult.verificationStats.avgConfidence * 100).toFixed(0)}%</span></span>
                      <span>Avg Verified: <span className="text-green-300">{(genericResult.verificationStats.avgVerifiedConfidence * 100).toFixed(0)}%</span></span>
                      {genericResult.verificationStats.replayTestedCount > 0 && (
                        <span>Replay: <span className="text-cyan-300">{genericResult.verificationStats.replayConfirmedCount}/{genericResult.verificationStats.replayTestedCount}</span></span>
                      )}
                    </div>
                  </div>
                )}

                {evidenceStats && evidenceStats.totalArtifacts > 0 && (
                  <div className="p-3 bg-[#252526] rounded border border-[#2d2d2d]" data-testid="evidence-stats-panel">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-xs font-bold text-blue-400">Evidence Storage</span>
                    </div>
                    <div className="grid grid-cols-4 gap-2 text-center">
                      <div><div className="text-lg font-bold text-blue-400">{evidenceStats.totalMissions}</div><div className="text-[10px] text-gray-500">Missions</div></div>
                      <div><div className="text-lg font-bold text-cyan-400">{evidenceStats.totalFindings}</div><div className="text-[10px] text-gray-500">Findings</div></div>
                      <div><div className="text-lg font-bold text-purple-400">{evidenceStats.totalArtifacts}</div><div className="text-[10px] text-gray-500">Artifacts</div></div>
                      <div><div className="text-xs font-mono text-gray-400 mt-1">{(evidenceStats.totalSizeBytes / (1024*1024)).toFixed(1)}MB</div><div className="text-[10px] text-gray-500">Disk Usage</div></div>
                    </div>
                  </div>
                )}

                {genericResult.findings.length === 0 && (
                  <div className="p-3 bg-[#252526] rounded border border-[#2d2d2d] text-center">
                    <p className="text-gray-500 text-sm">No vulnerabilities found</p>
                    <p className="text-gray-600 text-xs mt-1">The target may be well-secured, or try a different target</p>
                  </div>
                )}

                {genericResult.findings.map((f, i) => {
                  const v = f.verification;
                  const vStyle = v ? VERIFICATION_COLORS[v.status] : null;
                  return (
                  <div key={i} data-testid={`generic-finding-${i}`} className={`p-3 bg-[#252526] rounded border ${v?.status === 'rejected' ? 'border-red-900/40 opacity-60' : v?.status === 'duplicate' ? 'border-gray-700/40 opacity-50' : 'border-[#2d2d2d]'}`}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 text-[9px] font-bold rounded uppercase" style={{ backgroundColor: `${SEVERITY_COLORS[f.severity] || '#666'}20`, color: SEVERITY_COLORS[f.severity] || '#666' }}>
                          {f.severity}
                        </span>
                        <span className="text-sm font-medium text-gray-200">{f.vulnerability}</span>
                        {vStyle && (
                          <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${vStyle.bg} ${vStyle.text}`} data-testid={`verification-badge-${i}`}>
                            {vStyle.label}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {v && v.verifiedConfidence !== f.confidence && (
                          <span className="text-[10px] text-gray-500 line-through">{Math.round(f.confidence * 100)}%</span>
                        )}
                        <span className={`text-xs ${v?.status === 'confirmed' ? 'text-green-400' : v?.status === 'rejected' ? 'text-red-400' : 'text-yellow-400'}`}>
                          {Math.round((v?.verifiedConfidence ?? f.confidence) * 100)}%
                        </span>
                        {!f.browserVerification && (
                          <button
                            onClick={() => browserVerifyFinding(i)}
                            disabled={browserVerifying !== null}
                            data-testid={`button-browser-verify-${i}`}
                            className="px-2 py-0.5 text-[9px] bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded"
                          >
                            {browserVerifying === i ? 'Verifying...' : 'Browser Verify'}
                          </button>
                        )}
                      </div>
                    </div>
                    <div className="text-[10px] text-gray-400 mb-1">Endpoint: <span className="text-cyan-300 font-mono">{f.endpoint}</span></div>
                    <div className="text-[10px] text-gray-400 mb-1">Technique: <span className="text-gray-300">{f.technique}</span></div>
                    {v && (
                      <div className="flex items-center gap-2 text-[10px] mb-1 flex-wrap">
                        {v.evidenceVerified && <span className="text-green-400">Evidence verified</span>}
                        {!v.evidenceVerified && v.status !== 'duplicate' && <span className="text-red-400">Evidence failed</span>}
                        {v.isDuplicate && <span className="text-gray-400">Duplicate finding</span>}
                        {v.replayConfirmed === true && <span className="text-cyan-400">Replay confirmed</span>}
                        {v.replayConfirmed === false && <span className="text-orange-400">Replay failed</span>}
                        {v.rejectionReason && <span className="text-red-300 italic">{v.rejectionReason}</span>}
                        <span className="text-gray-600 font-mono ml-auto">{v.fingerprint}</span>
                      </div>
                    )}
                    {f.browserVerification && (
                      <div className="mt-1.5 p-2 bg-[#0d0d0d] rounded border border-[#333] space-y-1.5">
                        <div className="flex items-center gap-2">
                          <span className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${
                            f.browserVerification.status === 'verified' ? 'bg-green-900/30 text-green-400' :
                            f.browserVerification.status === 'false_positive' ? 'bg-red-900/30 text-red-400' :
                            'bg-orange-900/30 text-orange-400'
                          }`}>
                            {f.browserVerification.status === 'verified' ? 'BROWSER VERIFIED' :
                             f.browserVerification.status === 'false_positive' ? 'BROWSER FALSE POSITIVE' :
                             'BROWSER ERROR'}
                          </span>
                          <span className="text-[10px] text-gray-500">{f.browserVerification.durationMs}ms</span>
                        </div>
                        {f.browserVerification.domHashBefore && (
                          <div className="grid grid-cols-2 gap-2 text-[10px]">
                            <div>
                              <span className="text-gray-500">DOM Before: </span>
                              <span className="text-cyan-300 font-mono">{f.browserVerification.domHashBefore.slice(0, 12)}...</span>
                            </div>
                            <div>
                              <span className="text-gray-500">DOM After: </span>
                              <span className="text-purple-300 font-mono">{f.browserVerification.domHashAfter?.slice(0, 12)}...</span>
                            </div>
                            <div>
                              <span className="text-gray-500">Visual Before: </span>
                              <span className="text-cyan-300 font-mono">{f.browserVerification.screenshotHashBefore?.slice(0, 12)}...</span>
                            </div>
                            <div>
                              <span className="text-gray-500">Visual After: </span>
                              <span className="text-purple-300 font-mono">{f.browserVerification.screenshotHashAfter?.slice(0, 12)}...</span>
                            </div>
                          </div>
                        )}
                        <div className="flex items-center gap-3 text-[10px]">
                          {f.browserVerification.domChangedSignificantly && <span className="text-green-400">DOM changed</span>}
                          {f.browserVerification.visualChangedSignificantly && <span className="text-green-400">Visual changed</span>}
                          {!f.browserVerification.domChangedSignificantly && !f.browserVerification.visualChangedSignificantly && <span className="text-red-400">No visual/DOM change detected</span>}
                        </div>
                        {f.browserVerification.evidenceAttachments.length > 0 && (
                          <div className="flex items-center gap-2 flex-wrap">
                            {f.browserVerification.evidenceAttachments.map((a, ai) => (
                              <span key={ai} className="px-1.5 py-0.5 text-[9px] bg-[#1e1e1e] rounded text-gray-400 border border-[#333]">
                                {a.type}: {a.label || a.type} ({(a.sizeBytes / 1024).toFixed(1)}KB)
                              </span>
                            ))}
                          </div>
                        )}
                        {f.browserVerification.errorMessage && (
                          <div className="text-[10px] text-red-400 italic">{f.browserVerification.errorMessage}</div>
                        )}
                      </div>
                    )}
                    <div className="text-[11px] text-gray-300 bg-[#0d0d0d] p-1.5 rounded font-mono break-all">{f.evidence}</div>
                    {f.trace.length > 0 && (
                      <div className="mt-1.5 border-t border-[#333] pt-1">
                        {f.trace.map((t, j) => (
                          <div key={j} className="flex items-start gap-1.5 text-[10px]">
                            <span className="text-purple-300 font-mono shrink-0">[{t.phase}]</span>
                            <span className="text-gray-400">{t.result}</span>
                            <span className="text-gray-600 shrink-0">{t.durationMs}ms</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  );
                })}
              </div>
            )}

            {!genericResult && !genericScanning && (
              <div className="text-center py-8">
                <p className="text-gray-500 text-sm">Enter a target URL and click "Scan Target"</p>
                <p className="text-gray-600 text-xs mt-1">The AI will autonomously discover and exploit vulnerabilities</p>
                {!ollamaAvailable && <p className="text-red-400 text-xs mt-2">Start Ollama to enable adaptive scanning</p>}
              </div>
            )}
          </div>
        )}
      </ScrollArea>
    </div>
  );
}

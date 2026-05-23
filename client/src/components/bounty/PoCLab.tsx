import { useState, useEffect } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import {
  Play, Loader2, FlaskConical, CheckCircle, XCircle,
  Clock, ChevronRight, FileCode, AlertCircle
} from 'lucide-react';
import { csrfFetch } from '@/services/api';
import { useToast } from '@/hooks/use-toast';

interface PoCResult {
  id: string;
  vulnerability_type: string;
  target: string;
  payload: string;
  success: boolean;
  output: string;
  evidence?: string;
  timestamp: string;
}

const VULN_TYPES = [
  { value: 'xss', label: 'XSS' },
  { value: 'sqli', label: 'SQL Injection' },
  { value: 'rce', label: 'RCE' },
  { value: 'lfi', label: 'LFI' },
  { value: 'ssrf', label: 'SSRF' },
  { value: 'xxe', label: 'XXE' },
  { value: 'csrf', label: 'CSRF' },
  { value: 'auth_bypass', label: 'Auth Bypass' },
  { value: 'idor', label: 'IDOR' },
];

export function PoCLab() {
  const [vulnType, setVulnType] = useState('xss');
  const [target, setTarget] = useState('');
  const [payload, setPayload] = useState('');
  const [testing, setTesting] = useState(false);
  const [currentResult, setCurrentResult] = useState<PoCResult | null>(null);
  const [history, setHistory] = useState<PoCResult[]>([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const { toast } = useToast();

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await fetch('/api/bounty/poc/results');
      const data = await response.json();
      if (data.success) {
        setHistory(data.results || []);
      }
    } catch (error) {
      console.error('Failed to fetch PoC history:', error);
    }
  };

  const runTest = async () => {
    if (!target || !payload) return;
    setTesting(true);
    setCurrentResult(null);
    setError('');
    try {
      const response = await csrfFetch('/api/bounty/poc/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload,
          target,
          vulnerability_type: vulnType,
        }),
      });
      const data = await response.json();
      if (data.success !== undefined && data.result) {
        setCurrentResult(data.result);
        fetchHistory();
      } else if (data.id) {
        setCurrentResult(data as PoCResult);
        fetchHistory();
      }
    } catch (err) {
      const message = 'Failed to run PoC test. The backend service may be unavailable.';
      setError(message);
      toast({ variant: 'destructive', title: 'Test Failed', description: message });
    } finally {
      setTesting(false);
    }
  };

  const viewHistoryResult = async (id: string) => {
    setSelectedHistoryId(id);
    try {
      const response = await fetch(`/api/bounty/poc/results/${id}`);
      const data = await response.json();
      if (data.success && data.result) {
        setCurrentResult(data.result);
      }
    } catch (error) {
      console.error('Failed to fetch result detail:', error);
    }
  };

  const displayResult = currentResult;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-[#3d3d3d]">
        <FlaskConical className="w-6 h-6 text-cyan-400" />
        <h1 className="text-2xl font-bold text-gray-100">PoC Lab</h1>
        <span className="text-xs text-gray-500">Proof of Concept Testing Sandbox</span>
      </div>

      <div className="flex flex-1 min-h-0">
        <div className="w-[45%] border-r border-[#3d3d3d] flex flex-col">
          <ScrollArea className="flex-1">
            <div className="p-6 space-y-4">
              <h3 className="text-sm font-semibold text-gray-300">Test Configuration</h3>

              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Vulnerability Type</Label>
                <Select value={vulnType} onValueChange={setVulnType}>
                  <SelectTrigger className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-vuln-type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {VULN_TYPES.map(vt => (
                      <SelectItem key={vt.value} value={vt.value}>{vt.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Target URL</Label>
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://target.com/endpoint"
                  className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9"
                  data-testid="input-poc-target"
                />
              </div>

              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Payload</Label>
                <Textarea
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  placeholder="Enter your payload here..."
                  className="bg-[#0d0d0d] border-[#3d3d3d] text-green-400 font-mono text-sm min-h-[120px]"
                  data-testid="textarea-poc-payload"
                />
              </div>

              <Button
                onClick={runTest}
                disabled={testing || !target || !payload}
                className="w-full bg-cyan-600 hover:bg-cyan-700 text-white h-10"
                data-testid="button-run-test"
              >
                {testing ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Running Test...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" /> Run Test
                  </>
                )}
              </Button>
            </div>
          </ScrollArea>
        </div>

        <div className="flex-1 flex flex-col min-h-0">
          <ScrollArea className="flex-1">
            <div className="p-6 space-y-4">
              <h3 className="text-sm font-semibold text-gray-300">Results</h3>

              {error && (
                <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-md mb-4" data-testid="text-error">
                  <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                  <p className="text-xs text-red-400">{error}</p>
                </div>
              )}

              {!displayResult ? (
                !error && (
                  <div className="flex flex-col items-center justify-center py-16 text-gray-500" data-testid="text-no-results">
                    <FileCode className="w-12 h-12 mb-4 text-gray-600" />
                    <p className="text-sm">Run a test to see results</p>
                  </div>
                )
              ) : (
                <div className="space-y-4">
                  <Card className={`p-6 border ${
                    displayResult.success
                      ? 'bg-green-500/5 border-green-500/30'
                      : 'bg-red-500/5 border-red-500/30'
                  }`}>
                    <div className="flex items-center gap-3 mb-3">
                      {displayResult.success ? (
                        <CheckCircle className="w-10 h-10 text-green-400" />
                      ) : (
                        <XCircle className="w-10 h-10 text-red-400" />
                      )}
                      <div>
                        <p className={`text-lg font-bold ${displayResult.success ? 'text-green-400' : 'text-red-400'}`} data-testid="text-test-status">
                          {displayResult.success ? 'Vulnerability Confirmed' : 'Test Failed'}
                        </p>
                        <p className="text-xs text-gray-500">
                          {VULN_TYPES.find(v => v.value === displayResult.vulnerability_type)?.label || displayResult.vulnerability_type}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 text-[10px] text-gray-500">
                      <Clock className="w-3 h-3" />
                      <span>{new Date(displayResult.timestamp).toLocaleString()}</span>
                    </div>
                  </Card>

                  <div>
                    <Label className="text-xs text-gray-400 mb-1 block">Output</Label>
                    <pre
                      className="bg-[#0d0d0d] border border-[#3d3d3d] rounded-md p-4 text-xs text-green-400 font-mono whitespace-pre-wrap overflow-x-auto max-h-48"
                      data-testid="text-test-output"
                    >
                      {displayResult.output || 'No output captured'}
                    </pre>
                  </div>

                  {displayResult.evidence && (
                    <div>
                      <Label className="text-xs text-gray-400 mb-1 block">Evidence</Label>
                      <pre
                        className="bg-[#0d0d0d] border border-[#3d3d3d] rounded-md p-4 text-xs text-orange-400 font-mono whitespace-pre-wrap overflow-x-auto max-h-32"
                        data-testid="text-test-evidence"
                      >
                        {displayResult.evidence}
                      </pre>
                    </div>
                  )}

                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <span>Target: <span className="text-gray-300">{displayResult.target}</span></span>
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>
        </div>
      </div>

      <div className="border-t border-[#3d3d3d]">
        <div className="px-6 py-2 flex items-center justify-between">
          <span className="text-xs text-gray-400 font-semibold">Test History</span>
          <Badge variant="outline" className="text-[10px] text-gray-500 border-gray-600">
            {history.length}
          </Badge>
        </div>
        <ScrollArea className="h-36">
          <div className="px-6 pb-3 space-y-1">
            {history.length === 0 ? (
              <p className="text-xs text-gray-600 py-2">No test history yet</p>
            ) : (
              history.map(result => (
                <button
                  key={result.id}
                  onClick={() => viewHistoryResult(result.id)}
                  className={`w-full text-left px-3 py-2 rounded flex items-center gap-3 transition-colors ${
                    selectedHistoryId === result.id
                      ? 'bg-cyan-600/20 border border-cyan-500/30'
                      : 'hover:bg-[#252526] border border-transparent'
                  }`}
                  data-testid={`button-history-${result.id}`}
                >
                  {result.success ? (
                    <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                  )}
                  <Badge variant="outline" className="text-[10px] text-gray-400 border-gray-600">
                    {result.vulnerability_type}
                  </Badge>
                  <span className="text-xs text-gray-300 truncate flex-1">{result.target}</span>
                  <span className="text-[10px] text-gray-600 flex-shrink-0">
                    {new Date(result.timestamp).toLocaleTimeString()}
                  </span>
                  <ChevronRight className="w-3 h-3 text-gray-600 flex-shrink-0" />
                </button>
              ))
            )}
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}

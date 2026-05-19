import { useState } from 'react';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import {
  Search, Loader2, Shield, ExternalLink, AlertCircle,
  ChevronDown, ChevronUp, Zap
} from 'lucide-react';

interface CVE {
  cveId: string;
  name: string;
  description: string;
  severity: string;
  cvss: number;
  publishedDate: string;
  exploitAvailable: boolean;
  affectedProducts: string[];
  references: string[];
}

function getCvssColor(cvss: number): string {
  if (cvss >= 9) return 'text-red-400';
  if (cvss >= 7) return 'text-orange-400';
  if (cvss >= 4) return 'text-yellow-400';
  return 'text-green-400';
}

function getCvssBg(cvss: number): string {
  if (cvss >= 9) return 'bg-red-500/20 border-red-500/30';
  if (cvss >= 7) return 'bg-orange-500/20 border-orange-500/30';
  if (cvss >= 4) return 'bg-yellow-500/20 border-yellow-500/30';
  return 'bg-green-500/20 border-green-500/30';
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
};

const YEARS = ['all', '2025', '2024', '2023', '2022', '2021', '2020'];

export function CVEIntel() {
  const [query, setQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [yearFilter, setYearFilter] = useState('all');
  const [exploitFilter, setExploitFilter] = useState(false);
  const [cves, setCves] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [cveDetail, setCveDetail] = useState<CVE | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const searchCves = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const params = new URLSearchParams({ query: query.trim() });
      if (severityFilter !== 'all') params.set('severity', severityFilter);
      if (yearFilter !== 'all') params.set('year', yearFilter);
      const response = await fetch(`/api/bounty/cve/search?${params}`);
      const data = await response.json();
      if (data.success) {
        setCves(data.cves || []);
      }
    } catch (error) {
      console.error('Failed to search CVEs:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchCveDetail = async (cveId: string) => {
    if (expandedCve === cveId) {
      setExpandedCve(null);
      setCveDetail(null);
      return;
    }
    setExpandedCve(cveId);
    setLoadingDetail(true);
    try {
      const response = await fetch(`/api/bounty/cve/${cveId}`);
      const data = await response.json();
      if (data.success && data.cve) {
        setCveDetail(data.cve);
      }
    } catch (error) {
      console.error('Failed to fetch CVE detail:', error);
    } finally {
      setLoadingDetail(false);
    }
  };

  const filteredCves = exploitFilter ? cves.filter(c => c.exploitAvailable) : cves;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <div className="px-6 py-4 border-b border-[#3d3d3d]">
        <div className="flex items-center gap-3 mb-4">
          <Shield className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">CVE Intelligence</h1>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex-1">
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search CVEs (e.g., Apache, Log4j, WordPress)..."
              className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9"
              onKeyDown={(e) => e.key === 'Enter' && searchCves()}
              data-testid="input-cve-search"
            />
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9 w-32" data-testid="select-cve-severity">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={yearFilter} onValueChange={setYearFilter}>
            <SelectTrigger className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9 w-28" data-testid="select-cve-year">
              <SelectValue placeholder="Year" />
            </SelectTrigger>
            <SelectContent>
              {YEARS.map(y => (
                <SelectItem key={y} value={y}>{y === 'all' ? 'All Years' : y}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setExploitFilter(!exploitFilter)}
            className={`h-9 text-xs ${
              exploitFilter
                ? 'bg-red-500/20 border-red-500/30 text-red-400'
                : 'bg-[#252526] border-[#3d3d3d] text-gray-400'
            }`}
            data-testid="button-exploit-filter"
          >
            <Zap className="w-3 h-3 mr-1" /> Exploit Available
          </Button>
          <Button
            onClick={searchCves}
            disabled={loading || !query.trim()}
            className="bg-cyan-600 hover:bg-cyan-700 text-white h-9"
            data-testid="button-cve-search"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          </Button>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-6">
          {cves.length === 0 && !loading ? (
            <div className="flex flex-col items-center justify-center py-20 text-gray-500" data-testid="text-empty-state">
              <Shield className="w-12 h-12 mb-4 text-gray-600" />
              <p className="text-sm">Search for CVEs to get started</p>
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center py-20">
              <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
            </div>
          ) : (
            <div className="space-y-3">
              <p className="text-xs text-gray-500 mb-3" data-testid="text-result-count">
                {filteredCves.length} result(s) found
              </p>
              {filteredCves.map(cve => {
                const isExpanded = expandedCve === cve.cveId;
                return (
                  <Card
                    key={cve.cveId}
                    className={`bg-[#252526] border-[#3d3d3d] p-4 cursor-pointer transition-colors hover:border-gray-500 ${
                      isExpanded ? 'border-cyan-500/30' : ''
                    }`}
                    onClick={() => fetchCveDetail(cve.cveId)}
                    data-testid={`card-cve-${cve.cveId}`}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-sm font-bold text-gray-100">{cve.cveId}</span>
                          {cve.exploitAvailable && (
                            <span className="w-2 h-2 rounded-full bg-red-500" title="Exploit Available" data-testid={`indicator-exploit-${cve.cveId}`} />
                          )}
                        </div>
                        <p className="text-xs text-gray-300">{cve.name}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge className={`text-[10px] ${SEVERITY_BADGE[cve.severity] || SEVERITY_BADGE.medium}`}>
                          {cve.severity}
                        </Badge>
                        <span className={`text-sm font-bold px-2 py-0.5 rounded border ${getCvssBg(cve.cvss)} ${getCvssColor(cve.cvss)}`} data-testid={`text-cvss-${cve.cveId}`}>
                          {cve.cvss.toFixed(1)}
                        </span>
                        {isExpanded ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
                      </div>
                    </div>

                    <div className="flex items-center gap-3 text-[10px] text-gray-500">
                      <span>Published: {new Date(cve.publishedDate).toLocaleDateString()}</span>
                      {cve.exploitAvailable && (
                        <span className="text-red-400 flex items-center gap-1">
                          <AlertCircle className="w-3 h-3" /> Exploit Available
                        </span>
                      )}
                    </div>

                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-[#3d3d3d] space-y-3" onClick={(e) => e.stopPropagation()}>
                        {loadingDetail ? (
                          <div className="flex items-center gap-2 py-2">
                            <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
                            <span className="text-xs text-gray-500">Loading details...</span>
                          </div>
                        ) : cveDetail ? (
                          <>
                            <div>
                              <Label className="text-[10px] text-gray-500 block mb-1">Description</Label>
                              <p className="text-xs text-gray-300" data-testid={`text-description-${cve.cveId}`}>
                                {cveDetail.description}
                              </p>
                            </div>

                            {(cveDetail.affectedProducts || []).length > 0 && (
                              <div>
                                <Label className="text-[10px] text-gray-500 block mb-1">Affected Products</Label>
                                <div className="flex flex-wrap gap-1">
                                  {cveDetail.affectedProducts.map((product, i) => (
                                    <Badge key={i} variant="outline" className="text-[10px] text-gray-300 border-[#3d3d3d]">
                                      {product}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}

                            {(cveDetail.references || []).length > 0 && (
                              <div>
                                <Label className="text-[10px] text-gray-500 block mb-1">References</Label>
                                <div className="space-y-1">
                                  {cveDetail.references.map((ref, i) => (
                                    <a
                                      key={i}
                                      href={ref}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 truncate"
                                      data-testid={`link-reference-${cve.cveId}-${i}`}
                                    >
                                      <ExternalLink className="w-3 h-3 flex-shrink-0" />
                                      <span className="truncate">{ref}</span>
                                    </a>
                                  ))}
                                </div>
                              </div>
                            )}

                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-gray-500">Exploit:</span>
                              {cveDetail.exploitAvailable ? (
                                <Badge className="text-[10px] bg-red-500/20 text-red-400 border-red-500/30">
                                  Available
                                </Badge>
                              ) : (
                                <Badge className="text-[10px] bg-gray-500/20 text-gray-400 border-gray-500/30">
                                  Not Available
                                </Badge>
                              )}
                            </div>
                          </>
                        ) : null}
                      </div>
                    )}
                  </Card>
                );
              })}
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

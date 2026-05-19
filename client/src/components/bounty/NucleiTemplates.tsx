import { useState, useEffect, useCallback } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Sparkles, Play, Search, RefreshCw } from 'lucide-react';

interface NucleiTemplate {
  id?: string;
  name: string;
  path: string;
  severity: string;
  tags?: string[];
  author?: string;
}

function getSeverityBadge(severity: string) {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'low': return 'bg-green-500/20 text-green-400 border-green-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

export function NucleiTemplates() {
  const [templates, setTemplates] = useState<NucleiTemplate[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTemplate, setSelectedTemplate] = useState<NucleiTemplate | null>(null);
  const [yamlContent, setYamlContent] = useState('');
  const [runTarget, setRunTarget] = useState('');
  const [running, setRunning] = useState(false);
  const [runResult, setRunResult] = useState('');

  useEffect(() => {
    fetchTemplates();
    const interval = setInterval(() => {
      if (!searchQuery.trim()) fetchTemplates();
    }, 15000);
    return () => clearInterval(interval);
  }, [searchQuery]);

  const extractTemplates = (data: any): NucleiTemplate[] => {
    if (Array.isArray(data?.templates)) return data.templates;
    if (Array.isArray(data)) return data;
    return [];
  };

  const fetchTemplates = async () => {
    try {
      const response = await fetch('/api/bounty/nuclei/templates');
      const data = await response.json();
      setTemplates(extractTemplates(data));
    } catch (error) {
      console.error('Failed to fetch templates:', error);
      setTemplates([]);
    }
  };

  const searchTemplates = async (query: string) => {
    setSearchQuery(query);
    if (!query.trim()) {
      fetchTemplates();
      return;
    }
    try {
      const response = await fetch(`/api/bounty/nuclei/templates?search=${encodeURIComponent(query)}`);
      const data = await response.json();
      setTemplates(extractTemplates(data));
    } catch (error) {
      console.error('Search failed:', error);
      setTemplates([]);
    }
  };

  const selectTemplate = async (template: NucleiTemplate) => {
    setSelectedTemplate(template);
    setYamlContent('');
    setRunResult('');
    try {
      const response = await fetch(`/api/bounty/nuclei/templates/${encodeURIComponent(template.id || template.name)}`);
      const data = await response.json();
      setYamlContent(data.content || data.yaml || '');
    } catch (error) {
      console.error('Failed to read template:', error);
    }
  };

  const runTemplate = async () => {
    if (!selectedTemplate || !runTarget.trim()) return;
    setRunning(true);
    setRunResult('');
    try {
      const response = await csrfFetch('/api/bounty/nuclei/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ templateId: selectedTemplate.id || selectedTemplate.name, target: runTarget }),
      });
      const data = await response.json();
      setRunResult(data.output || data.result || JSON.stringify(data, null, 2));
    } catch (error) {
      setRunResult(`Error: ${error}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6">
      <div className="mb-4">
        <div className="flex items-center gap-3 mb-2">
          <Sparkles className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">Nuclei Templates</h1>
        </div>
        <p className="text-sm text-gray-400">Browse and run vulnerability scanning templates</p>
      </div>

      <Card className="bg-[#252526] border-[#3d3d3d] p-3 mb-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <Input
              placeholder="Search templates..."
              value={searchQuery}
              onChange={(e) => searchTemplates(e.target.value)}
              className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 pl-9"
              data-testid="input-search-templates"
            />
          </div>
        </div>
      </Card>

      <div className="flex gap-4 flex-1 min-h-0">
        <Card className="bg-[#252526] border-[#3d3d3d] w-80 flex-shrink-0 flex flex-col">
          <ScrollArea className="flex-1">
            <div className="p-2 space-y-1">
              {templates.length === 0 ? (
                <p className="text-xs text-gray-500 p-3">No templates found</p>
              ) : (
                templates.map((template, idx) => (
                  <button
                    key={template.path || idx}
                    onClick={() => selectTemplate(template)}
                    className={`w-full text-left p-3 rounded transition-colors ${
                      selectedTemplate?.path === template.path
                        ? 'bg-cyan-600/20 border border-cyan-500/30'
                        : 'hover:bg-[#333] border border-transparent'
                    }`}
                    data-testid={`button-template-${idx}`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-sm text-gray-200 font-medium truncate">{template.name}</span>
                      <Badge className={`text-[10px] flex-shrink-0 ${getSeverityBadge(template.severity)}`}>
                        {template.severity}
                      </Badge>
                    </div>
                    {template.tags && template.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {template.tags.slice(0, 3).map(tag => (
                          <span key={tag} className="text-[10px] px-1.5 py-0.5 bg-[#1e1e1e] text-gray-500 rounded">
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </button>
                ))
              )}
            </div>
          </ScrollArea>
        </Card>

        <div className="flex-1 flex flex-col min-h-0">
          {!selectedTemplate ? (
            <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
              Select a template to view its content
            </div>
          ) : (
            <>
              <Card className="bg-[#252526] border-[#3d3d3d] p-3 mb-3">
                <div className="flex gap-2">
                  <Input
                    placeholder="Target (e.g., https://example.com)"
                    value={runTarget}
                    onChange={(e) => setRunTarget(e.target.value)}
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 font-mono text-sm"
                    data-testid="input-run-target"
                  />
                  <Button
                    onClick={runTemplate}
                    disabled={running || !runTarget.trim()}
                    className="bg-green-600 hover:bg-green-700 text-white h-9"
                    data-testid="button-run-template"
                  >
                    <Play className="w-4 h-4 mr-1" />
                    {running ? 'Running...' : 'Run Template'}
                  </Button>
                </div>
              </Card>

              <ScrollArea className="flex-1">
                <pre className="bg-[#252526] border border-[#3d3d3d] rounded p-4 text-xs text-cyan-400 font-mono whitespace-pre-wrap">
                  {yamlContent || 'Loading template content...'}
                </pre>
              </ScrollArea>

              {runResult && (
                <Card className="bg-[#252526] border-[#3d3d3d] p-3 mt-3 max-h-48">
                  <ScrollArea className="h-full">
                    <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap" data-testid="text-run-result">
                      {runResult}
                    </pre>
                  </ScrollArea>
                </Card>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

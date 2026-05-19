import { useState, useEffect } from 'react';
import { csrfFetch } from '@/services/api';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import {
  Plus, Play, Trash2, Save, Loader2, GitBranch, Zap,
  AlertTriangle, ChevronRight, X, ArrowDown
} from 'lucide-react';

interface WorkflowStep {
  id: string;
  name: string;
  type: 'scan' | 'analyze' | 'exploit' | 'report';
  tool: string;
  critical: boolean;
}

interface Workflow {
  id: string;
  name: string;
  description: string;
  steps: WorkflowStep[];
  trigger: string;
  status: 'draft' | 'active' | 'archived';
  createdAt?: string;
}

const STEP_TYPE_COLORS: Record<string, string> = {
  scan: 'text-cyan-400 border-cyan-400/30 bg-cyan-400/10',
  analyze: 'text-purple-400 border-purple-400/30 bg-purple-400/10',
  exploit: 'text-red-400 border-red-400/30 bg-red-400/10',
  report: 'text-green-400 border-green-400/30 bg-green-400/10',
};

const STATUS_COLORS: Record<string, string> = {
  draft: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  active: 'bg-green-500/20 text-green-400 border-green-500/30',
  archived: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
};

export function WorkflowBuilder() {
  const [workflows, setWorkflows] = useState<Workflow[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [executeTarget, setExecuteTarget] = useState('');
  const [showExecutePrompt, setShowExecutePrompt] = useState(false);
  const [activeExecutions, setActiveExecutions] = useState<string[]>([]);
  const [editName, setEditName] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [editSteps, setEditSteps] = useState<WorkflowStep[]>([]);
  const [editTrigger, setEditTrigger] = useState('manual');
  const [isNew, setIsNew] = useState(false);

  useEffect(() => {
    fetchWorkflows();
  }, []);

  const fetchWorkflows = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/bounty/workflows');
      const data = await response.json();
      if (data.success) {
        setWorkflows(data.workflows || []);
      }
    } catch (error) {
      console.error('Failed to fetch workflows:', error);
    } finally {
      setLoading(false);
    }
  };

  const selectWorkflow = (wf: Workflow) => {
    setSelectedId(wf.id);
    setEditName(wf.name);
    setEditDescription(wf.description);
    setEditSteps(wf.steps || []);
    setEditTrigger(wf.trigger || 'manual');
    setIsNew(false);
  };

  const createNew = () => {
    setSelectedId(null);
    setEditName('');
    setEditDescription('');
    setEditSteps([]);
    setEditTrigger('manual');
    setIsNew(true);
  };

  const addStep = () => {
    setEditSteps(prev => [
      ...prev,
      {
        id: `step_${Date.now()}`,
        name: '',
        type: 'scan',
        tool: '',
        critical: false,
      },
    ]);
  };

  const updateStep = (index: number, field: keyof WorkflowStep, value: any) => {
    setEditSteps(prev => prev.map((s, i) => (i === index ? { ...s, [field]: value } : s)));
  };

  const removeStep = (index: number) => {
    setEditSteps(prev => prev.filter((_, i) => i !== index));
  };

  const saveWorkflow = async () => {
    setSaving(true);
    try {
      if (isNew) {
        const response = await csrfFetch('/api/bounty/workflows', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: editName,
            description: editDescription,
            steps: editSteps,
            trigger: editTrigger,
          }),
        });
        const data = await response.json();
        if (data.success) {
          setIsNew(false);
          setSelectedId(data.workflowId);
          fetchWorkflows();
        }
      } else if (selectedId) {
        await csrfFetch(`/api/bounty/workflows/${selectedId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: editName,
            description: editDescription,
            steps: editSteps,
            trigger: editTrigger,
            status: workflows.find(w => w.id === selectedId)?.status || 'draft',
          }),
        });
        fetchWorkflows();
      }
    } catch (error) {
      console.error('Failed to save workflow:', error);
    } finally {
      setSaving(false);
    }
  };

  const deleteWorkflow = async (id: string) => {
    try {
      await csrfFetch(`/api/bounty/workflows/${id}`, { method: 'DELETE' });
      if (selectedId === id) {
        setSelectedId(null);
        setIsNew(false);
      }
      fetchWorkflows();
    } catch (error) {
      console.error('Failed to delete workflow:', error);
    }
  };

  const executeWorkflow = async () => {
    if (!selectedId || !executeTarget) return;
    setExecuting(true);
    try {
      const response = await csrfFetch(`/api/bounty/workflows/${selectedId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: executeTarget }),
      });
      const data = await response.json();
      if (data.success) {
        setActiveExecutions(prev => [...prev, data.executionId]);
        setShowExecutePrompt(false);
        setExecuteTarget('');
      }
    } catch (error) {
      console.error('Failed to execute workflow:', error);
    } finally {
      setExecuting(false);
    }
  };

  const selectedWorkflow = workflows.find(w => w.id === selectedId);
  const showEditor = isNew || selectedId;

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#3d3d3d]">
        <div className="flex items-center gap-3">
          <GitBranch className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">Workflow Builder</h1>
        </div>
        <Button
          onClick={createNew}
          className="bg-cyan-600 hover:bg-cyan-700 text-white"
          data-testid="button-new-workflow"
        >
          <Plus className="w-4 h-4 mr-1" /> New Workflow
        </Button>
      </div>

      {activeExecutions.length > 0 && (
        <div className="px-6 py-2 bg-[#252526] border-b border-[#3d3d3d] flex items-center gap-3">
          <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />
          <span className="text-xs text-cyan-400" data-testid="text-active-executions">
            {activeExecutions.length} active execution(s)
          </span>
        </div>
      )}

      <div className="flex flex-1 min-h-0">
        <Card className="bg-[#252526] border-[#3d3d3d] border-t-0 border-l-0 border-b-0 w-72 flex-shrink-0 rounded-none flex flex-col">
          <div className="p-3 border-b border-[#3d3d3d]">
            <span className="text-xs text-gray-400 font-semibold uppercase">Workflows</span>
          </div>
          <ScrollArea className="flex-1">
            <div className="p-2 space-y-1">
              {loading && workflows.length === 0 ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-5 h-5 text-gray-500 animate-spin" />
                </div>
              ) : workflows.length === 0 ? (
                <p className="text-xs text-gray-500 p-3 text-center" data-testid="text-no-workflows">
                  No workflows yet. Create one to get started.
                </p>
              ) : (
                workflows.map(wf => (
                  <button
                    key={wf.id}
                    onClick={() => selectWorkflow(wf)}
                    className={`w-full text-left p-3 rounded transition-colors ${
                      selectedId === wf.id
                        ? 'bg-cyan-600/20 border border-cyan-500/30'
                        : 'hover:bg-[#333] border border-transparent'
                    }`}
                    data-testid={`button-workflow-${wf.id}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm text-gray-200 font-medium truncate">{wf.name}</span>
                      <Badge className={`text-[10px] ${STATUS_COLORS[wf.status] || STATUS_COLORS.draft}`}>
                        {wf.status}
                      </Badge>
                    </div>
                    <p className="text-[10px] text-gray-500 truncate">{wf.description}</p>
                    <p className="text-[10px] text-gray-600 mt-1">{(wf.steps || []).length} steps</p>
                  </button>
                ))
              )}
            </div>
          </ScrollArea>
        </Card>

        <div className="flex-1 flex flex-col min-h-0">
          {!showEditor ? (
            <div className="flex-1 flex items-center justify-center text-gray-500 text-sm" data-testid="text-empty-state">
              Select or create a workflow to start building
            </div>
          ) : (
            <ScrollArea className="flex-1">
              <div className="p-6 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-xs text-gray-400 mb-1 block">Workflow Name</Label>
                    <Input
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      placeholder="e.g., Full Recon Pipeline"
                      className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9"
                      data-testid="input-workflow-name"
                    />
                  </div>
                  <div>
                    <Label className="text-xs text-gray-400 mb-1 block">Trigger</Label>
                    <Select value={editTrigger} onValueChange={setEditTrigger}>
                      <SelectTrigger className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-workflow-trigger">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="manual">Manual</SelectItem>
                        <SelectItem value="scheduled">Scheduled</SelectItem>
                        <SelectItem value="on_finding">On Finding</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Description</Label>
                  <Textarea
                    value={editDescription}
                    onChange={(e) => setEditDescription(e.target.value)}
                    placeholder="Describe what this workflow does..."
                    className="bg-[#252526] border-[#3d3d3d] text-gray-200 min-h-[60px]"
                    data-testid="input-workflow-description"
                  />
                </div>

                <div>
                  <div className="flex items-center justify-between mb-3">
                    <Label className="text-sm text-gray-300 font-semibold">Steps Pipeline</Label>
                    <Button
                      onClick={addStep}
                      variant="outline"
                      size="sm"
                      className="bg-[#252526] border-[#3d3d3d] text-gray-300 hover:bg-[#333]"
                      data-testid="button-add-step"
                    >
                      <Plus className="w-3 h-3 mr-1" /> Add Step
                    </Button>
                  </div>

                  {editSteps.length === 0 ? (
                    <div className="text-center py-8 border border-dashed border-[#3d3d3d] rounded-md">
                      <p className="text-xs text-gray-500">No steps yet. Add steps to build your pipeline.</p>
                    </div>
                  ) : (
                    <div className="space-y-0">
                      {editSteps.map((step, index) => (
                        <div key={step.id}>
                          <Card className="bg-[#252526] border-[#3d3d3d] p-4 relative" data-testid={`card-step-${index}`}>
                            <div className="flex items-start gap-3">
                              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border ${STEP_TYPE_COLORS[step.type]}`}>
                                {index + 1}
                              </div>
                              <div className="flex-1 space-y-3">
                                <div className="grid grid-cols-3 gap-3">
                                  <div>
                                    <Label className="text-[10px] text-gray-500 mb-1 block">Step Name</Label>
                                    <Input
                                      value={step.name}
                                      onChange={(e) => updateStep(index, 'name', e.target.value)}
                                      placeholder="Step name"
                                      className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                                      data-testid={`input-step-name-${index}`}
                                    />
                                  </div>
                                  <div>
                                    <Label className="text-[10px] text-gray-500 mb-1 block">Type</Label>
                                    <Select value={step.type} onValueChange={(v) => updateStep(index, 'type', v)}>
                                      <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-8 text-xs" data-testid={`select-step-type-${index}`}>
                                        <SelectValue />
                                      </SelectTrigger>
                                      <SelectContent>
                                        <SelectItem value="scan">Scan</SelectItem>
                                        <SelectItem value="analyze">Analyze</SelectItem>
                                        <SelectItem value="exploit">Exploit</SelectItem>
                                        <SelectItem value="report">Report</SelectItem>
                                      </SelectContent>
                                    </Select>
                                  </div>
                                  <div>
                                    <Label className="text-[10px] text-gray-500 mb-1 block">Tool (optional)</Label>
                                    <Input
                                      value={step.tool}
                                      onChange={(e) => updateStep(index, 'tool', e.target.value)}
                                      placeholder="e.g., nmap"
                                      className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-8 text-xs"
                                      data-testid={`input-step-tool-${index}`}
                                    />
                                  </div>
                                </div>
                                <div className="flex items-center justify-between">
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => updateStep(index, 'critical', !step.critical)}
                                    className={`h-7 text-xs ${
                                      step.critical
                                        ? 'bg-red-500/20 border-red-500/30 text-red-400'
                                        : 'bg-[#1e1e1e] border-[#3d3d3d] text-gray-500'
                                    }`}
                                    data-testid={`button-step-critical-${index}`}
                                  >
                                    <AlertTriangle className="w-3 h-3 mr-1" />
                                    {step.critical ? 'Critical' : 'Not Critical'}
                                  </Button>
                                  <Badge className={`text-[10px] ${STEP_TYPE_COLORS[step.type]}`}>
                                    {step.type}
                                  </Badge>
                                </div>
                              </div>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => removeStep(index)}
                                className="text-gray-500 hover:text-red-400 h-7 w-7 p-0"
                                data-testid={`button-remove-step-${index}`}
                              >
                                <X className="w-4 h-4" />
                              </Button>
                            </div>
                          </Card>
                          {index < editSteps.length - 1 && (
                            <div className="flex justify-center py-1">
                              <ArrowDown className="w-4 h-4 text-[#3d3d3d]" />
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {showExecutePrompt && (
                  <Card className="bg-[#252526] border-cyan-500/30 p-4">
                    <Label className="text-xs text-gray-400 mb-2 block">Target URL for execution</Label>
                    <div className="flex gap-2">
                      <Input
                        value={executeTarget}
                        onChange={(e) => setExecuteTarget(e.target.value)}
                        placeholder="https://target.com"
                        className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9 flex-1"
                        data-testid="input-execute-target"
                      />
                      <Button
                        onClick={executeWorkflow}
                        disabled={executing || !executeTarget}
                        className="bg-cyan-600 hover:bg-cyan-700 text-white"
                        data-testid="button-confirm-execute"
                      >
                        {executing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                      </Button>
                      <Button
                        onClick={() => { setShowExecutePrompt(false); setExecuteTarget(''); }}
                        variant="outline"
                        className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-400"
                        data-testid="button-cancel-execute"
                      >
                        <X className="w-4 h-4" />
                      </Button>
                    </div>
                  </Card>
                )}

                <div className="flex items-center gap-2 pt-2">
                  <Button
                    onClick={saveWorkflow}
                    disabled={saving || !editName}
                    className="bg-cyan-600 hover:bg-cyan-700 text-white"
                    data-testid="button-save-workflow"
                  >
                    {saving ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Save className="w-4 h-4 mr-1" />}
                    {saving ? 'Saving...' : 'Save Workflow'}
                  </Button>
                  {selectedId && !isNew && (
                    <>
                      <Button
                        onClick={() => setShowExecutePrompt(true)}
                        variant="outline"
                        className="bg-[#252526] border-[#3d3d3d] text-cyan-400 hover:bg-cyan-600/20"
                        data-testid="button-execute-workflow"
                      >
                        <Zap className="w-4 h-4 mr-1" /> Execute
                      </Button>
                      <Button
                        onClick={() => deleteWorkflow(selectedId)}
                        variant="outline"
                        className="bg-[#252526] border-[#3d3d3d] text-red-400 hover:bg-red-600/20 ml-auto"
                        data-testid="button-delete-workflow"
                      >
                        <Trash2 className="w-4 h-4 mr-1" /> Delete
                      </Button>
                    </>
                  )}
                </div>
              </div>
            </ScrollArea>
          )}
        </div>
      </div>
    </div>
  );
}

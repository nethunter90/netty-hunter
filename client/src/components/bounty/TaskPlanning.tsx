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
  Plus, ChevronDown, ChevronRight, Loader2, Sparkles,
  Clock, ListChecks, Trash2, Save, Target
} from 'lucide-react';

interface Task {
  id: string;
  hunt_id: string;
  title: string;
  description: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  phase: string;
  status: 'pending' | 'in_progress' | 'completed' | 'blocked';
  estimated_time: string;
  dependencies: string[];
  notes: string;
}

const PHASES = [
  { key: 'reconnaissance', label: 'Reconnaissance', color: 'text-cyan-400', bg: 'bg-cyan-400', border: 'border-cyan-400/30' },
  { key: 'enumeration', label: 'Enumeration', color: 'text-blue-400', bg: 'bg-blue-400', border: 'border-blue-400/30' },
  { key: 'vulnerability_discovery', label: 'Vulnerability Discovery', color: 'text-orange-400', bg: 'bg-orange-400', border: 'border-orange-400/30' },
  { key: 'exploitation', label: 'Exploitation', color: 'text-red-400', bg: 'bg-red-400', border: 'border-red-400/30' },
  { key: 'reporting', label: 'Reporting', color: 'text-green-400', bg: 'bg-green-400', border: 'border-green-400/30' },
];

const PRIORITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  in_progress: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  completed: 'bg-green-500/20 text-green-400 border-green-500/30',
  blocked: 'bg-red-500/20 text-red-400 border-red-500/30',
};

export function TaskPlanning() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedTask, setExpandedTask] = useState<string | null>(null);
  const [collapsedPhases, setCollapsedPhases] = useState<Set<string>>(new Set());
  const [priorityFilter, setPriorityFilter] = useState('all');
  const [showAddForm, setShowAddForm] = useState(false);
  const [showAIGenerate, setShowAIGenerate] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [editNotes, setEditNotes] = useState('');

  const [newTask, setNewTask] = useState({
    hunt_id: '',
    title: '',
    description: '',
    priority: 'medium' as Task['priority'],
    phase: 'reconnaissance',
    estimated_time: '',
    dependencies: [] as string[],
  });

  const [aiTarget, setAiTarget] = useState('');
  const [aiGoal, setAiGoal] = useState('');
  const [aiHuntId, setAiHuntId] = useState('');

  useEffect(() => {
    fetchTasks();
  }, []);

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/bounty/tasks');
      const data = await response.json();
      if (data.success) {
        setTasks(data.tasks || []);
      }
    } catch (error) {
      console.error('Failed to fetch tasks:', error);
    } finally {
      setLoading(false);
    }
  };

  const addTask = async () => {
    try {
      const response = await csrfFetch('/api/bounty/tasks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newTask),
      });
      const data = await response.json();
      if (data.success || data.id) {
        setShowAddForm(false);
        setNewTask({ hunt_id: '', title: '', description: '', priority: 'medium', phase: 'reconnaissance', estimated_time: '', dependencies: [] });
        fetchTasks();
      }
    } catch (error) {
      console.error('Failed to add task:', error);
    }
  };

  const updateTask = async (id: string, status: string, notes?: string) => {
    try {
      await csrfFetch(`/api/bounty/tasks/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes }),
      });
      fetchTasks();
    } catch (error) {
      console.error('Failed to update task:', error);
    }
  };

  const deleteTask = async (id: string) => {
    try {
      await csrfFetch(`/api/bounty/tasks/${id}`, { method: 'DELETE' });
      if (expandedTask === id) setExpandedTask(null);
      fetchTasks();
    } catch (error) {
      console.error('Failed to delete task:', error);
    }
  };

  const generatePlan = async () => {
    setGenerating(true);
    try {
      const response = await csrfFetch('/api/bounty/tasks/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hunt_id: aiHuntId, goal: aiGoal, target: aiTarget }),
      });
      const data = await response.json();
      if (data.success) {
        setShowAIGenerate(false);
        fetchTasks();
      }
    } catch (error) {
      console.error('Failed to generate plan:', error);
    } finally {
      setGenerating(false);
    }
  };

  const togglePhase = (phase: string) => {
    setCollapsedPhases(prev => {
      const next = new Set(prev);
      if (next.has(phase)) next.delete(phase);
      else next.add(phase);
      return next;
    });
  };

  const filteredTasks = tasks.filter(t => priorityFilter === 'all' || t.priority === priorityFilter);

  const getPhaseProgress = (phaseKey: string) => {
    const phaseTasks = filteredTasks.filter(t => t.phase === phaseKey);
    if (phaseTasks.length === 0) return 0;
    const completed = phaseTasks.filter(t => t.status === 'completed').length;
    return Math.round((completed / phaseTasks.length) * 100);
  };

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] overflow-hidden">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#3d3d3d]">
        <div className="flex items-center gap-3">
          <ListChecks className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">Task Planning</h1>
        </div>
        <div className="flex items-center gap-2">
          <Select value={priorityFilter} onValueChange={setPriorityFilter}>
            <SelectTrigger className="bg-[#252526] border-[#3d3d3d] text-gray-200 h-9 w-36" data-testid="select-priority-filter">
              <SelectValue placeholder="Filter" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Priorities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Button
            onClick={() => setShowAIGenerate(!showAIGenerate)}
            variant="outline"
            className="bg-purple-600/20 border-purple-500/30 text-purple-400 hover:bg-purple-600/30"
            data-testid="button-ai-generate"
          >
            <Sparkles className="w-4 h-4 mr-1" /> AI Generate Plan
          </Button>
          <Button
            onClick={() => setShowAddForm(!showAddForm)}
            className="bg-cyan-600 hover:bg-cyan-700 text-white"
            data-testid="button-add-task"
          >
            <Plus className="w-4 h-4 mr-1" /> Add Task
          </Button>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-6 space-y-4">
          {showAIGenerate && (
            <Card className="bg-[#252526] border-purple-500/30 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-purple-400 flex items-center gap-2">
                <Sparkles className="w-4 h-4" /> AI Plan Generator
              </h3>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Hunt ID</Label>
                  <Input
                    value={aiHuntId}
                    onChange={(e) => setAiHuntId(e.target.value)}
                    placeholder="hunt_id"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-ai-hunt-id"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Target</Label>
                  <Input
                    value={aiTarget}
                    onChange={(e) => setAiTarget(e.target.value)}
                    placeholder="https://target.com"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-ai-target"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Goal</Label>
                  <Input
                    value={aiGoal}
                    onChange={(e) => setAiGoal(e.target.value)}
                    placeholder="e.g., Find auth bypass"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-ai-goal"
                  />
                </div>
              </div>
              <Button
                onClick={generatePlan}
                disabled={generating || !aiTarget || !aiGoal}
                className="bg-purple-600 hover:bg-purple-700 text-white"
                data-testid="button-generate-plan"
              >
                {generating ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Sparkles className="w-4 h-4 mr-1" />}
                {generating ? 'Generating...' : 'Generate Plan'}
              </Button>
            </Card>
          )}

          {showAddForm && (
            <Card className="bg-[#252526] border-[#3d3d3d] p-4 space-y-3">
              <h3 className="text-sm font-semibold text-gray-200">New Task</h3>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Title</Label>
                  <Input
                    value={newTask.title}
                    onChange={(e) => setNewTask(p => ({ ...p, title: e.target.value }))}
                    placeholder="Task title"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-new-task-title"
                  />
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Hunt ID</Label>
                  <Input
                    value={newTask.hunt_id}
                    onChange={(e) => setNewTask(p => ({ ...p, hunt_id: e.target.value }))}
                    placeholder="hunt_id"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-new-task-hunt-id"
                  />
                </div>
              </div>
              <div>
                <Label className="text-xs text-gray-400 mb-1 block">Description</Label>
                <Textarea
                  value={newTask.description}
                  onChange={(e) => setNewTask(p => ({ ...p, description: e.target.value }))}
                  placeholder="Task description"
                  className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 min-h-[60px]"
                  data-testid="input-new-task-description"
                />
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Priority</Label>
                  <Select value={newTask.priority} onValueChange={(v) => setNewTask(p => ({ ...p, priority: v as Task['priority'] }))}>
                    <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-new-task-priority">
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
                  <Label className="text-xs text-gray-400 mb-1 block">Phase</Label>
                  <Select value={newTask.phase} onValueChange={(v) => setNewTask(p => ({ ...p, phase: v }))}>
                    <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-new-task-phase">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {PHASES.map(p => (
                        <SelectItem key={p.key} value={p.key}>{p.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <Label className="text-xs text-gray-400 mb-1 block">Estimated Time</Label>
                  <Input
                    value={newTask.estimated_time}
                    onChange={(e) => setNewTask(p => ({ ...p, estimated_time: e.target.value }))}
                    placeholder="e.g., 2h"
                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
                    data-testid="input-new-task-time"
                  />
                </div>
              </div>
              <Button
                onClick={addTask}
                disabled={!newTask.title}
                className="bg-cyan-600 hover:bg-cyan-700 text-white"
                data-testid="button-submit-task"
              >
                <Plus className="w-4 h-4 mr-1" /> Create Task
              </Button>
            </Card>
          )}

          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 text-gray-500 animate-spin" />
            </div>
          ) : (
            PHASES.map(phase => {
              const phaseTasks = filteredTasks.filter(t => t.phase === phase.key);
              const progress = getPhaseProgress(phase.key);
              const isCollapsed = collapsedPhases.has(phase.key);

              return (
                <div key={phase.key}>
                  <button
                    onClick={() => togglePhase(phase.key)}
                    className="w-full flex items-center gap-3 py-2 group"
                    data-testid={`button-phase-${phase.key}`}
                  >
                    {isCollapsed ? (
                      <ChevronRight className={`w-4 h-4 ${phase.color}`} />
                    ) : (
                      <ChevronDown className={`w-4 h-4 ${phase.color}`} />
                    )}
                    <span className={`text-sm font-semibold ${phase.color}`}>{phase.label}</span>
                    <Badge variant="outline" className="text-[10px] text-gray-500 border-gray-600">
                      {phaseTasks.length}
                    </Badge>
                    <div className="flex-1 mx-3">
                      <div className="h-1.5 bg-[#252526] rounded-full overflow-hidden">
                        <div
                          className={`h-full ${phase.bg} rounded-full transition-all`}
                          style={{ width: `${progress}%` }}
                          data-testid={`progress-phase-${phase.key}`}
                        />
                      </div>
                    </div>
                    <span className="text-xs text-gray-500">{progress}%</span>
                  </button>

                  {!isCollapsed && (
                    <div className="space-y-2 ml-7 mb-4">
                      {phaseTasks.length === 0 ? (
                        <p className="text-xs text-gray-600 py-2">No tasks in this phase</p>
                      ) : (
                        phaseTasks.map(task => (
                          <Card
                            key={task.id}
                            className={`bg-[#252526] border-[#3d3d3d] p-3 cursor-pointer transition-colors hover:border-gray-500 ${
                              expandedTask === task.id ? `border-l-2 ${phase.border}` : ''
                            }`}
                            onClick={() => {
                              if (expandedTask === task.id) {
                                setExpandedTask(null);
                              } else {
                                setExpandedTask(task.id);
                                setEditNotes(task.notes || '');
                              }
                            }}
                            data-testid={`card-task-${task.id}`}
                          >
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-sm font-medium text-gray-200">{task.title}</span>
                              <div className="flex items-center gap-2">
                                {task.estimated_time && (
                                  <span className="text-[10px] text-gray-500 flex items-center gap-1">
                                    <Clock className="w-3 h-3" /> {task.estimated_time}
                                  </span>
                                )}
                                <Badge className={`text-[10px] ${PRIORITY_COLORS[task.priority]}`}>
                                  {task.priority}
                                </Badge>
                                <Badge className={`text-[10px] ${STATUS_COLORS[task.status]}`}>
                                  {task.status.replace('_', ' ')}
                                </Badge>
                              </div>
                            </div>
                            <p className="text-xs text-gray-500 truncate">{task.description}</p>

                            {expandedTask === task.id && (
                              <div className="mt-3 pt-3 border-t border-[#3d3d3d] space-y-3" onClick={(e) => e.stopPropagation()}>
                                <div>
                                  <Label className="text-xs text-gray-400 mb-1 block">Status</Label>
                                  <Select
                                    value={task.status}
                                    onValueChange={(v) => updateTask(task.id, v, editNotes)}
                                  >
                                    <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-8 text-xs" data-testid={`select-task-status-${task.id}`}>
                                      <SelectValue />
                                    </SelectTrigger>
                                    <SelectContent>
                                      <SelectItem value="pending">Pending</SelectItem>
                                      <SelectItem value="in_progress">In Progress</SelectItem>
                                      <SelectItem value="completed">Completed</SelectItem>
                                      <SelectItem value="blocked">Blocked</SelectItem>
                                    </SelectContent>
                                  </Select>
                                </div>
                                <div>
                                  <Label className="text-xs text-gray-400 mb-1 block">Notes</Label>
                                  <Textarea
                                    value={editNotes}
                                    onChange={(e) => setEditNotes(e.target.value)}
                                    placeholder="Add notes..."
                                    className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 min-h-[60px] text-xs"
                                    data-testid={`textarea-task-notes-${task.id}`}
                                  />
                                </div>
                                <div className="flex items-center gap-2">
                                  <Button
                                    onClick={() => updateTask(task.id, task.status, editNotes)}
                                    size="sm"
                                    className="bg-cyan-600 hover:bg-cyan-700 text-white h-7 text-xs"
                                    data-testid={`button-save-task-${task.id}`}
                                  >
                                    <Save className="w-3 h-3 mr-1" /> Save
                                  </Button>
                                  <Button
                                    onClick={() => deleteTask(task.id)}
                                    size="sm"
                                    variant="outline"
                                    className="bg-[#1e1e1e] border-[#3d3d3d] text-red-400 hover:bg-red-600/20 h-7 text-xs"
                                    data-testid={`button-delete-task-${task.id}`}
                                  >
                                    <Trash2 className="w-3 h-3 mr-1" /> Delete
                                  </Button>
                                </div>
                              </div>
                            )}
                          </Card>
                        ))
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

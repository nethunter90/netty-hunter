import { useState, useEffect, useRef } from 'react';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Eye } from 'lucide-react';

interface SecurityEvent {
  id: string;
  timestamp: string;
  type: string;
  description: string;
  severity: string;
}

const EVENT_TYPES = [
  { value: 'all', label: 'All Events' },
  { value: 'security_event', label: 'Security Event' },
  { value: 'prompt_injection_blocked', label: 'Prompt Injection Blocked' },
  { value: 'task_start', label: 'Task Start' },
  { value: 'task_complete', label: 'Task Complete' },
  { value: 'task_failed', label: 'Task Failed' },
];

const SEVERITY_OPTIONS = [
  { value: 'all', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

function getEventTypeBadgeColor(type: string): string {
  switch (type) {
    case 'security_event': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'prompt_injection_blocked': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'task_start': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
    case 'task_complete': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'task_failed': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-400';
    case 'high': return 'text-orange-400';
    case 'medium': return 'text-yellow-400';
    case 'low': return 'text-green-400';
    default: return 'text-gray-400';
  }
}

// The /api/bounty/audit store writes entries as { id, action, details, timestamp }
// but this view renders { type, description, severity }. Normalize so the events
// that ARE written (hunt start, scope validate/block) render instead of blank rows.
// Entries already in the UI shape pass through unchanged.
function normalizeAuditEntry(raw: any): SecurityEvent {
  if (raw && typeof raw.type === 'string' && typeof raw.description === 'string') {
    return {
      id: String(raw.id ?? `${raw.timestamp}-${Math.random().toString(36).slice(2, 7)}`),
      timestamp: String(raw.timestamp ?? new Date().toISOString()),
      type: raw.type,
      description: raw.description,
      severity: String(raw.severity ?? 'info'),
    };
  }
  const action = String(raw?.action ?? 'event');
  const TYPE_MAP: Record<string, string> = {
    'scope.block': 'security_event',
    'scope.validate': 'task_complete',
    'hunt.start': 'task_start',
    'hunt.complete': 'task_complete',
    'hunt.error': 'task_failed',
  };
  const SEV_MAP: Record<string, string> = {
    'scope.block': 'high',
    'hunt.error': 'high',
  };
  const details = raw?.details ?? {};
  const detailStr = typeof details === 'object'
    ? Object.entries(details).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' ')
    : String(details);
  return {
    id: String(raw?.id ?? `${raw?.timestamp ?? Date.now()}-${Math.random().toString(36).slice(2, 7)}`),
    timestamp: String(raw?.timestamp ?? new Date().toISOString()),
    type: TYPE_MAP[action] ?? action,
    description: `${action}${detailStr ? ` — ${detailStr}` : ''}`,
    severity: SEV_MAP[action] ?? 'info',
  };
}

export function AuditTrail() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [typeFilter, setTypeFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  const fetchEvents = async () => {
    try {
      const response = await fetch('/api/bounty/audit');
      const data = await response.json();
      const raw = Array.isArray(data) ? data : (Array.isArray(data.events) ? data.events : []);
      // Newest first, normalized to the view's shape.
      setEvents(raw.slice().reverse().map(normalizeAuditEntry));
    } catch (error) {
      console.error('Failed to fetch security events:', error);
    }
  };

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(fetchEvents, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [events, autoScroll]);

  const filteredEvents = events
    .filter(e => typeFilter === 'all' || e.type === typeFilter)
    .filter(e => severityFilter === 'all' || e.severity === severityFilter)
    .filter(e => {
      if (!searchQuery) return true;
      const q = searchQuery.toLowerCase();
      return e.description?.toLowerCase().includes(q) || e.type?.toLowerCase().includes(q);
    })
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  return (
    <div className="h-full flex flex-col bg-[#1e1e1e] p-6">
      <div className="mb-4">
        <div className="flex items-center gap-3 mb-2">
          <Eye className="w-6 h-6 text-cyan-400" />
          <h1 className="text-2xl font-bold text-gray-100">Audit Trail</h1>
        </div>
        <p className="text-sm text-gray-400">Real-time security event log viewer</p>
      </div>

      <Card className="bg-[#252526] border-[#3d3d3d] p-4 mb-4">
        <div className="flex flex-wrap gap-3">
          <div className="flex-1 min-w-[150px]">
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-event-type">
                <SelectValue placeholder="Event Type" />
              </SelectTrigger>
              <SelectContent>
                {EVENT_TYPES.map(t => (
                  <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex-1 min-w-[150px]">
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9" data-testid="select-severity-filter">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                {SEVERITY_OPTIONS.map(s => (
                  <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <Input
              placeholder="Search events..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-[#1e1e1e] border-[#3d3d3d] text-gray-200 h-9"
              data-testid="input-search-events"
            />
          </div>
          <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="accent-cyan-400"
              data-testid="checkbox-auto-scroll"
            />
            Auto-scroll
          </label>
        </div>
      </Card>

      <ScrollArea className="flex-1">
        <div ref={scrollRef} className="space-y-2 pr-2">
          {filteredEvents.length === 0 ? (
            <div className="text-center py-16 text-gray-500 text-sm" data-testid="text-no-events">
              No security events recorded yet
            </div>
          ) : (
            filteredEvents.map((event, idx) => (
              <Card
                key={event.id || idx}
                className="bg-[#252526] border-[#3d3d3d] p-3"
                data-testid={`card-event-${event.id || idx}`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge className={getEventTypeBadgeColor(event.type)}>
                        {event.type?.replace(/_/g, ' ')}
                      </Badge>
                      <span className={`text-xs font-medium ${getSeverityColor(event.severity)}`}>
                        {event.severity}
                      </span>
                    </div>
                    <p className="text-sm text-gray-300 break-words">{event.description}</p>
                  </div>
                  <span className="text-xs text-gray-500 whitespace-nowrap">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              </Card>
            ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

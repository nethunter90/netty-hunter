import { useState } from 'react';
import { BountyViewRouter } from '../components/bounty/BountyViewRouter';
import type { BountyView } from '../components/sidebar/BountyNavigation';

const BOUNTY_VIEWS: { id: BountyView; label: string }[] = [
  { id: 'hackerone', label: 'HackerOne' },
  { id: 'bounty-intelligence', label: 'Intelligence' },
  { id: 'analysis', label: 'Analysis' },
  { id: 'submissions', label: 'Submissions' },
  { id: 'scope', label: 'Scope' },
  { id: 'draft-reports', label: 'Reports' },
  { id: 'nuclei-templates', label: 'Nuclei' },
  { id: 'payloads', label: 'Payloads' },
  { id: 'deadlines', label: 'Deadlines' },
  { id: 'backward-hunt', label: 'Backward Hunt' },
  { id: 'tool-readiness', label: 'Tool Readiness' },
  { id: 'browser', label: 'Browser' },
  { id: 'audit-trail', label: 'Audit Trail' },
  { id: 'ai-advisor', label: 'AI Advisor' },
  { id: 'workflow', label: 'Workflow' },
  { id: 'task-planning', label: 'Tasks' },
  { id: 'opsec-intel', label: 'OpSec Intel' },
  { id: 'cve-intel', label: 'CVE Intel' },
  { id: 'poc-lab', label: 'PoC Lab' },
  { id: 'hunt-replay', label: 'Hunt Replay' },
];

export default function Bounty() {
  const [activeView, setActiveView] = useState<BountyView>('bounty-intelligence');

  return (
    <div className="flex h-full overflow-hidden">
      {/* Sub-navigation */}
      <div className="w-40 bg-hack-surface border-r border-hack-border flex flex-col py-2 flex-shrink-0 overflow-y-auto">
        <div className="px-3 py-1 text-[9px] text-hack-dim font-mono uppercase tracking-widest mb-1">Bounty</div>
        {BOUNTY_VIEWS.map((v) => (
          <button
            key={v.id}
            onClick={() => setActiveView(v.id)}
            className={`text-left px-3 py-1.5 text-xs font-mono transition-colors ${
              activeView === v.id
                ? 'text-hack-accent bg-hack-accent/10 border-l-2 border-hack-accent'
                : 'text-hack-dim hover:text-hack-text hover:bg-hack-muted'
            }`}
          >
            {v.label}
          </button>
        ))}
      </div>

      {/* View content */}
      <div className="flex-1 overflow-auto">
        <BountyViewRouter view={activeView} />
      </div>
    </div>
  );
}

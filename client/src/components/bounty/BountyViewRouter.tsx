import { Component, type ReactNode } from 'react';
import { HackerOneDashboard } from './HackerOneDashboard';
import { BackwardHunt } from './BackwardHunt';
import { ToolReadiness } from './ToolReadiness';
import { BrowserView } from './BrowserView';
import { NucleiTemplates } from './NucleiTemplates';
import { AuditTrail } from './AuditTrail';
import { DraftReports } from './DraftReports';
import { ScopeManager } from './ScopeManager';
import { AIAdvisor } from './AIAdvisor';
import { WorkflowBuilder } from './WorkflowBuilder';
import { TaskPlanning } from './TaskPlanning';
import { Analysis } from './Analysis';
import { CVEIntel } from './CVEIntel';
import { PoCLab } from './PoCLab';
import { Submissions } from './Submissions';
import { SyncStatus } from './SyncStatus';
import { Payloads } from './Payloads';
import { Deadlines } from './Deadlines';
import { BountyIntelligence } from './BountyIntelligence';
import { HuntReplay } from './HuntReplay';
import type { BountyView } from '../sidebar/BountyNavigation';

interface ErrorBoundaryState {
  hasError: boolean;
  error: string;
  viewName: string;
}

class ViewErrorBoundary extends Component<{ children: ReactNode; viewName: string }, ErrorBoundaryState> {
  constructor(props: { children: ReactNode; viewName: string }) {
    super(props);
    this.state = { hasError: false, error: '', viewName: props.viewName };
  }

  static getDerivedStateFromProps(props: { viewName: string }, state: ErrorBoundaryState) {
    if (props.viewName !== state.viewName) {
      return { hasError: false, error: '', viewName: props.viewName };
    }
    return null;
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error: error.message };
  }

  componentDidCatch(error: Error, info: any) {
    console.error(`[BountyView] Crash in ${this.props.viewName}:`, error, info?.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="h-full flex items-center justify-center bg-[#1e1e1e] p-6">
          <div className="text-center max-w-md">
            <div className="text-red-400 text-lg font-semibold mb-2">View Error</div>
            <p className="text-gray-400 text-sm mb-4">
              The "{this.props.viewName}" panel encountered an error and couldn't render.
            </p>
            <pre className="text-xs text-red-300 bg-[#252526] border border-[#3d3d3d] rounded p-3 mb-4 text-left overflow-auto max-h-32">
              {this.state.error}
            </pre>
            <button
              onClick={() => this.setState({ hasError: false, error: '' })}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm rounded"
            >
              Try Again
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

interface BountyViewRouterProps {
  view: BountyView;
}

function BountyViewContent({ view }: BountyViewRouterProps) {
  switch (view) {
    case 'hackerone':
      return <HackerOneDashboard />;
    case 'backward-hunt':
      return <BackwardHunt />;
    case 'tool-readiness':
      return <ToolReadiness />;
    case 'browser':
      return <BrowserView />;
    case 'nuclei-templates':
      return <NucleiTemplates />;
    case 'audit-trail':
      return <AuditTrail />;
    case 'draft-reports':
      return <DraftReports />;
    case 'scope':
      return <ScopeManager />;
    case 'ai-advisor':
      return <AIAdvisor />;
    case 'workflow':
      return <WorkflowBuilder />;
    case 'task-planning':
      return <TaskPlanning />;
    case 'analysis':
      return <Analysis />;
    case 'opsec-intel':
      return <SyncStatus />;
    case 'cve-intel':
      return <CVEIntel />;
    case 'poc-lab':
      return <PoCLab />;
    case 'submissions':
      return <Submissions />;
    case 'payloads':
      return <Payloads />;
    case 'deadlines':
      return <Deadlines />;
    case 'bounty-intelligence':
      return <BountyIntelligence />;
    case 'hunt-replay':
      return <HuntReplay />;
    default:
      return <BackwardHunt />;
  }
}

export function BountyViewRouter({ view }: BountyViewRouterProps) {
  return (
    <ViewErrorBoundary viewName={view}>
      <BountyViewContent view={view} />
    </ViewErrorBoundary>
  );
}

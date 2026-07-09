/**
 * Governance drift alert — passive, informational only. Mirrors the
 * always-mounted bridge pattern (huntEventBridge.ts/orchestrationEventBridge.ts)
 * so it keeps listening regardless of which panel is active.
 *
 * This does NOT pause, block, or restrict any hunt — it only surfaces that the
 * governance immunizer detected a drift signal (a heuristic based on recent
 * decision-rate changes), so you can decide whether to look into it. See
 * server/src/lib/governance/governance-immunizer.ts for what triggers it.
 */
import { useEffect } from 'react';
import toast from 'react-hot-toast';
import { getSocket } from './socket';

interface DriftAlertPayload {
  action: 'warn' | 'clamp' | 'full_reset';
  reasons: string[];
  blockRateChange: number;
  flaggedPillars: string[];
  baselineId?: string;
  timestamp: number;
}

let attached = false;

export function attachGovernanceAlerts(): () => void {
  const socket = getSocket();
  if (attached) return () => {};
  attached = true;

  const onDriftAlert = (data: DriftAlertPayload) => {
    const reason = data.reasons[0] ?? 'drift detected';
    const message = `Governance ${data.action}: ${reason}`;
    if (data.action === 'full_reset' || data.action === 'clamp') {
      toast.error(message, { duration: 10000, icon: '\u{1F6E1}️' });
    } else {
      toast(message, { duration: 8000, icon: '\u{1F6E1}️' });
    }
  };

  socket.on('governance:drift_alert', onDriftAlert);

  return () => {
    socket.off('governance:drift_alert', onDriftAlert);
    attached = false;
  };
}

/** Mount the governance alert bridge once, from an always-mounted layer. */
export function useGovernanceAlerts(): void {
  useEffect(() => attachGovernanceAlerts(), []);
}

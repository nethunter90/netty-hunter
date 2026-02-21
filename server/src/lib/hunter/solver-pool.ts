/**
 * SolverPool — lib/hunter singleton
 *
 * Manages solver lifecycle per session: spawn, complete, cancel, decision log.
 */
import { v4 as uuidv4 } from 'uuid';
import type { SolverEntry, SolverPoolState, SolverDecision } from './types';

class SolverPoolStore {
  private pools:     Map<string, SolverEntry[]>     = new Map();
  private decisions: Map<string, SolverDecision[]>  = new Map();

  private ensurePool(sessionId: string): SolverEntry[] {
    if (!this.pools.has(sessionId)) this.pools.set(sessionId, []);
    return this.pools.get(sessionId)!;
  }

  private ensureDecisions(sessionId: string): SolverDecision[] {
    if (!this.decisions.has(sessionId)) this.decisions.set(sessionId, []);
    return this.decisions.get(sessionId)!;
  }

  spawnSolvers(sessionId: string, endpoints: string[], vulnClasses?: string[]): SolverEntry[] {
    const pool = this.ensurePool(sessionId);
    const log  = this.ensureDecisions(sessionId);
    const classes = vulnClasses?.length ? vulnClasses : ['xss', 'sqli', 'ssrf', 'idor'];

    const spawned: SolverEntry[] = [];
    for (const endpoint of endpoints) {
      for (const vc of classes) {
        const solver: SolverEntry = {
          id:         uuidv4(),
          sessionId,
          endpoint,
          vulnClass:  vc,
          status:     'spawned',
          spawnedAt:  Date.now(),
        };
        pool.push(solver);
        spawned.push(solver);
      }
    }

    log.push({
      at:        Date.now(),
      action:    'spawn',
      endpoint:  endpoints.join(', '),
      vulnClass: classes.join(', '),
      reason:    `Spawned ${spawned.length} solvers for ${endpoints.length} endpoint(s)`,
    });

    return spawned;
  }

  completeSolver(sessionId: string, solverId: string, result: SolverEntry['result']): void {
    const pool = this.ensurePool(sessionId);
    const solver = pool.find(s => s.id === solverId);
    if (!solver) return;

    solver.status      = 'completed';
    solver.result      = result;
    solver.completedAt = Date.now();

    this.ensureDecisions(sessionId).push({
      at:        Date.now(),
      action:    'complete',
      endpoint:  solver.endpoint,
      vulnClass: solver.vulnClass,
      reason:    `Completed with ${result?.findingsCount ?? 0} finding(s)`,
    });
  }

  cancelSolver(sessionId: string, solverId: string): void {
    const pool = this.ensurePool(sessionId);
    const solver = pool.find(s => s.id === solverId);
    if (!solver) return;

    solver.status      = 'cancelled';
    solver.completedAt = Date.now();

    this.ensureDecisions(sessionId).push({
      at:        Date.now(),
      action:    'cancel',
      endpoint:  solver.endpoint,
      vulnClass: solver.vulnClass,
      reason:    'Cancelled by coordinator',
    });
  }

  getPoolState(sessionId: string): SolverPoolState | null {
    const pool = this.pools.get(sessionId);
    if (!pool) return null;

    return {
      sessionId,
      totalSpawned: pool.length,
      running:      pool.filter(s => s.status === 'running').length,
      completed:    pool.filter(s => s.status === 'completed').length,
      cancelled:    pool.filter(s => s.status === 'cancelled').length,
      solvers:      pool,
    };
  }

  getDecisionLog(sessionId: string): SolverDecision[] {
    return this.decisions.get(sessionId) ?? [];
  }
}

export const solverPool = new SolverPoolStore();

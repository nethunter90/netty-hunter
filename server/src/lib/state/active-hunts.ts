/**
 * Active-hunt registry — server-owned single-flight gate + real abort dispatch.
 *
 * THE SAFETY CORE. This is the one structure all hunt-launch entry points route
 * through. It enforces two invariants that make the cost-runaway incident
 * ($180 of unintended spend from ~60 stacked launches) structurally impossible
 * regardless of how many times any button in any panel is clicked:
 *
 *   1. SINGLE-FLIGHT: at most one hunt runs at a time, server-wide. A launch
 *      attempted while a hunt is active is REJECTED (never queued). All launch
 *      paths — POST /api/hunt/start, POST /api/orchestration/run, and the two
 *      Socket.IO equivalents — consult this same lock, so two different panels
 *      cannot both start a hunt.
 *
 *   2. REAL ABORT: stop() calls a genuine stop() on the running engine/
 *      orchestrator (which sets its abort flag and ceases issuing model calls),
 *      then releases the lock so a legitimate new hunt can start afterward.
 *
 * The lock is held by whichever launch path acquired it first; it is released
 * on completion, on error, or on explicit stop. A `Stoppable` is anything with
 * a real, propagating stop() — HunterEngine and CampaignOrchestrator both
 * implement it.
 */

export interface Stoppable {
  /** Real, propagating stop — must halt the loop AND stop issuing model calls. */
  stop(): void;
}

export type HuntKind = "hunt" | "orchestration";

export interface ActiveHuntHandle {
  /** sessionUuid (hunt) or orchestrationId (orchestration). */
  id: string;
  kind: HuntKind;
  handle: Stoppable;
  targetUrl: string;
  startedAt: number;
}

class ActiveHuntRegistry {
  // Single-flight: at most one active hunt server-wide. `active` holds a bound,
  // stoppable run. `reserved` is the synchronous claim a launch path takes at
  // its very first line — BEFORE any `await` — so two concurrent requests can't
  // both pass the busy-check during the async setup window between reserving the
  // slot and binding the real engine handle.
  private active: ActiveHuntHandle | null = null;
  private reserved: { targetUrl: string; reservedAt: number } | null = null;

  /** True if a hunt is reserved or running. */
  isActive(): boolean {
    return this.active !== null || this.reserved !== null;
  }

  /** The currently running hunt, if any (read-only view for status surfaces). */
  current(): { id: string; kind: HuntKind; targetUrl: string; startedAt: number } | null {
    if (!this.active) return null;
    const { id, kind, targetUrl, startedAt } = this.active;
    return { id, kind, targetUrl, startedAt };
  }

  /**
   * SYNCHRONOUS single-flight claim. Call this as the first statement of a launch
   * handler, before any `await`. Returns false WITHOUT claiming if a hunt is
   * already reserved or running — the caller must then reject the launch (409 /
   * error event) and do no further work. Returns true and claims the slot
   * otherwise. The caller MUST follow a successful reserve() with exactly one of
   * bind() (setup succeeded) or release() (setup failed/threw).
   */
  reserve(targetUrl: string): boolean {
    if (this.active || this.reserved) return false;
    this.reserved = { targetUrl, reservedAt: Date.now() };
    return true;
  }

  /**
   * Promote a reservation into a bound, stoppable run once async setup produced
   * the real id + engine handle. Clears the reservation. If the slot was stopped
   * during setup (race), the handle is stopped immediately so it doesn't run on.
   */
  bind(handle: ActiveHuntHandle): void {
    this.reserved = null;
    this.active = handle;
  }

  /**
   * Release the slot for a given id (completion/error) OR release a still-pending
   * reservation when id is omitted (setup failed before bind). No-op if the
   * active run is a different id, so a late completion callback from an
   * already-replaced hunt can't clobber a newer one. Safe to call repeatedly.
   */
  release(id?: string): void {
    if (id === undefined) {
      this.reserved = null;
      return;
    }
    if (this.active?.id === id) this.active = null;
  }

  /**
   * Real stop: invoke the handle's stop() (propagates to the engine's abort
   * flag and halts model calls) and release the lock. Returns true if a hunt
   * with this id was active and was stopped, false if no such hunt was running.
   */
  stop(id: string): boolean {
    if (this.active?.id !== id) return false;
    const handle = this.active.handle;
    this.active = null;
    try {
      handle.stop();
    } catch {
      /* a throwing stop() must still release the lock — already done above */
    }
    return true;
  }

  /** Stop whatever is running, if anything (emergency stop). */
  stopAll(): boolean {
    if (!this.active) return false;
    return this.stop(this.active.id);
  }
}

export const activeHunts = new ActiveHuntRegistry();

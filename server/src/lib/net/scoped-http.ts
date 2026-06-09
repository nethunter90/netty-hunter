/**
 * Scoped HTTP — defense-in-depth egress chokepoint.
 *
 * Wraps axios so that every outbound request a prober makes is validated
 * against the program's declared scope before it leaves the box. The hunt's
 * hypothesis target is already scope-checked at dispatch time, but probers
 * that construct *new* URLs (redirect targets, discovered endpoints, pivot
 * hosts) can drift off-target. Routing those through here guarantees a
 * fail-closed scope check at the network boundary.
 *
 * Backwards-compatible: if no programId is supplied (programId <= 0), the
 * check is skipped — existing call sites that have no program context keep
 * working unchanged. Local-lab programs (scope "*") always pass.
 */
import axios, { AxiosRequestConfig, AxiosResponse } from "axios";
import { ScopeGuard } from "../../middleware/scopeGuard";
import logger from "../../utils/logger";

export class OutOfScopeError extends Error {
  constructor(public readonly url: string, public readonly reason: string) {
    super(`Out of scope: ${url} — ${reason}`);
    this.name = "OutOfScopeError";
  }
}

const guard = ScopeGuard.getInstance();

async function assertInScope(url: string, programId?: number): Promise<void> {
  if (!programId || programId <= 0) return; // no program context — skip (back-compat)
  const { allowed, reason } = await guard.isInScope(url, programId);
  if (!allowed) {
    logger.warn("[scopedHttp] Blocked out-of-scope egress", { url, programId, reason });
    throw new OutOfScopeError(url, reason);
  }
}

export const scopedHttp = {
  async get(url: string, config: AxiosRequestConfig = {}, programId?: number): Promise<AxiosResponse> {
    await assertInScope(url, programId);
    return axios.get(url, config);
  },
  async post(url: string, data?: unknown, config: AxiosRequestConfig = {}, programId?: number): Promise<AxiosResponse> {
    await assertInScope(url, programId);
    return axios.post(url, data, config);
  },
  async request(config: AxiosRequestConfig & { url: string }, programId?: number): Promise<AxiosResponse> {
    await assertInScope(config.url, programId);
    return axios.request(config);
  },
};

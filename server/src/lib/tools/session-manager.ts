import { scopedHttp } from "../net/scoped-http";
import logger from "../../utils/logger";

export interface AuthConfig {
  loginUrl?: string;
  username?: string;
  password?: string;
  authType?: "form" | "basic" | "bearer";
  tokenHeaderName?: string;
  usernameField?: string;
  passwordField?: string;
  sessionCookieNames?: string[];
  /** 2026-07-23 (auth-expiry handoff, blocker #2): a real, authenticated-only
   *  endpoint (e.g. an /api/me-style route) that returns non-2xx when
   *  unauthenticated — checkLiveness()'s preferred baseline candidate, tried
   *  before falling back to the hunt's own target origin. Without a genuine
   *  discriminating baseline, a mid-hunt session drop cannot be detected at
   *  all (see checkLiveness()'s "inactive" branch). */
  livenessUrl?: string;
}

interface AuthSession {
  headers: Record<string, string>;
  cookies: string;
  expiresAt: number;
  /** False when login() could not establish real session material — the
   *  session object still exists (so callers always get a concrete result,
   *  never undefined) but carries no usable auth. See ensureSession()'s
   *  bounded retry, which treats valid:false as a real failure to retry. */
  valid: boolean;
  /** Set only when valid is false — the reason the last login attempt
   *  failed, surfaced through AuthSessionFailedError once retries exhaust. */
  failureReason?: string;
}

export class AuthSessionFailedError extends Error {
  constructor(public readonly programId: number, public readonly reason: string) {
    super(`Auth session failed for program ${programId}: ${reason}`);
    this.name = "AuthSessionFailedError";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 2026-07-23 (auth-expiry handoff, blocker #2): ensureSession() bounded retry —
// a transient login hiccup (a slow backend, a momentary 500) shouldn't
// immediately fail-closed the whole hunt the way a genuine bad-credentials
// failure should; a few short-backoff attempts absorb that without masking a
// real, persistent failure (which still throws after LOGIN_MAX_ATTEMPTS).
const LOGIN_MAX_ATTEMPTS = 3;
const LOGIN_BACKOFF_MS = [1000, 3000];
// Liveness re-check requires this many CONSECUTIVE 401/403s on a
// proven-authenticated baseline before declaring the session dropped — a
// single blip (a transient 401 from a race, a momentary backend hiccup)
// must not false-pause an otherwise healthy hunt.
const LIVENESS_DROP_THRESHOLD = 2;

interface LivenessState {
  baselineUrl: string;
  consecutiveFailures: number;
  /** True once every candidate baseline has been tried and none of them
   *  discriminates authenticated from unauthenticated responses — a mid-hunt
   *  session drop cannot be detected for this hunt at all. Surfaced loudly,
   *  once, by the caller (see HunterEngine's authLivenessInactiveSurfaced). */
  inactive: boolean;
  triedCandidates: string[];
}

export interface LivenessResult {
  checked: boolean;
  ok: boolean;
  consecutiveFailures: number;
  dropped: boolean;
  inactive?: boolean;
}

class SessionManager {
  private sessions = new Map<number, AuthSession>();
  private liveness = new Map<number, LivenessState>();

  private isValid(s: AuthSession): boolean {
    return s.valid && s.expiresAt > Date.now();
  }

  async login(programId: number, config: AuthConfig): Promise<AuthSession> {
    const TTL = 30 * 60 * 1000; // 30 minutes

    try {
      const authType = config.authType ?? "form";

      if (authType === "basic") {
        const cred = Buffer.from(`${config.username || ""}:${config.password || ""}`).toString("base64");
        const session: AuthSession = {
          headers: { Authorization: `Basic ${cred}` },
          cookies: "",
          expiresAt: Date.now() + TTL,
          valid: true,
        };
        this.sessions.set(programId, session);
        logger.info("[SessionManager] Basic auth session created", { programId });
        return session;
      }

      if (!config.loginUrl) throw new Error("loginUrl required for form/bearer auth");

      if (authType === "bearer") {
        const res = await scopedHttp.post(config.loginUrl, {
          [config.usernameField || "username"]: config.username,
          [config.passwordField || "password"]: config.password,
        }, { timeout: 15000, validateStatus: () => true }, programId);
        const token = (res.data as Record<string, unknown>)?.token
          || (res.data as Record<string, unknown>)?.access_token
          || (res.data as Record<string, unknown>)?.accessToken;
        if (!token) throw new Error("No token in bearer login response");
        const session: AuthSession = {
          headers: { [config.tokenHeaderName || "Authorization"]: `Bearer ${String(token)}` },
          cookies: "",
          expiresAt: Date.now() + TTL,
          valid: true,
        };
        this.sessions.set(programId, session);
        logger.info("[SessionManager] Bearer session created", { programId });
        return session;
      }

      // Default: form POST
      const params = new URLSearchParams();
      params.append(config.usernameField || "username", config.username || "");
      params.append(config.passwordField || "password", config.password || "");
      const res = await scopedHttp.post(config.loginUrl, params.toString(), {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        maxRedirects: 5,
        timeout: 15000,
        validateStatus: () => true,
      }, programId);
      const setCookie = res.headers["set-cookie"];
      const cookies = Array.isArray(setCookie) ? setCookie.map(c => c.split(";")[0]).join("; ") : "";
      if (!cookies) throw new Error("Form login produced no Set-Cookie header — likely bad credentials or wrong loginUrl");
      const session: AuthSession = {
        headers: { Cookie: cookies },
        cookies,
        expiresAt: Date.now() + TTL,
        valid: true,
      };
      this.sessions.set(programId, session);
      logger.info("[SessionManager] Form session created", { programId, hasCookies: true });
      return session;
    } catch (err) {
      const reason = String(err instanceof Error ? err.message : err);
      logger.warn("[SessionManager] Login failed", { programId, err: reason });
      const failed: AuthSession = { headers: {}, cookies: "", expiresAt: Date.now(), valid: false, failureReason: reason };
      this.sessions.set(programId, failed);
      return failed;
    }
  }

  getSession(programId: number): AuthSession | null {
    const s = this.sessions.get(programId);
    return s && this.isValid(s) ? s : null;
  }

  /** 2026-07-23 (auth-expiry handoff, blocker #2): previously returned
   *  login()'s result unconditionally — including an invalid/empty session
   *  on failure — so a caller checking "did I get a session back" always saw
   *  a truthy object and never learned the login actually failed (the bug
   *  this whole handoff item closes). Now retries a bounded number of times
   *  with backoff, and THROWS AuthSessionFailedError once exhausted, so a
   *  genuine auth failure is unmistakable to the caller instead of silently
   *  degrading to an unauthenticated hunt. */
  async ensureSession(programId: number, config: AuthConfig): Promise<AuthSession> {
    const existing = this.getSession(programId);
    if (existing) return existing;

    let lastReason = "unknown";
    for (let attempt = 1; attempt <= LOGIN_MAX_ATTEMPTS; attempt++) {
      const session = await this.login(programId, config);
      if (session.valid) return session;
      lastReason = session.failureReason ?? lastReason;
      if (attempt < LOGIN_MAX_ATTEMPTS) {
        await sleep(LOGIN_BACKOFF_MS[attempt - 1] ?? LOGIN_BACKOFF_MS[LOGIN_BACKOFF_MS.length - 1]);
      }
    }
    throw new AuthSessionFailedError(programId, lastReason);
  }

  injectAuth(programId: number, baseHeaders: Record<string, string> = {}): Record<string, string> {
    const s = this.getSession(programId);
    if (!s) return baseHeaders;
    return { ...baseHeaders, ...s.headers };
  }

  invalidate(programId: number): void {
    this.sessions.delete(programId);
    this.liveness.delete(programId);
    logger.debug("[SessionManager] Session invalidated", { programId });
  }

  /**
   * Throttled mid-hunt liveness re-check (2026-07-23 auth-expiry handoff,
   * blocker #2) — catches a previously-good session going dead server-side
   * (logout, rotation, IP-binding change) that TTL alone can't see, by
   * re-probing a baseline URL PROVEN to return non-2xx when unauthenticated
   * (probeDiscriminates()) and watching for a run of 401/403s.
   *
   * Baseline selection: prefer config.livenessUrl (an operator-declared
   * authenticated-only endpoint); fall back to the hunt's own target origin.
   * If NEITHER candidate discriminates auth (both are public / always 2xx),
   * liveness detection goes "inactive" for this hunt — surfaced loudly to
   * the caller exactly once (see the `inactive` result field) since a mid-
   * hunt drop then cannot be detected at all, not silently assumed healthy.
   */
  async checkLiveness(programId: number, targetOrigin: string, config: AuthConfig): Promise<LivenessResult> {
    const session = this.getSession(programId);
    if (!session) {
      return { checked: false, ok: true, consecutiveFailures: 0, dropped: false };
    }

    let state = this.liveness.get(programId);
    const candidates = [config.livenessUrl, targetOrigin].filter((c): c is string => !!c);
    const untried = candidates.filter(c => !(state?.triedCandidates ?? []).includes(c));
    const needsEstablishment = !state || (state.inactive && untried.length > 0);

    if (needsEstablishment) {
      const alreadyTried = state?.triedCandidates ?? [];
      let established: LivenessState | null = null;
      for (const candidate of untried.length > 0 ? untried : candidates) {
        const discriminates = await this.probeDiscriminates(candidate, programId, session.headers);
        alreadyTried.push(candidate);
        if (discriminates) {
          established = { baselineUrl: candidate, consecutiveFailures: 0, inactive: false, triedCandidates: alreadyTried };
          logger.info("[SessionManager] Liveness baseline established (proven to discriminate auth)", { programId, baselineUrl: candidate });
          break;
        }
        logger.debug("[SessionManager] Liveness candidate does not discriminate auth (2xx whether authed or not, or not 2xx-while-authed) — trying next", { programId, candidate });
      }
      if (established) {
        state = established;
        this.liveness.set(programId, state);
      } else {
        state = { baselineUrl: "", consecutiveFailures: 0, inactive: true, triedCandidates: alreadyTried };
        this.liveness.set(programId, state);
        logger.warn(
          "[SessionManager] Auth-liveness detection is INACTIVE for this hunt — no candidate baseline (configured livenessUrl or target origin) returns non-2xx when unauthenticated, so a mid-hunt session drop CANNOT be detected. Set AuthConfig.livenessUrl to a real authenticated-only endpoint (e.g. an /api/me-style route) to enable detection.",
          { programId, candidatesTried: alreadyTried }
        );
        return { checked: false, ok: true, consecutiveFailures: 0, dropped: false, inactive: true };
      }
    }

    if (!state) {
      return { checked: false, ok: true, consecutiveFailures: 0, dropped: false };
    }
    if (state.inactive) {
      return { checked: false, ok: true, consecutiveFailures: 0, dropped: false, inactive: true };
    }

    try {
      const res = await scopedHttp.get(state.baselineUrl, {
        headers: session.headers,
        timeout: 10000,
        validateStatus: () => true,
      }, programId);

      if (res.status === 401 || res.status === 403) {
        state.consecutiveFailures++;
        const dropped = state.consecutiveFailures >= LIVENESS_DROP_THRESHOLD;
        logger.warn("[SessionManager] Liveness re-check got 401/403 on a proven-authenticated baseline", {
          programId, baselineUrl: state.baselineUrl, status: res.status,
          consecutiveFailures: state.consecutiveFailures, threshold: LIVENESS_DROP_THRESHOLD, dropped,
        });
        return { checked: true, ok: false, consecutiveFailures: state.consecutiveFailures, dropped };
      }

      if (state.consecutiveFailures > 0) {
        logger.info("[SessionManager] Liveness re-check recovered", { programId, baselineUrl: state.baselineUrl });
      }
      state.consecutiveFailures = 0;
      return { checked: true, ok: true, consecutiveFailures: 0, dropped: false };
    } catch (err) {
      logger.debug("[SessionManager] Liveness re-check network error (not counted)", { programId, err: String(err) });
      return { checked: false, ok: true, consecutiveFailures: state.consecutiveFailures, dropped: false };
    }
  }

  /** True iff `url` returns 2xx when authenticated AND non-2xx when not —
   *  the only shape of "discriminates auth" checkLiveness() can safely rely
   *  on as a baseline (see its own docstring for why an always-2xx endpoint
   *  is useless as a liveness probe). */
  private async probeDiscriminates(url: string, programId: number, authHeaders: Record<string, string>): Promise<boolean> {
    try {
      const authedRes = await scopedHttp.get(url, { headers: authHeaders, timeout: 10000, validateStatus: () => true }, programId);
      if (!(authedRes.status >= 200 && authedRes.status < 300)) return false;
      const unauthedRes = await scopedHttp.get(url, { headers: {}, timeout: 10000, validateStatus: () => true }, programId);
      return !(unauthedRes.status >= 200 && unauthedRes.status < 300);
    } catch {
      return false;
    }
  }
}

export const sessionManager = new SessionManager();

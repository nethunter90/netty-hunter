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
}

interface AuthSession {
  headers: Record<string, string>;
  cookies: string;
  expiresAt: number;
}

class SessionManager {
  private sessions = new Map<number, AuthSession>();

  private isValid(s: AuthSession): boolean {
    return s.expiresAt > Date.now();
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
      const session: AuthSession = {
        headers: cookies ? { Cookie: cookies } : {},
        cookies,
        expiresAt: Date.now() + TTL,
      };
      this.sessions.set(programId, session);
      logger.info("[SessionManager] Form session created", { programId, hasCookies: !!cookies });
      return session;
    } catch (err) {
      logger.warn("[SessionManager] Login failed — continuing unauthenticated", { programId, err: String(err) });
      const empty: AuthSession = { headers: {}, cookies: "", expiresAt: Date.now() + TTL };
      this.sessions.set(programId, empty);
      return empty;
    }
  }

  getSession(programId: number): AuthSession | null {
    const s = this.sessions.get(programId);
    return s && this.isValid(s) ? s : null;
  }

  async ensureSession(programId: number, config: AuthConfig): Promise<AuthSession> {
    const existing = this.getSession(programId);
    if (existing) return existing;
    return this.login(programId, config);
  }

  injectAuth(programId: number, baseHeaders: Record<string, string> = {}): Record<string, string> {
    const s = this.getSession(programId);
    if (!s) return baseHeaders;
    return { ...baseHeaders, ...s.headers };
  }

  invalidate(programId: number): void {
    this.sessions.delete(programId);
    logger.debug("[SessionManager] Session invalidated", { programId });
  }
}

export const sessionManager = new SessionManager();

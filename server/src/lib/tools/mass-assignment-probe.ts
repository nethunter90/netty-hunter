import axios from "axios";
import logger from "../../utils/logger";

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
  hypotheses: Array<{ vulnClass: string; reasoning: string; confidence: number; priority: number }>;
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

  private async testUpdateEndpoint(
    baseUrl: string,
    path: string,
    fieldSet: Record<string, unknown>,
    baseline: unknown,
    authHeaders: Record<string, string>
  ): Promise<MassAssignmentVuln[]> {
    const url = `${baseUrl}${path}`;
    const methods = ["PUT", "PATCH"] as const;
    const vulns: MassAssignmentVuln[] = [];
    const body = { name: "test", ...fieldSet };
    const injectedKeys = Object.keys(fieldSet);

    for (const method of methods) {
      try {
        const response = await axios.request({
          method,
          url,
          data: body,
          headers: {
            ...authHeaders,
            "Content-Type": "application/json",
          },
          timeout: 7000,
          validateStatus: () => true,
        });

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
        const detail = reflected
          ? `Injected privileged fields [${reportedFields.join(", ")}] were reflected in ${method} ${path} response`
          : `Server accepted ${method} ${path} with privileged fields [${reportedFields.join(", ")}] (status ${response.status})`;

        logger.debug(
          `[MassAssignmentProber] Vuln at ${method} ${url} fields=${reportedFields.join(",")} accepted=${effectiveAccepted} reflected=${reflected}`
        );

        vulns.push({
          endpoint: path,
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
    authHeaders: Record<string, string>
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
      const response = await axios.post(url, body, {
        headers: {
          ...authHeaders,
          "Content-Type": "application/json",
        },
        timeout: 7000,
        validateStatus: () => true,
      });

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
      const detail = reflected
        ? `Injected privileged fields [${reportedFields.join(", ")}] were reflected in POST ${path} registration response`
        : `Server accepted POST ${path} registration with privileged fields [${reportedFields.join(", ")}] (status ${response.status})`;

      logger.debug(
        `[MassAssignmentProber] Vuln at POST ${url} fields=${reportedFields.join(",")} accepted=${accepted} reflected=${reflected}`
      );

      vulns.push({
        endpoint: path,
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

  async probe(targetUrl: string, authHeaders?: Record<string, string>): Promise<MassAssignmentResult> {
    const headers = authHeaders ?? {};
    const allVulns: MassAssignmentVuln[] = [];

    // Test update endpoints (PUT/PATCH)
    const updateTasks = UPDATE_ENDPOINTS.flatMap((path) =>
      PRIV_FIELDS.map(async (fieldSet) => {
        const baseline = await this.getBaseline(`${targetUrl}${path}`, headers);
        return this.testUpdateEndpoint(targetUrl, path, fieldSet, baseline, headers);
      })
    );

    // Test registration endpoints (POST)
    const registerTasks = REGISTER_ENDPOINTS.flatMap((path) =>
      PRIV_FIELDS.map((fieldSet) =>
        this.testRegisterEndpoint(targetUrl, path, fieldSet, headers)
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

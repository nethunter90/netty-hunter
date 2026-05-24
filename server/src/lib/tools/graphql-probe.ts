import axios from "axios";
import logger from "../../utils/logger";

export const GRAPHQL_PATHS = [
  "/graphql", "/api/graphql", "/gql", "/v1/graphql",
  "/query", "/api/query", "/graphql/v1", "/api/v2/graphql",
];

const INTROSPECTION_QUERY = `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind description fields { name description args { name type { name kind ofType { name kind } } } type { name kind ofType { name kind } } } } } }"}`;

const SIMPLE_QUERY = `{"query":"{ __typename }"}`;

export interface GraphQLField {
  name: string;
  typeName: string;
  args: Array<{ name: string; typeName: string }>;
}

export interface ParsedSchema {
  endpoint: string;
  queryFields: GraphQLField[];
  mutationFields: GraphQLField[];
  injectableArgs: Array<{ field: string; arg: string; typeName: string }>;
  typeCount: number;
}

export interface HypothesisSeed {
  vulnClass: string;
  targetUrl: string;
  reasoning: string;
  confidence: number;
  priority: number;
}

function extractTypeName(typeObj: unknown): string {
  if (!typeObj || typeof typeObj !== "object") return "Unknown";
  const t = typeObj as Record<string, unknown>;
  if (t.name && typeof t.name === "string") return t.name;
  if (t.ofType) return extractTypeName(t.ofType);
  return String(t.kind || "Unknown");
}

class GraphQLProber {
  async detectEndpoints(baseUrl: string, authHeaders: Record<string, string> = {}): Promise<string[]> {
    const base = baseUrl.replace(/\/$/, "");
    const detected: string[] = [];
    await Promise.allSettled(
      GRAPHQL_PATHS.map(async (path) => {
        try {
          const res = await axios.post(`${base}${path}`, SIMPLE_QUERY, {
            headers: { "Content-Type": "application/json", ...authHeaders },
            timeout: 8000,
            validateStatus: () => true,
          });
          if (res.status < 500) {
            const body = res.data as Record<string, unknown>;
            if (body?.data !== undefined || body?.errors !== undefined) {
              detected.push(`${base}${path}`);
            }
          }
        } catch { /* endpoint not reachable */ }
      })
    );
    return detected;
  }

  async introspect(endpoint: string, authHeaders: Record<string, string> = {}): Promise<ParsedSchema | null> {
    try {
      const res = await axios.post(endpoint, INTROSPECTION_QUERY, {
        headers: { "Content-Type": "application/json", ...authHeaders },
        timeout: 15000,
        validateStatus: () => true,
      });
      if (res.status >= 400) return null;
      const body = res.data as Record<string, unknown>;
      const schema = (body?.data as Record<string, unknown>)?.__schema as Record<string, unknown> | undefined;
      if (!schema) return null;
      return this.parseSchema(endpoint, schema);
    } catch (err) {
      logger.debug("[GraphQLProber] Introspection failed", { endpoint, err: String(err) });
      return null;
    }
  }

  async testBatch(endpoint: string, authHeaders: Record<string, string> = {}): Promise<boolean> {
    try {
      const batchPayload = JSON.stringify(
        Array.from({ length: 10 }, () => ({ query: "{ __typename }" }))
      );
      const res = await axios.post(endpoint, batchPayload, {
        headers: { "Content-Type": "application/json", ...authHeaders },
        timeout: 10000,
        validateStatus: () => true,
      });
      return Array.isArray(res.data) && res.data.length > 1;
    } catch {
      return false;
    }
  }

  toHypothesisSeeds(schema: ParsedSchema): HypothesisSeed[] {
    const seeds: HypothesisSeed[] = [];

    // Introspection enabled → info_disclosure
    seeds.push({
      vulnClass: "info_disclosure",
      targetUrl: schema.endpoint,
      reasoning: `GraphQL introspection is enabled at ${schema.endpoint} — full schema with ${schema.typeCount} types exposed. Introspection should be disabled in production.`,
      confidence: 0.8,
      priority: 7,
    });

    // Injectable String/ID args → xss + sqli
    if (schema.injectableArgs.length > 0) {
      const argSample = schema.injectableArgs.slice(0, 3).map(a => `${a.field}.${a.arg}`).join(", ");
      seeds.push({
        vulnClass: "sqli",
        targetUrl: schema.endpoint,
        reasoning: `GraphQL schema has ${schema.injectableArgs.length} injectable String/ID arguments (${argSample}) — test for SQL injection via query variables.`,
        confidence: 0.6,
        priority: 8,
      });
      seeds.push({
        vulnClass: "xss",
        targetUrl: schema.endpoint,
        reasoning: `GraphQL arguments accept String input (${argSample}) — test for reflected/stored XSS via GraphQL mutations and queries.`,
        confidence: 0.5,
        priority: 6,
      });
    }

    // Mutations present → csrf
    if (schema.mutationFields.length > 0) {
      seeds.push({
        vulnClass: "csrf",
        targetUrl: schema.endpoint,
        reasoning: `GraphQL endpoint has ${schema.mutationFields.length} mutations (${schema.mutationFields.slice(0, 3).map(f => f.name).join(", ")}) — test for CSRF via cross-origin GraphQL mutation.`,
        confidence: 0.5,
        priority: 5,
      });
    }

    // ID-type fields → idor
    const idFields = schema.injectableArgs.filter(a =>
      /^id$|id$|_id$/i.test(a.arg) || a.typeName === "ID"
    );
    if (idFields.length > 0) {
      seeds.push({
        vulnClass: "idor",
        targetUrl: schema.endpoint,
        reasoning: `GraphQL schema exposes ${idFields.length} ID-type arguments (${idFields.slice(0, 3).map(a => `${a.field}.${a.arg}`).join(", ")}) — test for IDOR by enumerating object IDs.`,
        confidence: 0.65,
        priority: 8,
      });
    }

    return seeds;
  }

  private parseSchema(endpoint: string, schema: Record<string, unknown>): ParsedSchema {
    const types = (schema.types as unknown[]) || [];
    const queryTypeName = (schema.queryType as Record<string, string> | undefined)?.name || "Query";
    const mutationTypeName = (schema.mutationType as Record<string, string> | undefined)?.name || "Mutation";

    const queryType = types.find((t: unknown) => (t as Record<string, unknown>).name === queryTypeName) as Record<string, unknown> | undefined;
    const mutationType = types.find((t: unknown) => (t as Record<string, unknown>).name === mutationTypeName) as Record<string, unknown> | undefined;

    const parseFields = (typeObj: Record<string, unknown> | undefined): GraphQLField[] => {
      if (!typeObj) return [];
      return ((typeObj.fields as unknown[]) || []).map((f: unknown) => {
        const field = f as Record<string, unknown>;
        const rawArgs = (field.args as unknown[]) || [];
        return {
          name: String(field.name),
          typeName: extractTypeName(field.type),
          args: rawArgs.map((a: unknown) => {
            const arg = a as Record<string, unknown>;
            return { name: String(arg.name), typeName: extractTypeName(arg.type) };
          }),
        };
      });
    };

    const queryFields = parseFields(queryType);
    const mutationFields = parseFields(mutationType);
    const allFields = [...queryFields, ...mutationFields];

    const injectableArgs = allFields.flatMap(f =>
      f.args
        .filter(a => ["String", "ID", "Int"].includes(a.typeName))
        .map(a => ({ field: f.name, arg: a.name, typeName: a.typeName }))
    );

    return {
      endpoint,
      queryFields,
      mutationFields,
      injectableArgs,
      typeCount: types.filter((t: unknown) => {
        const tn = String((t as Record<string, unknown>).name || "");
        return !tn.startsWith("__");
      }).length,
    };
  }
}

export const graphqlProber = new GraphQLProber();

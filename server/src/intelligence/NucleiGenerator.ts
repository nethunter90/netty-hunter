/**
 * Nuclei Template Auto-Generator
 * Automatically generates Nuclei YAML templates from verified findings.
 */
import yaml from "js-yaml";
import { v4 as uuidv4 } from "uuid";
import logger from "../utils/logger";
import type { VerificationResult } from "../agents/VerifierAgent";
import type { SolverResult } from "../agents/SolverPool";

interface NucleiTemplate {
  id: string;
  info: {
    name: string;
    author: string;
    severity: string;
    description: string;
    tags: string[];
    metadata: { "max-request": number };
  };
  http: NucleiRequest[];
}

interface NucleiRequest {
  method: string;
  path: string[];
  headers?: Record<string, string>;
  body?: string;
  "follow-redirects"?: boolean;
  matchers: NucleiMatcher[];
  extractors?: NucleiExtractor[];
  "attack"?: string;
  payloads?: Record<string, string[]>;
}

interface NucleiMatcher {
  type: "word" | "regex" | "status" | "dsl";
  words?: string[];
  regex?: string[];
  status?: number[];
  dsl?: string[];
  condition?: "and" | "or";
  part?: string;
}

interface NucleiExtractor {
  type: "regex" | "xpath" | "json";
  regex?: string[];
  name?: string;
}

export class NucleiTemplateGenerator {
  generateTemplate(
    finding: SolverResult,
    verification: VerificationResult,
    metadata: { severity: string; programName: string }
  ): string {
    const templateId = `netty-hunter-${finding.vulnClass.replace(/_/g, "-")}-${uuidv4().slice(0, 8)}`;

    const template: NucleiTemplate = {
      id: templateId,
      info: {
        name: `[NettyHunter] ${finding.vulnClass.toUpperCase()} - ${finding.endpoint}`,
        author: "netty-hunter",
        severity: metadata.severity,
        description: `Auto-generated template for ${finding.vulnClass} vulnerability found at ${finding.endpoint}`,
        tags: ["netty-hunter", finding.vulnClass, "auto-generated"],
        metadata: { "max-request": 3 },
      },
      http: this.buildRequests(finding, verification),
    };

    return yaml.dump(template, {
      lineWidth: 120,
      quotingType: "'",
      forceQuotes: false,
    });
  }

  private buildRequests(finding: SolverResult, verification: VerificationResult): NucleiRequest[] {
    switch (finding.vulnClass) {
      case "xss":
        return this.buildXSSRequests(finding);
      case "sqli":
        return this.buildSQLiRequests(finding);
      case "ssrf":
        return this.buildSSRFRequests(finding);
      case "open_redirect":
        return this.buildRedirectRequests(finding);
      case "idor":
        return this.buildIDORRequests(finding);
      case "security_headers":
        return this.buildHeaderCheckRequests(finding);
      default:
        return this.buildGenericRequests(finding);
    }
  }

  private buildXSSRequests(finding: SolverResult): NucleiRequest[] {
    const payloads = [
      finding.payload || "<script>alert(1)</script>",
      "<img src=x onerror=alert(document.domain)>",
      "'><svg onload=alert(1)>",
    ];

    return [{
      method: "GET",
      path: payloads.map(p => `{{BaseURL}}?q=${encodeURIComponent(p)}&search=${encodeURIComponent(p)}`),
      "follow-redirects": true,
      matchers: [
        {
          type: "word",
          words: payloads.slice(0, 2),
          part: "body",
          condition: "or",
        },
        {
          type: "status",
          status: [200],
        },
      ],
    }];
  }

  private buildSQLiRequests(finding: SolverResult): NucleiRequest[] {
    return [{
      method: "GET",
      path: [
        "{{BaseURL}}?id=1'",
        "{{BaseURL}}?id=1 AND SLEEP(5)--",
        "{{BaseURL}}?id=1 UNION SELECT NULL,NULL,NULL--",
      ],
      matchers: [
        {
          type: "regex",
          regex: ["SQL syntax.*MySQL", "Warning.*mysql_", "Unclosed quotation mark", "pg_query\\(\\)"],
          part: "body",
          condition: "or",
        },
        {
          type: "dsl",
          dsl: ["duration>=5"],
        },
      ],
    }];
  }

  private buildSSRFRequests(finding: SolverResult): NucleiRequest[] {
    return [{
      method: "GET",
      path: [
        "{{BaseURL}}?url=http://169.254.169.254/latest/meta-data/",
        "{{BaseURL}}?url=http://metadata.google.internal/computeMetadata/v1/",
        "{{BaseURL}}?redirect=http://169.254.169.254/",
      ],
      matchers: [
        {
          type: "word",
          words: ["ami-id", "instance-id", "iam", "computeMetadata", "project-id"],
          part: "body",
          condition: "or",
        },
      ],
    }];
  }

  private buildRedirectRequests(finding: SolverResult): NucleiRequest[] {
    return [{
      method: "GET",
      path: [
        "{{BaseURL}}?redirect=https://example.com",
        "{{BaseURL}}?next=//example.com",
        "{{BaseURL}}?url=https://example.com",
      ],
      "follow-redirects": false,
      matchers: [
        {
          type: "regex",
          regex: ["Location: https://example\\.com", "Location: //example\\.com"],
          part: "header",
          condition: "or",
        },
        {
          type: "status",
          status: [301, 302, 303, 307, 308],
        },
      ],
    }];
  }

  private buildIDORRequests(finding: SolverResult): NucleiRequest[] {
    const endpointWithPlaceholder = finding.endpoint.replace(/\/\d+/, "/{{id}}");
    return [{
      method: "GET",
      path: ["{{BaseURL}}/{{id}}", endpointWithPlaceholder],
      attack: "pitchfork",
      payloads: {
        id: ["1", "2", "3", "100", "999"],
      },
      matchers: [
        {
          type: "status",
          status: [200],
        },
        {
          type: "dsl",
          dsl: ["len(body) > 100"],
        },
      ],
    }];
  }

  private buildHeaderCheckRequests(finding: SolverResult): NucleiRequest[] {
    return [{
      method: "GET",
      path: ["{{BaseURL}}"],
      matchers: [
        {
          type: "dsl",
          dsl: [
            "!contains(tolower(header), 'content-security-policy')",
            "!contains(tolower(header), 'x-frame-options')",
            "!contains(tolower(header), 'x-content-type-options')",
          ],
          condition: "or",
        },
      ],
    }];
  }

  private buildGenericRequests(finding: SolverResult): NucleiRequest[] {
    return [{
      method: "GET",
      path: [finding.request || `{{BaseURL}}?q=${encodeURIComponent(finding.payload || "test")}`],
      matchers: [
        {
          type: "status",
          status: [200],
        },
        ...(finding.payload ? [{
          type: "word" as const,
          words: [finding.payload.slice(0, 50)],
          part: "body",
        }] : []),
      ],
    }];
  }
}

export default NucleiTemplateGenerator;

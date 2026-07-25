/**
 * Hunt Strategy Builder
 * Auto-populates structured execution plans based on hunt goals.
 * Includes 10 built-in hunt templates.
 */
import { ModelRouter } from "../intelligence/ModelRouter";
import { TargetSelectionIntelligence } from "../intelligence/TargetSelection";
import { ROIModel } from "../intelligence/ROIModel";
import { resolveProvenance } from "../lib/hunter/custom-target-program";

const HUNT_TEMPLATES: Record<string, HuntTemplate> = {
  recon_first: {
    id: "recon_first",
    name: "Reconnaissance First",
    description: "Full recon before exploitation – best for new programs",
    phases: ["fingerprint", "enumerate", "map_attack_surface", "prioritize", "exploit"],
    tools: ["nmap", "whatweb", "gobuster", "ffuf", "nuclei"],
    vulnClasses: ["info_disclosure", "security_headers", "hidden_endpoints", "misconfig"],
  },
  xss_focus: {
    id: "xss_focus",
    name: "XSS Campaign",
    description: "Focused XSS hunting across all input points",
    phases: ["map_inputs", "test_reflection", "test_stored", "test_dom"],
    tools: ["nuclei", "manual"],
    vulnClasses: ["xss"],
  },
  api_abuse: {
    id: "api_abuse",
    name: "API Abuse",
    description: "REST/GraphQL API vulnerability hunting",
    phases: ["discover_endpoints", "test_auth", "test_idor", "test_rate_limit", "test_injection"],
    tools: ["ffuf", "nuclei", "manual"],
    vulnClasses: ["idor", "auth_bypass", "sqli", "rate_limit_bypass", "info_disclosure"],
  },
  sqli_hunt: {
    id: "sqli_hunt",
    name: "SQL Injection Hunt",
    description: "Systematic SQLi testing across all parameters",
    phases: ["enumerate_params", "test_error_based", "test_time_based", "test_union"],
    tools: ["sqlmap", "nuclei"],
    vulnClasses: ["sqli"],
  },
  ssrf_hunt: {
    id: "ssrf_hunt",
    name: "SSRF Hunt",
    description: "SSRF and cloud metadata exposure hunting",
    phases: ["find_url_params", "test_internal", "test_cloud_metadata", "test_blind"],
    tools: ["nuclei", "manual"],
    vulnClasses: ["ssrf"],
  },
  auth_testing: {
    id: "auth_testing",
    name: "Authentication Testing",
    description: "Authentication and session management testing",
    phases: ["test_login", "test_password_reset", "test_mfa", "test_session", "test_tokens"],
    tools: ["nuclei", "manual"],
    vulnClasses: ["auth_bypass", "idor", "csrf"],
  },
  cloud_exposure: {
    id: "cloud_exposure",
    name: "Cloud/Infrastructure Exposure",
    description: "S3 buckets, exposed APIs, cloud misconfigs",
    phases: ["enumerate_subdomains", "check_s3", "check_gcs", "check_metadata", "check_exposed_services"],
    tools: ["nuclei", "nmap"],
    vulnClasses: ["ssrf", "misconfig", "info_disclosure", "exposed_admin"],
  },
  logic_flaws: {
    id: "logic_flaws",
    name: "Business Logic Flaws",
    description: "Testing for business logic and access control issues",
    phases: ["map_workflows", "test_horizontal_ac", "test_vertical_ac", "test_price_manipulation"],
    tools: ["manual"],
    vulnClasses: ["idor", "business_logic", "auth_bypass"],
  },
  subdomain_takeover: {
    id: "subdomain_takeover",
    name: "Subdomain Takeover",
    description: "Hunting for dangling DNS and subdomain takeover opportunities",
    phases: ["enumerate_subdomains", "check_dns", "test_takeover"],
    tools: ["nuclei", "nmap"],
    vulnClasses: ["subdomain_takeover"],
  },
  full_spectrum: {
    id: "full_spectrum",
    name: "Full Spectrum Hunt",
    description: "Comprehensive multi-vector vulnerability hunting",
    phases: ["recon", "fingerprint", "enumerate", "probe_all_classes", "chain_findings"],
    tools: ["nmap", "nuclei", "sqlmap", "ffuf", "gobuster", "nikto", "whatweb"],
    vulnClasses: ["xss", "sqli", "ssrf", "idor", "lfi", "rce", "auth_bypass", "misconfig", "info_disclosure"],
  },
};

interface HuntTemplate {
  id: string;
  name: string;
  description: string;
  phases: string[];
  tools: string[];
  vulnClasses: string[];
}

export interface HuntStrategy {
  template: HuntTemplate;
  executionPlan: ExecutionStep[];
  prioritizedVulnClasses: string[];
  estimatedRequests: number;
  toolChain: string[];
}

interface ExecutionStep {
  phase: string;
  action: string;
  tool: string;
  parameters: Record<string, unknown>;
  successCriteria: string;
  onSuccess: string;
  onFailure: string;
}

export class HuntStrategyBuilder {
  static async build(params: {
    programId?: number;
    targetUrl?: string;
    goal?: string;
  }): Promise<HuntStrategy> {
    const roiModel = new ROIModel();
    const targetSelection = new TargetSelectionIntelligence();

    // Select template based on goal
    const template = HuntStrategyBuilder.selectTemplate(params.goal || "full_spectrum");

    // Build execution plan
    const executionPlan: ExecutionStep[] = template.phases.map(phase => ({
      phase,
      action: `Execute ${phase} phase`,
      tool: template.tools[0] || "nuclei",
      parameters: { url: params.targetUrl || "" },
      successCriteria: `${phase} phase completed with findings or confirmed clean`,
      onSuccess: "Proceed to next phase",
      onFailure: "Log and continue",
    }));

    // Get ROI-sorted vuln classes (pass programId for program-specific blending when available)
    const provenance = await resolveProvenance(params.programId);
    const roiRanking = await roiModel.rankVulnClasses(10000, provenance, params.programId);
    const prioritized = roiRanking
      .filter(r => template.vulnClasses.includes(r.vulnClass))
      .map(r => r.vulnClass);

    // Estimate request budget
    const estimatedRequests = template.tools.length * 200;

    return {
      template,
      executionPlan,
      prioritizedVulnClasses: prioritized,
      estimatedRequests,
      toolChain: template.tools,
    };
  }

  static getTemplates(): HuntTemplate[] {
    return Object.values(HUNT_TEMPLATES);
  }

  private static selectTemplate(goal: string): HuntTemplate {
    const g = goal.toLowerCase();
    if (g.includes("xss")) return HUNT_TEMPLATES.xss_focus;
    if (g.includes("sql")) return HUNT_TEMPLATES.sqli_hunt;
    if (g.includes("ssrf") || g.includes("cloud") || g.includes("metadata")) return HUNT_TEMPLATES.ssrf_hunt;
    if (g.includes("auth") || g.includes("login") || g.includes("session")) return HUNT_TEMPLATES.auth_testing;
    if (g.includes("api") || g.includes("idor")) return HUNT_TEMPLATES.api_abuse;
    if (g.includes("logic") || g.includes("business")) return HUNT_TEMPLATES.logic_flaws;
    if (g.includes("subdomain") || g.includes("takeover")) return HUNT_TEMPLATES.subdomain_takeover;
    if (g.includes("recon") || g.includes("new")) return HUNT_TEMPLATES.recon_first;
    return HUNT_TEMPLATES.full_spectrum;
  }
}

export default HuntStrategyBuilder;

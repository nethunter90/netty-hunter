import { reasoningEngine, MissionMemory } from './reasoning-engine';
import { huntCortex, SignalType } from './hunt-cortex';
import { circuitBreaker } from './circuit-breaker';

export interface Implication {
  condition: string;
  implies: string[];
  suggestedTools: string[];
  weight: number;
}

export interface ToolYield {
  tool: string;
  expectedOutputTypes: string[];
  noveltyScore: number;
}

export interface ToolPipeline {
  name: string;
  steps: string[];
  trigger: string;
  completedSteps: number;
}

export interface NegativeEvidence {
  tool: string;
  target: string;
  timestamp: number;
  category: string;
}

export interface KnownFacts {
  endpoints: Set<string>;
  technologies: Set<string>;
  vulnerabilities: Set<string>;
  testedCombinations: Set<string>;
  negativeResults: NegativeEvidence[];
}

export interface RankedTool {
  tool: string;
  target: string;
  score: number;
  rationale: string;
  parameters: any;
  pipeline?: string;
}

const TOOL_OUTPUT_MAP: Record<string, string[]> = {
  nmap: ['endpoints', 'technologies', 'services'],
  masscan: ['endpoints', 'services'],
  banner_grab: ['technologies', 'versions'],
  version_cve_lookup: ['vulnerabilities', 'cves'],
  httpx: ['endpoints', 'technologies', 'status_codes'],
  whatweb: ['technologies', 'frameworks', 'versions'],
  nuclei: ['vulnerabilities', 'misconfigurations'],
  nuclei_api: ['vulnerabilities', 'api_issues'],
  nuclei_auth: ['vulnerabilities', 'auth_issues'],
  nikto: ['vulnerabilities', 'misconfigurations', 'technologies'],
  subfinder: ['subdomains', 'endpoints'],
  amass: ['subdomains', 'endpoints', 'dns_records'],
  ffuf: ['endpoints', 'directories', 'parameters'],
  gobuster: ['endpoints', 'directories'],
  dirb: ['endpoints', 'directories'],
  sqlmap: ['vulnerabilities', 'databases', 'credentials'],
  sslyze: ['tls_config', 'certificates', 'vulnerabilities'],
  testssl: ['tls_config', 'certificates', 'vulnerabilities'],
  hydra: ['credentials', 'auth_bypass'],
  medusa: ['credentials', 'auth_bypass'],
  wpscan: ['vulnerabilities', 'technologies', 'users'],
  joomscan: ['vulnerabilities', 'technologies'],
  droopescan: ['vulnerabilities', 'technologies'],
  wafw00f: ['waf_detection', 'defenses'],
  arjun: ['parameters', 'endpoints'],
  paramspider: ['parameters', 'endpoints'],
  dalfox: ['vulnerabilities', 'xss'],
  xsstrike: ['vulnerabilities', 'xss'],
  commix: ['vulnerabilities', 'command_injection'],
  upload_bypass: ['vulnerabilities', 'file_upload'],
  jwt_tool: ['vulnerabilities', 'auth_issues', 'tokens'],
  graphql_introspection: ['endpoints', 'schema', 'api_structure'],
  feroxbuster: ['endpoints', 'directories'],
  crt_sh: ['subdomains', 'certificates'],
  shodan: ['technologies', 'services', 'vulnerabilities'],
  censys: ['technologies', 'services', 'certificates'],
};

const TOOL_PARAMETERS: Record<string, any> = {
  nmap: { flags: '-sV -sC -T4' },
  masscan: { flags: '--rate=1000' },
  banner_grab: {},
  version_cve_lookup: {},
  httpx: { flags: '-status-code -title -tech-detect' },
  whatweb: { flags: '--aggression=3' },
  nuclei: { templates: 'all' },
  nuclei_api: { templates: 'api' },
  nuclei_auth: { templates: 'auth' },
  nikto: { flags: '-Tuning 1234' },
  subfinder: { flags: '-silent' },
  amass: { flags: 'enum -passive' },
  ffuf: { wordlist: '/usr/share/wordlists/common.txt', flags: '-mc 200,301,302,403' },
  gobuster: { wordlist: '/usr/share/wordlists/common.txt', mode: 'dir' },
  sqlmap: { flags: '--batch --risk=2 --level=3' },
  sslyze: { flags: '--regular' },
  testssl: { flags: '--severity HIGH' },
  hydra: { flags: '-V -f' },
  wpscan: { flags: '--enumerate vp,vt,u' },
  wafw00f: {},
  arjun: { flags: '-m GET,POST' },
  dalfox: { flags: '--silence' },
  xsstrike: {},
  commix: { flags: '--batch' },
  jwt_tool: { flags: '-M at' },
  graphql_introspection: {
    paths: ["/graphql", "/api/graphql", "/gql", "/v1/graphql", "/query", "/api/query"],
    timeout: 10000,
    followIntrospection: true,
  },
  feroxbuster: { wordlist: '/usr/share/wordlists/common.txt' },
};

export class ContextualToolSelector {
  private implications: Implication[] = [];
  private activePipelines: Map<string, ToolPipeline[]> = new Map();
  private negativeEvidenceStore: Map<string, NegativeEvidence[]> = new Map();
  private pipelines: ToolPipeline[];

  constructor() {
    this.implications = this.buildImplications();
    this.pipelines = this.buildPipelines();
  }

  private buildImplications(): Implication[] {
    return [
      {
        condition: 'open_port_80',
        implies: ['http_service', 'web_application'],
        suggestedTools: ['httpx', 'whatweb', 'nikto', 'nuclei', 'ffuf'],
        weight: 0.9,
      },
      {
        condition: 'open_port_443',
        implies: ['tls_active', 'web_service', 'https'],
        suggestedTools: ['sslyze', 'nuclei', 'nikto', 'httpx', 'whatweb'],
        weight: 0.9,
      },
      {
        condition: 'open_port_8080',
        implies: ['http_proxy', 'web_application', 'dev_server'],
        suggestedTools: ['httpx', 'nuclei', 'nikto', 'ffuf'],
        weight: 0.85,
      },
      {
        condition: 'open_port_8443',
        implies: ['https_alt', 'web_application'],
        suggestedTools: ['sslyze', 'httpx', 'nuclei'],
        weight: 0.85,
      },
      {
        condition: 'open_port_21',
        implies: ['ftp_service'],
        suggestedTools: ['nmap', 'hydra'],
        weight: 0.8,
      },
      {
        condition: 'open_port_22',
        implies: ['ssh_service'],
        suggestedTools: ['hydra', 'nmap'],
        weight: 0.7,
      },
      {
        condition: 'open_port_25',
        implies: ['smtp_service', 'email_server'],
        suggestedTools: ['nmap', 'nuclei'],
        weight: 0.7,
      },
      {
        condition: 'open_port_53',
        implies: ['dns_service'],
        suggestedTools: ['amass', 'subfinder'],
        weight: 0.8,
      },
      {
        condition: 'open_port_3306',
        implies: ['mysql_service', 'database'],
        suggestedTools: ['nmap', 'hydra', 'sqlmap'],
        weight: 0.85,
      },
      {
        condition: 'open_port_5432',
        implies: ['postgresql_service', 'database'],
        suggestedTools: ['nmap', 'hydra', 'sqlmap'],
        weight: 0.85,
      },
      {
        condition: 'open_port_27017',
        implies: ['mongodb_service', 'nosql_database'],
        suggestedTools: ['nmap', 'nuclei'],
        weight: 0.85,
      },
      {
        condition: 'open_port_6379',
        implies: ['redis_service'],
        suggestedTools: ['nmap', 'nuclei'],
        weight: 0.8,
      },
      {
        condition: 'open_port_3389',
        implies: ['rdp_service'],
        suggestedTools: ['nmap', 'hydra'],
        weight: 0.7,
      },
      {
        condition: 'open_port_445',
        implies: ['smb_service'],
        suggestedTools: ['nmap', 'nuclei'],
        weight: 0.8,
      },
      {
        condition: 'open_port_9200',
        implies: ['elasticsearch_service'],
        suggestedTools: ['nuclei', 'nmap'],
        weight: 0.85,
      },
      {
        condition: 'tech_wordpress',
        implies: ['cms', 'php', 'mysql_likely'],
        suggestedTools: ['wpscan', 'nuclei', 'sqlmap'],
        weight: 0.95,
      },
      {
        condition: 'tech_joomla',
        implies: ['cms', 'php', 'mysql_likely'],
        suggestedTools: ['joomscan', 'nuclei', 'sqlmap'],
        weight: 0.9,
      },
      {
        condition: 'tech_drupal',
        implies: ['cms', 'php'],
        suggestedTools: ['droopescan', 'nuclei'],
        weight: 0.9,
      },
      {
        condition: 'tech_php',
        implies: ['server_side_language', 'potential_rce'],
        suggestedTools: ['nuclei', 'nikto', 'ffuf', 'commix'],
        weight: 0.8,
      },
      {
        condition: 'tech_java',
        implies: ['server_side_language', 'deserialization_risk'],
        suggestedTools: ['nuclei', 'nmap'],
        weight: 0.85,
      },
      {
        condition: 'tech_nodejs',
        implies: ['server_side_language', 'npm_packages'],
        suggestedTools: ['nuclei', 'ffuf'],
        weight: 0.75,
      },
      {
        condition: 'tech_python',
        implies: ['server_side_language', 'template_injection_risk'],
        suggestedTools: ['nuclei', 'ffuf', 'commix'],
        weight: 0.8,
      },
      {
        condition: 'tech_ruby',
        implies: ['server_side_language', 'deserialization_risk'],
        suggestedTools: ['nuclei', 'ffuf'],
        weight: 0.8,
      },
      {
        condition: 'tech_nginx',
        implies: ['web_server', 'reverse_proxy_possible'],
        suggestedTools: ['nuclei', 'nikto'],
        weight: 0.7,
      },
      {
        condition: 'tech_apache',
        implies: ['web_server', 'mod_status_possible'],
        suggestedTools: ['nuclei', 'nikto'],
        weight: 0.7,
      },
      {
        condition: 'tech_iis',
        implies: ['web_server', 'windows', 'asp_net_likely'],
        suggestedTools: ['nuclei', 'nikto', 'nmap'],
        weight: 0.8,
      },
      {
        condition: 'tech_react',
        implies: ['spa', 'api_backend_likely'],
        suggestedTools: ['ffuf', 'nuclei_api', 'arjun'],
        weight: 0.7,
      },
      {
        condition: 'tech_angular',
        implies: ['spa', 'api_backend_likely'],
        suggestedTools: ['ffuf', 'nuclei_api', 'arjun'],
        weight: 0.7,
      },
      {
        condition: 'tech_vue',
        implies: ['spa', 'api_backend_likely'],
        suggestedTools: ['ffuf', 'nuclei_api', 'arjun'],
        weight: 0.7,
      },
      {
        condition: 'waf_detected',
        implies: ['filtered_traffic', 'evasion_needed'],
        suggestedTools: ['nuclei', 'sqlmap', 'dalfox'],
        weight: 0.9,
      },
      {
        condition: 'waf_cloudflare',
        implies: ['cloudflare_protection', 'rate_limited'],
        suggestedTools: ['nuclei', 'subfinder'],
        weight: 0.85,
      },
      {
        condition: 'waf_akamai',
        implies: ['akamai_protection', 'rate_limited'],
        suggestedTools: ['nuclei', 'subfinder'],
        weight: 0.85,
      },
      {
        condition: 'waf_aws_waf',
        implies: ['aws_protection', 'cloud_hosted'],
        suggestedTools: ['nuclei', 'subfinder'],
        weight: 0.85,
      },
      {
        condition: 'auth_form_detected',
        implies: ['login_page', 'credentials_required'],
        suggestedTools: ['hydra', 'nuclei_auth', 'ffuf'],
        weight: 0.9,
      },
      {
        condition: 'auth_basic',
        implies: ['basic_auth', 'credentials_required'],
        suggestedTools: ['hydra', 'medusa'],
        weight: 0.85,
      },
      {
        condition: 'auth_jwt',
        implies: ['jwt_tokens', 'token_based_auth'],
        suggestedTools: ['jwt_tool', 'nuclei_auth'],
        weight: 0.9,
      },
      {
        condition: 'auth_oauth',
        implies: ['oauth_flow', 'redirect_uri_issues'],
        suggestedTools: ['nuclei_auth', 'ffuf'],
        weight: 0.85,
      },
      {
        condition: 'api_rest',
        implies: ['rest_api', 'api_endpoints'],
        suggestedTools: ['ffuf', 'nuclei_api', 'arjun', 'sqlmap'],
        weight: 0.9,
      },
      {
        condition: 'api_graphql',
        implies: ['graphql_api', 'introspection_possible'],
        suggestedTools: ['graphql_introspection', 'nuclei_api'],
        weight: 0.95,
      },
      {
        condition: 'api_swagger',
        implies: ['documented_api', 'api_endpoints'],
        suggestedTools: ['nuclei_api', 'ffuf', 'sqlmap'],
        weight: 0.9,
      },
      {
        condition: 'subdomains_discovered',
        implies: ['expanded_attack_surface', 'http_probing_needed'],
        suggestedTools: ['httpx', 'nuclei'],
        weight: 0.85,
      },
      {
        condition: 'sql_error_detected',
        implies: ['sql_injection_likely', 'database_exposed'],
        suggestedTools: ['sqlmap'],
        weight: 0.95,
      },
      {
        condition: 'sql_error_mysql',
        implies: ['mysql_database', 'sql_injection_likely'],
        suggestedTools: ['sqlmap'],
        weight: 0.95,
      },
      {
        condition: 'sql_error_postgresql',
        implies: ['postgresql_database', 'sql_injection_likely'],
        suggestedTools: ['sqlmap'],
        weight: 0.95,
      },
      {
        condition: 'sql_error_mssql',
        implies: ['mssql_database', 'sql_injection_likely', 'windows_host'],
        suggestedTools: ['sqlmap'],
        weight: 0.95,
      },
      {
        condition: 'file_upload_found',
        implies: ['file_upload_endpoint', 'rce_possible'],
        suggestedTools: ['upload_bypass', 'nuclei', 'commix'],
        weight: 0.9,
      },
      {
        condition: 'file_inclusion_detected',
        implies: ['lfi_possible', 'rfi_possible'],
        suggestedTools: ['nuclei', 'ffuf', 'commix'],
        weight: 0.9,
      },
      {
        condition: 'cors_misconfiguration',
        implies: ['cors_bypass', 'data_exfiltration'],
        suggestedTools: ['nuclei'],
        weight: 0.7,
      },
      {
        condition: 'open_redirect',
        implies: ['redirect_abuse', 'phishing_vector'],
        suggestedTools: ['nuclei', 'ffuf'],
        weight: 0.7,
      },
      {
        condition: 'xss_reflected',
        implies: ['reflected_xss', 'input_not_sanitized'],
        suggestedTools: ['dalfox', 'xsstrike'],
        weight: 0.9,
      },
      {
        condition: 'xss_stored',
        implies: ['stored_xss', 'persistent_injection'],
        suggestedTools: ['dalfox', 'xsstrike'],
        weight: 0.95,
      },
      {
        condition: 'directory_listing',
        implies: ['information_disclosure', 'misconfiguration'],
        suggestedTools: ['ffuf', 'nuclei'],
        weight: 0.7,
      },
      {
        condition: 'git_exposed',
        implies: ['source_code_leak', 'credential_exposure'],
        suggestedTools: ['nuclei'],
        weight: 0.95,
      },
      {
        condition: 'backup_files',
        implies: ['information_disclosure', 'old_configs'],
        suggestedTools: ['ffuf', 'nuclei'],
        weight: 0.8,
      },
      {
        condition: 'cve_known',
        implies: ['known_vulnerability', 'exploit_available'],
        suggestedTools: ['nuclei', 'version_cve_lookup'],
        weight: 0.95,
      },
      {
        condition: 'rate_limit_absent',
        implies: ['brute_force_possible', 'no_rate_limiting'],
        suggestedTools: ['hydra', 'ffuf'],
        weight: 0.8,
      },
      {
        condition: 'password_reset',
        implies: ['account_takeover_vector', 'token_prediction'],
        suggestedTools: ['nuclei_auth', 'ffuf'],
        weight: 0.85,
      },
      {
        condition: 'idor_pattern',
        implies: ['sequential_ids', 'access_control_issue'],
        suggestedTools: ['ffuf', 'nuclei_api'],
        weight: 0.9,
      },
      {
        condition: 'ssrf_indicator',
        implies: ['url_fetch', 'internal_network_access'],
        suggestedTools: ['nuclei', 'ffuf'],
        weight: 0.9,
      },
      {
        condition: 'deserialization_risk',
        implies: ['rce_possible', 'object_injection'],
        suggestedTools: ['nuclei'],
        weight: 0.9,
      },
      {
        condition: 'admin_panel',
        implies: ['privileged_access', 'credential_guessing'],
        suggestedTools: ['hydra', 'nuclei_auth', 'ffuf'],
        weight: 0.85,
      },
    ];
  }

  private buildPipelines(): ToolPipeline[] {
    return [
      {
        name: 'port_discovery',
        steps: ['nmap', 'banner_grab', 'version_cve_lookup'],
        trigger: 'initial_recon',
        completedSteps: 0,
      },
      {
        name: 'web_app_recon',
        steps: ['httpx', 'whatweb', 'nuclei'],
        trigger: 'web_service_detected',
        completedSteps: 0,
      },
      {
        name: 'subdomain_enum',
        steps: ['subfinder', 'httpx', 'nuclei'],
        trigger: 'domain_target',
        completedSteps: 0,
      },
      {
        name: 'api_testing',
        steps: ['ffuf', 'nuclei_api', 'sqlmap'],
        trigger: 'api_endpoint_found',
        completedSteps: 0,
      },
      {
        name: 'auth_testing',
        steps: ['hydra', 'nuclei_auth'],
        trigger: 'auth_detected',
        completedSteps: 0,
      },
      {
        name: 'cms_wordpress',
        steps: ['wpscan', 'nuclei'],
        trigger: 'tech_wordpress',
        completedSteps: 0,
      },
      {
        name: 'tls_analysis',
        steps: ['sslyze', 'testssl'],
        trigger: 'open_port_443',
        completedSteps: 0,
      },
      {
        name: 'xss_validation',
        steps: ['dalfox', 'xsstrike'],
        trigger: 'xss_reflected',
        completedSteps: 0,
      },
      {
        name: 'sqli_exploitation',
        steps: ['sqlmap'],
        trigger: 'sql_error_detected',
        completedSteps: 0,
      },
      {
        name: 'directory_bruteforce',
        steps: ['ffuf', 'feroxbuster'],
        trigger: 'web_service_detected',
        completedSteps: 0,
      },
    ];
  }

  aggregateKnownFacts(huntId: string): KnownFacts {
    const facts: KnownFacts = {
      endpoints: new Set<string>(),
      technologies: new Set<string>(),
      vulnerabilities: new Set<string>(),
      testedCombinations: new Set<string>(),
      negativeResults: this.negativeEvidenceStore.get(huntId) || [],
    };

    const memory = reasoningEngine.getMissionMemory(huntId);
    if (!memory) return facts;

    memory.discoveredEndpoints.forEach((_, url) => {
      facts.endpoints.add(url);
    });

    memory.discoveredTechnologies.forEach((_, key) => {
      facts.technologies.add(key);
    });

    memory.discoveredVulnerabilities.forEach((_, key) => {
      facts.vulnerabilities.add(key);
    });

    for (const action of memory.actionHistory) {
      facts.testedCombinations.add(`${action.tool}:${action.target}`);
    }

    return facts;
  }

  calculateNovelty(tool: string, knownFacts: KnownFacts): number {
    const outputTypes = TOOL_OUTPUT_MAP[tool] || [];
    if (outputTypes.length === 0) return 0.5;

    let knownOverlap = 0;
    let totalTypes = outputTypes.length;

    for (const outputType of outputTypes) {
      switch (outputType) {
        case 'endpoints':
        case 'directories':
        case 'subdomains':
          if (knownFacts.endpoints.size > 20) knownOverlap += 0.8;
          else if (knownFacts.endpoints.size > 10) knownOverlap += 0.5;
          else if (knownFacts.endpoints.size > 5) knownOverlap += 0.3;
          break;
        case 'technologies':
        case 'frameworks':
        case 'versions':
          if (knownFacts.technologies.size > 10) knownOverlap += 0.7;
          else if (knownFacts.technologies.size > 5) knownOverlap += 0.4;
          break;
        case 'vulnerabilities':
        case 'misconfigurations':
        case 'cves':
        case 'xss':
        case 'command_injection':
        case 'api_issues':
        case 'auth_issues':
        case 'file_upload':
          if (knownFacts.vulnerabilities.size > 10) knownOverlap += 0.3;
          else knownOverlap += 0.1;
          break;
        case 'credentials':
        case 'auth_bypass':
        case 'tokens':
          knownOverlap += 0.05;
          break;
        default:
          knownOverlap += 0.1;
          break;
      }
    }

    const overlapRatio = knownOverlap / totalTypes;
    return Math.max(0.05, 1 - overlapRatio);
  }

  getActivePipeline(huntId: string, lastTool: string): ToolPipeline | null {
    const huntPipelines = this.activePipelines.get(huntId);
    if (!huntPipelines) return null;

    for (const pipeline of huntPipelines) {
      const currentStepIndex = pipeline.completedSteps;
      if (currentStepIndex > 0 && currentStepIndex < pipeline.steps.length) {
        const previousStep = pipeline.steps[currentStepIndex - 1];
        if (previousStep === lastTool) {
          return pipeline;
        }
      }
    }

    for (const pipeline of huntPipelines) {
      const stepIndex = pipeline.steps.indexOf(lastTool);
      if (stepIndex >= 0 && stepIndex < pipeline.steps.length - 1) {
        pipeline.completedSteps = stepIndex + 1;
        return pipeline;
      }
    }

    return null;
  }

  getNegativePenalty(
    tool: string,
    target: string,
    negativeEvidence: NegativeEvidence[]
  ): number {
    const relevant = negativeEvidence.filter(
      (ne) => ne.target === target
    );

    if (relevant.length === 0) return 1.0;

    const toolOutputs = TOOL_OUTPUT_MAP[tool] || [];
    const directNegative = relevant.filter((ne) => ne.tool === tool);
    if (directNegative.length > 0) {
      const recency = Date.now() - directNegative[0].timestamp;
      const hoursSince = recency / (1000 * 60 * 60);
      if (hoursSince < 1) return 0.1;
      if (hoursSince < 6) return 0.3;
      if (hoursSince < 24) return 0.5;
      return 0.7;
    }

    const categoryOverlap = relevant.filter((ne) =>
      toolOutputs.includes(ne.category)
    );

    if (categoryOverlap.length === 0) return 1.0;

    const penaltyPerOverlap = 0.15;
    const totalPenalty = Math.min(0.6, categoryOverlap.length * penaltyPerOverlap);
    return Math.max(0.4, 1.0 - totalPenalty);
  }

  select(huntId: string, availableTools: string[]): RankedTool[] {
    const memory = reasoningEngine.getMissionMemory(huntId);
    if (!memory) return [];

    const knownFacts = this.aggregateKnownFacts(huntId);
    const activeConditions = this.deriveConditions(memory);
    const triggeredImplications = this.matchImplications(activeConditions);
    const rankedTools: RankedTool[] = [];

    this.ensurePipelines(huntId, activeConditions);

    const lastAction = memory.actionHistory.length > 0
      ? memory.actionHistory[memory.actionHistory.length - 1]
      : null;

    const activePipeline = lastAction
      ? this.getActivePipeline(huntId, lastAction.tool)
      : null;

    if (activePipeline && activePipeline.completedSteps < activePipeline.steps.length) {
      const nextStep = activePipeline.steps[activePipeline.completedSteps];
      if (availableTools.includes(nextStep)) {
        const novelty = this.calculateNovelty(nextStep, knownFacts);
        const negativePenalty = this.getNegativePenalty(
          nextStep,
          memory.target,
          knownFacts.negativeResults
        );

        rankedTools.push({
          tool: nextStep,
          target: memory.target,
          score: 0.95 * novelty * negativePenalty,
          rationale: `Pipeline "${activePipeline.name}" step ${activePipeline.completedSteps + 1}/${activePipeline.steps.length}: ${nextStep}`,
          parameters: TOOL_PARAMETERS[nextStep] || {},
          pipeline: activePipeline.name,
        });
      }
    }

    const impliedToolScores = new Map<string, { score: number; rationales: string[] }>();
    for (const impl of triggeredImplications) {
      for (const tool of impl.suggestedTools) {
        if (!availableTools.includes(tool)) continue;

        const existing = impliedToolScores.get(tool) || { score: 0, rationales: [] };
        existing.score += impl.weight;
        existing.rationales.push(
          `${impl.condition} → ${tool} (weight: ${impl.weight})`
        );
        impliedToolScores.set(tool, existing);
      }
    }

    const targets = this.deriveTargets(memory);

    const impliedEntries = Array.from(impliedToolScores.entries());
    for (let i = 0; i < impliedEntries.length; i++) {
      const [tool, data] = impliedEntries[i];
      for (let j = 0; j < targets.length; j++) {
        const target = targets[j];
        const comboKey = `${tool}:${target}`;
        if (knownFacts.testedCombinations.has(comboKey)) continue;

        const novelty = this.calculateNovelty(tool, knownFacts);
        const negativePenalty = this.getNegativePenalty(
          tool,
          target,
          knownFacts.negativeResults
        );

        const implicationScore = Math.min(1.0, data.score / 2);
        const finalScore = implicationScore * novelty * negativePenalty;

        if (finalScore < 0.05) continue;

        const pipelineForTool = rankedTools.find(
          (r) => r.tool === tool && r.pipeline
        );
        if (pipelineForTool) continue;

        rankedTools.push({
          tool,
          target,
          score: finalScore,
          rationale: data.rationales.join('; ') +
            ` | novelty: ${novelty.toFixed(2)}, negativePenalty: ${negativePenalty.toFixed(2)}`,
          parameters: this.buildParameters(tool, memory, target),
        });
      }
    }

    for (const tool of availableTools) {
      if (impliedToolScores.has(tool)) continue;

      const novelty = this.calculateNovelty(tool, knownFacts);
      if (novelty < 0.2) continue;

      const comboKey = `${tool}:${memory.target}`;
      if (knownFacts.testedCombinations.has(comboKey)) continue;

      const negativePenalty = this.getNegativePenalty(
        tool,
        memory.target,
        knownFacts.negativeResults
      );

      const baseScore = 0.3 * novelty * negativePenalty;
      if (baseScore < 0.05) continue;

      rankedTools.push({
        tool,
        target: memory.target,
        score: baseScore,
        rationale: `Fallback selection: no direct implication, novelty: ${novelty.toFixed(2)}`,
        parameters: TOOL_PARAMETERS[tool] || {},
      });
    }

    rankedTools.sort((a, b) => b.score - a.score);

    const seen = new Set<string>();
    const deduped: RankedTool[] = [];
    for (const rt of rankedTools) {
      const key = `${rt.tool}:${rt.target}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(rt);
      }
    }

    // Filter out tools on open circuits; substitute fallback tool if one exists
    const circuitFiltered: RankedTool[] = [];
    for (const rt of deduped) {
      const circuit = circuitBreaker.canExecute(rt.tool);
      if (circuit.allowed) {
        circuitFiltered.push(rt);
      } else if (circuit.fallback) {
        circuitFiltered.push({ ...rt, tool: circuit.fallback, rationale: `${rt.rationale} [circuit fallback: ${circuit.fallback}]` });
      }
      // tools with no fallback are silently dropped — the circuit is open
    }

    if (circuitFiltered.length > 0) {
      const topTool = circuitFiltered[0];
      const noveltyScore = this.calculateNovelty(topTool.tool, knownFacts);
      huntCortex.broadcast({
        signalType: SignalType.TOOL_NOVELTY,
        sourceSystem: 'tool_selector',
        huntId,
        payload: { noveltyScore, topTool: topTool.tool },
        confidence: 1.0,
      });
    }

    return circuitFiltered;
  }

  recordResult(
    huntId: string,
    tool: string,
    target: string,
    foundSomething: boolean
  ): void {
    if (!foundSomething) {
      const outputTypes = TOOL_OUTPUT_MAP[tool] || ['unknown'];
      const negList = this.negativeEvidenceStore.get(huntId) || [];

      for (const category of outputTypes) {
        negList.push({
          tool,
          target,
          timestamp: Date.now(),
          category,
        });

        huntCortex.broadcast({
          signalType: SignalType.TOOL_NEGATIVE_EVIDENCE,
          sourceSystem: 'tool_selector',
          huntId,
          payload: { tool, target, category },
          confidence: 1.0,
        });
      }

      if (negList.length > 500) {
        negList.splice(0, negList.length - 500);
      }

      this.negativeEvidenceStore.set(huntId, negList);
    }

    const huntPipelines = this.activePipelines.get(huntId);
    if (huntPipelines) {
      for (const pipeline of huntPipelines) {
        const stepIndex = pipeline.steps.indexOf(tool);
        if (stepIndex >= 0 && stepIndex === pipeline.completedSteps) {
          pipeline.completedSteps = stepIndex + 1;
        }
      }
    }
  }

  private deriveConditions(memory: MissionMemory): string[] {
    const conditions: string[] = [];

    memory.discoveredEndpoints.forEach((endpoint) => {
      const ep = endpoint as any;
      const url: string = ep.url || '';

      const portMatch = url.match(/:(\d+)/);
      if (portMatch) {
        conditions.push(`open_port_${portMatch[1]}`);
      }

      if (url.includes('443') || url.startsWith('https')) {
        conditions.push('open_port_443');
      }
      if (url.includes(':80') || url.startsWith('http://')) {
        conditions.push('open_port_80');
      }

      if (ep.authenticated) {
        conditions.push('auth_form_detected');
      }

      if (ep.riskLevel === 'high') {
        conditions.push('high_risk_endpoint');
      }

      const lowerUrl = url.toLowerCase();
      if (lowerUrl.includes('/api/') || lowerUrl.includes('/api/v')) {
        conditions.push('api_rest');
      }
      if (lowerUrl.includes('/graphql')) {
        conditions.push('api_graphql');
      }
      if (lowerUrl.includes('/swagger') || lowerUrl.includes('/openapi')) {
        conditions.push('api_swagger');
      }
      if (lowerUrl.includes('/admin')) {
        conditions.push('admin_panel');
      }
      if (lowerUrl.includes('/upload')) {
        conditions.push('file_upload_found');
      }
      if (lowerUrl.includes('/login') || lowerUrl.includes('/auth')) {
        conditions.push('auth_form_detected');
      }
      if (lowerUrl.includes('/reset') || lowerUrl.includes('/forgot')) {
        conditions.push('password_reset');
      }
    });

    memory.discoveredTechnologies.forEach((tech) => {
      const t = tech as any;
      const name = (t.name || '').toLowerCase();

      conditions.push(`tech_${name}`);

      if (t.category === 'waf') {
        conditions.push('waf_detected');
        conditions.push(`waf_${name}`);
      }
      if (t.category === 'cms') {
        conditions.push(`tech_${name}`);
      }
      if (t.category === 'framework') {
        if (['react', 'angular', 'vue'].includes(name)) {
          conditions.push(`tech_${name}`);
        }
      }
      if (t.category === 'language') {
        conditions.push(`tech_${name}`);
      }
      if (t.category === 'server') {
        conditions.push(`tech_${name}`);
      }
      if (t.category === 'database') {
        conditions.push(`tech_${name}`);
      }
    });

    memory.discoveredVulnerabilities.forEach((vuln) => {
      const v = vuln as any;
      const type = (v.type || '').toLowerCase();

      if (type.includes('sql') || type.includes('sqli')) {
        conditions.push('sql_error_detected');
        const evidence = (v.evidence || '').toLowerCase();
        if (evidence.includes('mysql')) conditions.push('sql_error_mysql');
        if (evidence.includes('postgres')) conditions.push('sql_error_postgresql');
        if (evidence.includes('mssql') || evidence.includes('microsoft'))
          conditions.push('sql_error_mssql');
      }
      if (type.includes('xss')) {
        if (type.includes('stored')) conditions.push('xss_stored');
        else conditions.push('xss_reflected');
      }
      if (type.includes('cors')) conditions.push('cors_misconfiguration');
      if (type.includes('redirect')) conditions.push('open_redirect');
      if (type.includes('file inclusion') || type.includes('lfi') || type.includes('rfi')) {
        conditions.push('file_inclusion_detected');
      }
      if (type.includes('deserialization')) conditions.push('deserialization_risk');
      if (type.includes('ssrf')) conditions.push('ssrf_indicator');
      if (type.includes('idor')) conditions.push('idor_pattern');
      if (type.includes('directory listing')) conditions.push('directory_listing');
      if (type.includes('.git')) conditions.push('git_exposed');
      if (v.cvss && v.cvss > 0) conditions.push('cve_known');
    });

    if (memory.beliefs) {
      for (const belief of memory.beliefs) {
        const stmt = belief.statement.toLowerCase();
        if (stmt.includes('jwt')) conditions.push('auth_jwt');
        if (stmt.includes('oauth')) conditions.push('auth_oauth');
        if (stmt.includes('basic auth')) conditions.push('auth_basic');
      }
    }

    if (memory.discoveredEndpoints.size > 0) {
      conditions.push('subdomains_discovered');
    }

    return Array.from(new Set(conditions));
  }

  private matchImplications(conditions: string[]): Implication[] {
    const matched: Implication[] = [];
    const conditionSet = new Set(conditions);

    for (const impl of this.implications) {
      if (conditionSet.has(impl.condition)) {
        matched.push(impl);
      }
    }

    return matched;
  }

  private deriveTargets(memory: MissionMemory): string[] {
    const targets = new Set<string>();
    targets.add(memory.target);

    memory.discoveredEndpoints.forEach((_, url) => {
      try {
        const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
        targets.add(parsed.origin);
      } catch {
        targets.add(url);
      }
    });

    const targetArray = Array.from(targets);
    return targetArray.slice(0, 10);
  }

  private buildParameters(tool: string, memory: MissionMemory, target: string): any {
    const base = { ...(TOOL_PARAMETERS[tool] || {}) };

    if (tool === 'sqlmap' && target !== memory.target) {
      base.url = target;
    }

    if (tool === 'nuclei') {
      const goal = memory.goal.toLowerCase().replace(/ /g, '');
      base.templates = goal;
    }

    if (tool === 'ffuf' || tool === 'gobuster' || tool === 'feroxbuster') {
      base.url = target;
    }

    if (tool === 'hydra') {
      base.target = target;
    }

    if (tool === 'httpx') {
      base.target = target;
    }

    return base;
  }

  private ensurePipelines(huntId: string, conditions: string[]): void {
    if (!this.activePipelines.has(huntId)) {
      this.activePipelines.set(huntId, []);
    }

    const existing = this.activePipelines.get(huntId)!;
    const existingNames = new Set(existing.map((p) => p.name));
    const conditionSet = new Set(conditions);

    const triggerMap: Record<string, string[]> = {
      initial_recon: ['open_port_80', 'open_port_443'],
      web_service_detected: ['open_port_80', 'open_port_443', 'open_port_8080', 'open_port_8443'],
      domain_target: ['subdomains_discovered'],
      api_endpoint_found: ['api_rest', 'api_graphql', 'api_swagger'],
      auth_detected: ['auth_form_detected', 'auth_basic', 'auth_jwt', 'auth_oauth'],
      tech_wordpress: ['tech_wordpress'],
      open_port_443: ['open_port_443'],
      xss_reflected: ['xss_reflected'],
      sql_error_detected: ['sql_error_detected', 'sql_error_mysql', 'sql_error_postgresql', 'sql_error_mssql'],
    };

    for (const pipelineTemplate of this.pipelines) {
      if (existingNames.has(pipelineTemplate.name)) continue;

      const triggerConditions = triggerMap[pipelineTemplate.trigger] || [pipelineTemplate.trigger];
      const triggered = triggerConditions.some((c) => conditionSet.has(c));

      if (triggered) {
        existing.push({
          name: pipelineTemplate.name,
          steps: [...pipelineTemplate.steps],
          trigger: pipelineTemplate.trigger,
          completedSteps: 0,
        });
      }
    }
  }

  getToolYield(tool: string, knownFacts: KnownFacts): ToolYield {
    return {
      tool,
      expectedOutputTypes: TOOL_OUTPUT_MAP[tool] || [],
      noveltyScore: this.calculateNovelty(tool, knownFacts),
    };
  }

  getImplications(): Implication[] {
    return this.implications;
  }

  getActivePipelines(huntId: string): ToolPipeline[] {
    return this.activePipelines.get(huntId) || [];
  }

  getNegativeEvidence(huntId: string): NegativeEvidence[] {
    return this.negativeEvidenceStore.get(huntId) || [];
  }

  clearHuntData(huntId: string): void {
    this.activePipelines.delete(huntId);
    this.negativeEvidenceStore.delete(huntId);
  }
}

export const contextualToolSelector = new ContextualToolSelector();

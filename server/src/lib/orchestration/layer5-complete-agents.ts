/**
 * Prompt-template / capability metadata registry for the 6-layer
 * orchestration subsystem's agent types — consumed by layer6-ai-bridge.ts's
 * invokeByAgent() (promptTemplate, confidenceThreshold, capabilities, tools
 * fields only; this is plain data, never executed).
 *
 * 2026-07-22 (Phase 2, external-tool chokepoint): this file used to ALSO
 * define CompleteMetaAgent and 10 concrete agent classes (ReconAgent,
 * ExploitAgent, CredentialAgent, IntelAgent, BlueTeamAgent, PivotAgent,
 * ReportAgent, WordlistAgent, SimGenAgent, SmartAgent) whose runTool()
 * methods shelled out via raw exec() with the same weak/no-escaping pattern
 * found live-exploitable in lib/orchestration/layer5-meta-agents.ts — plus a
 * `completeAgents` Record of instances of them. Dynamic-reference-checked
 * (every call form: direct calls, string-keyed dispatch, DI/config lookup)
 * and confirmed dead: `completeAgents` had exactly one consumer,
 * PassKEvaluator.evaluate() in pass-k-evaluator.ts, which itself had zero
 * live callers (only PassKEvaluatorService.resolveK() — a different, safe
 * method — was ever called, from layer2-agent-loop.ts). Both the dead
 * exec-invoking classes AND their sole dead caller were deleted rather than
 * migrated, since nothing reachable exercised either. This file now
 * contains only the metadata layer6-ai-bridge.ts genuinely uses.
 */

export interface MetaAgent {
  id: string;
  name: string;
  description: string;
  capabilities: string[];
  tools: string[];
  promptTemplate: string;
  confidenceThreshold: number;
  confidenceRules?: Record<string, number>;
  outputSchema?: Record<string, string>;
  securityControls?: {
    autoRedaction?: boolean;
    prioritizeAdmins?: boolean;
    rateLimitBruteforce?: boolean;
    logCredentialSource?: boolean;
  };
  externalAPIs?: Record<string, any>;
  dualPerspective?: boolean;
  outputFormats?: Record<string, boolean>;
  networkAware?: boolean;
  credentialIntegration?: boolean;
  audienceAdaptation?: Record<string, boolean>;
  contextSources?: string[];
  trainingIntegration?: boolean;
  difficultyLevels?: string[];
  adaptivePrompting?: boolean;
  contextWindowLimit?: number;
  confidenceDriftThreshold?: number;
}

export const reconAgentMeta: MetaAgent = {
  id: 'recon',
  name: 'Recon Agent',
  description: 'Reconnaissance and discovery agent for subdomain enumeration, port scanning, and service detection',
  capabilities: ['subdomain_enumeration', 'port_scanning', 'service_detection', 'web_fingerprinting', 'subdomain_takeover_detection', 'live_host_validation'],
  tools: ['subfinder', 'amass', 'httpx', 'nmap', 'whatweb', 'masscan'],
  promptTemplate: 'recon_scan',
  confidenceThreshold: 0.7,
  outputSchema: {
    target: 'string',
    hosts_discovered: 'string[]',
    open_ports: 'number[]',
    services_detected: 'string[]',
    subdomains: 'string[]',
    takeover_vulnerable: 'boolean',
    confidence: 'number',
    next_step: 'string'
  }
};

export const exploitAgentMeta: MetaAgent = {
  id: 'exploit',
  name: 'Exploit Agent',
  description: 'Vulnerability exploitation agent for CVE matching, payload generation, and exploit validation',
  capabilities: ['vulnerability_exploitation', 'cve_matching', 'payload_generation', 'exploit_validation', 'privilege_escalation'],
  tools: ['sqlmap', 'nuclei', 'metasploit', 'custom_exploits'],
  promptTemplate: 'exploit_execute',
  confidenceThreshold: 0.9,
  confidenceRules: {
    detection: 0.7,
    data_extraction: 0.85,
    remote_execution: 0.9,
    privilege_escalation: 0.9
  }
};

export const credentialAgentMeta: MetaAgent = {
  id: 'credential',
  name: 'Credential Agent',
  description: 'Credential extraction and analysis agent for hash cracking, password analysis, and account enumeration',
  capabilities: ['credential_extraction', 'hash_cracking', 'password_analysis', 'account_enumeration', 'pass_the_hash', 'credential_reuse_testing', 'admin_prioritization'],
  tools: ['mimikatz', 'secretsdump', 'hashcat', 'john', 'hydra'],
  promptTemplate: 'credential_extract',
  confidenceThreshold: 0.85,
  confidenceRules: {
    hash_extraction: 0.7,
    credential_validation: 0.85,
    pass_the_hash: 0.9,
    domain_admin_attack: 0.95
  },
  securityControls: {
    autoRedaction: true,
    prioritizeAdmins: true,
    rateLimitBruteforce: true,
    logCredentialSource: true
  }
};

export const intelAgentMeta: MetaAgent = {
  id: 'intel',
  name: 'Intel Agent',
  description: 'Threat intelligence agent for IOC analysis, MITRE ATT&CK mapping, and threat actor attribution',
  capabilities: ['threat_correlation', 'ioc_analysis', 'mitre_attack_mapping', 'attribution', 'campaign_tracking', 'actor_profiling', 'external_enrichment'],
  tools: ['virustotal_api', 'abuseipdb_api', 'shodan_api', 'mitre_attack'],
  promptTemplate: 'intel_correlate',
  confidenceThreshold: 0.85,
  confidenceRules: {
    ioc_identification: 0.7,
    threat_correlation: 0.8,
    attribution: 0.85,
    campaign_linkage: 0.9
  },
  externalAPIs: {
    virustotal: { enabled: true },
    abuseipdb: { enabled: true },
    shodan: { enabled: true }
  }
};

export const blueTeamAgentMeta: MetaAgent = {
  id: 'blueteam',
  name: 'Blue Team Agent',
  description: 'Defensive security agent for detection validation, hunting query generation, and incident analysis',
  capabilities: ['detection_validation', 'hunting_query_generation', 'incident_analysis', 'siem_rule_creation', 'detection_gap_analysis', 'adversarial_simulation', 'containment_recommendation'],
  tools: ['sigma', 'yara', 'splunk_query', 'elastic_query', 'defender_query'],
  promptTemplate: 'blueteam_detect',
  confidenceThreshold: 0.8,
  dualPerspective: true,
  outputFormats: {
    sigma: true,
    splunk: true,
    elastic: true,
    defender: true,
    yara: true
  }
};

export const pivotAgentMeta: MetaAgent = {
  id: 'pivot',
  name: 'Pivot Agent',
  description: 'Lateral movement agent for credential reuse, persistence establishment, and network topology mapping',
  capabilities: ['lateral_movement', 'credential_reuse', 'persistence_establishment', 'network_topology_mapping', 'pivot_path_planning', 'os_specific_techniques', 'stealth_movement'],
  tools: ['psexec', 'wmi', 'ssh', 'rdp', 'smb', 'bloodhound'],
  promptTemplate: 'pivot_move',
  confidenceThreshold: 0.85,
  confidenceRules: {
    reconnaissance: 0.7,
    credential_validation: 0.85,
    lateral_movement: 0.9,
    persistence: 0.9
  },
  networkAware: true,
  credentialIntegration: true
};

export const reportAgentMeta: MetaAgent = {
  id: 'report',
  name: 'Report Agent',
  description: 'Report generation agent for finding documentation, CVSS scoring, and remediation roadmaps',
  capabilities: ['finding_documentation', 'cvss_scoring', 'executive_summary', 'technical_detail', 'remediation_roadmap', 'evidence_attachment', 'finding_deduplication', 'severity_prioritization'],
  tools: ['pandoc', 'wkhtmltopdf', 'docx_generator'],
  promptTemplate: 'report_generate',
  confidenceThreshold: 0.8,
  outputFormats: {
    pdf: true,
    docx: true,
    html: true,
    json: true,
    markdown: true
  },
  audienceAdaptation: {
    executive: true,
    technical: true,
    developer: true
  }
};

export const wordlistAgentMeta: MetaAgent = {
  id: 'wordlist',
  name: 'Wordlist Agent',
  description: 'Wordlist generation agent for context-aware password lists and corporate terminology extraction',
  capabilities: ['context_wordlist_generation', 'password_pattern_analysis', 'corporate_terminology_extraction', 'industry_specific_words', 'mutation_rules', 'smart_combination'],
  tools: ['cewl', 'crunch', 'hashcat_rules', 'custom_generators'],
  promptTemplate: 'wordlist_generate',
  confidenceThreshold: 0.7,
  contextSources: ['website_content', 'company_documents', 'social_media', 'job_postings', 'industry_terms']
};

export const simgenAgentMeta: MetaAgent = {
  id: 'simgen',
  name: 'SimGen Agent',
  description: 'Simulation generation agent for scenario creation, CTF challenges, and training path design',
  capabilities: ['scenario_generation', 'ctf_challenge_creation', 'training_path_design', 'difficulty_calibration', 'solution_validation', 'learning_objective_mapping'],
  tools: ['docker', 'vagrant', 'scenario_templates'],
  promptTemplate: 'simgen_create',
  confidenceThreshold: 0.75,
  trainingIntegration: true,
  difficultyLevels: ['beginner', 'intermediate', 'advanced', 'expert']
};

export const smartAgentMeta: MetaAgent = {
  id: 'smart',
  name: 'Smart Agent',
  description: 'Orchestration agent for prompt phase switching, tool chain optimization, and cross-agent synthesis',
  capabilities: ['prompt_phase_switching', 'tool_chain_optimization', 'pattern_learning', 'confidence_drift_detection', 'context_window_management', 'cross_agent_synthesis', 'learned_pivot_application'],
  tools: ['all'],
  promptTemplate: 'smart_orchestrate',
  confidenceThreshold: 0.8,
  adaptivePrompting: true,
  contextWindowLimit: 4096,
  confidenceDriftThreshold: 0.15
};

import { codegenAgentMeta } from './layer5-codegen-agent';

export const ALL_AGENTS: MetaAgent[] = [reconAgentMeta, exploitAgentMeta, credentialAgentMeta, intelAgentMeta, blueTeamAgentMeta, pivotAgentMeta, reportAgentMeta, wordlistAgentMeta, simgenAgentMeta, smartAgentMeta, codegenAgentMeta];

export const AGENTS_BY_ID: Record<string, MetaAgent> = ALL_AGENTS.reduce((acc, agent) => {
  acc[agent.id] = agent;
  return acc;
}, {} as Record<string, MetaAgent>);

export function getAgentById(id: string): MetaAgent | undefined {
  return AGENTS_BY_ID[id];
}

export function getAgentsByCapability(capability: string): MetaAgent[] {
  return ALL_AGENTS.filter(agent => agent.capabilities.includes(capability));
}

export function getAgentsByTool(tool: string): MetaAgent[] {
  return ALL_AGENTS.filter(agent => agent.tools.includes(tool) || agent.tools.includes('all'));
}

export type CompleteAgentType = 'recon' | 'exploit' | 'credential' | 'intel' | 'blueteam' | 'pivot' | 'report' | 'wordlist' | 'simgen' | 'smart' | 'codegen';

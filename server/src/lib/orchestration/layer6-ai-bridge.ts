import { AgentType } from './types';
import { CompleteAgentType, MetaAgent, getAgentById } from './layer5-complete-agents';
import { promptManager } from './prompt-loader';

export class AIBridge {
  private ollamaUrl: string;

  constructor(ollamaUrl: string = 'http://localhost:11434') {
    this.ollamaUrl = ollamaUrl;
  }

  async invokeAgent(
    agentType: AgentType | CompleteAgentType | 'orchestrator' | 'planner' | 'analyst' | 'researcher' | 'validator',
    prompt: string,
    context: Record<string, any> = {}
  ): Promise<{ success: boolean; result?: any; error?: string; provider?: string }> {
    const systemPrompt = this.getAgentSystemPrompt(agentType);

    try {
      const result = await this.callOllama(systemPrompt, prompt, context);
      return { success: true, result, provider: 'ollama' };
    } catch (ollamaError) {
      if (process.env.REAL_TOOLS === 'true') {
        console.error('[AIBridge] Ollama unavailable in REAL_TOOLS mode - returning error instead of simulation');
        return { success: false, error: 'Ollama AI backend unavailable. Start Ollama or configure an alternative AI provider.', provider: 'none' };
      }
      console.log('[AIBridge] Ollama unavailable, using simulation fallback...');
    }

    const result = this.simulate(agentType, prompt, context);
    return { success: true, result, provider: 'simulation' };
  }

  async invokeWithTemplate(
    templateId: string,
    variables: Record<string, string>,
    context: Record<string, any> = {}
  ): Promise<{ success: boolean; result?: any; error?: string; provider?: string; templateId?: string }> {
    const rendered = promptManager.renderTemplate(templateId, variables);
    if (!rendered) {
      return { success: false, error: `Template not found: ${templateId}` };
    }

    const template = promptManager.getTemplate(templateId);
    const agentType = template?.agent || 'smart';

    try {
      const result = await this.callOllama(
        this.getAgentSystemPrompt(agentType),
        rendered,
        context
      );
      return { success: true, result, provider: 'ollama', templateId };
    } catch {
      if (process.env.REAL_TOOLS === 'true') {
        console.error('[AIBridge] Ollama unavailable for template in REAL_TOOLS mode - returning error');
        return { success: false, error: 'Ollama AI backend unavailable for template execution.', provider: 'none', templateId };
      }
      console.log('[AIBridge] Ollama unavailable for template, using simulation...');
    }

    const result = this.simulate(agentType, rendered, context);
    return { success: true, result, provider: 'simulation', templateId };
  }

  private getAgentSystemPrompt(agentType: string): string {
    const prompts: Record<string, string> = {
      recon: 'You are a reconnaissance agent. Discover subdomains, endpoints, and technologies. Be thorough but efficient. Look for interesting attack surface. Return results in JSON format with keys: subdomains[], endpoints[], technologies[].',

      scanner: 'You are a vulnerability scanner agent. Analyze endpoints for common vulnerabilities. Focus on: SQL injection, XSS, authentication issues, misconfigurations. Return results in JSON format with keys: vulnerabilities[] containing {type, severity, endpoint, description, exploitable}.',

      exploit: 'You are an exploitation agent. Given a vulnerability, determine if it is exploitable and how. Be precise and provide proof-of-concept payloads when possible. Return results in JSON format with keys: {exploitable: boolean, payload?: string, steps?: string[]}.',

      support: 'You are a support agent. Help other agents by providing wordlists, cracking passwords, or running auxiliary tasks. Be helpful and efficient. Return results in JSON format.',

      credential: 'You are a credential security agent. Extract, crack, and manage credentials with automatic redaction. Prioritize admin/root accounts. Rate-limit brute force attempts. Return results in JSON with keys: {credentials[], cracked_count, admin_count}.',

      intel: 'You are a threat intelligence agent. Correlate findings with external threat intel sources (VirusTotal, AbuseIPDB, Shodan). Map to MITRE ATT&CK framework. Track campaigns and attribute actors. Return results in JSON with keys: {iocs[], mitre_mappings[], threat_actors[], attribution_confidence}.',

      blueteam: 'You are a blue team defense agent. Generate Sigma detection rules, SIEM queries (Splunk SPL, Elastic KQL), and YARA rules. Analyze detection gaps. Provide dual red/blue team perspective. Return results in JSON with keys: {rules[], queries[], gaps[], coverage_percentage, recommendations[]}.',

      pivot: 'You are a lateral movement agent. Plan pivot paths, establish persistence, and manage tunnels. Use OS-appropriate techniques. Reuse credentials from credential agent. Return results in JSON with keys: {pivot_path[], persistence_methods[], tunnels[], network_map}.',

      report: 'You are a reporting agent. Generate professional security reports with CVSS scoring, finding deduplication, executive summaries, and remediation roadmaps. Return results in JSON with keys: {report_type, findings_count, cvss_scores[], executive_summary, remediation_steps[]}.',

      wordlist: 'You are a wordlist generation agent. Create context-aware wordlists using target company info, industry terms, and mutation rules (leet speak, case variations, year suffixes). Return results in JSON with keys: {wordlist[], total_words, mutations_applied[]}.',

      simgen: 'You are a scenario generation agent. Create CTF challenges, training scenarios, and security exercises with progressive difficulty. Return results in JSON with keys: {scenario_id, title, difficulty, description, hints[], solution_hash}.',

      smart: 'You are an adaptive smart agent. Chain tools intelligently, detect confidence drift, learn from successful patterns, and manage context windows. Return results in JSON with keys: {recommended_action, tool_chain[], confidence_trend, drift_detected, learned_patterns[]}.',

      orchestrator: 'You are an orchestration agent. Plan multi-step workflows, coordinate other agents, and make strategic decisions. Think step-by-step. Consider dependencies and parallel opportunities. Return results in JSON format with keys: {plan: {steps: [], dependencies: {}}, reasoning: string}.',

      planner: 'You are a task planning agent. Break down complex goals into executable tasks. Identify dependencies and parallel opportunities. Create efficient execution plans. Return results in JSON format with keys: {tasks: [], topology: {}, parallelGroups: []}.',

      analyst: 'You are an analysis agent. Review findings, identify patterns, and provide insights. Look for connections between vulnerabilities. Assess overall security posture. Return results in JSON format with keys: {analysis: string, patterns: [], recommendations: []}.',

      researcher: 'You are a research agent. Gather OSINT, look up CVEs, and find relevant exploits. Provide context and background information to support hunting. Return results in JSON format with keys: {findings: [], sources: []}.',

      validator: 'You are a coverage validation agent. Ensure all testing objectives are met. Identify gaps in testing coverage and suggest additional tests. Return results in JSON format with keys: {coverage: number, gaps: [], suggestions: []}.'
    };

    return prompts[agentType] || 'You are a security testing agent. Analyze the input and provide structured output in JSON format.';
  }

  private async callOllama(systemPrompt: string, userPrompt: string, context: any): Promise<any> {
    const response = await fetch(`${this.ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: process.env.OLLAMA_MODEL || 'llama3',
        prompt: `${systemPrompt}\n\nContext: ${JSON.stringify(context)}\n\nTask: ${userPrompt}`,
        stream: false,
        format: 'json'
      }),
      signal: AbortSignal.timeout(60000)
    });

    if (!response.ok) {
      throw new Error(`Ollama API error: ${response.statusText}`);
    }

    const data = await response.json() as any;
    try {
      return JSON.parse(data.response);
    } catch {
      return { raw: data.response };
    }
  }

  private simulate(agentType: string, prompt: string, context: any): any {
    console.log(`[AIBridge] SIMULATION MODE - ${agentType}`);

    const simulations: Record<string, any> = {
      recon: {
        subdomains: ['www.example.com', 'api.example.com', 'admin.example.com'],
        endpoints: [
          { url: 'https://www.example.com/', statusCode: 200 },
          { url: 'https://api.example.com/v1', statusCode: 200 }
        ],
        technologies: [
          { name: 'nginx', category: 'web-server' },
          { name: 'react', category: 'frontend' }
        ]
      },
      scanner: {
        vulnerabilities: [
          {
            type: 'XSS',
            severity: 'medium',
            endpoint: 'https://www.example.com/search?q=test',
            description: 'Reflected XSS in search parameter',
            exploitable: true
          }
        ]
      },
      exploit: {
        exploitable: true,
        payload: '<script>alert(1)</script>',
        steps: ['Find injection point', 'Test payload', 'Capture proof']
      },
      support: {
        credentials: [
          { username: 'admin', password: 'admin123', success: true }
        ]
      },
      orchestrator: {
        plan: {
          steps: ['Run recon', 'Scan endpoints', 'Exploit vulns', 'Generate report'],
          dependencies: { 1: [0], 2: [1], 3: [2] }
        },
        reasoning: 'Standard penetration testing workflow'
      },
      planner: {
        tasks: [
          { id: 'recon-1', tool: 'subfinder', target: context.goal || 'target', dependencies: [] },
          { id: 'scan-1', tool: 'nuclei', target: context.goal || 'target', dependencies: ['recon-1'] }
        ],
        topology: { 'scan-1': ['recon-1'] },
        parallelGroups: [['recon-1'], ['scan-1']]
      },
      analyst: {
        analysis: 'Initial analysis of findings shows potential attack vectors.',
        patterns: [{ pattern: 'Input validation issues', occurrences: 2, significance: 'high' }],
        recommendations: ['Test all input fields for injection', 'Review authentication mechanisms']
      },
      researcher: {
        findings: [{ source: 'NVD', data: 'Related CVE found', relevance: 'high' }],
        sources: ['National Vulnerability Database']
      },
      validator: {
        coverage: 45,
        gaps: ['Authentication endpoints not tested', 'API rate limiting not checked'],
        suggestions: ['Run hydra against login', 'Test API throttling']
      },
      credential: {
        credentials: [
          { username: 'admin', password_redacted: '[REDACTED]', source: 'secretsdump', is_admin: true, hash_type: 'NTLM' },
          { username: 'user1', password_redacted: '[REDACTED]', source: 'hydra', is_admin: false, hash_type: 'plaintext' }
        ],
        cracked_count: 2,
        admin_count: 1
      },
      intel: {
        iocs: [{ type: 'ip', value: '192.168.1.100', malicious: false, source: 'VirusTotal' }],
        mitre_mappings: [{ technique: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' }],
        threat_actors: [],
        attribution_confidence: 0.3,
        campaign_id: null
      },
      blueteam: {
        rules: [{ type: 'sigma', name: 'Port Scan Detection', content: 'title: Port Scan\nstatus: experimental\nlogsource:\n  category: firewall' }],
        queries: [{ platform: 'splunk', query: 'index=firewall action=blocked | stats count by src_ip' }],
        gaps: ['No detection for DNS tunneling'],
        coverage_percentage: 65,
        recommendations: ['Add DNS exfiltration monitoring', 'Enable process creation logging']
      },
      pivot: {
        pivot_path: [{ from: '10.0.0.1', to: '10.0.0.5', method: 'ssh', success: true }],
        persistence_methods: [{ method: 'crontab', os: 'linux', command: '*/5 * * * * /tmp/.update' }],
        tunnels: [{ type: 'ssh', source: '10.0.0.1', destination: '10.0.0.5', port: 8080 }],
        network_map: { nodes: 2, edges: 1 },
        hops_count: 1
      },
      report: {
        report_type: 'technical',
        findings_count: 5,
        unique_findings: 4,
        cvss_scores: [{ finding: 'XSS', score: 6.1, vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' }],
        executive_summary: 'Security assessment identified 4 unique vulnerabilities requiring remediation.',
        remediation_steps: ['Implement input validation', 'Enable CSP headers', 'Patch outdated software'],
        severity_breakdown: { critical: 0, high: 1, medium: 2, low: 1, info: 1 }
      },
      wordlist: {
        wordlist: ['admin2024', 'P@ssw0rd', 'Summer2024!', 'company123'],
        total_words: 4,
        mutations_applied: ['leet_speak', 'year_suffix', 'case_variation'],
        context_terms: ['company', 'admin'],
        estimated_crack_time: '2 hours'
      },
      simgen: {
        scenario_id: 'ctf-001',
        title: 'SQL Injection Challenge',
        difficulty: 'medium',
        description: 'Find and exploit the SQL injection vulnerability in the login form.',
        hints: ['Check the login endpoint', 'Try single quote in username'],
        solution_hash: 'abc123',
        environment_setup: 'docker-compose up -d',
        points: 200
      },
      smart: {
        recommended_action: { tool: 'nuclei', target: 'example.com', reason: 'High-value scan based on recon results' },
        tool_chain: ['subfinder', 'httpx', 'nuclei'],
        confidence_trend: [0.7, 0.75, 0.8],
        drift_detected: false,
        learned_patterns: [{ pattern: 'recon->scan->exploit', success_rate: 0.85 }]
      }
    };

    return simulations[agentType] || { simulated: true, message: 'Simulation fallback response' };
  }

  async invokeByAgent(
    agentId: string,
    variables: Record<string, string>,
    context: Record<string, any> = {}
  ): Promise<{ success: boolean; result?: any; error?: string; provider?: string; agent?: MetaAgent }> {
    const agent = getAgentById(agentId);
    if (!agent) {
      return { success: false, error: `Agent not found: ${agentId}` };
    }

    const thresholds = promptManager.getConfidenceThresholds();
    const threshold = thresholds[agentId] || agent.confidenceThreshold;

    const result = await this.invokeWithTemplate(agent.promptTemplate, variables, {
      ...context,
      confidenceThreshold: threshold,
      agentCapabilities: agent.capabilities,
      agentTools: agent.tools
    });

    return { ...result, agent };
  }

  async testConnection(): Promise<{ ollama: boolean }> {
    let ollamaOk = false;

    try {
      const response = await fetch(`${this.ollamaUrl}/api/tags`, {
        signal: AbortSignal.timeout(5000)
      });
      ollamaOk = response.ok;
    } catch {
      ollamaOk = false;
    }

    return { ollama: ollamaOk };
  }
}

export const aiBridge = new AIBridge(
  process.env.OLLAMA_URL || 'http://localhost:11434'
);

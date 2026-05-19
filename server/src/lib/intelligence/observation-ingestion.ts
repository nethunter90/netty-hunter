import { ModelRouter } from '../../intelligence/ModelRouter';

export interface Observation {
  id: string;
  timestamp: string;
  source: 'tool' | 'browser' | 'vision' | 'network' | 'manual';
  type: string;
  rawOutput: string;
  missionId?: string;
  huntGoal?: string;
  target?: string;
}

export interface ExtractedIntelligence {
  technologies: TechnologyDetection[];
  defenseSignals: DefenseSignal[];
  vulnerabilities: VulnerabilityIndicator[];
  endpoints: EndpointDiscovery[];
  credentials: CredentialLeak[];
  patterns: Pattern[];
  confidence: number;
}

export interface TechnologyDetection {
  name: string;
  version?: string;
  category: 'framework' | 'language' | 'server' | 'database' | 'cdn' | 'waf' | 'cms';
  confidence: number;
  evidence: string[];
}

export interface DefenseSignal {
  type: 'waf' | 'rate_limit' | 'captcha' | 'honeypot' | 'ids' | 'csp' | 'hsts';
  detected: boolean;
  vendor?: string;
  severity: 'low' | 'medium' | 'high';
  evidence: string;
}

export interface VulnerabilityIndicator {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  location: string;
  evidence: string;
  cvss?: number;
}

export interface EndpointDiscovery {
  url: string;
  method: string;
  parameters: string[];
  authenticated: boolean;
  riskLevel: 'high' | 'medium' | 'low';
}

export interface CredentialLeak {
  type: 'api_key' | 'password' | 'token' | 'secret';
  value: string;
  context: string;
  severity: 'critical' | 'high' | 'medium';
}

export interface Pattern {
  name: string;
  description: string;
  indicators: string[];
  actionable: boolean;
}

export interface IngestedObservation {
  observation: Observation;
  intelligence: ExtractedIntelligence;
  expectationResult?: ExpectationResult;
  ingestedAt: string;
}

interface GoalExpectations {
  goal: string;
  expectedTechnologies: string[];
  expectedEndpoints: string[];
  expectedParameters: string[];
  expectedBehaviors: string[];
  priorityScore: number;
  typicalPayload: string;
}

interface ExpectationResult {
  goal: string;
  met: string[];
  unmet: string[];
  confidence: number;
  recommendations: string[];
}

export class ExpectationEngine {
  private expectations: Map<string, GoalExpectations> = new Map();

  constructor() {
    this.initializeExpectations();
  }

  private initializeExpectations() {
    this.expectations.set('SSRF', {
      goal: 'SSRF',
      expectedTechnologies: ['webhook', 'image_proxy', 'pdf_generator', 'import_feature'],
      expectedEndpoints: ['url', 'callback', 'fetch', 'import', 'webhook'],
      expectedParameters: ['url', 'uri', 'link', 'callback', 'redirect', 'fetch'],
      expectedBehaviors: ['url_fetch', 'http_request', 'external_resource'],
      priorityScore: 9,
      typicalPayload: 'http://169.254.169.254/latest/meta-data/'
    });

    this.expectations.set('SQL Injection', {
      goal: 'SQL Injection',
      expectedTechnologies: ['mysql', 'postgresql', 'mssql', 'oracle'],
      expectedEndpoints: ['search', 'filter', 'id', 'user', 'product'],
      expectedParameters: ['id', 'search', 'query', 'filter', 'sort', 'user_id'],
      expectedBehaviors: ['database_query', 'sql_error'],
      priorityScore: 9,
      typicalPayload: "' OR '1'='1"
    });

    this.expectations.set('XSS', {
      goal: 'XSS',
      expectedTechnologies: ['javascript', 'react', 'angular', 'vue'],
      expectedEndpoints: ['comment', 'post', 'search', 'profile', 'message'],
      expectedParameters: ['comment', 'message', 'search', 'name', 'description'],
      expectedBehaviors: ['reflect_input', 'dom_manipulation', 'render_html'],
      priorityScore: 7,
      typicalPayload: '<script>alert(1)</script>'
    });

    this.expectations.set('RCE', {
      goal: 'RCE',
      expectedTechnologies: ['php', 'python', 'java', 'nodejs', 'ruby'],
      expectedEndpoints: ['upload', 'import', 'convert', 'execute', 'compile'],
      expectedParameters: ['file', 'code', 'command', 'script', 'template'],
      expectedBehaviors: ['code_execution', 'file_processing', 'command_injection'],
      priorityScore: 10,
      typicalPayload: '; whoami'
    });

    this.expectations.set('Auth Bypass', {
      goal: 'Auth Bypass',
      expectedTechnologies: ['jwt', 'oauth', 'saml', 'session'],
      expectedEndpoints: ['login', 'auth', 'token', 'verify', 'reset'],
      expectedParameters: ['token', 'session', 'user', 'role', 'admin'],
      expectedBehaviors: ['authentication', 'authorization', 'session_management'],
      priorityScore: 9,
      typicalPayload: 'admin'
    });

    this.expectations.set('IDOR', {
      goal: 'IDOR',
      expectedTechnologies: ['rest_api', 'graphql'],
      expectedEndpoints: ['user', 'profile', 'document', 'file', 'order'],
      expectedParameters: ['id', 'user_id', 'doc_id', 'file_id', 'order_id'],
      expectedBehaviors: ['direct_object_reference', 'sequential_ids'],
      priorityScore: 7,
      typicalPayload: 'increment ID by 1'
    });

    this.expectations.set('Account Takeover', {
      goal: 'Account Takeover',
      expectedTechnologies: ['password_reset', 'email', 'sms', '2fa'],
      expectedEndpoints: ['reset', 'forgot', 'verify', '2fa', 'recovery'],
      expectedParameters: ['email', 'token', 'code', 'phone'],
      expectedBehaviors: ['password_reset', 'account_recovery', 'token_validation'],
      priorityScore: 10,
      typicalPayload: 'victim@example.com'
    });

    this.expectations.set('API Security', {
      goal: 'API Security',
      expectedTechnologies: ['rest_api', 'graphql', 'swagger', 'openapi'],
      expectedEndpoints: ['api', 'v1', 'v2', 'graphql'],
      expectedParameters: ['key', 'token', 'auth', 'apikey'],
      expectedBehaviors: ['rate_limiting', 'authentication', 'authorization'],
      priorityScore: 8,
      typicalPayload: 'excessive requests'
    });
  }

  checkExpectations(goal: string, intelligence: ExtractedIntelligence): ExpectationResult {
    const expectations = this.expectations.get(goal);
    if (!expectations) {
      return {
        goal,
        met: [],
        unmet: [],
        confidence: 0,
        recommendations: ['Unknown hunt goal - using generic approach']
      };
    }

    const met: string[] = [];
    const unmet: string[] = [];

    const detectedTechs = intelligence.technologies.map(t => t.name.toLowerCase());
    expectations.expectedTechnologies.forEach(tech => {
      if (detectedTechs.some(d => d.includes(tech))) {
        met.push(`Technology: ${tech}`);
      } else {
        unmet.push(`Technology: ${tech}`);
      }
    });

    const detectedEndpoints = intelligence.endpoints.map(e => e.url.toLowerCase());
    expectations.expectedEndpoints.forEach(endpoint => {
      if (detectedEndpoints.some(d => d.includes(endpoint))) {
        met.push(`Endpoint: ${endpoint}`);
      } else {
        unmet.push(`Endpoint: ${endpoint}`);
      }
    });

    const detectedParams = intelligence.endpoints.flatMap(e => e.parameters.map(p => p.toLowerCase()));
    expectations.expectedParameters.forEach(param => {
      if (detectedParams.includes(param)) {
        met.push(`Parameter: ${param}`);
      } else {
        unmet.push(`Parameter: ${param}`);
      }
    });

    const confidence = met.length / (met.length + unmet.length) || 0;
    const recommendations = this.generateRecommendations(expectations, met, unmet);

    return { goal, met, unmet, confidence, recommendations };
  }

  private generateRecommendations(
    expectations: GoalExpectations,
    met: string[],
    unmet: string[]
  ): string[] {
    const recommendations: string[] = [];

    if (met.length === 0) {
      recommendations.push(`Target may not be vulnerable to ${expectations.goal}`);
      recommendations.push('Consider pivoting to different attack vector');
    } else if (met.length < 2) {
      recommendations.push('Some indicators present - continue reconnaissance');
      recommendations.push(`Focus on finding: ${unmet.slice(0, 3).join(', ')}`);
    } else {
      recommendations.push(`Strong indicators for ${expectations.goal} detected`);
      recommendations.push('Proceed to exploitation phase');
      recommendations.push(`Try payload: ${expectations.typicalPayload}`);
    }

    return recommendations;
  }

  getExpectations(goal: string): GoalExpectations | undefined {
    return this.expectations.get(goal);
  }

  getAllGoals(): string[] {
    return Array.from(this.expectations.keys());
  }
}

export class IntelligenceExtractor {
  private ollama: ModelRouter;

  constructor(_ollamaUrl: string) {
    this.ollama = ModelRouter.getInstance();
  }

  async extract(observation: Observation): Promise<ExtractedIntelligence> {
    switch (observation.type) {
      case 'nmap':
        return this.extractFromNmap(observation);
      case 'sqlmap':
        return this.extractFromSqlmap(observation);
      case 'nuclei':
        return this.extractFromNuclei(observation);
      case 'gobuster':
      case 'ffuf':
        return this.extractFromDirectoryBruteforce(observation);
      case 'httpx':
      case 'whatweb':
        return this.extractFromWebFingerprint(observation);
      case 'subfinder':
      case 'amass':
        return this.extractFromSubdomainEnum(observation);
      default:
        return this.extractWithAI(observation);
    }
  }

  private extractFromNmap(observation: Observation): ExtractedIntelligence {
    const output = observation.rawOutput;
    const intelligence: ExtractedIntelligence = {
      technologies: [],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [],
      credentials: [],
      patterns: [],
      confidence: 0.8
    };

    const portRegex = /(\d+)\/tcp\s+open\s+([^\s]+)/g;
    let match;
    while ((match = portRegex.exec(output)) !== null) {
      const port = match[1];
      const service = match[2];

      intelligence.endpoints.push({
        url: `${observation.target}:${port}`,
        method: 'TCP',
        parameters: [],
        authenticated: false,
        riskLevel: this.assessPortRisk(parseInt(port), service)
      });

      intelligence.technologies.push({
        name: service,
        category: this.categorizeService(service),
        confidence: 0.9,
        evidence: [`Port ${port} running ${service}`]
      });
    }

    const versionRegex = /([^\s]+)\s+([\d.]+)/g;
    let vMatch: RegExpExecArray | null;
    while ((vMatch = versionRegex.exec(output)) !== null) {
      const tech = intelligence.technologies.find(t => t.name === vMatch![1]);
      if (tech) {
        tech.version = vMatch[2];
      }
    }

    if (output.includes('vsftpd 2.3.4')) {
      intelligence.vulnerabilities.push({
        type: 'Known Vulnerable Version',
        severity: 'critical',
        confidence: 0.95,
        location: 'vsftpd 2.3.4',
        evidence: 'Backdoor vulnerability CVE-2011-2523',
        cvss: 10.0
      });
    }

    return intelligence;
  }

  private extractFromSqlmap(observation: Observation): ExtractedIntelligence {
    const output = observation.rawOutput;
    const intelligence: ExtractedIntelligence = {
      technologies: [],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [],
      credentials: [],
      patterns: [],
      confidence: 0.9
    };

    if (output.includes('is vulnerable')) {
      const severityMatch = output.match(/risk:\s*(\w+)/i);
      intelligence.vulnerabilities.push({
        type: 'SQL Injection',
        severity: (severityMatch?.[1]?.toLowerCase() as any) || 'high',
        confidence: 0.95,
        location: observation.target || 'unknown',
        evidence: output.slice(0, 500),
        cvss: 9.0
      });
    }

    const dbMatch = output.match(/back-end DBMS:\s*([^\n]+)/i);
    if (dbMatch) {
      intelligence.technologies.push({
        name: dbMatch[1].trim(),
        category: 'database',
        confidence: 0.95,
        evidence: [dbMatch[0]]
      });
    }

    if (output.includes('WAF/IPS detected')) {
      const wafMatch = output.match(/WAF\/IPS:\s*([^\n]+)/i);
      intelligence.defenseSignals.push({
        type: 'waf',
        detected: true,
        vendor: wafMatch?.[1]?.trim(),
        severity: 'high',
        evidence: 'SQLMap detected WAF protection'
      });
    }

    return intelligence;
  }

  private extractFromNuclei(observation: Observation): ExtractedIntelligence {
    const output = observation.rawOutput;
    const intelligence: ExtractedIntelligence = {
      technologies: [],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [],
      credentials: [],
      patterns: [],
      confidence: 0.95
    };

    try {
      const lines = output.split('\n').filter(l => l.trim().startsWith('{'));
      for (const line of lines) {
        const finding = JSON.parse(line);
        intelligence.vulnerabilities.push({
          type: finding.info?.name || 'Unknown',
          severity: finding.info?.severity?.toLowerCase() || 'info',
          confidence: 0.9,
          location: finding.host || observation.target || 'unknown',
          evidence: finding.matched || finding.extracted || '',
          cvss: this.severityToCvss(finding.info?.severity)
        });
      }
    } catch {
      const lines = output.split('\n');
      for (const line of lines) {
        if (line.includes('[') && line.includes(']')) {
          const severityMatch = line.match(/\[([^\]]+)\]/);
          const nameMatch = line.match(/\]\s*([^\[]+)/);
          if (severityMatch && nameMatch) {
            intelligence.vulnerabilities.push({
              type: nameMatch[1].trim(),
              severity: severityMatch[1].toLowerCase() as any,
              confidence: 0.85,
              location: observation.target || 'unknown',
              evidence: line,
              cvss: this.severityToCvss(severityMatch[1])
            });
          }
        }
      }
    }

    return intelligence;
  }

  private extractFromDirectoryBruteforce(observation: Observation): ExtractedIntelligence {
    const output = observation.rawOutput;
    const intelligence: ExtractedIntelligence = {
      technologies: [],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [],
      credentials: [],
      patterns: [],
      confidence: 0.8
    };

    const lines = output.split('\n');
    for (const line of lines) {
      const gobusterMatch = line.match(/([\/\w\-\.]+)\s+\(Status:\s*(\d+)\)/);
      if (gobusterMatch) {
        const path = gobusterMatch[1];
        const status = parseInt(gobusterMatch[2]);
        intelligence.endpoints.push({
          url: `${observation.target}${path}`,
          method: 'GET',
          parameters: [],
          authenticated: status === 401 || status === 403,
          riskLevel: this.assessEndpointRisk(path, status)
        });
      }

      const ffufMatch = line.match(/\[Status:\s*(\d+).*?\]\s+([^\s]+)/);
      if (ffufMatch) {
        const status = parseInt(ffufMatch[1]);
        const path = ffufMatch[2];
        intelligence.endpoints.push({
          url: path,
          method: 'GET',
          parameters: [],
          authenticated: status === 401 || status === 403,
          riskLevel: this.assessEndpointRisk(path, status)
        });
      }
    }

    const interestingPaths = ['/admin', '/api', '/.git', '/config', '/backup'];
    intelligence.endpoints.forEach(endpoint => {
      if (interestingPaths.some(p => endpoint.url.includes(p))) {
        intelligence.patterns.push({
          name: 'Interesting Path Detected',
          description: `Found potentially sensitive path: ${endpoint.url}`,
          indicators: [endpoint.url],
          actionable: true
        });
      }
    });

    return intelligence;
  }

  private extractFromWebFingerprint(observation: Observation): ExtractedIntelligence {
    const output = observation.rawOutput;
    const intelligence: ExtractedIntelligence = {
      technologies: [],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [],
      credentials: [],
      patterns: [],
      confidence: 0.85
    };

    const techPatterns = [
      { pattern: /nginx[\/\s]*([\d.]+)?/i, name: 'nginx', category: 'server' as const },
      { pattern: /apache[\/\s]*([\d.]+)?/i, name: 'apache', category: 'server' as const },
      { pattern: /php[\/\s]*([\d.]+)?/i, name: 'php', category: 'language' as const },
      { pattern: /wordpress[\/\s]*([\d.]+)?/i, name: 'wordpress', category: 'cms' as const },
      { pattern: /react[\/\s]*([\d.]+)?/i, name: 'react', category: 'framework' as const },
      { pattern: /cloudflare/i, name: 'cloudflare', category: 'cdn' as const }
    ];

    for (const { pattern, name, category } of techPatterns) {
      const match = output.match(pattern);
      if (match) {
        intelligence.technologies.push({
          name,
          version: match[1],
          category,
          confidence: 0.9,
          evidence: [match[0]]
        });
      }
    }

    if (output.match(/X-Frame-Options/i)) {
      intelligence.defenseSignals.push({
        type: 'csp',
        detected: true,
        severity: 'low',
        evidence: 'X-Frame-Options header present'
      });
    }

    if (output.match(/Strict-Transport-Security/i)) {
      intelligence.defenseSignals.push({
        type: 'hsts',
        detected: true,
        severity: 'low',
        evidence: 'HSTS header present'
      });
    }

    return intelligence;
  }

  private extractFromSubdomainEnum(observation: Observation): ExtractedIntelligence {
    const output = observation.rawOutput;
    const intelligence: ExtractedIntelligence = {
      technologies: [],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [],
      credentials: [],
      patterns: [],
      confidence: 0.95
    };

    const lines = output.split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && this.isValidDomain(trimmed)) {
        intelligence.endpoints.push({
          url: `https://${trimmed}`,
          method: 'HTTP',
          parameters: [],
          authenticated: false,
          riskLevel: this.assessSubdomainRisk(trimmed)
        });
      }
    }

    return intelligence;
  }

  private async extractWithAI(observation: Observation): Promise<ExtractedIntelligence> {
    try {
      const content = await this.ollama.generate(
        `Extract security intelligence from this tool output. Return JSON with:
{
  "technologies": [{"name": "", "version": "", "category": ""}],
  "vulnerabilities": [{"type": "", "severity": "", "confidence": 0}],
  "endpoints": [{"url": "", "riskLevel": "high|medium|low"}]
}

Output:
${observation.rawOutput.slice(0, 2000)}`,
        'analyze'
      );

      return JSON.parse(content);
    } catch {
      return {
        technologies: [],
        defenseSignals: [],
        vulnerabilities: [],
        endpoints: [],
        credentials: [],
        patterns: [],
        confidence: 0.5
      };
    }
  }

  private assessPortRisk(port: number, _service: string): 'high' | 'medium' | 'low' {
    const highRiskPorts = [21, 23, 3389, 445, 139];
    const mediumRiskPorts = [22, 3306, 5432, 27017];
    if (highRiskPorts.includes(port)) return 'high';
    if (mediumRiskPorts.includes(port)) return 'medium';
    return 'low';
  }

  private categorizeService(service: string): TechnologyDetection['category'] {
    const categories: Record<string, TechnologyDetection['category']> = {
      'http': 'server',
      'https': 'server',
      'ssh': 'server',
      'ftp': 'server',
      'mysql': 'database',
      'postgresql': 'database',
      'mongodb': 'database'
    };
    return categories[service.toLowerCase()] || 'server';
  }

  private assessEndpointRisk(path: string, status: number): 'high' | 'medium' | 'low' {
    const highRiskPaths = ['/admin', '/api', '/.git', '/config', '/backup', '/.env'];
    const mediumRiskPaths = ['/login', '/upload', '/search'];
    if (highRiskPaths.some(p => path.includes(p))) return 'high';
    if (mediumRiskPaths.some(p => path.includes(p))) return 'medium';
    if (status === 401 || status === 403) return 'high';
    return 'low';
  }

  private assessSubdomainRisk(subdomain: string): 'high' | 'medium' | 'low' {
    const highRiskSubdomains = ['admin', 'dev', 'staging', 'test', 'internal', 'api'];
    const parts = subdomain.split('.');
    for (const part of parts) {
      if (highRiskSubdomains.includes(part.toLowerCase())) {
        return 'high';
      }
    }
    return 'medium';
  }

  private isValidDomain(str: string): boolean {
    return /^[a-zA-Z0-9][a-zA-Z0-9-_.]*\.[a-zA-Z]{2,}$/.test(str);
  }

  private severityToCvss(severity?: string): number {
    switch (severity?.toLowerCase()) {
      case 'critical': return 9.5;
      case 'high': return 7.5;
      case 'medium': return 5.5;
      case 'low': return 3.5;
      default: return 0;
    }
  }
}

export class ObservationIngestion {
  private extractor: IntelligenceExtractor;
  private expectationEngine: ExpectationEngine;
  private observations: Observation[] = [];

  constructor(ollamaUrl: string) {
    this.extractor = new IntelligenceExtractor(ollamaUrl);
    this.expectationEngine = new ExpectationEngine();
  }

  async ingest(observation: Observation): Promise<IngestedObservation> {
    this.observations.push(observation);

    const intelligence = await this.extractor.extract(observation);

    let expectationResult: ExpectationResult | undefined;
    if (observation.huntGoal) {
      expectationResult = this.expectationEngine.checkExpectations(
        observation.huntGoal,
        intelligence
      );
    }

    return {
      observation,
      intelligence,
      expectationResult,
      ingestedAt: new Date().toISOString()
    };
  }

  getObservations(missionId?: string): Observation[] {
    if (missionId) {
      return this.observations.filter(o => o.missionId === missionId);
    }
    return this.observations;
  }

  getExpectationEngine(): ExpectationEngine {
    return this.expectationEngine;
  }

  async aggregateIntelligence(missionId: string): Promise<ExtractedIntelligence> {
    const missionObservations = this.observations.filter(o => o.missionId === missionId);

    const aggregated: ExtractedIntelligence = {
      technologies: [],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [],
      credentials: [],
      patterns: [],
      confidence: 0
    };

    for (const obs of missionObservations) {
      const intel = await this.extractor.extract(obs);

      intel.technologies.forEach(tech => {
        if (!aggregated.technologies.find(t => t.name === tech.name)) {
          aggregated.technologies.push(tech);
        }
      });

      aggregated.defenseSignals.push(...intel.defenseSignals);
      aggregated.vulnerabilities.push(...intel.vulnerabilities);
      aggregated.endpoints.push(...intel.endpoints);
      aggregated.credentials.push(...intel.credentials);
      aggregated.patterns.push(...intel.patterns);
    }

    aggregated.confidence = missionObservations.length > 0 ? 0.8 : 0;

    return aggregated;
  }
}

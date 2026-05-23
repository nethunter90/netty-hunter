export interface VirusTotalHashResult {
  found?: boolean;
  malicious: boolean;
  maliciousCount?: number;
  totalEngines?: number;
  sha256?: string;
  md5?: string;
  fileType?: string;
  detections?: Array<{ engine: string; result: string }>;
  error?: string;
}

export interface VirusTotalDomainResult {
  found?: boolean;
  malicious: boolean;
  maliciousCount?: number;
  suspiciousCount?: number;
  categories?: Record<string, string>;
  reputation?: number;
  error?: string;
}

export interface VirusTotalIPResult {
  found?: boolean;
  malicious: boolean;
  maliciousCount?: number;
  asOwner?: string;
  country?: string;
  reputation?: number;
  error?: string;
}

export interface AbuseIPDBResult {
  ipAddress?: string;
  abuseScore: number;
  usageType?: string;
  isp?: string;
  domain?: string;
  country?: string;
  totalReports?: number;
  numDistinctUsers?: number;
  lastReportedAt?: string;
  isWhitelisted?: boolean;
  malicious?: boolean;
  error?: string;
}

export interface ShodanHostResult {
  found?: boolean;
  ip?: string;
  ports?: number[];
  hostnames?: string[];
  organization?: string;
  os?: string;
  services?: Array<{
    port: number;
    protocol: string;
    product?: string;
    version?: string;
    banner?: string;
  }>;
  vulnerabilities?: string[];
  tags?: string[];
  error?: string;
}

export interface ShodanSearchResult {
  total?: number;
  results: Array<{
    ip: string;
    port: number;
    organization?: string;
    hostnames?: string[];
    product?: string;
    version?: string;
  }>;
  error?: string;
}

export interface MITRETechnique {
  id: string;
  name: string;
  tactic: string;
  description?: string;
}

class VirusTotalClient {
  private apiKey: string | undefined;

  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
  }

  private getSimulatedResult() {
    return { malicious: false, reputation: 0, categories: [], last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 5 } };
  }

  async lookupDomain(domain: string): Promise<any> {
    if (!this.apiKey) return this.getSimulatedResult();
    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
        headers: { 'x-apikey': this.apiKey },
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) return this.getSimulatedResult();
      return await response.json();
    } catch {
      return this.getSimulatedResult();
    }
  }

  async lookupIP(ip: string): Promise<any> {
    if (!this.apiKey) return this.getSimulatedResult();
    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: { 'x-apikey': this.apiKey },
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) return this.getSimulatedResult();
      return await response.json();
    } catch {
      return this.getSimulatedResult();
    }
  }

  async lookupHash(hash: string): Promise<any> {
    if (!this.apiKey) return this.getSimulatedResult();
    try {
      const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
        headers: { 'x-apikey': this.apiKey },
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) return this.getSimulatedResult();
      return await response.json();
    } catch {
      return this.getSimulatedResult();
    }
  }
}

class AbuseIPDBClient {
  private apiKey: string | undefined;

  constructor() {
    this.apiKey = process.env.ABUSEIPDB_API_KEY;
  }

  private getSimulatedResult() {
    return { abuseConfidenceScore: 0, totalReports: 0, countryCode: 'US', isp: 'Unknown', isWhitelisted: false };
  }

  async checkIP(ip: string): Promise<any> {
    if (!this.apiKey) return this.getSimulatedResult();
    try {
      const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
        headers: { 'Key': this.apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) return this.getSimulatedResult();
      return await response.json();
    } catch {
      return this.getSimulatedResult();
    }
  }

  async getBlacklist(limit?: number): Promise<any> {
    if (!this.apiKey) return this.getSimulatedResult();
    try {
      const url = `https://api.abuseipdb.com/api/v2/blacklist?limit=${limit || 100}`;
      const response = await fetch(url, {
        headers: { 'Key': this.apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) return this.getSimulatedResult();
      return await response.json();
    } catch {
      return this.getSimulatedResult();
    }
  }
}

class ShodanClient {
  private apiKey: string | undefined;

  constructor() {
    this.apiKey = process.env.SHODAN_API_KEY;
  }

  private getSimulatedResult() {
    return { ports: [], vulns: [], os: 'Unknown', hostnames: [], org: 'Unknown' };
  }

  async searchHost(ip: string): Promise<any> {
    if (!this.apiKey) return this.getSimulatedResult();
    try {
      const response = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${this.apiKey}`, {
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) return this.getSimulatedResult();
      return await response.json();
    } catch {
      return this.getSimulatedResult();
    }
  }

  async searchQuery(query: string): Promise<any> {
    if (!this.apiKey) return this.getSimulatedResult();
    try {
      const response = await fetch(`https://api.shodan.io/shodan/host/search?key=${this.apiKey}&query=${encodeURIComponent(query)}`, {
        signal: AbortSignal.timeout(10000)
      });
      if (!response.ok) return this.getSimulatedResult();
      return await response.json();
    } catch {
      return this.getSimulatedResult();
    }
  }
}

class MitreAttackClient {
  private static TECHNIQUE_MAP: Record<string, { id: string; name: string; tactic: string; description: string }> = {
    'T1595': { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance', description: 'Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.' },
    'T1059': { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.' },
    'T1078': { id: 'T1078', name: 'Valid Accounts', tactic: 'Persistence, Privilege Escalation', description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.' },
    'T1021': { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', description: 'Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.' },
    'T1003': { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', description: 'Adversaries may attempt to dump credentials to obtain account login and credential material.' },
    'T1190': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', description: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.' },
    'T1071': { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', description: 'Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.' },
    'T1486': { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', description: 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.' },
    'T1110': { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.' },
    'T1053': { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Execution, Persistence', description: 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.' },
    'T1548': { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation', description: 'Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions.' },
    'T1027': { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', description: 'Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.' },
    'T1055': { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion, Privilege Escalation', description: 'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.' },
    'T1036': { id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion', description: 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools.' },
    'T1070': { id: 'T1070', name: 'Indicator Removal', tactic: 'Defense Evasion', description: 'Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses.' },
    'T1046': { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', description: 'Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.' },
    'T1018': { id: 'T1018', name: 'Remote System Discovery', tactic: 'Discovery', description: 'Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network.' },
    'T1087': { id: 'T1087', name: 'Account Discovery', tactic: 'Discovery', description: 'Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment.' },
    'T1083': { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery', description: 'Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.' },
    'T1005': { id: 'T1005', name: 'Data from Local System', tactic: 'Collection', description: 'Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.' },
    'T1041': { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', description: 'Adversaries may steal data by exfiltrating it over an existing command and control channel.' },
    'T1566': { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', description: 'Adversaries may send phishing messages to gain access to victim systems.' },
    'T1098': { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', description: 'Adversaries may manipulate accounts to maintain access to victim systems.' },
    'T1068': { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', description: 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.' },
    'T1133': { id: 'T1133', name: 'External Remote Services', tactic: 'Persistence', description: 'Adversaries may leverage external-facing remote services to initially access and/or persist within a network.' },
    'T1562': { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion', description: 'Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.' },
    'T1105': { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', description: 'Adversaries may transfer tools or other files from an external system into a compromised environment.' },
    'T1047': { id: 'T1047', name: 'Windows Management Instrumentation', tactic: 'Execution', description: 'Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.' },
    'T1569': { id: 'T1569', name: 'System Services', tactic: 'Execution', description: 'Adversaries may abuse system services or daemons to execute commands or programs.' },
    'T1543': { id: 'T1543', name: 'Create or Modify System Process', tactic: 'Persistence', description: 'Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.' }
  };

  mapTechnique(techniqueId: string): { id: string; name: string; tactic: string; description: string } | null {
    return MitreAttackClient.TECHNIQUE_MAP[techniqueId] || null;
  }

  mapKeywords(keywords: string[]): Array<{ id: string; name: string; tactic: string; description: string }> {
    const results: Array<{ id: string; name: string; tactic: string; description: string }> = [];
    const lowerKeywords = keywords.map(k => k.toLowerCase());

    for (const technique of Object.values(MitreAttackClient.TECHNIQUE_MAP)) {
      const searchText = `${technique.name} ${technique.tactic} ${technique.description}`.toLowerCase();
      for (const keyword of lowerKeywords) {
        if (searchText.includes(keyword)) {
          results.push(technique);
          break;
        }
      }
    }

    return results;
  }

  getTacticTechniques(tactic: string): Array<{ id: string; name: string; tactic: string; description: string }> {
    const lowerTactic = tactic.toLowerCase();
    return Object.values(MitreAttackClient.TECHNIQUE_MAP).filter(
      t => t.tactic.toLowerCase().includes(lowerTactic)
    );
  }

  getAllTechniques(): Record<string, { id: string; name: string; tactic: string; description: string }> {
    return { ...MitreAttackClient.TECHNIQUE_MAP };
  }
}

export const virusTotalClient = new VirusTotalClient();
export const abuseIPDBClient = new AbuseIPDBClient();
export const shodanClient = new ShodanClient();
export const mitreAttackClient = new MitreAttackClient();

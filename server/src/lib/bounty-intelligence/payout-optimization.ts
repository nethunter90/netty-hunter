import fs from 'fs/promises';
import path from 'path';
import { PayoutDataPoint, ImpactFraming } from './intelligence-types';

export interface PayoutEstimateResult {
  vulnType: string;
  programId: string;
  median: number;
  p75: number;
  p95: number;
  sampleSize: number;
  confidence: number;
  basedOnHistorical: boolean;
}

export interface EscalationChain {
  vulnType: string;
  chain: string[];
  description: string;
  payoutMultiplier: number;
  difficulty: 'easy' | 'moderate' | 'hard';
}

export interface PayoutStats {
  totalPayouts: number;
  totalEarned: number;
  avgPayout: number;
  byVulnType: Record<string, { count: number; totalEarned: number; avgPayout: number }>;
  byProgram: Record<string, { count: number; totalEarned: number; avgPayout: number }>;
  topFramings: { vulnType: string; framing: string; avgPayout: number }[];
}

const DEFAULT_FRAMING_TEMPLATES: ImpactFraming[] = [
  {
    vulnType: 'ssrf',
    lowValueFraming: 'Internal service access',
    highValueFraming: 'Cloud metadata extraction -> IAM credential theft -> full account takeover',
    payoutMultiplier: 4,
    escalationChain: ['internal-access', 'cloud-metadata', 'iam-credentials', 'account-takeover'],
  },
  {
    vulnType: 'idor',
    lowValueFraming: 'Unauthorized data access',
    highValueFraming: 'Mass PII exfiltration affecting N users, GDPR Article 33 notification trigger',
    payoutMultiplier: 3,
    escalationChain: ['single-user-access', 'mass-data-access', 'pii-exfiltration', 'gdpr-violation'],
  },
  {
    vulnType: 'xss',
    lowValueFraming: 'Script execution in browser',
    highValueFraming: 'Account takeover via session hijack, admin panel access, persistent worm potential',
    payoutMultiplier: 2.5,
    escalationChain: ['session-hijack', 'admin-access', 'stored-worm', 'mass-account-takeover'],
  },
  {
    vulnType: 'sqli',
    lowValueFraming: 'Database query manipulation',
    highValueFraming: 'Full database dump, credential extraction, lateral movement to internal systems',
    payoutMultiplier: 3,
    escalationChain: ['data-extraction', 'credential-dump', 'privilege-escalation', 'lateral-movement'],
  },
  {
    vulnType: 'open-redirect',
    lowValueFraming: 'URL redirection',
    highValueFraming: 'OAuth token theft via redirect chain, phishing amplification',
    payoutMultiplier: 5.5,
    escalationChain: ['phishing', 'oauth-token-theft', 'session-fixation'],
  },
  {
    vulnType: 'ssti',
    lowValueFraming: 'Template injection',
    highValueFraming: 'Remote code execution, server compromise, internal network access',
    payoutMultiplier: 4,
    escalationChain: ['template-injection', 'rce', 'server-compromise', 'internal-network-access'],
  },
  {
    vulnType: 'lfi',
    lowValueFraming: 'File inclusion',
    highValueFraming: 'Source code disclosure, credential files, /etc/passwd to privilege escalation',
    payoutMultiplier: 2.5,
    escalationChain: ['file-read', 'source-code-disclosure', 'credential-extraction', 'privilege-escalation'],
  },
  {
    vulnType: 'rce',
    lowValueFraming: 'Code execution',
    highValueFraming: 'Full server compromise, lateral movement, data exfiltration, persistent backdoor',
    payoutMultiplier: 1.5,
    escalationChain: ['code-execution', 'server-compromise', 'lateral-movement', 'persistent-backdoor'],
  },
  {
    vulnType: 'auth-bypass',
    lowValueFraming: 'Authentication bypass',
    highValueFraming: 'Full admin access, account takeover affecting all users',
    payoutMultiplier: 3,
    escalationChain: ['auth-bypass', 'admin-access', 'mass-account-takeover'],
  },
  {
    vulnType: 'csrf',
    lowValueFraming: 'Cross-site request forgery',
    highValueFraming: 'One-click account takeover, privilege escalation via admin action',
    payoutMultiplier: 2.5,
    escalationChain: ['csrf-trigger', 'account-takeover', 'privilege-escalation'],
  },
];

const DEFAULT_ESCALATION_CHAINS: EscalationChain[] = [
  {
    vulnType: 'ssrf',
    chain: ['internal-access', 'cloud-metadata', 'iam-credentials', 'account-takeover'],
    description: 'Escalate SSRF from internal access to full cloud account takeover via metadata service',
    payoutMultiplier: 4,
    difficulty: 'moderate',
  },
  {
    vulnType: 'xss',
    chain: ['session-hijack', 'admin-access', 'stored-worm', 'mass-account-takeover'],
    description: 'Escalate XSS from session hijack to mass account takeover via stored worm',
    payoutMultiplier: 2.5,
    difficulty: 'hard',
  },
  {
    vulnType: 'sqli',
    chain: ['data-extraction', 'credential-dump', 'privilege-escalation', 'lateral-movement'],
    description: 'Escalate SQL injection from data extraction to lateral movement via credential dump',
    payoutMultiplier: 3,
    difficulty: 'moderate',
  },
  {
    vulnType: 'idor',
    chain: ['single-user-access', 'mass-data-access', 'pii-exfiltration', 'gdpr-violation'],
    description: 'Escalate IDOR from single user access to GDPR violation via mass PII exfiltration',
    payoutMultiplier: 3,
    difficulty: 'easy',
  },
  {
    vulnType: 'open-redirect',
    chain: ['phishing', 'oauth-token-theft', 'session-fixation'],
    description: 'Escalate open redirect from phishing to OAuth token theft via redirect chain',
    payoutMultiplier: 5.5,
    difficulty: 'moderate',
  },
];

const HEURISTIC_BASELINES: Record<string, { median: number; p75: number; p95: number }> = {
  critical: { median: 5000, p75: 10000, p95: 25000 },
  high: { median: 2000, p75: 5000, p95: 10000 },
  medium: { median: 500, p75: 1500, p95: 3000 },
  low: { median: 100, p75: 300, p95: 750 },
};

const VULN_TYPE_SEVERITY: Record<string, string> = {
  rce: 'critical',
  sqli: 'critical',
  ssti: 'critical',
  ssrf: 'high',
  'auth-bypass': 'high',
  idor: 'high',
  xss: 'medium',
  lfi: 'medium',
  csrf: 'medium',
  'open-redirect': 'low',
};

export class PayoutOptimization {
  private storageDir: string;

  constructor(storageDir: string) {
    this.storageDir = path.join(storageDir, 'payout');
  }

  private async ensureDir(): Promise<void> {
    await fs.mkdir(this.storageDir, { recursive: true });
  }

  private async loadJson<T>(filename: string, fallback: T): Promise<T> {
    try {
      const filePath = path.join(this.storageDir, filename);
      const data = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(data) as T;
    } catch {
      return fallback;
    }
  }

  private async saveJson(filename: string, data: unknown): Promise<void> {
    await this.ensureDir();
    const filePath = path.join(this.storageDir, filename);
    await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  private percentile(sorted: number[], p: number): number {
    if (sorted.length === 0) return 0;
    const index = (p / 100) * (sorted.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    if (lower === upper) return sorted[lower];
    return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
  }

  async estimatePayout(programId: string, vulnType: string): Promise<PayoutEstimateResult> {
    if (!vulnType || !programId) {
      return {
        vulnType: vulnType || 'unknown',
        programId: programId || 'unknown',
        median: 500,
        p75: 1000,
        p95: 2500,
        sampleSize: 0,
        confidence: 0,
        basedOnHistorical: false,
      };
    }
    const payouts = await this.loadJson<PayoutDataPoint[]>('historical-payouts.json', []);
    const normalizedType = vulnType.toLowerCase();

    const relevant = payouts.filter(
      (p) => p.programId === programId && p.vulnType.toLowerCase() === normalizedType
    );

    if (relevant.length >= 3) {
      const values = relevant.map((p) => p.payout).sort((a, b) => a - b);
      const median = this.percentile(values, 50);
      const p75 = this.percentile(values, 75);
      const p95 = this.percentile(values, 95);
      const confidence = Math.min(relevant.length / 20, 1);

      return {
        vulnType,
        programId,
        median,
        p75,
        p95,
        sampleSize: relevant.length,
        confidence,
        basedOnHistorical: true,
      };
    }

    const typeByVuln = payouts.filter(
      (p) => p.vulnType.toLowerCase() === normalizedType
    );

    if (typeByVuln.length >= 3) {
      const values = typeByVuln.map((p) => p.payout).sort((a, b) => a - b);
      const median = this.percentile(values, 50);
      const p75 = this.percentile(values, 75);
      const p95 = this.percentile(values, 95);
      const confidence = Math.min(typeByVuln.length / 20, 1) * 0.7;

      return {
        vulnType,
        programId,
        median,
        p75,
        p95,
        sampleSize: typeByVuln.length,
        confidence,
        basedOnHistorical: true,
      };
    }

    const severity = VULN_TYPE_SEVERITY[normalizedType] || 'medium';
    const baseline = HEURISTIC_BASELINES[severity] || HEURISTIC_BASELINES['medium'];

    return {
      vulnType,
      programId,
      median: baseline.median,
      p75: baseline.p75,
      p95: baseline.p95,
      sampleSize: 0,
      confidence: 0.1,
      basedOnHistorical: false,
    };
  }

  async getFramingSuggestions(vulnType: string, _context?: Record<string, any>): Promise<ImpactFraming[]> {
    const stored = await this.loadJson<ImpactFraming[]>('framing-templates.json', []);
    const normalizedType = vulnType.toLowerCase();

    const storedMatches = stored.filter(
      (f) => f.vulnType.toLowerCase() === normalizedType
    );

    if (storedMatches.length > 0) {
      return storedMatches;
    }

    return DEFAULT_FRAMING_TEMPLATES.filter(
      (f) => f.vulnType.toLowerCase() === normalizedType
    );
  }

  async recordPayout(dataPoint: PayoutDataPoint): Promise<void> {
    const payouts = await this.loadJson<PayoutDataPoint[]>('historical-payouts.json', []);
    payouts.push(dataPoint);
    await this.saveJson('historical-payouts.json', payouts);
  }

  async getEscalationChains(vulnType: string): Promise<EscalationChain[]> {
    const stored = await this.loadJson<EscalationChain[]>('escalation-chains.json', []);
    const normalizedType = vulnType.toLowerCase();

    const storedMatches = stored.filter(
      (c) => c.vulnType.toLowerCase() === normalizedType
    );

    if (storedMatches.length > 0) {
      return storedMatches;
    }

    return DEFAULT_ESCALATION_CHAINS.filter(
      (c) => c.vulnType.toLowerCase() === normalizedType
    );
  }

  async getPayoutStats(): Promise<PayoutStats> {
    const payouts = await this.loadJson<PayoutDataPoint[]>('historical-payouts.json', []);

    if (payouts.length === 0) {
      return {
        totalPayouts: 0,
        totalEarned: 0,
        avgPayout: 0,
        byVulnType: {},
        byProgram: {},
        topFramings: [],
      };
    }

    const totalEarned = payouts.reduce((sum, p) => sum + p.payout, 0);
    const avgPayout = totalEarned / payouts.length;

    const byVulnType: Record<string, { count: number; totalEarned: number; avgPayout: number }> = {};
    const byProgram: Record<string, { count: number; totalEarned: number; avgPayout: number }> = {};
    const framingMap: Map<string, { vulnType: string; framing: string; total: number; count: number }> = new Map();

    for (const p of payouts) {
      if (!byVulnType[p.vulnType]) {
        byVulnType[p.vulnType] = { count: 0, totalEarned: 0, avgPayout: 0 };
      }
      byVulnType[p.vulnType].count++;
      byVulnType[p.vulnType].totalEarned += p.payout;

      if (!byProgram[p.programId]) {
        byProgram[p.programId] = { count: 0, totalEarned: 0, avgPayout: 0 };
      }
      byProgram[p.programId].count++;
      byProgram[p.programId].totalEarned += p.payout;

      if (p.impactFraming) {
        const key = `${p.vulnType}::${p.impactFraming}`;
        const existing = framingMap.get(key);
        if (existing) {
          existing.total += p.payout;
          existing.count++;
        } else {
          framingMap.set(key, { vulnType: p.vulnType, framing: p.impactFraming, total: p.payout, count: 1 });
        }
      }
    }

    for (const key of Object.keys(byVulnType)) {
      byVulnType[key].avgPayout = byVulnType[key].totalEarned / byVulnType[key].count;
    }

    for (const key of Object.keys(byProgram)) {
      byProgram[key].avgPayout = byProgram[key].totalEarned / byProgram[key].count;
    }

    const topFramings = Array.from(framingMap.values())
      .map((f) => ({
        vulnType: f.vulnType,
        framing: f.framing,
        avgPayout: f.total / f.count,
      }))
      .sort((a, b) => b.avgPayout - a.avgPayout)
      .slice(0, 10);

    return {
      totalPayouts: payouts.length,
      totalEarned,
      avgPayout,
      byVulnType,
      byProgram,
      topFramings,
    };
  }
}

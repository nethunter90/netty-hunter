import type { GroundTruth } from './decision-trace';
import { ATTACK_PATHS, GOAL_PAYOUT_DATA } from './seed-knowledge';

export interface LabVulnerability {
  id: string;
  name: string;
  category: string;
  difficulty: 1 | 2 | 3 | 4 | 5;
  plannerGoal: string;
  plannerPathId: string;
  description: string;
  expectedTool: string;
  expectedEVRank: number;
  expectedCycles: number;
  expectedConfidence: number;
}

export interface LabTargetProfile {
  id: string;
  name: string;
  description: string;
  targetUrl: string;
  vulnerabilities: LabVulnerability[];
  expectedGoalRankings: { goal: string; expectedRank: number }[];
  totalChallenges: number;
  targetCharacteristics: {
    stack: string;
    wafDetected: boolean;
    cloudHosted: boolean;
    authRequired: boolean;
    complexity: number;
  };
}

export interface LabScore {
  profileId: string;
  huntId: string;
  coverage: number;
  goalAccuracy: number;
  evRankingAccuracy: number;
  cycleEfficiency: number;
  pathSelectionAccuracy: number;
  categoryBreakdown: { category: string; found: number; total: number; coverage: number }[];
  difficultyBreakdown: { difficulty: number; found: number; total: number; coverage: number }[];
  missedVulns: LabVulnerability[];
  decisionQualitySummary: {
    topPathCorrect: boolean;
    avgRankDeviation: number;
    overconfidentPaths: number;
    underconfidentPaths: number;
  };
  timestamp: number;
}

export interface DivergencePoint {
  step: number;
  timestamp: number;
  plannedAction: string;
  plannedGoal: string;
  plannedConfidence: number;
  actualAction: string;
  actualGoal: string;
  actualConfidence: number;
  diverged: boolean;
  divergenceType: 'none' | 'goal_mismatch' | 'path_mismatch' | 'early_pivot' | 'missed_pivot' | 'tool_mismatch';
  insight: string;
}

const JUICE_SHOP_TARGET: LabTargetProfile['targetCharacteristics'] = {
  stack: 'Node.js/Express/Angular/SQLite',
  wafDetected: false,
  cloudHosted: false,
  authRequired: true,
  complexity: 0.3,
};

function computeExpectedEVRank(pathId: string, goal: string): number {
  const goalPaths = ATTACK_PATHS.filter(p => p.goal.toLowerCase() === goal.toLowerCase());
  const ranked = goalPaths.map(p => {
    let adj = p.likelihood;
    if (JUICE_SHOP_TARGET.authRequired) {
      const authRelated = ['auth', 'session', 'oauth', '2fa', 'password'];
      if (authRelated.some(t => p.vulnerability.toLowerCase().includes(t))) adj *= 1.2;
    }
    if (JUICE_SHOP_TARGET.complexity < 0.3) adj *= 1.2;
    adj = Math.min(1, Math.max(0, adj));
    return { id: p.id, ev: adj * p.avgPayout };
  });
  ranked.sort((a, b) => b.ev - a.ev);
  const idx = ranked.findIndex(r => r.id === pathId);
  return idx >= 0 ? idx + 1 : ranked.length + 1;
}

function estimateCycles(difficulty: 1 | 2 | 3 | 4 | 5): number {
  const cycleMap: Record<number, number> = { 1: 2, 2: 4, 3: 7, 4: 12, 5: 20 };
  return cycleMap[difficulty] || 7;
}

function estimateConfidence(difficulty: 1 | 2 | 3 | 4 | 5, pathId: string): number {
  const path = ATTACK_PATHS.find(p => p.id === pathId);
  const baseLikelihood = path ? path.likelihood : 0.3;
  let adj = baseLikelihood;
  if (JUICE_SHOP_TARGET.authRequired) {
    const authRelated = ['auth', 'session', 'oauth', '2fa', 'password'];
    if (path && authRelated.some(t => path.vulnerability.toLowerCase().includes(t))) adj *= 1.2;
  }
  if (JUICE_SHOP_TARGET.complexity < 0.3) adj *= 1.2;
  const difficultyPenalty = 1 - (difficulty - 1) * 0.1;
  return Math.min(0.95, Math.max(0.1, adj * difficultyPenalty));
}

const JUICE_SHOP_VULNERABILITIES: LabVulnerability[] = [
  {
    id: 'js-sqli-login',
    name: 'Login bypass via SQL injection',
    category: 'Injection',
    difficulty: 2,
    plannerGoal: 'SQL Injection',
    plannerPathId: 'sqli-search',
    description: "Login form vulnerable to SQL injection allowing authentication bypass with payload like ' OR 1=1--",
    expectedTool: 'sqlmap',
    expectedEVRank: computeExpectedEVRank('sqli-search', 'SQL Injection'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'sqli-search'),
  },
  {
    id: 'js-sqli-christmas',
    name: 'Christmas special',
    category: 'Injection',
    difficulty: 2,
    plannerGoal: 'SQL Injection',
    plannerPathId: 'sqli-search',
    description: 'Order the Christmas Super-Surprise-Box via SQL injection in the search endpoint',
    expectedTool: 'sqlmap',
    expectedEVRank: computeExpectedEVRank('sqli-search', 'SQL Injection'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'sqli-search'),
  },
  {
    id: 'js-sqli-schema',
    name: 'Database schema extraction',
    category: 'Injection',
    difficulty: 4,
    plannerGoal: 'SQL Injection',
    plannerPathId: 'sqli-orderby',
    description: 'Extract the complete database schema using UNION-based SQL injection',
    expectedTool: 'sqlmap',
    expectedEVRank: computeExpectedEVRank('sqli-orderby', 'SQL Injection'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'sqli-orderby'),
  },
  {
    id: 'js-sqli-creds',
    name: 'User credential dump',
    category: 'Injection',
    difficulty: 4,
    plannerGoal: 'SQL Injection',
    plannerPathId: 'sqli-orderby',
    description: 'Dump all user credentials from the database via UNION-based SQL injection',
    expectedTool: 'sqlmap',
    expectedEVRank: computeExpectedEVRank('sqli-orderby', 'SQL Injection'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'sqli-orderby'),
  },
  {
    id: 'js-xss-dom',
    name: 'DOM XSS',
    category: 'XSS',
    difficulty: 1,
    plannerGoal: 'XSS',
    plannerPathId: 'xss-dom',
    description: 'DOM-based XSS via the search field rendered without sanitization',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('xss-dom', 'XSS'),
    expectedCycles: estimateCycles(1),
    expectedConfidence: estimateConfidence(1, 'xss-dom'),
  },
  {
    id: 'js-xss-reflected',
    name: 'Reflected XSS in search',
    category: 'XSS',
    difficulty: 2,
    plannerGoal: 'XSS',
    plannerPathId: 'xss-stored',
    description: 'Reflected XSS through the search query parameter echoed back unsanitized',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('xss-stored', 'XSS'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'xss-stored'),
  },
  {
    id: 'js-xss-stored',
    name: 'Stored XSS in product review',
    category: 'XSS',
    difficulty: 3,
    plannerGoal: 'XSS',
    plannerPathId: 'xss-stored',
    description: 'Stored XSS via malicious product review that executes when other users view the product',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('xss-stored', 'XSS'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'xss-stored'),
  },
  {
    id: 'js-xss-bypass',
    name: 'Client-side XSS protection bypass',
    category: 'XSS',
    difficulty: 4,
    plannerGoal: 'XSS',
    plannerPathId: 'xss-dom',
    description: 'Bypass client-side XSS filters using encoding tricks and alternative event handlers',
    expectedTool: 'manual_injection_test',
    expectedEVRank: computeExpectedEVRank('xss-dom', 'XSS'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'xss-dom'),
  },
  {
    id: 'js-ato-password',
    name: 'Password strength abuse',
    category: 'Broken Auth',
    difficulty: 2,
    plannerGoal: 'Account Takeover',
    plannerPathId: 'ato-password-reset',
    description: 'Brute-force weak admin password due to missing rate limiting and weak password policy',
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('ato-password-reset', 'Account Takeover'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'ato-password-reset'),
  },
  {
    id: 'js-ato-jim',
    name: "Reset Jim's password via security question",
    category: 'Broken Auth',
    difficulty: 3,
    plannerGoal: 'Account Takeover',
    plannerPathId: 'ato-password-reset',
    description: "Reset Jim's password by answering his security question with publicly available information",
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('ato-password-reset', 'Account Takeover'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'ato-password-reset'),
  },
  {
    id: 'js-ato-csrf',
    name: 'CSRF token bypass',
    category: 'Broken Auth',
    difficulty: 3,
    plannerGoal: 'Account Takeover',
    plannerPathId: 'ato-session-fixation',
    description: 'Bypass CSRF protection to perform state-changing actions on behalf of other users',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('ato-session-fixation', 'Account Takeover'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'ato-session-fixation'),
  },
  {
    id: 'js-ato-jwt-none',
    name: 'JWT manipulation - none algorithm',
    category: 'Broken Auth',
    difficulty: 4,
    plannerGoal: 'Account Takeover',
    plannerPathId: 'ato-2fa-bypass',
    description: 'Forge JWT tokens by changing the algorithm to "none" to bypass signature verification',
    expectedTool: 'manual_injection_test',
    expectedEVRank: computeExpectedEVRank('ato-2fa-bypass', 'Account Takeover'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'ato-2fa-bypass'),
  },
  {
    id: 'js-ato-jwt-admin',
    name: 'Forged admin JWT',
    category: 'Broken Auth',
    difficulty: 5,
    plannerGoal: 'Account Takeover',
    plannerPathId: 'ato-oauth-misconfig',
    description: 'Forge a valid admin JWT by exploiting weak signing key or algorithm confusion',
    expectedTool: 'manual_injection_test',
    expectedEVRank: computeExpectedEVRank('ato-oauth-misconfig', 'Account Takeover'),
    expectedCycles: estimateCycles(5),
    expectedConfidence: estimateConfidence(5, 'ato-oauth-misconfig'),
  },
  {
    id: 'js-ato-oauth',
    name: 'OAuth redirect manipulation',
    category: 'Broken Auth',
    difficulty: 4,
    plannerGoal: 'Account Takeover',
    plannerPathId: 'ato-oauth-misconfig',
    description: 'Manipulate OAuth redirect URI to steal authorization codes or tokens',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('ato-oauth-misconfig', 'Account Takeover'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'ato-oauth-misconfig'),
  },
  {
    id: 'js-ssrf-pdf',
    name: 'Server-side XSS via PDF generation',
    category: 'SSRF',
    difficulty: 3,
    plannerGoal: 'SSRF',
    plannerPathId: 'ssrf-webhook',
    description: 'Inject HTML/JS into PDF generation to read server-side files or access internal services',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('ssrf-webhook', 'SSRF'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'ssrf-webhook'),
  },
  {
    id: 'js-ssrf-url',
    name: 'SSRF via URL parameter',
    category: 'SSRF',
    difficulty: 3,
    plannerGoal: 'SSRF',
    plannerPathId: 'ssrf-import',
    description: 'Server-side request forgery through URL parameter allowing access to internal services',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('ssrf-import', 'SSRF'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'ssrf-import'),
  },
  {
    id: 'js-pii-metrics',
    name: 'Exposed metrics',
    category: 'PII Exposure',
    difficulty: 1,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-idor',
    description: 'Application metrics endpoint exposed without authentication revealing internal data',
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('pii-idor', 'PII Exposure'),
    expectedCycles: estimateCycles(1),
    expectedConfidence: estimateConfidence(1, 'pii-idor'),
  },
  {
    id: 'js-pii-ftp',
    name: 'FTP server access',
    category: 'PII Exposure',
    difficulty: 2,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-idor',
    description: 'Unsecured FTP server containing confidential files accessible without authentication',
    expectedTool: 'nmap',
    expectedEVRank: computeExpectedEVRank('pii-idor', 'PII Exposure'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'pii-idor'),
  },
  {
    id: 'js-pii-docs',
    name: 'Confidential document leak',
    category: 'PII Exposure',
    difficulty: 2,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-idor',
    description: 'Confidential documents accessible through directory traversal or direct URL access',
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('pii-idor', 'PII Exposure'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'pii-idor'),
  },
  {
    id: 'js-pii-export',
    name: 'User data export exposure',
    category: 'PII Exposure',
    difficulty: 3,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-export',
    description: 'User data export feature accessible without proper authorization checks',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('pii-export', 'PII Exposure'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'pii-export'),
  },
  {
    id: 'js-pii-email',
    name: 'Email leak via user search',
    category: 'PII Exposure',
    difficulty: 2,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-idor',
    description: 'User email addresses leaked through the user search API endpoint',
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('pii-idor', 'PII Exposure'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'pii-idor'),
  },
  {
    id: 'js-pii-basket',
    name: 'Basket manipulation / IDOR',
    category: 'PII Exposure',
    difficulty: 2,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-idor',
    description: "View other users' shopping baskets by manipulating basket IDs (IDOR)",
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('pii-idor', 'PII Exposure'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'pii-idor'),
  },
  {
    id: 'js-rce-filewrite',
    name: 'Arbitrary file write',
    category: 'Injection',
    difficulty: 5,
    plannerGoal: 'RCE',
    plannerPathId: 'rce-upload',
    description: 'Achieve arbitrary file write through deserialization vulnerability leading to RCE',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('rce-upload', 'RCE'),
    expectedCycles: estimateCycles(5),
    expectedConfidence: estimateConfidence(5, 'rce-upload'),
  },
  {
    id: 'js-rce-prototype',
    name: 'Prototype pollution',
    category: 'Injection',
    difficulty: 4,
    plannerGoal: 'RCE',
    plannerPathId: 'rce-ssti',
    description: 'Prototype pollution via malicious JSON input leading to potential RCE',
    expectedTool: 'manual_injection_test',
    expectedEVRank: computeExpectedEVRank('rce-ssti', 'RCE'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'rce-ssti'),
  },
  {
    id: 'js-pay-basket',
    name: 'Manipulate basket total',
    category: 'Broken Access Control',
    difficulty: 3,
    plannerGoal: 'Payment Manipulation',
    plannerPathId: 'pay-price-tampering',
    description: 'Manipulate product prices or basket totals by intercepting and modifying API requests',
    expectedTool: 'manual_injection_test',
    expectedEVRank: computeExpectedEVRank('pay-price-tampering', 'Payment Manipulation'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'pay-price-tampering'),
  },
  {
    id: 'js-pay-coupon',
    name: 'Coupon code bypass',
    category: 'Broken Access Control',
    difficulty: 4,
    plannerGoal: 'Payment Manipulation',
    plannerPathId: 'pay-coupon-abuse',
    description: 'Bypass coupon validation to apply unlimited or forged discount codes',
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('pay-coupon-abuse', 'Payment Manipulation'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'pay-coupon-abuse'),
  },
  {
    id: 'js-pay-negative',
    name: 'Negative quantity ordering',
    category: 'Broken Access Control',
    difficulty: 3,
    plannerGoal: 'Payment Manipulation',
    plannerPathId: 'pay-race-condition',
    description: 'Order products with negative quantity to receive credit instead of being charged',
    expectedTool: 'manual_injection_test',
    expectedEVRank: computeExpectedEVRank('pay-race-condition', 'Payment Manipulation'),
    expectedCycles: estimateCycles(3),
    expectedConfidence: estimateConfidence(3, 'pay-race-condition'),
  },
  {
    id: 'js-misc-error',
    name: 'Error handling disclosure',
    category: 'Security Misconfiguration',
    difficulty: 1,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-idor',
    description: 'Verbose error messages revealing stack traces, framework versions, and internal paths',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('pii-idor', 'PII Exposure'),
    expectedCycles: estimateCycles(1),
    expectedConfidence: estimateConfidence(1, 'pii-idor'),
  },
  {
    id: 'js-misc-admin',
    name: 'Admin section discovery',
    category: 'Security Misconfiguration',
    difficulty: 2,
    plannerGoal: 'Account Takeover',
    plannerPathId: 'ato-idor-user',
    description: 'Hidden admin panel accessible through directory enumeration at /#/administration',
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('ato-idor-user', 'Account Takeover'),
    expectedCycles: estimateCycles(2),
    expectedConfidence: estimateConfidence(2, 'ato-idor-user'),
  },
  {
    id: 'js-misc-headers',
    name: 'Missing security headers',
    category: 'Security Misconfiguration',
    difficulty: 1,
    plannerGoal: 'XSS',
    plannerPathId: 'xss-stored',
    description: 'Missing Content-Security-Policy, X-Frame-Options, and other security headers',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('xss-stored', 'XSS'),
    expectedCycles: estimateCycles(1),
    expectedConfidence: estimateConfidence(1, 'xss-stored'),
  },
  {
    id: 'js-misc-swagger',
    name: 'Exposed Swagger/API docs',
    category: 'Security Misconfiguration',
    difficulty: 1,
    plannerGoal: 'PII Exposure',
    plannerPathId: 'pii-idor',
    description: 'Swagger API documentation exposed at /api-docs revealing all API endpoints',
    expectedTool: 'ffuf',
    expectedEVRank: computeExpectedEVRank('pii-idor', 'PII Exposure'),
    expectedCycles: estimateCycles(1),
    expectedConfidence: estimateConfidence(1, 'pii-idor'),
  },
  {
    id: 'js-misc-xxe',
    name: 'B2B order XML injection',
    category: 'Injection',
    difficulty: 4,
    plannerGoal: 'RCE',
    plannerPathId: 'rce-ssti',
    description: 'XML External Entity injection via B2B order upload feature allowing file read or SSRF',
    expectedTool: 'nuclei',
    expectedEVRank: computeExpectedEVRank('rce-ssti', 'RCE'),
    expectedCycles: estimateCycles(4),
    expectedConfidence: estimateConfidence(4, 'rce-ssti'),
  },
];

const JUICE_SHOP_PROFILE: LabTargetProfile = {
  id: 'juice-shop',
  name: 'OWASP Juice Shop',
  description: 'OWASP Juice Shop is the most modern and sophisticated insecure web application for security training, awareness demos, and CTFs. It encompasses vulnerabilities from the entire OWASP Top Ten along with many other security flaws found in real-world applications.',
  targetUrl: 'http://localhost:3000',
  vulnerabilities: JUICE_SHOP_VULNERABILITIES,
  expectedGoalRankings: [
    { goal: 'PII Exposure', expectedRank: 1 },
    { goal: 'Account Takeover', expectedRank: 2 },
    { goal: 'SQL Injection', expectedRank: 3 },
    { goal: 'XSS', expectedRank: 4 },
    { goal: 'Payment Manipulation', expectedRank: 5 },
    { goal: 'RCE', expectedRank: 6 },
    { goal: 'SSRF', expectedRank: 7 },
  ],
  totalChallenges: 47,
  targetCharacteristics: JUICE_SHOP_TARGET,
};

const LAB_PROFILES: Map<string, LabTargetProfile> = new Map([
  [JUICE_SHOP_PROFILE.id, JUICE_SHOP_PROFILE],
]);

export class LabScorer {
  /**
   * Exact `host` (hostname:port) values of the platform's known,
   * pre-scored practice-lab targets — the narrow, explicit marker
   * `resolveCustomTargetProgram()` uses to decide `isLab` (see the
   * scope-binding handoff, Fix 1). Deliberately NOT a broad heuristic like
   * `isLocalHostname()` (any loopback/RFC-1918 address): a real ad-hoc
   * engagement can legitimately target an internal/loopback host too, and
   * that must still resolve to `isLab: false` (gated). Only a host this
   * platform actually ships a scored lab profile for is "the lab."
   */
  getKnownLabHosts(): string[] {
    return Array.from(LAB_PROFILES.values()).map((p) => new URL(p.targetUrl).host);
  }

  scoreHunt(huntId: string, profileId: string, confirmedFindings: string[], traceData?: any[]): LabScore {
    const profile = this.getProfile(profileId);
    if (!profile) {
      return {
        profileId,
        huntId,
        coverage: 0,
        goalAccuracy: 0,
        evRankingAccuracy: 0,
        cycleEfficiency: 0,
        pathSelectionAccuracy: 0,
        categoryBreakdown: [],
        difficultyBreakdown: [],
        missedVulns: [],
        decisionQualitySummary: { topPathCorrect: false, avgRankDeviation: 0, overconfidentPaths: 0, underconfidentPaths: 0 },
        timestamp: Date.now(),
      };
    }

    const normalizedFindings = confirmedFindings.map(f => f.toLowerCase());

    const foundVulns: LabVulnerability[] = [];
    const missedVulns: LabVulnerability[] = [];

    for (const vuln of profile.vulnerabilities) {
      const isFound = normalizedFindings.some(f =>
        f.includes(vuln.id.toLowerCase()) ||
        f.includes(vuln.name.toLowerCase()) ||
        vuln.name.toLowerCase().includes(f) ||
        f.includes(vuln.plannerPathId.toLowerCase())
      );
      if (isFound) {
        foundVulns.push(vuln);
      } else {
        missedVulns.push(vuln);
      }
    }

    const coverage = profile.vulnerabilities.length > 0
      ? foundVulns.length / profile.vulnerabilities.length
      : 0;

    const goalAccuracy = this.computeGoalAccuracy(profile, foundVulns);
    const evRankingAccuracy = this.computeEVRankingAccuracy(profile, traceData);
    const cycleEfficiency = this.computeCycleEfficiency(profile, traceData);
    const pathSelectionAccuracy = this.computePathSelectionAccuracy(profile, traceData);
    const decisionQualitySummary = this.computeDecisionQualitySummary(profile, traceData);

    const categoryBreakdown = this.computeCategoryBreakdown(profile.vulnerabilities, foundVulns);
    const difficultyBreakdown = this.computeDifficultyBreakdown(profile.vulnerabilities, foundVulns);

    return {
      profileId,
      huntId,
      coverage,
      goalAccuracy,
      evRankingAccuracy,
      cycleEfficiency,
      pathSelectionAccuracy,
      categoryBreakdown,
      difficultyBreakdown,
      missedVulns,
      decisionQualitySummary,
      timestamp: Date.now(),
    };
  }

  computeDivergence(huntId: string, profileId: string, traceData: any[]): DivergencePoint[] {
    const profile = this.getProfile(profileId);
    if (!profile || traceData.length === 0) return [];

    const plannerEvents = traceData.filter((e: any) => e.eventType === 'planner_ranking');
    const toolEvents = traceData.filter((e: any) => e.eventType === 'tool_selection' || e.eventType === 'tool_execution');
    const pivotEvents = traceData.filter((e: any) => e.eventType === 'meta_pivot');
    const findingEvents = traceData.filter((e: any) => e.eventType === 'finding_confirmed');

    const divergencePoints: DivergencePoint[] = [];
    let step = 0;

    const plannedGoalOrder = profile.expectedGoalRankings.map(r => r.goal);
    const plannedPaths = profile.vulnerabilities.reduce((acc: Map<string, string[]>, v) => {
      if (!acc.has(v.plannerGoal)) acc.set(v.plannerGoal, []);
      acc.get(v.plannerGoal)!.push(v.plannerPathId);
      return acc;
    }, new Map<string, string[]>());

    if (plannerEvents.length > 0) {
      const firstPlanner = plannerEvents[0];
      const plannedTopGoal = plannedGoalOrder[0] || '';
      const actualGoal = firstPlanner.data?.goal || '';
      const diverged = plannedTopGoal.toLowerCase() !== actualGoal.toLowerCase();

      divergencePoints.push({
        step: step++,
        timestamp: firstPlanner.timestamp,
        plannedAction: `Start with goal: ${plannedTopGoal}`,
        plannedGoal: plannedTopGoal,
        plannedConfidence: profile.vulnerabilities.find(v => v.plannerGoal === plannedTopGoal)?.expectedConfidence || 0.5,
        actualAction: `Started with goal: ${actualGoal}`,
        actualGoal: actualGoal,
        actualConfidence: firstPlanner.confidenceAtEvent || 0,
        diverged,
        divergenceType: diverged ? 'goal_mismatch' : 'none',
        insight: diverged
          ? `Planner chose '${actualGoal}' over expected top goal '${plannedTopGoal}'. Check if EV ranking reflects target profile.`
          : 'Initial goal matches expected ranking.',
      });
    }

    for (const pivot of pivotEvents) {
      const fromGoal = pivot.data?.fromStrategy || pivot.data?.from || '';
      const toGoal = pivot.data?.toStrategy || pivot.data?.to || '';

      const expectedNextGoalIdx = plannedGoalOrder.findIndex(g =>
        g.toLowerCase() === fromGoal.toLowerCase()
      );
      const expectedNextGoal = expectedNextGoalIdx >= 0 && expectedNextGoalIdx + 1 < plannedGoalOrder.length
        ? plannedGoalOrder[expectedNextGoalIdx + 1]
        : '';

      const pivotMatchesExpected = expectedNextGoal.toLowerCase() === toGoal.toLowerCase();
      let divergenceType: DivergencePoint['divergenceType'] = 'none';
      let insight = 'Pivot follows expected goal sequence.';

      if (!pivotMatchesExpected && expectedNextGoal) {
        divergenceType = 'path_mismatch';
        insight = `Pivoted to '${toGoal}' instead of expected '${expectedNextGoal}'. May indicate planner adapted to runtime signals.`;
      }

      const nextFinding = findingEvents.find((f: any) => f.timestamp > pivot.timestamp);
      const nextPivot = pivotEvents.find((p: any) => p.timestamp > pivot.timestamp && p !== pivot);
      if (nextPivot && !nextFinding) {
        divergenceType = 'early_pivot';
        insight = `Early pivot: moved to '${toGoal}' before confirming any finding. May indicate impatience or correct dead-end detection.`;
      }

      divergencePoints.push({
        step: step++,
        timestamp: pivot.timestamp,
        plannedAction: expectedNextGoal ? `Pivot to: ${expectedNextGoal}` : 'Continue current path',
        plannedGoal: expectedNextGoal || fromGoal,
        plannedConfidence: 0.5,
        actualAction: `Pivoted: ${fromGoal} → ${toGoal}`,
        actualGoal: toGoal,
        actualConfidence: pivot.confidenceAtEvent || 0,
        diverged: divergenceType !== 'none',
        divergenceType,
        insight,
      });
    }

    for (const finding of findingEvents) {
      const findingGoal = finding.data?.goal || finding.data?.plannerGoal || finding.data?.vulnerability || '';
      const matchedVuln = profile.vulnerabilities.find(v =>
        v.name.toLowerCase().includes(findingGoal.toLowerCase()) ||
        findingGoal.toLowerCase().includes(v.plannerGoal.toLowerCase()) ||
        findingGoal.toLowerCase().includes(v.plannerPathId.toLowerCase())
      );

      const wasExpected = !!matchedVuln;
      const expectedTool = matchedVuln?.expectedTool || '';
      const actualTool = finding.data?.tool || '';
      const toolMismatch = expectedTool && actualTool && expectedTool.toLowerCase() !== actualTool.toLowerCase();

      let divergenceType: DivergencePoint['divergenceType'] = 'none';
      let insight = 'Finding matches expected vulnerability.';

      if (!wasExpected) {
        divergenceType = 'goal_mismatch';
        insight = `Unexpected finding '${findingGoal}' — not in ground truth. Could be a bonus discovery or false positive.`;
      } else if (toolMismatch) {
        divergenceType = 'tool_mismatch';
        insight = `Found '${matchedVuln!.name}' using '${actualTool}' instead of expected '${expectedTool}'. Tool choice deviation.`;
      }

      divergencePoints.push({
        step: step++,
        timestamp: finding.timestamp,
        plannedAction: matchedVuln ? `Find: ${matchedVuln.name} via ${expectedTool}` : 'N/A',
        plannedGoal: matchedVuln?.plannerGoal || '',
        plannedConfidence: matchedVuln?.expectedConfidence || 0,
        actualAction: `Found: ${findingGoal}`,
        actualGoal: finding.data?.goal || '',
        actualConfidence: finding.confidenceAtEvent || 0,
        diverged: divergenceType !== 'none',
        divergenceType,
        insight,
      });
    }

    divergencePoints.sort((a, b) => a.timestamp - b.timestamp);
    divergencePoints.forEach((d, i) => { d.step = i; });

    return divergencePoints;
  }

  getProfile(profileId: string): LabTargetProfile | undefined {
    return LAB_PROFILES.get(profileId);
  }

  getAllProfiles(): LabTargetProfile[] {
    return Array.from(LAB_PROFILES.values());
  }

  getGroundTruth(profileId: string): GroundTruth {
    const profile = this.getProfile(profileId);
    if (!profile) {
      return { expectedFindings: [], plannerTopPaths: [] };
    }

    const expectedFindings = profile.vulnerabilities.map(v => v.name);

    const plannerTopPaths = profile.expectedGoalRankings
      .sort((a, b) => a.expectedRank - b.expectedRank)
      .map(r => r.goal);

    return { expectedFindings, plannerTopPaths };
  }

  getEnrichedProfile(profileId: string): any {
    const profile = this.getProfile(profileId);
    if (!profile) return null;

    const goalStats = new Map<string, { vulnCount: number; avgDifficulty: number; avgEVRank: number; avgCycles: number; avgConfidence: number }>();
    for (const vuln of profile.vulnerabilities) {
      if (!goalStats.has(vuln.plannerGoal)) {
        goalStats.set(vuln.plannerGoal, { vulnCount: 0, avgDifficulty: 0, avgEVRank: 0, avgCycles: 0, avgConfidence: 0 });
      }
      const s = goalStats.get(vuln.plannerGoal)!;
      s.vulnCount++;
      s.avgDifficulty += vuln.difficulty;
      s.avgEVRank += vuln.expectedEVRank;
      s.avgCycles += vuln.expectedCycles;
      s.avgConfidence += vuln.expectedConfidence;
    }

    const goalSummary = Array.from(goalStats.entries()).map(([goal, stats]) => ({
      goal,
      vulnCount: stats.vulnCount,
      avgDifficulty: +(stats.avgDifficulty / stats.vulnCount).toFixed(2),
      avgEVRank: +(stats.avgEVRank / stats.vulnCount).toFixed(2),
      expectedCycles: Math.round(stats.avgCycles / stats.vulnCount),
      avgExpectedConfidence: +(stats.avgConfidence / stats.vulnCount).toFixed(3),
      expectedRank: profile.expectedGoalRankings.find(r => r.goal === goal)?.expectedRank || 0,
    })).sort((a, b) => a.expectedRank - b.expectedRank);

    return {
      id: profile.id,
      name: profile.name,
      targetCharacteristics: profile.targetCharacteristics,
      totalVulnerabilities: profile.vulnerabilities.length,
      totalChallenges: profile.totalChallenges,
      goalSummary,
      vulnerabilities: profile.vulnerabilities.map(v => ({
        id: v.id,
        name: v.name,
        goal: v.plannerGoal,
        pathId: v.plannerPathId,
        difficulty: v.difficulty,
        expectedEVRank: v.expectedEVRank,
        expectedCycles: v.expectedCycles,
        expectedConfidence: +(v.expectedConfidence).toFixed(3),
        expectedTool: v.expectedTool,
      })),
    };
  }

  private computeEVRankingAccuracy(profile: LabTargetProfile, traceData?: any[]): number {
    if (!traceData || traceData.length === 0) return 0;

    const plannerRankings = traceData.filter((e: any) => e.eventType === 'planner_ranking');
    if (plannerRankings.length === 0) return 0;

    let totalDeviation = 0;
    let comparisons = 0;

    for (const ranking of plannerRankings) {
      const goal = ranking.data?.goal || '';
      const rankedPaths = ranking.data?.rankedPaths || [];

      const expectedVulns = profile.vulnerabilities.filter(v => v.plannerGoal.toLowerCase() === goal.toLowerCase());
      if (expectedVulns.length === 0) continue;

      for (const vuln of expectedVulns) {
        const actualRankEntry = rankedPaths.find((r: any) => r.pathId === vuln.plannerPathId);
        if (actualRankEntry) {
          totalDeviation += Math.abs((actualRankEntry.rank || 1) - vuln.expectedEVRank);
          comparisons++;
        }
      }
    }

    if (comparisons === 0) return 0;
    const maxDeviation = comparisons * 5;
    return Math.max(0, 1 - (totalDeviation / maxDeviation));
  }

  private computeCycleEfficiency(profile: LabTargetProfile, traceData?: any[]): number {
    if (!traceData || traceData.length === 0) return 0;

    const findings = traceData.filter((e: any) => e.eventType === 'finding_confirmed');
    if (findings.length === 0) return 0;

    let totalRatio = 0;
    let matched = 0;

    for (const finding of findings) {
      const findingName = (finding.data?.vulnerability || finding.data?.findingType || '').toLowerCase();
      const matchedVuln = profile.vulnerabilities.find(v =>
        v.name.toLowerCase().includes(findingName) || findingName.includes(v.name.toLowerCase())
      );

      if (matchedVuln) {
        const startEvent = traceData.find((e: any) => e.eventType === 'hunt_start');
        const actualCycles = traceData.filter((e: any) =>
          e.eventType === 'meta_evaluation' && e.timestamp <= finding.timestamp &&
          (startEvent ? e.timestamp >= startEvent.timestamp : true)
        ).length;

        const expected = matchedVuln.expectedCycles;
        const ratio = expected > 0 ? Math.min(1, expected / Math.max(1, actualCycles)) : 0;
        totalRatio += ratio;
        matched++;
      }
    }

    return matched > 0 ? totalRatio / matched : 0;
  }

  private computePathSelectionAccuracy(profile: LabTargetProfile, traceData?: any[]): number {
    if (!traceData || traceData.length === 0) return 0;

    const plannerRankings = traceData.filter((e: any) => e.eventType === 'planner_ranking');
    const findings = traceData.filter((e: any) => e.eventType === 'finding_confirmed');
    if (plannerRankings.length === 0 || findings.length === 0) return 0;

    let topPathHits = 0;
    let totalGoals = 0;

    for (const ranking of plannerRankings) {
      const goal = ranking.data?.goal || '';
      const topPaths = (ranking.data?.rankedPaths || []).slice(0, 3).map((r: any) => r.pathId);

      const goalFindings = findings.filter((f: any) =>
        (f.data?.goal || '').toLowerCase() === goal.toLowerCase()
      );

      if (goalFindings.length > 0) {
        totalGoals++;
        const anyTopPathHit = profile.vulnerabilities.some(v =>
          v.plannerGoal.toLowerCase() === goal.toLowerCase() &&
          topPaths.includes(v.plannerPathId)
        );
        if (anyTopPathHit) topPathHits++;
      }
    }

    return totalGoals > 0 ? topPathHits / totalGoals : 0;
  }

  private computeDecisionQualitySummary(profile: LabTargetProfile, traceData?: any[]) {
    if (!traceData || traceData.length === 0) {
      return { topPathCorrect: false, avgRankDeviation: 0, overconfidentPaths: 0, underconfidentPaths: 0 };
    }

    const plannerRankings = traceData.filter((e: any) => e.eventType === 'planner_ranking');
    const findings = traceData.filter((e: any) => e.eventType === 'finding_confirmed');

    let topPathCorrect = false;
    if (plannerRankings.length > 0) {
      const firstGoal = plannerRankings[0].data?.goal || '';
      const firstTopPath = (plannerRankings[0].data?.rankedPaths || [])[0]?.pathId || '';
      topPathCorrect = findings.some((f: any) =>
        (f.data?.goal || '').toLowerCase() === firstGoal.toLowerCase() &&
        profile.vulnerabilities.some(v =>
          v.plannerGoal.toLowerCase() === firstGoal.toLowerCase() &&
          v.plannerPathId === firstTopPath
        )
      );
    }

    let totalDeviation = 0;
    let comparisons = 0;
    let overconfident = 0;
    let underconfident = 0;

    for (const vuln of profile.vulnerabilities) {
      const ranking = plannerRankings.find((r: any) => (r.data?.goal || '').toLowerCase() === vuln.plannerGoal.toLowerCase());
      if (!ranking) continue;

      const rankedPaths = ranking.data?.rankedPaths || [];
      const pathEntry = rankedPaths.find((r: any) => r.pathId === vuln.plannerPathId);
      if (!pathEntry) continue;

      const actualRank = pathEntry.rank || 1;
      totalDeviation += Math.abs(actualRank - vuln.expectedEVRank);
      comparisons++;

      const wasFound = findings.some((f: any) =>
        (f.data?.vulnerability || f.data?.findingType || '').toLowerCase().includes(vuln.name.toLowerCase()) ||
        vuln.name.toLowerCase().includes((f.data?.vulnerability || f.data?.findingType || '').toLowerCase())
      );

      if (pathEntry.ev > vuln.expectedConfidence * 20000 && !wasFound) overconfident++;
      if (pathEntry.ev < vuln.expectedConfidence * 5000 && wasFound) underconfident++;
    }

    return {
      topPathCorrect,
      avgRankDeviation: comparisons > 0 ? +(totalDeviation / comparisons).toFixed(2) : 0,
      overconfidentPaths: overconfident,
      underconfidentPaths: underconfident,
    };
  }

  private computeGoalAccuracy(profile: LabTargetProfile, foundVulns: LabVulnerability[]): number {
    if (profile.expectedGoalRankings.length === 0) return 0;

    const foundGoalCounts = new Map<string, number>();
    for (const vuln of foundVulns) {
      foundGoalCounts.set(vuln.plannerGoal, (foundGoalCounts.get(vuln.plannerGoal) || 0) + 1);
    }

    const foundGoalsSorted = Array.from(foundGoalCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([goal], idx) => ({ goal, actualRank: idx + 1 }));

    let totalRankDiff = 0;

    for (const expected of profile.expectedGoalRankings) {
      const actual = foundGoalsSorted.find(g => g.goal === expected.goal);
      if (actual) {
        totalRankDiff += Math.abs(expected.expectedRank - actual.actualRank);
      } else {
        totalRankDiff += profile.expectedGoalRankings.length;
      }
    }

    const maxPossibleDiff = profile.expectedGoalRankings.length * profile.expectedGoalRankings.length;
    return Math.max(0, 1 - (totalRankDiff / maxPossibleDiff));
  }

  private computeCategoryBreakdown(
    allVulns: LabVulnerability[],
    foundVulns: LabVulnerability[]
  ): { category: string; found: number; total: number; coverage: number }[] {
    const categories = new Map<string, { found: number; total: number }>();

    for (const vuln of allVulns) {
      if (!categories.has(vuln.category)) {
        categories.set(vuln.category, { found: 0, total: 0 });
      }
      categories.get(vuln.category)!.total++;
    }

    const foundIds = new Set(foundVulns.map(v => v.id));
    for (const vuln of allVulns) {
      if (foundIds.has(vuln.id)) {
        categories.get(vuln.category)!.found++;
      }
    }

    return Array.from(categories.entries()).map(([category, data]) => ({
      category,
      found: data.found,
      total: data.total,
      coverage: data.total > 0 ? data.found / data.total : 0,
    }));
  }

  private computeDifficultyBreakdown(
    allVulns: LabVulnerability[],
    foundVulns: LabVulnerability[]
  ): { difficulty: number; found: number; total: number; coverage: number }[] {
    const difficulties = new Map<number, { found: number; total: number }>();

    for (const vuln of allVulns) {
      if (!difficulties.has(vuln.difficulty)) {
        difficulties.set(vuln.difficulty, { found: 0, total: 0 });
      }
      difficulties.get(vuln.difficulty)!.total++;
    }

    const foundIds = new Set(foundVulns.map(v => v.id));
    for (const vuln of allVulns) {
      if (foundIds.has(vuln.id)) {
        difficulties.get(vuln.difficulty)!.found++;
      }
    }

    return Array.from(difficulties.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([difficulty, data]) => ({
        difficulty,
        found: data.found,
        total: data.total,
        coverage: data.total > 0 ? data.found / data.total : 0,
      }));
  }
}

export const labScorer = new LabScorer();

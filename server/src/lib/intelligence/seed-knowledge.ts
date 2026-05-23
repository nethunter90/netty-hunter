export interface PivotStrategy {
  strategy: string;
  reason: string;
  weight: number;
}

export interface PivotPlaybook {
  condition: string;
  pivots: PivotStrategy[];
}

export interface AttackPath {
  id: string;
  goal: string;
  vulnerability: string;
  likelihood: number;
  priority: number;
  testMethods: string[];
  avgPayout: number;
  payoutRange: [number, number];
}

export type MitreNodeType = 'entry' | 'pivot' | 'escalate' | 'persist' | 'exfil' | 'goal';

export interface MitreTechnique {
  id: string;
  name: string;
  nodeType: MitreNodeType;
  requires: string[];
  provides: string[];
  probability: number;
  impact: number;
  stealth: number;
}

export interface ToolFallback {
  tool: string;
  degradationCoefficient: number;
  reason: string;
}

export interface ToolFallbackChain {
  primary: string;
  fallbacks: ToolFallback[];
}

export interface IntentPattern {
  category: string;
  triggers: string[];
}

export type PayoutLikelihood = 'very_rare' | 'rare' | 'uncommon' | 'common' | 'very_common';

export interface GoalPayoutData {
  goal: string;
  avgPayout: number;
  payoutRange: [number, number];
  likelihood: PayoutLikelihood;
}

export interface HuntPhaseStep {
  name: string;
  actions: string[];
}

export interface HuntGoalPath {
  goal: string;
  phases: HuntPhaseStep[];
}

export const PIVOT_PLAYBOOKS: PivotPlaybook[] = [
  {
    condition: 'port_scan_empty',
    pivots: [
      { strategy: 'udp_scan', reason: 'nmap returns no open ports', weight: 0.9 },
      { strategy: 'subdomain_enum', reason: 'nmap returns no open ports', weight: 0.85 },
      { strategy: 'cloud_metadata', reason: 'nmap returns no open ports', weight: 0.7 },
      { strategy: 'historical_recon', reason: 'nmap returns no open ports', weight: 0.65 },
    ],
  },
  {
    condition: 'subdomain_enum_exhausted',
    pivots: [
      { strategy: 'vhost_bruteforce', reason: 'diminishing returns on subdomain discovery', weight: 0.85 },
      { strategy: 'certificate_transparency', reason: 'diminishing returns on subdomain discovery', weight: 0.9 },
      { strategy: 'github_dorking', reason: 'diminishing returns on subdomain discovery', weight: 0.8 },
      { strategy: 'asn_expansion', reason: 'diminishing returns on subdomain discovery', weight: 0.7 },
    ],
  },
  {
    condition: 'dirbusting_empty',
    pivots: [
      { strategy: 'parameter_discovery', reason: 'directory bruteforce yields nothing', weight: 0.9 },
      { strategy: 'tech_fingerprint_then_wordlist', reason: 'directory bruteforce yields nothing', weight: 0.85 },
      { strategy: 'js_source_analysis', reason: 'directory bruteforce yields nothing', weight: 0.95 },
      { strategy: 'wayback_urls', reason: 'directory bruteforce yields nothing', weight: 0.75 },
    ],
  },
  {
    condition: 'sqli_failed',
    pivots: [
      { strategy: 'nosql_injection', reason: 'SQL injection attempts blocked', weight: 0.7 },
      { strategy: 'ssti', reason: 'SQL injection attempts blocked', weight: 0.8 },
      { strategy: 'ssrf', reason: 'SQL injection attempts blocked', weight: 0.75 },
      { strategy: 'header_injection', reason: 'SQL injection attempts blocked', weight: 0.65 },
      { strategy: 'second_order', reason: 'SQL injection attempts blocked', weight: 0.6 },
    ],
  },
  {
    condition: 'xss_filtered',
    pivots: [
      { strategy: 'xss_encoding_bypass', reason: 'XSS payloads being sanitized', weight: 0.85 },
      { strategy: 'dom_xss', reason: 'XSS payloads being sanitized', weight: 0.9 },
      { strategy: 'csti', reason: 'XSS payloads being sanitized', weight: 0.75 },
      { strategy: 'open_redirect_chain', reason: 'XSS payloads being sanitized', weight: 0.6 },
    ],
  },
  {
    condition: 'login_bruteforce_blocked',
    pivots: [
      { strategy: 'credential_stuffing_slow', reason: 'rate limiting hit', weight: 0.5 },
      { strategy: 'password_spray', reason: 'rate limiting hit', weight: 0.8 },
      { strategy: 'registration_abuse', reason: 'rate limiting hit', weight: 0.85 },
      { strategy: 'forgot_password_flow', reason: 'rate limiting hit', weight: 0.9 },
      { strategy: 'oauth_misconfiguration', reason: 'rate limiting hit', weight: 0.7 },
    ],
  },
  {
    condition: 'privilege_escalation_stalled',
    pivots: [
      { strategy: 'idor_hunting', reason: 'low-priv access, can\'t escalate', weight: 0.95 },
      { strategy: 'api_endpoint_enum', reason: 'low-priv access, can\'t escalate', weight: 0.9 },
      { strategy: 'jwt_manipulation', reason: 'low-priv access, can\'t escalate', weight: 0.85 },
      { strategy: 'mass_assignment', reason: 'low-priv access, can\'t escalate', weight: 0.8 },
      { strategy: 'graphql_introspection', reason: 'low-priv access, can\'t escalate', weight: 0.75 },
    ],
  },
  {
    condition: 'waf_detected',
    pivots: [
      { strategy: 'waf_fingerprint_bypass', reason: 'WAF blocking payloads', weight: 0.85 },
      { strategy: 'origin_ip_discovery', reason: 'WAF blocking payloads', weight: 0.95 },
      { strategy: 'http_smuggling', reason: 'WAF blocking payloads', weight: 0.8 },
      { strategy: 'api_direct', reason: 'WAF blocking payloads', weight: 0.75 },
      { strategy: 'websocket_abuse', reason: 'WAF blocking payloads', weight: 0.7 },
    ],
  },
  {
    condition: 'cloud_target',
    pivots: [
      { strategy: 's3_bucket_enum', reason: 'target uses AWS/GCP/Azure', weight: 0.9 },
      { strategy: 'metadata_ssrf', reason: 'target uses AWS/GCP/Azure', weight: 0.95 },
      { strategy: 'lambda_function_urls', reason: 'target uses AWS/GCP/Azure', weight: 0.7 },
      { strategy: 'cognito_misconfiguration', reason: 'target uses AWS/GCP/Azure', weight: 0.75 },
      { strategy: 'azure_ad_enum', reason: 'target uses AWS/GCP/Azure', weight: 0.7 },
    ],
  },
  {
    condition: 'shell_obtained',
    pivots: [
      { strategy: 'credential_harvesting', reason: 'have command execution', weight: 0.95 },
      { strategy: 'internal_network_scan', reason: 'have command execution', weight: 0.9 },
      { strategy: 'container_escape', reason: 'have command execution', weight: 0.8 },
      { strategy: 'persistence_check', reason: 'have command execution', weight: 0.7 },
    ],
  },
];

export const ATTACK_PATHS: AttackPath[] = [
  {
    id: 'ato-password-reset',
    goal: 'Account Takeover',
    vulnerability: 'Password Reset Token Prediction',
    likelihood: 0.35,
    priority: 95,
    testMethods: ['Token entropy analysis', 'time-based pattern detection', 'user-id correlation', 'sequential token analysis'],
    avgPayout: 15000,
    payoutRange: [5000, 50000],
  },
  {
    id: 'ato-session-fixation',
    goal: 'Account Takeover',
    vulnerability: 'Session Fixation',
    likelihood: 0.15,
    priority: 70,
    testMethods: ['Session not regenerated', 'session in URL', 'predictable session ID'],
    avgPayout: 15000,
    payoutRange: [5000, 50000],
  },
  {
    id: 'ato-oauth-misconfig',
    goal: 'Account Takeover',
    vulnerability: 'OAuth Misconfiguration',
    likelihood: 0.40,
    priority: 90,
    testMethods: ['Open redirect in callback', 'missing state param', 'auth code reuse', 'PKCE bypass'],
    avgPayout: 15000,
    payoutRange: [5000, 50000],
  },
  {
    id: 'ato-idor-user',
    goal: 'Account Takeover',
    vulnerability: 'IDOR on User Settings',
    likelihood: 0.55,
    priority: 85,
    testMethods: ['Parameter manipulation', 'mass assignment', 'missing auth check'],
    avgPayout: 15000,
    payoutRange: [5000, 50000],
  },
  {
    id: 'ato-2fa-bypass',
    goal: 'Account Takeover',
    vulnerability: '2FA Bypass',
    likelihood: 0.25,
    priority: 80,
    testMethods: ['Rate limit bypass', 'direct endpoint access', 'code prediction', 'backup code brute force'],
    avgPayout: 15000,
    payoutRange: [5000, 50000],
  },
  {
    id: 'pay-race-condition',
    goal: 'Payment Manipulation',
    vulnerability: 'Race Condition on Credits',
    likelihood: 0.30,
    priority: 90,
    testMethods: ['Parallel requests', 'double spend', 'negative balance'],
    avgPayout: 12000,
    payoutRange: [3000, 40000],
  },
  {
    id: 'pay-price-tampering',
    goal: 'Payment Manipulation',
    vulnerability: 'Price Manipulation',
    likelihood: 0.45,
    priority: 95,
    testMethods: ['Parameter tampering', 'negative price', 'currency confusion', 'quantity overflow'],
    avgPayout: 12000,
    payoutRange: [3000, 40000],
  },
  {
    id: 'pay-coupon-abuse',
    goal: 'Payment Manipulation',
    vulnerability: 'Coupon/Discount Abuse',
    likelihood: 0.50,
    priority: 75,
    testMethods: ['Coupon reuse', 'stacking', 'negative discount', 'expired bypass'],
    avgPayout: 12000,
    payoutRange: [3000, 40000],
  },
  {
    id: 'pii-idor',
    goal: 'PII Exposure',
    vulnerability: 'IDOR on Sensitive Data',
    likelihood: 0.55,
    priority: 90,
    testMethods: ['ID enumeration', 'UUID prediction', 'sequential ID access'],
    avgPayout: 8000,
    payoutRange: [2000, 25000],
  },
  {
    id: 'pii-graphql-introspection',
    goal: 'PII Exposure',
    vulnerability: 'GraphQL Information Disclosure',
    likelihood: 0.40,
    priority: 85,
    testMethods: ['Introspection query', 'query depth exploitation', 'field suggestion'],
    avgPayout: 8000,
    payoutRange: [2000, 25000],
  },
  {
    id: 'pii-export',
    goal: 'PII Exposure',
    vulnerability: 'Data Export IDOR',
    likelihood: 0.35,
    priority: 80,
    testMethods: ['ID manipulation in export', 'path traversal in filename'],
    avgPayout: 8000,
    payoutRange: [2000, 25000],
  },
  {
    id: 'rce-ssrf-to-rce',
    goal: 'RCE',
    vulnerability: 'SSRF to RCE Chain',
    likelihood: 0.15,
    priority: 95,
    testMethods: ['Internal service access', 'cloud metadata', 'gopher protocol', 'Redis injection'],
    avgPayout: 25000,
    payoutRange: [10000, 100000],
  },
  {
    id: 'rce-upload',
    goal: 'RCE',
    vulnerability: 'Unrestricted File Upload',
    likelihood: 0.20,
    priority: 90,
    testMethods: ['Extension bypass', 'content-type confusion', 'null byte injection', 'polyglot files'],
    avgPayout: 25000,
    payoutRange: [10000, 100000],
  },
  {
    id: 'rce-ssti',
    goal: 'RCE',
    vulnerability: 'Server-Side Template Injection',
    likelihood: 0.10,
    priority: 85,
    testMethods: ['Template syntax probing', 'sandbox escape', 'object introspection'],
    avgPayout: 25000,
    payoutRange: [10000, 100000],
  },
  {
    id: 'ssrf-webhook',
    goal: 'SSRF',
    vulnerability: 'Webhook SSRF',
    likelihood: 0.50,
    priority: 90,
    testMethods: ['Localhost bypass', 'DNS rebinding', 'cloud metadata access'],
    avgPayout: 5000,
    payoutRange: [1000, 15000],
  },
  {
    id: 'ssrf-import',
    goal: 'SSRF',
    vulnerability: 'Import/Fetch SSRF',
    likelihood: 0.45,
    priority: 85,
    testMethods: ['Protocol smuggling', 'IP whitelist bypass', 'redirect chain'],
    avgPayout: 5000,
    payoutRange: [1000, 15000],
  },
  {
    id: 'sqli-search',
    goal: 'SQL Injection',
    vulnerability: 'Search SQL Injection',
    likelihood: 0.25,
    priority: 90,
    testMethods: ['Error-based', 'union-based', 'blind boolean', 'time-based'],
    avgPayout: 6000,
    payoutRange: [1500, 20000],
  },
  {
    id: 'sqli-orderby',
    goal: 'SQL Injection',
    vulnerability: 'Order By SQL Injection',
    likelihood: 0.35,
    priority: 85,
    testMethods: ['Conditional error', 'time-based blind'],
    avgPayout: 6000,
    payoutRange: [1500, 20000],
  },
  {
    id: 'xss-stored',
    goal: 'XSS',
    vulnerability: 'Stored XSS',
    likelihood: 0.40,
    priority: 80,
    testMethods: ['Basic payloads', 'filter bypass', 'event handlers', 'DOM clobbering'],
    avgPayout: 2000,
    payoutRange: [500, 8000],
  },
  {
    id: 'xss-dom',
    goal: 'XSS',
    vulnerability: 'DOM XSS',
    likelihood: 0.35,
    priority: 75,
    testMethods: ['Source/sink analysis', 'postMessage exploitation', 'URL fragment injection'],
    avgPayout: 2000,
    payoutRange: [500, 8000],
  },
];

export const MITRE_TECHNIQUES: MitreTechnique[] = [
  {
    id: 'T1566',
    name: 'Phishing',
    nodeType: 'entry',
    requires: ['email_access'],
    provides: ['user_credentials', 'initial_access'],
    probability: 0.30,
    impact: 0.4,
    stealth: 0.6,
  },
  {
    id: 'T1190',
    name: 'Exploit Public App',
    nodeType: 'entry',
    requires: ['exposed_service'],
    provides: ['web_shell', 'initial_access'],
    probability: 0.25,
    impact: 0.6,
    stealth: 0.4,
  },
  {
    id: 'T1003',
    name: 'Credential Dumping',
    nodeType: 'escalate',
    requires: ['local_admin'],
    provides: ['domain_credentials', 'hash_collection'],
    probability: 0.70,
    impact: 0.8,
    stealth: 0.3,
  },
  {
    id: 'T1021.002',
    name: 'Lateral SMB',
    nodeType: 'pivot',
    requires: ['domain_credentials'],
    provides: ['remote_access', 'pivot_point'],
    probability: 0.60,
    impact: 0.5,
    stealth: 0.4,
  },
  {
    id: 'T1558.003',
    name: 'Kerberoasting',
    nodeType: 'escalate',
    requires: ['domain_user'],
    provides: ['service_hashes', 'potential_admin'],
    probability: 0.80,
    impact: 0.7,
    stealth: 0.7,
  },
  {
    id: 'T1003.006',
    name: 'DCSync',
    nodeType: 'escalate',
    requires: ['domain_admin_equiv'],
    provides: ['all_hashes', 'domain_dominance'],
    probability: 0.90,
    impact: 1.0,
    stealth: 0.2,
  },
  {
    id: 'T1041',
    name: 'Data Exfiltration',
    nodeType: 'exfil',
    requires: ['data_access', 'c2_channel'],
    provides: ['mission_complete'],
    probability: 0.70,
    impact: 1.0,
    stealth: 0.5,
  },
];

export const TOOL_FALLBACK_CHAINS: ToolFallbackChain[] = [
  {
    primary: 'nmap',
    fallbacks: [
      { tool: 'masscan', degradationCoefficient: 0.6, reason: 'faster but less detail' },
      { tool: 'ping', degradationCoefficient: 0.2, reason: 'only confirms host is up' },
    ],
  },
  {
    primary: 'nuclei',
    fallbacks: [
      { tool: 'nikto', degradationCoefficient: 0.5, reason: 'fewer templates, less coverage' },
    ],
  },
  {
    primary: 'sqlmap',
    fallbacks: [
      { tool: 'manual_injection_test', degradationCoefficient: 0.4, reason: 'basic pattern matching only' },
    ],
  },
  {
    primary: 'subfinder',
    fallbacks: [
      { tool: 'amass', degradationCoefficient: 0.9, reason: 'comparable coverage' },
      { tool: 'theharvester', degradationCoefficient: 0.5, reason: 'limited sources' },
    ],
  },
  {
    primary: 'httpx',
    fallbacks: [
      { tool: 'curl', degradationCoefficient: 0.6, reason: 'no tech detection' },
      { tool: 'wget', degradationCoefficient: 0.3, reason: 'basic HTTP only' },
    ],
  },
  {
    primary: 'ffuf',
    fallbacks: [
      { tool: 'gobuster', degradationCoefficient: 0.85, reason: 'comparable fuzzing' },
      { tool: 'dirbuster', degradationCoefficient: 0.6, reason: 'slower, fewer features' },
    ],
  },
  {
    primary: 'playwright',
    fallbacks: [
      { tool: 'puppeteer', degradationCoefficient: 0.9, reason: 'comparable browser control' },
      { tool: 'selenium', degradationCoefficient: 0.7, reason: 'older API, more overhead' },
    ],
  },
];

export const TOOL_CATEGORIES: Record<string, string[]> = {
  recon: ['subfinder', 'amass', 'assetfinder', 'waybackurls', 'gau', 'nmap', 'dnsrecon', 'fierce', 'recon-ng', 'whatweb'],
  web_vuln: ['nuclei', 'xsstrike', 'dalfox', 'sqlmap', 'nikto'],
  api: ['kiterunner', 'graphqlmap', 'jwt-tool', 'arjun'],
  network: ['nmap', 'masscan', 'tlsx'],
  fuzzing: ['ffuf', 'gobuster', 'feroxbuster', 'dirb', 'wfuzz'],
  passive: ['shodan', 'censys', 'crtsh'],
  password: ['hydra', 'medusa', 'hashcat', 'john'],
  exploitation: ['msfconsole', 'msfvenom', 'metasploit'],
  post_exploitation: ['impacket-psexec', 'evil-winrm', 'bloodhound', 'chisel'],
};

export const INTENT_PATTERNS: IntentPattern[] = [
  {
    category: 'attack_surface',
    triggers: ['map attack surface', 'find all endpoints', 'discover assets', 'enumerate'],
  },
  {
    category: 'auth_bypass',
    triggers: ['auth bypass', 'authentication', 'login bypass', 'session hijack'],
  },
  {
    category: 'high_impact',
    triggers: ['high impact', 'critical bugs', 'rce', 'ssrf', 'sqli'],
  },
  {
    category: 'api_focus',
    triggers: ['api', 'graphql', 'rest', 'endpoints', 'jwt'],
  },
  {
    category: 'web_focus',
    triggers: ['xss', 'csrf', 'idor', 'injection', 'upload'],
  },
  {
    category: 'quiet_recon',
    triggers: ['quietly', 'stealth', 'low noise', 'undetected'],
  },
  {
    category: 'fast_scan',
    triggers: ['quick', 'fast', 'rapid', 'surface level'],
  },
  {
    category: 'deep_dive',
    triggers: ['deep', 'thorough', 'comprehensive', 'full scan'],
  },
];

export const GOAL_PAYOUT_DATA: GoalPayoutData[] = [
  { goal: 'RCE', avgPayout: 25000, payoutRange: [10000, 100000], likelihood: 'very_rare' },
  { goal: 'Account Takeover', avgPayout: 15000, payoutRange: [5000, 50000], likelihood: 'uncommon' },
  { goal: 'Payment Manipulation', avgPayout: 12000, payoutRange: [3000, 40000], likelihood: 'rare' },
  { goal: 'PII Exposure', avgPayout: 8000, payoutRange: [2000, 25000], likelihood: 'common' },
  { goal: 'SQL Injection', avgPayout: 6000, payoutRange: [1500, 20000], likelihood: 'uncommon' },
  { goal: 'SSRF', avgPayout: 5000, payoutRange: [1000, 15000], likelihood: 'common' },
  { goal: 'XSS', avgPayout: 2000, payoutRange: [500, 8000], likelihood: 'very_common' },
];

export const HUNT_GOAL_PATHS: HuntGoalPath[] = [
  {
    goal: 'account_takeover',
    phases: [
      { name: 'map_auth_endpoints', actions: ['discover login pages', 'find registration endpoints', 'locate password reset flows', 'identify OAuth endpoints'] },
      { name: 'test_auth_mechanisms', actions: ['test session management', 'check token entropy', 'analyze cookie flags', 'test remember-me functionality'] },
      { name: 'test_password_reset', actions: ['analyze reset token', 'test token expiry', 'check user enumeration', 'test rate limiting'] },
      { name: 'test_oauth', actions: ['test redirect URI validation', 'check state parameter', 'test auth code reuse', 'check PKCE implementation'] },
      { name: 'attempt_takeover', actions: ['chain discovered weaknesses', 'test account enumeration', 'attempt session hijacking', 'verify impact'] },
    ],
  },
  {
    goal: 'payment_manipulation',
    phases: [
      { name: 'find_payment_flows', actions: ['map checkout process', 'identify price parameters', 'find discount endpoints', 'locate payment API calls'] },
      { name: 'test_price_tampering', actions: ['modify price parameters', 'test negative values', 'test currency switching', 'test quantity overflow'] },
      { name: 'test_race_conditions', actions: ['send parallel requests', 'test double-spend scenarios', 'check balance consistency', 'test concurrent transactions'] },
      { name: 'test_coupon_logic', actions: ['test coupon reuse', 'test stacking discounts', 'test expired coupons', 'test negative discounts'] },
    ],
  },
  {
    goal: 'pii_exposure',
    phases: [
      { name: 'find_data_endpoints', actions: ['map user data APIs', 'find profile endpoints', 'locate data export features', 'identify search functionality'] },
      { name: 'test_idor_patterns', actions: ['test sequential IDs', 'test UUID prediction', 'test parameter manipulation', 'test horizontal access'] },
      { name: 'test_export_functions', actions: ['test export ID manipulation', 'test path traversal in filenames', 'test bulk data access', 'test format manipulation'] },
      { name: 'test_graphql', actions: ['run introspection query', 'test query depth', 'test field suggestions', 'test batch queries'] },
    ],
  },
  {
    goal: 'rce',
    phases: [
      { name: 'identify_injection_points', actions: ['find file upload endpoints', 'locate API deserialization points', 'find template rendering endpoints', 'identify command parameters'] },
      { name: 'test_file_upload', actions: ['test extension bypass', 'test content-type confusion', 'test null byte injection', 'test polyglot files'] },
      { name: 'test_command_injection', actions: ['test OS command injection', 'test argument injection', 'test environment variable injection', 'test backtick execution'] },
      { name: 'test_ssti', actions: ['probe template syntax', 'test sandbox escape', 'test object introspection', 'test expression evaluation'] },
      { name: 'achieve_rce', actions: ['chain vulnerabilities', 'establish command execution', 'verify impact scope', 'document exploitation path'] },
    ],
  },
  {
    goal: 'ssrf',
    phases: [
      { name: 'find_url_params', actions: ['find URL input parameters', 'locate webhook endpoints', 'find import/fetch features', 'identify redirect parameters'] },
      { name: 'test_localhost_bypass', actions: ['test 127.0.0.1 variations', 'test IPv6 localhost', 'test decimal IP notation', 'test DNS shortcuts'] },
      { name: 'test_cloud_metadata', actions: ['test AWS metadata endpoint', 'test GCP metadata endpoint', 'test Azure metadata endpoint', 'test DigitalOcean metadata'] },
      { name: 'test_dns_rebinding', actions: ['set up DNS rebinding domain', 'test time-of-check bypass', 'test with short TTL', 'verify internal access'] },
    ],
  },
  {
    goal: 'sqli',
    phases: [
      { name: 'discover_db_endpoints', actions: ['find search parameters', 'locate filter parameters', 'identify sort/order parameters', 'find ID-based lookups'] },
      { name: 'test_error_based', actions: ['inject single quotes', 'test syntax errors', 'use error-based payloads', 'identify database type'] },
      { name: 'test_blind', actions: ['test boolean-based blind', 'use conditional responses', 'test content-based differences', 'enumerate with binary search'] },
      { name: 'test_time_based', actions: ['test SLEEP/WAITFOR payloads', 'measure response delays', 'calibrate timing thresholds', 'extract data character by character'] },
      { name: 'extract_data', actions: ['enumerate databases', 'enumerate tables', 'extract columns', 'dump sensitive data'] },
    ],
  },
  {
    goal: 'xss',
    phases: [
      { name: 'find_input_points', actions: ['find reflected parameters', 'locate stored input fields', 'identify URL fragment handlers', 'find postMessage listeners'] },
      { name: 'test_filter_bypass', actions: ['test encoding bypasses', 'test case variations', 'test tag alternatives', 'test event handler variations'] },
      { name: 'test_dom_sinks', actions: ['analyze innerHTML usage', 'find document.write calls', 'check eval usage', 'identify jQuery sinks'] },
      { name: 'craft_payload', actions: ['build context-aware payload', 'test in target context', 'verify execution', 'demonstrate impact'] },
    ],
  },
  {
    goal: 'idor',
    phases: [
      { name: 'find_object_references', actions: ['map ID parameters', 'find UUID references', 'locate file references', 'identify sequential patterns'] },
      { name: 'test_horizontal_access', actions: ['swap user IDs', 'test cross-account access', 'verify authorization checks', 'test with multiple accounts'] },
      { name: 'test_vertical_access', actions: ['test admin endpoint access', 'test role-based restrictions', 'test privileged operations', 'verify permission boundaries'] },
      { name: 'test_bulk_operations', actions: ['test batch endpoint access', 'test enumeration at scale', 'test export manipulation', 'verify rate limiting on enumeration'] },
    ],
  },
  {
    goal: 'auth_bypass',
    phases: [
      { name: 'map_auth_flow', actions: ['document authentication flow', 'identify token types', 'map session management', 'find auth endpoints'] },
      { name: 'test_token_manipulation', actions: ['test JWT algorithm confusion', 'test token forgery', 'test signature bypass', 'test token reuse'] },
      { name: 'test_privilege_escalation', actions: ['test role parameter tampering', 'test admin access', 'test function-level access', 'test API key permissions'] },
      { name: 'test_session_handling', actions: ['test session fixation', 'test concurrent sessions', 'test session invalidation', 'test cookie manipulation'] },
    ],
  },
  {
    goal: 'custom',
    phases: [
      { name: 'generic_recon', actions: ['gather target information', 'identify technologies', 'map network infrastructure', 'collect OSINT'] },
      { name: 'enumerate', actions: ['enumerate subdomains', 'discover endpoints', 'identify parameters', 'map attack surface'] },
      { name: 'discover_vulns', actions: ['run vulnerability scanners', 'test common weaknesses', 'check misconfigurations', 'analyze responses'] },
      { name: 'validate', actions: ['confirm vulnerabilities', 'test exploitability', 'assess impact', 'check for false positives'] },
      { name: 'exploit', actions: ['develop proof of concept', 'chain vulnerabilities', 'demonstrate impact', 'capture evidence'] },
      { name: 'report', actions: ['document findings', 'write reproduction steps', 'assess severity', 'prepare submission'] },
    ],
  },
];

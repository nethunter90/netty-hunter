/**
 * Prompt Knowledge Base — 22 expert-verified security prompt templates for bug bounty hunting.
 * Covers recon, scanning, exploitation, credential testing, intelligence, reporting, and orchestration.
 * Defense, pivot, simulation, and codegen phases are excluded as out-of-scope for bug bounty.
 */

export interface PromptTemplate {
  id: string;
  phase: string;
  agent: string;
  name: string;
  description: string;
  template: string;
  variables: string[];
  confidenceThreshold: number;
  tags: string[];
}

// ─── Templates ────────────────────────────────────────────────────────────────

export const PROMPT_TEMPLATES: PromptTemplate[] = [
  // ── Recon ────────────────────────────────────────────────────────────────────
  {
    id: "recon_subdomain_enum",
    phase: "recon",
    agent: "recon",
    name: "Subdomain Enumeration",
    description: "Enumerate subdomains for a given target domain using passive and active techniques",
    template: `Perform comprehensive subdomain enumeration for {{target}}.

Objective:
- Discover all subdomains associated with the target domain
- Identify DNS records, CNAME entries, and wildcard domains
- Classify subdomains by likely purpose (api, admin, dev, staging, etc.)

Tools to use:
- subfinder for passive enumeration
- amass for active DNS brute-forcing
- httpx for live subdomain verification

Scope: Only enumerate subdomains within the authorized target domain {{target}}. Do not interact with out-of-scope assets.

Return results as JSON with the following structure:
{
  "target": "{{target}}",
  "subdomains": [{"hostname": "", "ip": "", "status_code": 0, "title": "", "cname": "", "category": ""}],
  "wildcard_detected": false,
  "total_found": 0,
  "sources": []
}`,
    variables: ["target"],
    confidenceThreshold: 0.7,
    tags: ["recon", "subdomain", "dns", "enumeration", "passive", "active"],
  },
  {
    id: "recon_port_scan",
    phase: "recon",
    agent: "recon",
    name: "Port Scanning",
    description: "Perform port scanning on the target with configurable scan type approach",
    template: `Execute a port scan against {{target}} using a {{scan_type}} scanning approach.

Objective:
- Identify open, closed, and filtered ports on the target
- Determine service banners where possible
- Adapt scan speed and technique based on the {{scan_type}} approach (stealth, aggressive, or balanced)

Tools to use:
- nmap with appropriate flags for {{scan_type}} scanning
- masscan for initial fast discovery if aggressive mode selected

Scan type guidelines:
- stealth: SYN scan with rate limiting, randomized port order, decoy packets
- aggressive: Full connect scan, all 65535 ports, service version detection
- balanced: Top 1000 ports with SYN scan and moderate timing

Scope: Only scan the authorized target {{target}}. Respect rate limits and do not disrupt production services.

Return results as JSON:
{
  "target": "{{target}}",
  "scan_type": "{{scan_type}}",
  "open_ports": [{"port": 0, "protocol": "tcp", "state": "open", "service": "", "version": ""}],
  "filtered_ports": [],
  "scan_duration": "",
  "os_detection": ""
}`,
    variables: ["target", "scan_type"],
    confidenceThreshold: 0.7,
    tags: ["recon", "port-scan", "nmap", "network", "discovery"],
  },
  {
    id: "recon_service_detection",
    phase: "recon",
    agent: "recon",
    name: "Service Detection",
    description: "Detect and fingerprint services running on specified ports of a target",
    template: `Perform detailed service detection and fingerprinting on {{target}} for ports {{ports}}.

Objective:
- Identify exact service names and versions running on each port
- Detect underlying operating system indicators
- Identify potential misconfigurations or default installations
- Map services to known CVEs where version information is available

Tools to use:
- nmap with -sV flag for version detection
- whatweb for HTTP service fingerprinting
- sslscan for TLS/SSL service analysis

Scope: Only fingerprint services on {{target}}:{{ports}}. Do not attempt exploitation or brute-force during this phase.

Return results as JSON:
{
  "target": "{{target}}",
  "services": [{"port": 0, "service": "", "product": "", "version": "", "extra_info": "", "cpe": "", "known_cves": []}],
  "os_fingerprint": "",
  "technologies": [{"name": "", "version": "", "category": ""}],
  "notes": []
}`,
    variables: ["target", "ports"],
    confidenceThreshold: 0.7,
    tags: ["recon", "service-detection", "fingerprinting", "version-detection"],
  },
  {
    id: "recon_takeover_check",
    phase: "recon",
    agent: "recon",
    name: "Subdomain Takeover Check",
    description: "Check a list of subdomains for potential subdomain takeover vulnerabilities",
    template: `Analyze the following subdomains for subdomain takeover vulnerabilities: {{subdomains}}.

Objective:
- Check each subdomain for dangling DNS records (CNAME, A, AAAA)
- Identify unclaimed cloud resources (S3 buckets, Azure blobs, GitHub Pages, Heroku apps, etc.)
- Verify if the subdomain resolves to a deprovisioned or claimable service
- Assess exploitability of each finding

Tools to use:
- subjack or nuclei takeover templates for automated detection
- dig/nslookup for DNS record verification
- httpx for response fingerprinting

Scope: Only check the provided subdomains {{subdomains}}. Do not attempt to claim or register any discovered resources.

Return results as JSON:
{
  "subdomains_checked": [],
  "vulnerable": [{"subdomain": "", "cname": "", "service": "", "status": "vulnerable|potentially_vulnerable|not_vulnerable", "evidence": "", "takeover_type": ""}],
  "not_vulnerable": [],
  "total_checked": 0,
  "total_vulnerable": 0
}`,
    variables: ["subdomains"],
    confidenceThreshold: 0.7,
    tags: ["recon", "subdomain-takeover", "dns", "cloud", "dangling-cname"],
  },

  // ── Scanning ─────────────────────────────────────────────────────────────────
  {
    id: "scan_vuln_general",
    phase: "scanning",
    agent: "recon",
    name: "General Vulnerability Scan",
    description: "Perform a general vulnerability scan against the target using multiple scanning engines",
    template: `Conduct a comprehensive general vulnerability scan against {{target}}.

Objective:
- Scan for known CVEs and common vulnerabilities
- Check for misconfigurations, default credentials, and exposed sensitive files
- Identify OWASP Top 10 issues where applicable
- Prioritize findings by severity and exploitability

Tools to use:
- nuclei with community templates for broad coverage
- nikto for web server misconfiguration checks
- nmap NSE scripts for service-specific vulnerabilities

Scope: Scan only the authorized target {{target}}. Use non-destructive checks only. Do not attempt exploitation.

Return results as JSON:
{
  "target": "{{target}}",
  "vulnerabilities": [{"id": "", "name": "", "severity": "critical|high|medium|low|info", "cvss": 0.0, "cve": "", "description": "", "location": "", "evidence": "", "remediation": ""}],
  "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
  "scan_coverage": ""
}`,
    variables: ["target"],
    confidenceThreshold: 0.7,
    tags: ["scanning", "vulnerability", "nuclei", "nikto", "cve"],
  },
  {
    id: "scan_web_app",
    phase: "scanning",
    agent: "recon",
    name: "Web Application Scan",
    description: "Perform targeted web application vulnerability scanning focusing on specified vulnerability types",
    template: `Perform a targeted web application security scan on {{target}} focusing on {{vuln_types}} vulnerabilities.

Objective:
- Crawl and map the web application attack surface
- Test for the specified vulnerability types: {{vuln_types}}
- Identify input vectors, forms, and API endpoints
- Validate findings to reduce false positives

Tools to use:
- nuclei with web-specific templates
- dalfox for XSS-specific scanning
- sqlmap for SQLi detection (detection only, not exploitation)
- ffuf for parameter fuzzing

Scope: Only test the authorized web application at {{target}}. Focus specifically on {{vuln_types}}. Do not test for vulnerability types outside the specified scope.

Return results as JSON:
{
  "target": "{{target}}",
  "vuln_types_tested": "{{vuln_types}}",
  "findings": [{"type": "", "severity": "", "endpoint": "", "parameter": "", "payload": "", "evidence": "", "confirmed": false, "cvss": 0.0}],
  "endpoints_discovered": [],
  "forms_analyzed": 0,
  "coverage_percentage": 0
}`,
    variables: ["target", "vuln_types"],
    confidenceThreshold: 0.7,
    tags: ["scanning", "web-app", "owasp", "xss", "sqli", "application-security"],
  },
  {
    id: "scan_api_security",
    phase: "scanning",
    agent: "recon",
    name: "API Security Assessment",
    description: "Assess API endpoint security including authentication, authorization, and input validation",
    template: `Perform an API security assessment on {{api_endpoint}}.

Objective:
- Test authentication and authorization mechanisms
- Check for BOLA/IDOR vulnerabilities
- Assess rate limiting and throttling controls
- Test input validation and serialization issues
- Check for sensitive data exposure in responses
- Verify proper HTTP method restrictions

Tools to use:
- nuclei API-specific templates
- ffuf for parameter and path fuzzing
- jwt_tool for JWT analysis if applicable

Scope: Only test the authorized API at {{api_endpoint}}. Do not attempt to access other tenants' data or perform destructive operations.

Return results as JSON:
{
  "api_endpoint": "{{api_endpoint}}",
  "authentication": {"type": "", "issues": []},
  "authorization": {"idor_found": false, "privilege_escalation": false, "issues": []},
  "rate_limiting": {"present": false, "threshold": "", "bypassable": false},
  "input_validation": {"issues": []},
  "data_exposure": {"sensitive_fields": [], "pii_found": false},
  "findings": [{"type": "", "severity": "", "description": "", "endpoint": "", "evidence": ""}]
}`,
    variables: ["api_endpoint"],
    confidenceThreshold: 0.7,
    tags: ["scanning", "api", "rest", "authentication", "authorization", "idor"],
  },
  {
    id: "scan_config_audit",
    phase: "scanning",
    agent: "recon",
    name: "Configuration Audit",
    description: "Audit the configuration of a specific service on the target for security misconfigurations",
    template: `Perform a security configuration audit of {{service}} running on {{target}}.

Objective:
- Check for default credentials and configurations
- Identify insecure protocol versions and cipher suites
- Assess logging and monitoring configurations
- Verify access control settings and permissions
- Check for unnecessary features or modules enabled
- Compare against CIS benchmarks where applicable

Tools to use:
- Service-specific audit tools (sslscan, testssl.sh for TLS services)
- nmap NSE scripts for configuration checks

Scope: Only audit {{service}} on {{target}}. Read-only checks preferred. Do not modify any configurations.

Return results as JSON:
{
  "target": "{{target}}",
  "service": "{{service}}",
  "configuration_issues": [{"check": "", "status": "pass|fail|warning", "current_value": "", "recommended_value": "", "severity": "", "cis_ref": ""}],
  "default_creds_found": false,
  "tls_issues": [],
  "overall_score": 0,
  "recommendations": []
}`,
    variables: ["service", "target"],
    confidenceThreshold: 0.7,
    tags: ["scanning", "configuration", "audit", "hardening", "cis-benchmark"],
  },

  // ── Exploitation ─────────────────────────────────────────────────────────────
  {
    id: "exploit_sqli",
    phase: "exploitation",
    agent: "exploit",
    name: "SQL Injection Exploitation",
    description: "Exploit SQL injection vulnerability on a specified endpoint with database type context",
    template: `Exploit the SQL injection vulnerability on {{endpoint}} targeting a {{db_type}} database backend.

Objective:
- Confirm the SQL injection vulnerability with a proof-of-concept
- Determine injection type (union-based, blind, error-based, time-based)
- Extract database version, current user, and database name
- Document the full exploitation chain

Tools to use:
- sqlmap with appropriate {{db_type}} tamper scripts
- Manual payloads for validation

IMPORTANT: Only exploit within authorized scope. Do not exfiltrate actual sensitive data. Capture proof-of-concept evidence only.

Return results as JSON:
{
  "endpoint": "{{endpoint}}",
  "db_type": "{{db_type}}",
  "injection_type": "",
  "injectable_parameter": "",
  "poc_payload": "",
  "db_version": "",
  "current_user": "",
  "current_db": "",
  "tables_enumerated": [],
  "evidence": {"request": "", "response": ""},
  "impact": "",
  "cvss": 0.0
}`,
    variables: ["endpoint", "db_type"],
    confidenceThreshold: 0.9,
    tags: ["exploitation", "sqli", "sql-injection", "database", "injection"],
  },
  {
    id: "exploit_xss",
    phase: "exploitation",
    agent: "exploit",
    name: "XSS Exploitation",
    description: "Exploit cross-site scripting vulnerability on an endpoint with given injection context",
    template: `Exploit the XSS vulnerability on {{endpoint}} within the {{context}} context.

Objective:
- Confirm the XSS vulnerability with a harmless proof-of-concept payload
- Determine XSS type (reflected, stored, DOM-based)
- Identify the injection context (HTML body, attribute, JavaScript, URL)
- Craft a context-appropriate payload that bypasses any filters
- Demonstrate potential impact (cookie theft, session hijacking, etc.)

Tools to use:
- dalfox for automated payload testing
- Browser developer tools for DOM analysis
- Custom payload lists for filter bypass

IMPORTANT: Use only benign proof-of-concept payloads (alert, console.log). Do not execute malicious actions against real users.

Return results as JSON:
{
  "endpoint": "{{endpoint}}",
  "context": "{{context}}",
  "xss_type": "reflected|stored|dom",
  "injection_point": "",
  "payload": "",
  "filter_bypass": "",
  "browser_tested": "",
  "evidence": {"request": "", "response": "", "screenshot": ""},
  "impact": "",
  "cvss": 0.0
}`,
    variables: ["endpoint", "context"],
    confidenceThreshold: 0.9,
    tags: ["exploitation", "xss", "cross-site-scripting", "injection", "client-side"],
  },
  {
    id: "exploit_rce",
    phase: "exploitation",
    agent: "exploit",
    name: "Remote Code Execution",
    description: "Exploit remote code execution vulnerability on a target via a specified attack vector",
    template: `Exploit remote code execution on {{target}} via the {{vector}} attack vector.

Objective:
- Confirm code execution capability with a benign command (whoami, id, hostname)
- Determine execution context (user privileges, environment)
- Identify the vulnerability root cause
- Document the complete exploitation chain from entry to execution

Vector: {{vector}} (e.g., deserialization, template injection, command injection, file upload)

CRITICAL SAFETY: Only execute benign proof-of-concept commands. Do not deploy persistent backdoors, destroy data, or pivot without explicit authorization.

Return results as JSON:
{
  "target": "{{target}}",
  "vector": "{{vector}}",
  "vulnerability": "",
  "poc_command": "",
  "poc_output": "",
  "execution_context": {"user": "", "privileges": "", "os": "", "hostname": ""},
  "exploitation_chain": [],
  "impact": "",
  "cvss": 0.0
}`,
    variables: ["target", "vector"],
    confidenceThreshold: 0.9,
    tags: ["exploitation", "rce", "remote-code-execution", "critical"],
  },
  {
    id: "exploit_auth_bypass",
    phase: "exploitation",
    agent: "exploit",
    name: "Authentication Bypass",
    description: "Exploit authentication bypass on a target using a specified technique",
    template: `Attempt authentication bypass on {{target}} using the {{technique}} technique.

Objective:
- Test the specified authentication bypass technique against the target
- Verify if unauthorized access is achievable
- Document the authentication mechanism and its weaknesses
- Determine the level of access gained
- Identify all affected endpoints and resources

Technique: {{technique}} (e.g., JWT manipulation, parameter tampering, forced browsing, default credentials, session fixation, OAuth misconfiguration)

IMPORTANT: Only attempt bypass on authorized targets. Document all attempts for the audit trail.

Return results as JSON:
{
  "target": "{{target}}",
  "technique": "{{technique}}",
  "success": false,
  "auth_mechanism": "",
  "weakness": "",
  "access_level": "",
  "affected_endpoints": [],
  "poc_steps": [],
  "evidence": {"request": "", "response": ""},
  "impact": "",
  "cvss": 0.0
}`,
    variables: ["target", "technique"],
    confidenceThreshold: 0.9,
    tags: ["exploitation", "authentication", "bypass", "access-control"],
  },

  // ── Credential ───────────────────────────────────────────────────────────────
  {
    id: "cred_brute_force",
    phase: "credential",
    agent: "credential",
    name: "Brute Force Attack",
    description: "Perform brute force attack against a service with configurable rate limiting",
    template: `Execute a brute force attack against {{service}} on {{target}} with a rate limit of {{rate}} attempts per second.

Objective:
- Attempt credential guessing against the specified service
- Respect the configured rate limit of {{rate}} attempts/second to avoid lockouts
- Monitor for account lockout mechanisms
- Track successful and failed attempts
- Identify any anti-brute-force defenses

Tools to use:
- hydra for network service brute-forcing
- Custom scripts for web form brute-forcing

IMPORTANT: Respect the rate limit of {{rate}} attempts/second. Monitor for lockout indicators and pause if detected.

Return results as JSON:
{
  "target": "{{target}}",
  "service": "{{service}}",
  "rate_limit": "{{rate}}",
  "credentials_found": [{"username": "", "password": "", "success": true}],
  "attempts_made": 0,
  "lockouts_detected": 0,
  "duration": "",
  "defenses_observed": [],
  "wordlist_used": ""
}`,
    variables: ["service", "target", "rate"],
    confidenceThreshold: 0.85,
    tags: ["credential", "brute-force", "hydra", "password", "authentication"],
  },
  {
    id: "cred_pass_spray",
    phase: "credential",
    agent: "credential",
    name: "Password Spray",
    description: "Perform password spraying attack against multiple targets using a specified wordlist",
    template: `Execute a password spray attack against {{targets}} using the {{wordlist}} wordlist.

Objective:
- Spray a small set of common passwords across many accounts simultaneously
- Avoid account lockout by limiting attempts per account
- Identify accounts using weak or common passwords
- Monitor for lockout thresholds across the target environment

Tools to use:
- Custom scripts for web application spraying

IMPORTANT: Use a low-and-slow approach. Wait between spray rounds to avoid lockout policies. Only target authorized accounts.

Return results as JSON:
{
  "targets": "{{targets}}",
  "wordlist": "{{wordlist}}",
  "successful_logins": [{"target": "", "username": "", "password": ""}],
  "total_targets": 0,
  "total_passwords": 0,
  "attempts_per_account": 0,
  "lockouts_triggered": 0,
  "spray_rounds": 0,
  "duration": ""
}`,
    variables: ["targets", "wordlist"],
    confidenceThreshold: 0.85,
    tags: ["credential", "password-spray", "authentication"],
  },

  // ── Intelligence ─────────────────────────────────────────────────────────────
  {
    id: "intel_ioc_lookup",
    phase: "intelligence",
    agent: "intel",
    name: "IOC Lookup",
    description: "Look up indicators of compromise against threat intelligence sources",
    template: `Perform an IOC lookup for {{ioc_type}}: {{ioc_value}} against available threat intelligence sources.

Objective:
- Query multiple threat intelligence feeds and databases
- Determine if the IOC is known malicious, suspicious, or benign
- Gather context about associated campaigns, actors, and malware families
- Identify related IOCs for further investigation

Tools to use:
- VirusTotal API for file/URL/IP reputation
- AbuseIPDB for IP reputation
- Shodan for infrastructure intelligence

IOC Type: {{ioc_type}} (e.g., IP, domain, hash, URL)
IOC Value: {{ioc_value}}

Return results as JSON:
{
  "ioc_type": "{{ioc_type}}",
  "ioc_value": "{{ioc_value}}",
  "verdict": "malicious|suspicious|benign|unknown",
  "confidence": 0.0,
  "sources": [{"name": "", "verdict": "", "details": "", "last_seen": ""}],
  "associated_campaigns": [],
  "associated_malware": [],
  "related_iocs": [],
  "context": "",
  "recommendations": []
}`,
    variables: ["ioc_type", "ioc_value"],
    confidenceThreshold: 0.85,
    tags: ["intelligence", "ioc", "threat-intel", "reputation", "lookup"],
  },
  {
    id: "intel_threat_correlate",
    phase: "intelligence",
    agent: "intel",
    name: "Threat Intelligence Correlation",
    description: "Correlate engagement findings against known threat intelligence for a target",
    template: `Correlate all current findings against threat intelligence databases for {{target}}.

Objective:
- Cross-reference discovered vulnerabilities with known exploited vulnerabilities (KEV)
- Map findings to known threat actor TTPs
- Assess likelihood of active threats based on intelligence overlap
- Generate a threat-informed risk assessment

Tools to use:
- CISA KEV database for known exploited vulnerabilities
- MITRE ATT&CK for TTP mapping
- CVE databases for vulnerability intelligence

Return results as JSON:
{
  "target": "{{target}}",
  "correlations": [{"finding": "", "threat_match": "", "confidence": 0.0, "source": "", "threat_actor": ""}],
  "kev_matches": [],
  "active_threat_likelihood": "high|medium|low",
  "threat_actors_relevant": [],
  "risk_assessment": "",
  "priority_actions": []
}`,
    variables: ["target"],
    confidenceThreshold: 0.85,
    tags: ["intelligence", "correlation", "threat-intel", "kev", "risk-assessment"],
  },

  // ── Reporting ────────────────────────────────────────────────────────────────
  {
    id: "report_executive",
    phase: "reporting",
    agent: "report",
    name: "Executive Summary Report",
    description: "Generate an executive summary report for a penetration testing engagement",
    template: `Generate an executive summary report for the engagement "{{engagement_name}}" targeting {{target}}.

Objective:
- Provide a high-level overview of the engagement scope, objectives, and timeline
- Summarize key findings in business-impact terms
- Highlight critical and high-severity issues requiring immediate attention
- Provide an overall risk rating with supporting rationale
- Include strategic recommendations for security improvement
- Keep language accessible for non-technical stakeholders

Return results as JSON:
{
  "engagement_name": "{{engagement_name}}",
  "target": "{{target}}",
  "executive_summary": "",
  "scope": "",
  "timeline": {"start": "", "end": ""},
  "overall_risk_rating": "critical|high|medium|low",
  "key_findings": [{"title": "", "business_impact": "", "severity": "", "recommendation": ""}],
  "statistics": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
  "strategic_recommendations": [],
  "positive_observations": []
}`,
    variables: ["engagement_name", "target"],
    confidenceThreshold: 0.5,
    tags: ["reporting", "executive", "summary", "management", "risk"],
  },
  {
    id: "report_technical",
    phase: "reporting",
    agent: "report",
    name: "Technical Findings Report",
    description: "Generate a detailed technical findings report with all discovered vulnerabilities",
    template: `Generate a detailed technical findings report containing {{findings_count}} findings.

Objective:
- Document each vulnerability with full technical detail
- Include reproduction steps for each finding
- Provide evidence (requests, responses) for each finding
- Assign CVSS scores and severity ratings
- Include specific technical remediation guidance
- Reference relevant CVEs and CWEs

Return results as JSON:
{
  "report_title": "",
  "findings_count": {{findings_count}},
  "findings": [{
    "id": "",
    "title": "",
    "severity": "critical|high|medium|low|info",
    "cvss_score": 0.0,
    "cvss_vector": "",
    "cwe": "",
    "cve": "",
    "description": "",
    "affected_component": "",
    "reproduction_steps": [],
    "evidence": {"request": "", "response": ""},
    "impact": "",
    "remediation": "",
    "references": []
  }],
  "methodology": "",
  "tools_used": []
}`,
    variables: ["findings_count"],
    confidenceThreshold: 0.5,
    tags: ["reporting", "technical", "findings", "vulnerability", "detailed"],
  },
  {
    id: "report_remediation",
    phase: "reporting",
    agent: "report",
    name: "Remediation Roadmap",
    description: "Generate a prioritized remediation roadmap based on finding severity distribution",
    template: `Generate a remediation roadmap for {{severity_counts}} findings.

Objective:
- Prioritize remediation efforts by severity and business impact
- Create a phased remediation plan (immediate, short-term, long-term)
- Estimate remediation effort and resources needed
- Identify quick wins and dependencies between fixes
- Provide specific, actionable remediation steps
- Include verification criteria for each remediation

Severity Counts: {{severity_counts}} (e.g., 2 critical, 5 high, 10 medium, 8 low)

Return results as JSON:
{
  "severity_counts": "{{severity_counts}}",
  "total_findings": 0,
  "phases": [{
    "phase": "immediate|short_term|long_term",
    "timeline": "",
    "findings": [{"id": "", "title": "", "severity": "", "remediation": "", "effort": "low|medium|high", "verification": ""}]
  }],
  "quick_wins": [],
  "dependencies": [],
  "estimated_total_effort": "",
  "resource_requirements": [],
  "risk_acceptance_candidates": []
}`,
    variables: ["severity_counts"],
    confidenceThreshold: 0.5,
    tags: ["reporting", "remediation", "roadmap", "prioritization", "planning"],
  },
  {
    id: "report_cvss",
    phase: "reporting",
    agent: "report",
    name: "CVSS Scoring",
    description: "Calculate and justify CVSS score for a vulnerability affecting a specific component",
    template: `Calculate the CVSS 3.1 score for {{vulnerability}} affecting {{component}}.

Objective:
- Evaluate each CVSS 3.1 base metric for the vulnerability
- Provide justification for each metric selection
- Calculate the final base score
- Provide context for the severity rating

Return results as JSON:
{
  "vulnerability": "{{vulnerability}}",
  "component": "{{component}}",
  "cvss_version": "3.1",
  "base_score": 0.0,
  "severity": "critical|high|medium|low|none",
  "vector_string": "",
  "metrics": {
    "attack_vector": {"value": "", "justification": ""},
    "attack_complexity": {"value": "", "justification": ""},
    "privileges_required": {"value": "", "justification": ""},
    "user_interaction": {"value": "", "justification": ""},
    "scope": {"value": "", "justification": ""},
    "confidentiality": {"value": "", "justification": ""},
    "integrity": {"value": "", "justification": ""},
    "availability": {"value": "", "justification": ""}
  },
  "context": ""
}`,
    variables: ["vulnerability", "component"],
    confidenceThreshold: 0.5,
    tags: ["reporting", "cvss", "scoring", "severity", "risk-assessment"],
  },

  // ── Smart Orchestration ──────────────────────────────────────────────────────
  {
    id: "smart_tool_chain",
    phase: "smart",
    agent: "smart",
    name: "Tool Chain Recommendation",
    description: "Recommend an optimal tool chain based on engagement goals and current findings",
    template: `Recommend an optimal tool chain for achieving {{goal}} given the current findings: {{current_findings}}.

Objective:
- Analyze the current engagement state and findings
- Identify the most effective tools for the next steps
- Create an ordered tool execution chain with dependencies
- Configure each tool with optimal parameters
- Identify parallel execution opportunities

Tools available:
- Recon: subfinder, amass, httpx, nmap, masscan, whatweb
- Scanning: nuclei, nikto, sqlmap, dalfox, ffuf, gobuster
- Exploitation: nuclei, burp, custom scripts
- Credential: hydra

Return results as JSON:
{
  "goal": "{{goal}}",
  "current_findings": "{{current_findings}}",
  "recommended_chain": [{
    "order": 0,
    "tool": "",
    "purpose": "",
    "command": "",
    "parameters": {},
    "depends_on": [],
    "estimated_duration": "",
    "parallel_group": 0
  }],
  "rationale": "",
  "alternative_chains": [],
  "total_estimated_time": "",
  "success_probability": 0.0
}`,
    variables: ["goal", "current_findings"],
    confidenceThreshold: 0.7,
    tags: ["smart", "tool-chain", "automation", "orchestration", "recommendation"],
  },
  {
    id: "smart_phase_switch",
    phase: "smart",
    agent: "smart",
    name: "Phase Transition Evaluator",
    description: "Evaluate whether to transition to a new engagement phase based on current progress",
    template: `Evaluate whether a phase transition from {{current_phase}} is warranted based on the current progress: {{progress}}.

Objective:
- Assess completeness of the current phase
- Determine if phase objectives have been met
- Identify any remaining tasks in the current phase
- Evaluate readiness for the next logical phase
- Provide a recommendation with supporting rationale

Phase progression: recon → scanning → exploitation → credential → reporting
(intelligence can run in parallel at any stage)

Return results as JSON:
{
  "current_phase": "{{current_phase}}",
  "progress": "{{progress}}",
  "phase_completion": 0.0,
  "objectives_met": [],
  "objectives_remaining": [],
  "transition_recommended": false,
  "recommended_next_phase": "",
  "rationale": "",
  "remaining_tasks": [],
  "risk_of_early_transition": "high|medium|low",
  "confidence": 0.0
}`,
    variables: ["current_phase", "progress"],
    confidenceThreshold: 0.7,
    tags: ["smart", "phase-transition", "workflow", "decision", "orchestration"],
  },
];

// ─── Vuln-class → template mapping ───────────────────────────────────────────

const VULN_CLASS_MAP: Record<string, string[]> = {
  sqli:               ["exploit_sqli", "scan_web_app"],
  xss:                ["exploit_xss", "scan_web_app"],
  rce:                ["exploit_rce", "scan_vuln_general"],
  ssrf:               ["scan_api_security", "scan_web_app"],
  auth_bypass:        ["exploit_auth_bypass", "scan_api_security"],
  idor:               ["scan_api_security"],
  lfi:                ["scan_vuln_general"],
  misconfig:          ["scan_config_audit"],
  exposed_admin:      ["scan_config_audit", "cred_brute_force"],
  subdomain_takeover: ["recon_takeover_check"],
  tech_stack:         ["recon_service_detection"],
  hidden_endpoints:   ["scan_web_app"],
  open_redirect:      ["scan_web_app"],
  cors:               ["scan_api_security"],
  info_disclosure:    ["scan_config_audit"],
  security_headers:   ["scan_config_audit"],
  business_logic:     ["scan_api_security", "scan_web_app"],
  rate_limit_bypass:  ["scan_api_security"],
};

// ─── Singleton ────────────────────────────────────────────────────────────────

export class PromptKnowledgeBase {
  private static instance: PromptKnowledgeBase;
  private readonly byId: Map<string, PromptTemplate>;
  private readonly byPhase: Map<string, PromptTemplate[]>;
  private readonly byAgent: Map<string, PromptTemplate[]>;

  private constructor() {
    this.byId = new Map(PROMPT_TEMPLATES.map(t => [t.id, t]));

    this.byPhase = new Map();
    this.byAgent = new Map();
    for (const t of PROMPT_TEMPLATES) {
      if (!this.byPhase.has(t.phase)) this.byPhase.set(t.phase, []);
      if (!this.byAgent.has(t.agent)) this.byAgent.set(t.agent, []);
      this.byPhase.get(t.phase)!.push(t);
      this.byAgent.get(t.agent)!.push(t);
    }
  }

  static getInstance(): PromptKnowledgeBase {
    if (!PromptKnowledgeBase.instance) {
      PromptKnowledgeBase.instance = new PromptKnowledgeBase();
    }
    return PromptKnowledgeBase.instance;
  }

  getTemplate(id: string): PromptTemplate | undefined {
    return this.byId.get(id);
  }

  getByPhase(phase: string): PromptTemplate[] {
    return this.byPhase.get(phase) || [];
  }

  getByAgent(agent: string): PromptTemplate[] {
    return this.byAgent.get(agent) || [];
  }

  getForVulnClass(vulnClass: string): PromptTemplate[] {
    const ids = VULN_CLASS_MAP[vulnClass] || ["scan_vuln_general"];
    return ids.map(id => this.byId.get(id)).filter(Boolean) as PromptTemplate[];
  }

  render(id: string, variables: Record<string, string>): string {
    const tmpl = this.byId.get(id);
    if (!tmpl) throw new Error(`Unknown prompt template: ${id}`);
    return tmpl.template.replace(/\{\{(\w+)\}\}/g, (_, key) => variables[key] ?? `{{${key}}}`);
  }

  get totalTemplates(): number {
    return PROMPT_TEMPLATES.length;
  }
}

export const promptKB = PromptKnowledgeBase.getInstance();
export default promptKB;

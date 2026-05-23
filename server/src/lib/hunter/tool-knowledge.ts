/**
 * Tool Knowledge System
 * Structured profiles for 39 security tools and 10 chain pipelines.
 * Provides AI-injectable context blocks for intelligent tool selection.
 */

export interface ToolProfile {
  name: string;
  category: "recon" | "scanning" | "exploitation" | "credential" | "fuzzing" | "web" | "network" | "reporting";
  description: string;
  capabilities: string[];
  vulnClasses: string[];
  commandTemplate: string;
  riskLevel: "low" | "medium" | "high";
  stealthRating: number; // 1–10, higher = stealthier
  requiredBinaries: string[];
  tags: string[];
}

export interface PipelinePhase {
  tool: string;
  purpose: string;
  dependsOn?: string[];
}

export interface ToolChainPipeline {
  id: string;
  name: string;
  description: string;
  phases: PipelinePhase[];
  targetVulnClasses: string[];
  estimatedTime: string;
}

// ── 39 Tool Profiles ──────────────────────────────────────────────────────────

export const TOOL_PROFILES: ToolProfile[] = [
  // ── Recon (8) ──────────────────────────────────────────────────────────────
  {
    name: "nmap",
    category: "recon",
    description: "Network port scanner and service fingerprinter",
    capabilities: ["port scanning", "service detection", "OS detection", "script scanning"],
    vulnClasses: ["open_ports", "service_enumeration", "os_detection", "misconfig"],
    commandTemplate: "nmap -sV -sC -p 80,443,8080,8443 {{target}}",
    riskLevel: "medium",
    stealthRating: 4,
    requiredBinaries: ["nmap"],
    tags: ["recon", "network", "fingerprint"],
  },
  {
    name: "masscan",
    category: "recon",
    description: "Ultra-fast port scanner for wide-area scanning",
    capabilities: ["fast port scanning", "banner grabbing"],
    vulnClasses: ["open_ports", "service_enumeration"],
    commandTemplate: "masscan {{target}} -p 80,443,8080,8443,8000-9000 --rate=1000",
    riskLevel: "high",
    stealthRating: 2,
    requiredBinaries: ["masscan"],
    tags: ["recon", "network", "fast"],
  },
  {
    name: "subfinder",
    category: "recon",
    description: "Subdomain discovery via passive sources",
    capabilities: ["subdomain enumeration", "DNS resolution"],
    vulnClasses: ["subdomain_takeover", "exposed_panels", "hidden_endpoints"],
    commandTemplate: "subfinder -d {{target}} -silent -o /tmp/subdomains.txt",
    riskLevel: "low",
    stealthRating: 9,
    requiredBinaries: ["subfinder"],
    tags: ["recon", "dns", "passive"],
  },
  {
    name: "amass",
    category: "recon",
    description: "In-depth subdomain enumeration with ASN mapping",
    capabilities: ["subdomain enumeration", "ASN mapping", "certificate transparency"],
    vulnClasses: ["subdomain_takeover", "exposed_panels"],
    commandTemplate: "amass enum -passive -d {{target}} -o /tmp/amass.txt",
    riskLevel: "low",
    stealthRating: 8,
    requiredBinaries: ["amass"],
    tags: ["recon", "dns", "passive", "certificate-transparency"],
  },
  {
    name: "dnsx",
    category: "recon",
    description: "Fast DNS resolver and zone-walk helper",
    capabilities: ["DNS resolution", "DNS record enumeration", "wildcard detection"],
    vulnClasses: ["subdomain_takeover", "dns_misconfiguration"],
    commandTemplate: "dnsx -l /tmp/subdomains.txt -a -cname -resp-only",
    riskLevel: "low",
    stealthRating: 9,
    requiredBinaries: ["dnsx"],
    tags: ["recon", "dns"],
  },
  {
    name: "httpx",
    category: "recon",
    description: "Fast HTTP probing and technology detection",
    capabilities: ["HTTP probing", "title extraction", "status code detection", "tech fingerprinting"],
    vulnClasses: ["exposed_panels", "security_headers", "tech_stack"],
    commandTemplate: "httpx -l /tmp/subdomains.txt -title -tech-detect -status-code -json",
    riskLevel: "low",
    stealthRating: 8,
    requiredBinaries: ["httpx"],
    tags: ["recon", "http", "fingerprint"],
  },
  {
    name: "whatweb",
    category: "recon",
    description: "Web technology fingerprinter — CMS, frameworks, libraries",
    capabilities: ["CMS detection", "framework detection", "version fingerprinting"],
    vulnClasses: ["tech_stack", "cms_detection", "framework_detection"],
    commandTemplate: "whatweb --no-errors --aggression=3 --log-json=- {{target}}",
    riskLevel: "low",
    stealthRating: 7,
    requiredBinaries: ["whatweb"],
    tags: ["recon", "fingerprint", "cms"],
  },
  {
    name: "shodan-cli",
    category: "recon",
    description: "Shodan CLI for passive internet-wide recon",
    capabilities: ["passive host info", "open port history", "vulnerability data"],
    vulnClasses: ["open_ports", "misconfig", "exposed_panels"],
    commandTemplate: "shodan host {{target}}",
    riskLevel: "low",
    stealthRating: 10,
    requiredBinaries: ["shodan"],
    tags: ["recon", "passive", "osint"],
  },

  // ── Scanning (8) ───────────────────────────────────────────────────────────
  {
    name: "nuclei",
    category: "scanning",
    description: "Template-based vulnerability scanner with 5000+ templates",
    capabilities: ["CVE detection", "misconfiguration detection", "exposed panel detection", "XSS/SQLi probing"],
    vulnClasses: ["xss", "sqli", "ssrf", "rce", "lfi", "idor", "exposed_panels", "misconfig", "auth_bypass"],
    commandTemplate: "nuclei -u {{target}} -severity medium,high,critical -json -silent",
    riskLevel: "medium",
    stealthRating: 6,
    requiredBinaries: ["nuclei"],
    tags: ["scanning", "templates", "cve"],
  },
  {
    name: "nikto",
    category: "scanning",
    description: "Web server vulnerability scanner — outdated software and dangerous files",
    capabilities: ["outdated software detection", "dangerous file enumeration", "misconfig detection"],
    vulnClasses: ["misconfig", "outdated_software", "dangerous_files", "security_headers"],
    commandTemplate: "nikto -h {{target}} -Format json -timeout 10 -maxtime 60",
    riskLevel: "medium",
    stealthRating: 3,
    requiredBinaries: ["nikto"],
    tags: ["scanning", "misconfig"],
  },
  {
    name: "wapiti",
    category: "scanning",
    description: "Black-box web application vulnerability scanner",
    capabilities: ["SQL injection", "XSS", "SSRF", "file disclosure", "CRLF injection"],
    vulnClasses: ["xss", "sqli", "ssrf", "lfi", "info_disclosure"],
    commandTemplate: "wapiti -u {{target}} -f json -o /tmp/wapiti_report.json --flush-session",
    riskLevel: "medium",
    stealthRating: 4,
    requiredBinaries: ["wapiti"],
    tags: ["scanning", "web-app"],
  },
  {
    name: "zap-baseline",
    category: "scanning",
    description: "OWASP ZAP passive baseline scan for common issues",
    capabilities: ["passive vulnerability detection", "security header analysis", "information disclosure"],
    vulnClasses: ["security_headers", "info_disclosure", "misconfig", "xss"],
    commandTemplate: "zap-baseline.py -t {{target}} -J /tmp/zap_baseline.json -I",
    riskLevel: "low",
    stealthRating: 7,
    requiredBinaries: ["zap-baseline.py"],
    tags: ["scanning", "owasp", "passive"],
  },
  {
    name: "feroxbuster",
    category: "scanning",
    description: "Fast recursive content discovery tool",
    capabilities: ["directory brute-forcing", "file discovery", "recursive scanning"],
    vulnClasses: ["hidden_endpoints", "backup_files", "exposed_configs", "admin_panels"],
    commandTemplate: "feroxbuster -u {{target}} -w /usr/share/wordlists/dirb/common.txt -n -q --json",
    riskLevel: "medium",
    stealthRating: 5,
    requiredBinaries: ["feroxbuster"],
    tags: ["scanning", "directory", "bruteforce"],
  },
  {
    name: "ffuf",
    category: "scanning",
    description: "Fast web fuzzer for directory, parameter, and vhost discovery",
    capabilities: ["directory fuzzing", "parameter fuzzing", "vhost discovery"],
    vulnClasses: ["hidden_endpoints", "backup_files", "admin_panels", "parameter_pollution"],
    commandTemplate: "ffuf -u {{target}}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -json",
    riskLevel: "medium",
    stealthRating: 5,
    requiredBinaries: ["ffuf"],
    tags: ["scanning", "fuzzing", "directory"],
  },
  {
    name: "gobuster",
    category: "scanning",
    description: "Directory and DNS enumeration tool",
    capabilities: ["directory brute-forcing", "DNS subdomain enumeration", "vhost brute-forcing"],
    vulnClasses: ["hidden_endpoints", "backup_files", "exposed_configs"],
    commandTemplate: "gobuster dir -u {{target}} -w /usr/share/wordlists/dirb/common.txt -q --no-error",
    riskLevel: "medium",
    stealthRating: 5,
    requiredBinaries: ["gobuster"],
    tags: ["scanning", "directory"],
  },
  {
    name: "dirb",
    category: "scanning",
    description: "Classic web content scanner using dictionary-based attacks",
    capabilities: ["directory scanning", "file discovery"],
    vulnClasses: ["hidden_endpoints", "backup_files"],
    commandTemplate: "dirb {{target}} /usr/share/dirb/wordlists/common.txt -o /tmp/dirb.txt",
    riskLevel: "medium",
    stealthRating: 4,
    requiredBinaries: ["dirb"],
    tags: ["scanning", "directory", "classic"],
  },

  // ── Exploitation (7) ───────────────────────────────────────────────────────
  {
    name: "sqlmap",
    category: "exploitation",
    description: "Automated SQL injection detection and exploitation",
    capabilities: ["SQL injection detection", "database dumping", "OS shell"],
    vulnClasses: ["sqli", "blind_sqli", "time_based_sqli", "error_based_sqli"],
    commandTemplate: "sqlmap -u {{target}} --batch --level=2 --risk=2 --timeout=10 --forms",
    riskLevel: "high",
    stealthRating: 3,
    requiredBinaries: ["sqlmap"],
    tags: ["exploitation", "sql", "database"],
  },
  {
    name: "commix",
    category: "exploitation",
    description: "Automated command injection exploiter",
    capabilities: ["command injection detection", "OS command execution"],
    vulnClasses: ["rce", "command_injection"],
    commandTemplate: "commix --url={{target}} --batch --output-dir=/tmp/commix",
    riskLevel: "high",
    stealthRating: 3,
    requiredBinaries: ["commix"],
    tags: ["exploitation", "rce", "command-injection"],
  },
  {
    name: "xsstrike",
    category: "exploitation",
    description: "Advanced XSS scanner with mutation engine",
    capabilities: ["XSS detection", "DOM XSS", "blind XSS", "payload mutation"],
    vulnClasses: ["xss", "dom_xss", "stored_xss"],
    commandTemplate: "xsstrike --url={{target}} --crawl --blind --json",
    riskLevel: "medium",
    stealthRating: 5,
    requiredBinaries: ["python3"],
    tags: ["exploitation", "xss"],
  },
  {
    name: "dalfox",
    category: "exploitation",
    description: "Parameter analysis and XSS scanner",
    capabilities: ["XSS scanning", "parameter analysis", "header injection"],
    vulnClasses: ["xss", "header_injection"],
    commandTemplate: "dalfox url {{target}} --silence --json --output /tmp/dalfox.json",
    riskLevel: "medium",
    stealthRating: 6,
    requiredBinaries: ["dalfox"],
    tags: ["exploitation", "xss", "parameter"],
  },
  {
    name: "tplmap",
    category: "exploitation",
    description: "Server-side template injection detection and exploitation",
    capabilities: ["SSTI detection", "template engine identification", "code execution"],
    vulnClasses: ["ssti", "rce"],
    commandTemplate: "tplmap.py -u {{target}} --level 5",
    riskLevel: "high",
    stealthRating: 4,
    requiredBinaries: ["python3"],
    tags: ["exploitation", "ssti", "rce"],
  },
  {
    name: "ssrfmap",
    category: "exploitation",
    description: "SSRF detection and exploitation tool",
    capabilities: ["SSRF detection", "internal network probing", "cloud metadata access"],
    vulnClasses: ["ssrf", "cloud_metadata"],
    commandTemplate: "ssrfmap.py -r /tmp/request.txt -p url --level 3",
    riskLevel: "high",
    stealthRating: 5,
    requiredBinaries: ["python3"],
    tags: ["exploitation", "ssrf", "cloud"],
  },
  {
    name: "arjun",
    category: "exploitation",
    description: "HTTP parameter discovery tool",
    capabilities: ["parameter discovery", "hidden parameter detection"],
    vulnClasses: ["parameter_pollution", "hidden_endpoints", "sqli", "xss"],
    commandTemplate: "arjun -u {{target}} --json -o /tmp/arjun_params.json",
    riskLevel: "low",
    stealthRating: 7,
    requiredBinaries: ["arjun"],
    tags: ["exploitation", "parameter", "discovery"],
  },

  // ── Web (5) ────────────────────────────────────────────────────────────────
  {
    name: "burpsuite-cli",
    category: "web",
    description: "Burp Suite CLI for HTTP interception and scanning",
    capabilities: ["HTTP interception", "active scanning", "passive scanning"],
    vulnClasses: ["xss", "sqli", "ssrf", "idor", "auth_bypass", "business_logic"],
    commandTemplate: "java -jar burpsuite_pro.jar --project-file=/tmp/burp.burp --config-file=/tmp/burp_config.json",
    riskLevel: "medium",
    stealthRating: 6,
    requiredBinaries: ["java"],
    tags: ["web", "proxy", "scanner"],
  },
  {
    name: "wfuzz",
    category: "web",
    description: "Web application fuzzer with filter capabilities",
    capabilities: ["directory fuzzing", "parameter fuzzing", "authentication bypass"],
    vulnClasses: ["hidden_endpoints", "auth_bypass", "sqli", "xss"],
    commandTemplate: "wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 {{target}}/FUZZ",
    riskLevel: "medium",
    stealthRating: 5,
    requiredBinaries: ["wfuzz"],
    tags: ["web", "fuzzing"],
  },
  {
    name: "jwt-tool",
    category: "web",
    description: "JWT analysis and exploitation toolkit",
    capabilities: ["JWT decoding", "algorithm confusion", "key injection", "claim tampering"],
    vulnClasses: ["auth_bypass", "jwt_weakness", "privilege_escalation"],
    commandTemplate: "python3 jwt_tool.py {{target}} -t {{target}} -M at -cv",
    riskLevel: "medium",
    stealthRating: 7,
    requiredBinaries: ["python3"],
    tags: ["web", "jwt", "auth"],
  },
  {
    name: "cors-scanner",
    category: "web",
    description: "CORS misconfiguration detection tool",
    capabilities: ["CORS policy analysis", "origin reflection detection", "credential exposure"],
    vulnClasses: ["cors", "info_disclosure"],
    commandTemplate: "python3 cors_scan.py -u {{target}} -v",
    riskLevel: "low",
    stealthRating: 8,
    requiredBinaries: ["python3"],
    tags: ["web", "cors"],
  },
  {
    name: "smuggler",
    category: "web",
    description: "HTTP request smuggling detection tool",
    capabilities: ["CL.TE detection", "TE.CL detection", "TE.TE detection"],
    vulnClasses: ["http_smuggling", "cache_poisoning"],
    commandTemplate: "python3 smuggler.py -u {{target}} --log-level WARNING",
    riskLevel: "medium",
    stealthRating: 7,
    requiredBinaries: ["python3"],
    tags: ["web", "smuggling", "http"],
  },

  // ── Network (4) ────────────────────────────────────────────────────────────
  {
    name: "ncrack",
    category: "network",
    description: "High-speed network authentication cracker",
    capabilities: ["SSH brute-force", "FTP brute-force", "RDP brute-force"],
    vulnClasses: ["weak_credentials", "auth_bypass"],
    commandTemplate: "ncrack -U /tmp/users.txt -P /tmp/passwords.txt {{target}}:22",
    riskLevel: "high",
    stealthRating: 2,
    requiredBinaries: ["ncrack"],
    tags: ["network", "credential", "bruteforce"],
  },
  {
    name: "hydra",
    category: "network",
    description: "Network login cracker supporting 50+ protocols",
    capabilities: ["HTTP form brute-force", "FTP/SSH/RDP brute-force", "credential stuffing"],
    vulnClasses: ["weak_credentials", "auth_bypass", "account_takeover"],
    commandTemplate: "hydra -L /tmp/users.txt -P /tmp/passwords.txt {{target}} http-post-form",
    riskLevel: "high",
    stealthRating: 2,
    requiredBinaries: ["hydra"],
    tags: ["network", "credential", "bruteforce"],
  },
  {
    name: "medusa",
    category: "network",
    description: "Parallel network login auditor",
    capabilities: ["parallel credential testing", "multiple protocol support"],
    vulnClasses: ["weak_credentials", "auth_bypass"],
    commandTemplate: "medusa -h {{target}} -u admin -P /tmp/passwords.txt -M http",
    riskLevel: "high",
    stealthRating: 2,
    requiredBinaries: ["medusa"],
    tags: ["network", "credential"],
  },
  {
    name: "netcat",
    category: "network",
    description: "TCP/UDP utility for banner grabbing and port testing",
    capabilities: ["banner grabbing", "port connectivity testing", "data transfer"],
    vulnClasses: ["service_enumeration", "info_disclosure"],
    commandTemplate: "nc -v -w 3 {{target}} 80",
    riskLevel: "low",
    stealthRating: 8,
    requiredBinaries: ["nc"],
    tags: ["network", "utility"],
  },

  // ── Credential (3) ─────────────────────────────────────────────────────────
  {
    name: "hashcat",
    category: "credential",
    description: "GPU-accelerated password recovery tool",
    capabilities: ["hash cracking", "rule-based attacks", "mask attacks"],
    vulnClasses: ["weak_credentials", "password_reuse"],
    commandTemplate: "hashcat -m 0 /tmp/hashes.txt /usr/share/wordlists/rockyou.txt",
    riskLevel: "low",
    stealthRating: 10,
    requiredBinaries: ["hashcat"],
    tags: ["credential", "hash", "offline"],
  },
  {
    name: "john",
    category: "credential",
    description: "John the Ripper — password cracker for various hash formats",
    capabilities: ["hash cracking", "format auto-detection", "wordlist attacks"],
    vulnClasses: ["weak_credentials"],
    commandTemplate: "john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes.txt",
    riskLevel: "low",
    stealthRating: 10,
    requiredBinaries: ["john"],
    tags: ["credential", "hash", "offline"],
  },
  {
    name: "crunch",
    category: "credential",
    description: "Wordlist generator based on character sets and patterns",
    capabilities: ["custom wordlist generation", "pattern-based generation"],
    vulnClasses: ["weak_credentials"],
    commandTemplate: "crunch 8 12 abcdefghijklmnopqrstuvwxyz0123456789 -o /tmp/wordlist.txt",
    riskLevel: "low",
    stealthRating: 10,
    requiredBinaries: ["crunch"],
    tags: ["credential", "wordlist", "generation"],
  },

  // ── Fuzzing (2) ────────────────────────────────────────────────────────────
  {
    name: "radamsa",
    category: "fuzzing",
    description: "General-purpose data mutation fuzzer",
    capabilities: ["input mutation", "protocol fuzzing", "edge case generation"],
    vulnClasses: ["rce", "memory_corruption", "parsing_bugs"],
    commandTemplate: "echo '{{input}}' | radamsa",
    riskLevel: "medium",
    stealthRating: 7,
    requiredBinaries: ["radamsa"],
    tags: ["fuzzing", "mutation"],
  },
  {
    name: "boofuzz",
    category: "fuzzing",
    description: "Protocol fuzzer framework for network services",
    capabilities: ["protocol fuzzing", "session handling", "crash detection"],
    vulnClasses: ["rce", "dos", "parsing_bugs"],
    commandTemplate: "python3 boofuzz_session.py --target={{target}} --port=80",
    riskLevel: "high",
    stealthRating: 3,
    requiredBinaries: ["python3"],
    tags: ["fuzzing", "protocol", "network"],
  },

  // ── Reporting (2) ──────────────────────────────────────────────────────────
  {
    name: "metabigor",
    category: "reporting",
    description: "Passive recon aggregator — IPs, ASNs, company footprint",
    capabilities: ["passive IP enumeration", "ASN lookup", "company footprint"],
    vulnClasses: ["exposed_panels", "subdomain_takeover"],
    commandTemplate: "echo '{{target}}' | metabigor company --json",
    riskLevel: "low",
    stealthRating: 10,
    requiredBinaries: ["metabigor"],
    tags: ["reporting", "passive", "osint"],
  },
  {
    name: "reconftw",
    category: "reporting",
    description: "Automated recon framework orchestrating 35+ tools",
    capabilities: ["full recon automation", "subdomain + web + vuln scan", "report generation"],
    vulnClasses: ["open_ports", "subdomain_takeover", "exposed_panels", "misconfig"],
    commandTemplate: "reconftw.sh -d {{target}} -a -o /tmp/reconftw/",
    riskLevel: "medium",
    stealthRating: 4,
    requiredBinaries: ["reconftw.sh"],
    tags: ["reporting", "automation", "recon"],
  },
];

// ── 10 Chain Pipelines ────────────────────────────────────────────────────────

export const TOOL_CHAIN_PIPELINES: ToolChainPipeline[] = [
  {
    id: "full_recon",
    name: "Full Recon",
    description: "Comprehensive target reconnaissance from passive to active",
    phases: [
      { tool: "subfinder", purpose: "Enumerate subdomains passively" },
      { tool: "dnsx", purpose: "Resolve and validate subdomains", dependsOn: ["subfinder"] },
      { tool: "httpx", purpose: "Probe live hosts and fingerprint technologies", dependsOn: ["dnsx"] },
      { tool: "nmap", purpose: "Port scan live hosts", dependsOn: ["dnsx"] },
      { tool: "whatweb", purpose: "Deep technology fingerprinting", dependsOn: ["httpx"] },
    ],
    targetVulnClasses: ["open_ports", "subdomain_takeover", "exposed_panels", "tech_stack"],
    estimatedTime: "30-60 min",
  },
  {
    id: "api_vuln_scan",
    name: "API Vulnerability Scan",
    description: "API-focused scanning for auth, injection, and business logic",
    phases: [
      { tool: "arjun", purpose: "Discover API parameters and hidden endpoints" },
      { tool: "nuclei", purpose: "Template-based API vulnerability checks", dependsOn: ["arjun"] },
      { tool: "jwt-tool", purpose: "Test JWT authentication weaknesses", dependsOn: ["arjun"] },
      { tool: "ffuf", purpose: "Fuzz API endpoints for hidden routes" },
    ],
    targetVulnClasses: ["idor", "auth_bypass", "jwt_weakness", "sqli", "ssrf"],
    estimatedTime: "20-40 min",
  },
  {
    id: "deep_sqli",
    name: "Deep SQL Injection Hunt",
    description: "Thorough SQL injection discovery and exploitation",
    phases: [
      { tool: "arjun", purpose: "Discover all injectable parameters" },
      { tool: "sqlmap", purpose: "Test discovered parameters for SQL injection", dependsOn: ["arjun"] },
      { tool: "nuclei", purpose: "Template-based SQLi validation", dependsOn: ["arjun"] },
    ],
    targetVulnClasses: ["sqli", "blind_sqli", "time_based_sqli", "error_based_sqli"],
    estimatedTime: "15-30 min",
  },
  {
    id: "xss_chain",
    name: "XSS Discovery Chain",
    description: "Multi-tool XSS discovery including DOM and stored variants",
    phases: [
      { tool: "arjun", purpose: "Discover reflection points and parameters" },
      { tool: "dalfox", purpose: "Parameter analysis and XSS scanning", dependsOn: ["arjun"] },
      { tool: "xsstrike", purpose: "Advanced XSS with mutation engine", dependsOn: ["arjun"] },
      { tool: "nuclei", purpose: "Template-based XSS validation" },
    ],
    targetVulnClasses: ["xss", "dom_xss", "stored_xss"],
    estimatedTime: "10-25 min",
  },
  {
    id: "auth_bypass_chain",
    name: "Authentication Bypass Chain",
    description: "Comprehensive authentication weakness discovery",
    phases: [
      { tool: "jwt-tool", purpose: "Test JWT weaknesses and algorithm confusion" },
      { tool: "nuclei", purpose: "Template-based auth bypass checks" },
      { tool: "wfuzz", purpose: "Fuzz authentication endpoints" },
      { tool: "cors-scanner", purpose: "Check CORS misconfiguration leaking credentials" },
    ],
    targetVulnClasses: ["auth_bypass", "jwt_weakness", "cors", "privilege_escalation"],
    estimatedTime: "15-30 min",
  },
  {
    id: "credential_spray",
    name: "Credential Spray",
    description: "Low-and-slow credential testing against login endpoints",
    phases: [
      { tool: "arjun", purpose: "Locate login endpoints and parameters" },
      { tool: "hydra", purpose: "HTTP form-based credential testing", dependsOn: ["arjun"] },
      { tool: "nuclei", purpose: "Default credential template checks" },
    ],
    targetVulnClasses: ["weak_credentials", "auth_bypass", "account_takeover"],
    estimatedTime: "20-60 min",
  },
  {
    id: "ssrf_discovery",
    name: "SSRF Discovery",
    description: "Server-side request forgery discovery and impact assessment",
    phases: [
      { tool: "arjun", purpose: "Find URL/callback parameters" },
      { tool: "ssrfmap", purpose: "SSRF exploitation and internal probing", dependsOn: ["arjun"] },
      { tool: "nuclei", purpose: "Cloud metadata SSRF template checks" },
    ],
    targetVulnClasses: ["ssrf", "cloud_metadata"],
    estimatedTime: "15-25 min",
  },
  {
    id: "rce_hunt",
    name: "Remote Code Execution Hunt",
    description: "RCE discovery via injection and template flaws",
    phases: [
      { tool: "commix", purpose: "Command injection detection" },
      { tool: "tplmap", purpose: "Server-side template injection detection" },
      { tool: "nuclei", purpose: "CVE-based RCE template scanning" },
    ],
    targetVulnClasses: ["rce", "command_injection", "ssti"],
    estimatedTime: "20-40 min",
  },
  {
    id: "logic_flaw_hunt",
    name: "Business Logic Flaw Hunt",
    description: "Price manipulation, privilege escalation, and workflow bypass",
    phases: [
      { tool: "arjun", purpose: "Discover all parameters for manipulation" },
      { tool: "nuclei", purpose: "Business logic template checks" },
      { tool: "ffuf", purpose: "Fuzz parameter values for unexpected behavior" },
      { tool: "jwt-tool", purpose: "Test role/permission claims in JWTs" },
    ],
    targetVulnClasses: ["idor", "privilege_escalation", "business_logic", "auth_bypass"],
    estimatedTime: "25-50 min",
  },
  {
    id: "report_generation",
    name: "Intelligence Gathering for Report",
    description: "Passive evidence collection for report scaffolding",
    phases: [
      { tool: "shodan-cli", purpose: "Passive host information gathering" },
      { tool: "metabigor", purpose: "Company footprint and IP ranges" },
      { tool: "httpx", purpose: "Technology fingerprinting for report context" },
      { tool: "curl_probe", purpose: "Security header gap analysis" },
    ],
    targetVulnClasses: ["security_headers", "info_disclosure", "misconfig"],
    estimatedTime: "5-10 min",
  },
];

// ── ToolKnowledge Singleton ───────────────────────────────────────────────────

export class ToolKnowledge {
  private static instance: ToolKnowledge;
  private readonly profileMap: Map<string, ToolProfile>;

  private constructor() {
    this.profileMap = new Map(TOOL_PROFILES.map(p => [p.name, p]));
  }

  static getInstance(): ToolKnowledge {
    if (!ToolKnowledge.instance) {
      ToolKnowledge.instance = new ToolKnowledge();
    }
    return ToolKnowledge.instance;
  }

  getProfile(name: string): ToolProfile | undefined {
    return this.profileMap.get(name);
  }

  getByCategory(category: string): ToolProfile[] {
    return TOOL_PROFILES.filter(p => p.category === category);
  }

  getForVulnClass(vulnClass: string): ToolProfile[] {
    return TOOL_PROFILES.filter(p => p.vulnClasses.includes(vulnClass));
  }

  getPipeline(id: string): ToolChainPipeline | undefined {
    return TOOL_CHAIN_PIPELINES.find(p => p.id === id);
  }

  getPipelinesForVulnClass(vulnClass: string): ToolChainPipeline[] {
    return TOOL_CHAIN_PIPELINES.filter(p => p.targetVulnClasses.includes(vulnClass));
  }

  rankForHypothesis(vulnClass: string, stealthMode: boolean): ToolProfile[] {
    const matching = this.getForVulnClass(vulnClass);
    if (matching.length === 0) {
      return stealthMode
        ? TOOL_PROFILES.filter(p => p.stealthRating >= 7).slice(0, 5)
        : TOOL_PROFILES.slice(0, 5);
    }

    return [...matching].sort((a, b) => {
      // Exact vuln class match score
      const aExact = a.vulnClasses[0] === vulnClass ? 1 : 0;
      const bExact = b.vulnClasses[0] === vulnClass ? 1 : 0;
      if (aExact !== bExact) return bExact - aExact;

      // Stealth mode: prioritize by stealthRating
      if (stealthMode) return b.stealthRating - a.stealthRating;

      // Normal mode: prioritize by fewer vuln classes (more specialized)
      return a.vulnClasses.length - b.vulnClasses.length;
    });
  }

  // Returns a compact context block for injection into AI prompts
  getContextBlock(vulnClass: string): string {
    const tools = this.rankForHypothesis(vulnClass, false).slice(0, 4);
    const pipelines = this.getPipelinesForVulnClass(vulnClass).slice(0, 1);

    const lines: string[] = [`[Tool Knowledge: ${vulnClass}]`];

    tools.forEach(t => {
      lines.push(`  ${t.name} (stealth:${t.stealthRating}/10) — ${t.description}`);
    });

    if (pipelines.length > 0) {
      const p = pipelines[0];
      lines.push(`  Pipeline: ${p.id} → ${p.phases.map(ph => ph.tool).join(' → ')} (${p.estimatedTime})`);
    }

    return lines.join('\n');
  }

  // Returns a compact multi-class summary for hypothesize() prompt injection
  getSummaryBlock(): string {
    const priorityClasses = [
      "xss", "sqli", "ssrf", "rce", "idor", "auth_bypass",
      "misconfig", "security_headers", "hidden_endpoints", "ssti",
    ];
    const lines = ["[Available tool capabilities by vuln class]"];
    for (const vc of priorityClasses) {
      const tools = this.getForVulnClass(vc);
      if (tools.length > 0) {
        lines.push(`  ${vc}: ${tools.slice(0, 3).map(t => t.name).join(', ')}`);
      }
    }
    return lines.join('\n');
  }
}

export const toolKnowledge = ToolKnowledge.getInstance();

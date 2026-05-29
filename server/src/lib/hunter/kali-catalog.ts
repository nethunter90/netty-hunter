/**
 * Kali Linux Tool Catalog
 * 100+ web security tools with command templates, vuln class mappings, and metadata.
 * Templates use {url} (full URL) and {domain} (hostname only) as placeholders.
 * HunterEngine auto-detects which are installed via `which` and merges them into
 * the active tool registry at hunt start — zero configuration required.
 */

export type KaliCategory =
  | "recon"
  | "scanning"
  | "fuzzing"
  | "exploitation"
  | "web"
  | "credential"
  | "network"
  | "reporting";

export interface KaliToolEntry {
  name: string;
  displayName: string;
  binary: string;
  category: KaliCategory;
  commandTemplate: string;
  vulnClasses: string[];
  rateLimit: number;
  riskLevel: "low" | "medium" | "high";
  stealthRating: number;
  parserType: "lines" | "plain" | "json";
  description: string;
}

export const KALI_CATALOG: KaliToolEntry[] = [

  // ── RECON (15) ──────────────────────────────────────────────────────────────

  {
    name: "subfinder", displayName: "Subfinder", binary: "subfinder",
    category: "recon",
    commandTemplate: "subfinder -d {domain} -silent",
    vulnClasses: ["subdomain_takeover", "exposed_panels", "hidden_endpoints"],
    rateLimit: 30, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Fast passive subdomain discovery via multiple OSINT sources",
  },
  {
    name: "amass", displayName: "Amass", binary: "amass",
    category: "recon",
    commandTemplate: "amass enum -d {domain} -passive -norecursive",
    vulnClasses: ["subdomain_takeover", "exposed_panels"],
    rateLimit: 60, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "In-depth subdomain enumeration with ASN and certificate mapping",
  },
  {
    name: "dnsx", displayName: "DNSx", binary: "dnsx",
    category: "recon",
    commandTemplate: "dnsx -d {domain} -silent -a -cname",
    vulnClasses: ["subdomain_takeover", "dns_misconfig"],
    rateLimit: 15, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Fast DNS resolution toolkit with A, CNAME, and MX probing",
  },
  {
    name: "assetfinder", displayName: "Assetfinder", binary: "assetfinder",
    category: "recon",
    commandTemplate: "assetfinder --subs-only {domain}",
    vulnClasses: ["subdomain_takeover", "exposed_panels"],
    rateLimit: 30, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Find domains and subdomains related to a target from passive sources",
  },
  {
    name: "findomain", displayName: "Findomain", binary: "findomain",
    category: "recon",
    commandTemplate: "findomain -t {domain} -q",
    vulnClasses: ["subdomain_takeover"],
    rateLimit: 30, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Fast cross-platform subdomain enumerator using certificate transparency",
  },
  {
    name: "gau", displayName: "GAU (Get All URLs)", binary: "gau",
    category: "recon",
    commandTemplate: "gau {domain}",
    vulnClasses: ["exposed_endpoints", "info_disclosure", "hidden_endpoints"],
    rateLimit: 30, riskLevel: "low", stealthRating: 10, parserType: "lines",
    description: "Fetch known URLs from AlienVault OTX, Wayback Machine, and Common Crawl",
  },
  {
    name: "waybackurls", displayName: "Waybackurls", binary: "waybackurls",
    category: "recon",
    commandTemplate: "waybackurls {domain}",
    vulnClasses: ["exposed_endpoints", "info_disclosure"],
    rateLimit: 30, riskLevel: "low", stealthRating: 10, parserType: "lines",
    description: "Fetch all URLs the Wayback Machine knows about for a domain",
  },
  {
    name: "hakrawler", displayName: "Hakrawler", binary: "hakrawler",
    category: "recon",
    commandTemplate: "hakrawler -url {url} -depth 2 -plain",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 20, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "Web crawler for gathering URLs and JavaScript file links",
  },
  {
    name: "gospider", displayName: "GoSpider", binary: "gospider",
    category: "recon",
    commandTemplate: "gospider -s {url} -t 5 -q",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 20, riskLevel: "low", stealthRating: 7, parserType: "lines",
    description: "Fast web spider written in Go with JavaScript parsing support",
  },
  {
    name: "katana", displayName: "Katana", binary: "katana",
    category: "recon",
    commandTemplate: "katana -u {url} -silent -depth 2",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 20, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "Next-generation web crawler with headless browser support",
  },
  {
    name: "wafw00f", displayName: "Wafw00f", binary: "wafw00f",
    category: "recon",
    commandTemplate: "wafw00f {url}",
    vulnClasses: ["waf_detection", "misconfig"],
    rateLimit: 15, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "Web Application Firewall fingerprinting tool",
  },
  {
    name: "dnsrecon", displayName: "DNSrecon", binary: "dnsrecon",
    category: "recon",
    commandTemplate: "dnsrecon -d {domain} -t std",
    vulnClasses: ["dns_misconfig", "zone_transfer", "subdomain_takeover"],
    rateLimit: 30, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "DNS enumeration with zone transfer detection and brute-force",
  },
  {
    name: "fierce", displayName: "Fierce", binary: "fierce",
    category: "recon",
    commandTemplate: "fierce --domain {domain}",
    vulnClasses: ["dns_misconfig", "subdomain_takeover"],
    rateLimit: 30, riskLevel: "low", stealthRating: 7, parserType: "lines",
    description: "DNS reconnaissance tool for locating non-contiguous IP spaces",
  },
  {
    name: "theHarvester", displayName: "theHarvester", binary: "theHarvester",
    category: "recon",
    commandTemplate: "theHarvester -d {domain} -b google,bing,yahoo",
    vulnClasses: ["info_disclosure"],
    rateLimit: 60, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "OSINT email, subdomain, IP, and URL discovery via search engines",
  },
  {
    name: "masscan", displayName: "Masscan", binary: "masscan",
    category: "recon",
    commandTemplate: "masscan {domain} -p 80,443,8080,8443 --rate=500",
    vulnClasses: ["open_ports", "service_enumeration"],
    rateLimit: 60, riskLevel: "high", stealthRating: 2, parserType: "plain",
    description: "Ultra-fast TCP port scanner — scans the entire internet in minutes",
  },

  // ── SCANNING (10) ────────────────────────────────────────────────────────────

  {
    name: "nuclei", displayName: "Nuclei", binary: "nuclei",
    category: "scanning",
    commandTemplate: "nuclei -u {url} -silent -severity medium,high,critical",
    vulnClasses: ["xss", "sqli", "rce", "ssrf", "lfi", "idor", "misconfig", "exposed_panels"],
    rateLimit: 30, riskLevel: "medium", stealthRating: 5, parserType: "lines",
    description: "Fast template-based vulnerability scanner with 8000+ community templates",
  },
  {
    name: "nikto", displayName: "Nikto", binary: "nikto",
    category: "scanning",
    commandTemplate: "nikto -h {url} -nointeractive -Format txt",
    vulnClasses: ["misconfig", "info_disclosure", "xss", "sqli"],
    rateLimit: 30, riskLevel: "medium", stealthRating: 3, parserType: "lines",
    description: "Web server scanner for dangerous files, outdated software, and misconfigs",
  },
  {
    name: "wapiti", displayName: "Wapiti", binary: "wapiti",
    category: "scanning",
    commandTemplate: "wapiti -u {url} --quiet --format txt",
    vulnClasses: ["xss", "sqli", "lfi", "rce", "ssrf"],
    rateLimit: 60, riskLevel: "medium", stealthRating: 4, parserType: "lines",
    description: "Black-box web application vulnerability auditor",
  },
  {
    name: "skipfish", displayName: "Skipfish", binary: "skipfish",
    category: "scanning",
    commandTemplate: "skipfish -o /tmp/skipfish_out -Y -m 10 {url}",
    vulnClasses: ["xss", "sqli", "misconfig", "info_disclosure"],
    rateLimit: 60, riskLevel: "medium", stealthRating: 3, parserType: "plain",
    description: "Active web application security reconnaissance tool by Google",
  },
  {
    name: "wpscan", displayName: "WPScan", binary: "wpscan",
    category: "scanning",
    commandTemplate: "wpscan --url {url} --no-banner -f cli-no-colour",
    vulnClasses: ["misconfig", "info_disclosure", "exposed_panels", "rce"],
    rateLimit: 30, riskLevel: "medium", stealthRating: 5, parserType: "lines",
    description: "WordPress CMS vulnerability scanner with plugin/theme enumeration",
  },
  {
    name: "joomscan", displayName: "JoomScan", binary: "joomscan",
    category: "scanning",
    commandTemplate: "joomscan --url {url}",
    vulnClasses: ["misconfig", "info_disclosure", "exposed_panels"],
    rateLimit: 30, riskLevel: "medium", stealthRating: 5, parserType: "lines",
    description: "Joomla CMS vulnerability scanner",
  },
  {
    name: "testssl", displayName: "Testssl.sh", binary: "testssl.sh",
    category: "scanning",
    commandTemplate: "testssl.sh --quiet {domain}:443",
    vulnClasses: ["ssl_misconfig", "misconfig", "info_disclosure"],
    rateLimit: 30, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "TLS/SSL cipher suite and certificate configuration scanner",
  },
  {
    name: "sslscan", displayName: "SSLScan", binary: "sslscan",
    category: "scanning",
    commandTemplate: "sslscan --no-colour {domain}:443",
    vulnClasses: ["ssl_misconfig", "misconfig"],
    rateLimit: 15, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "TLS cipher suite and SSL/TLS version scanner",
  },
  {
    name: "sslyze", displayName: "SSLyze", binary: "sslyze",
    category: "scanning",
    commandTemplate: "sslyze {domain}",
    vulnClasses: ["ssl_misconfig", "misconfig"],
    rateLimit: 15, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Fast SSL/TLS configuration analyzer",
  },
  {
    name: "zaproxy", displayName: "ZAP Baseline", binary: "zap-baseline.py",
    category: "scanning",
    commandTemplate: "zap-baseline.py -t {url}",
    vulnClasses: ["xss", "sqli", "misconfig", "info_disclosure", "cors"],
    rateLimit: 120, riskLevel: "medium", stealthRating: 4, parserType: "lines",
    description: "OWASP ZAP automated baseline vulnerability scan",
  },

  // ── FUZZING (9) ──────────────────────────────────────────────────────────────

  {
    name: "ffuf", displayName: "FFUF", binary: "ffuf",
    category: "fuzzing",
    commandTemplate: "ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,201,301,302,403 -s",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints", "info_disclosure"],
    rateLimit: 15, riskLevel: "low", stealthRating: 6, parserType: "lines",
    description: "Fast web fuzzer for directories, VHosts, and parameter discovery",
  },
  {
    name: "gobuster", displayName: "Gobuster", binary: "gobuster",
    category: "fuzzing",
    commandTemplate: "gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -q -n",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 15, riskLevel: "low", stealthRating: 6, parserType: "lines",
    description: "Directory and DNS brute-force enumeration tool",
  },
  {
    name: "feroxbuster", displayName: "Feroxbuster", binary: "feroxbuster",
    category: "fuzzing",
    commandTemplate: "feroxbuster --url {url} -q --no-progress",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 15, riskLevel: "low", stealthRating: 5, parserType: "lines",
    description: "Recursive content discovery tool written in Rust",
  },
  {
    name: "dirsearch", displayName: "Dirsearch", binary: "dirsearch",
    category: "fuzzing",
    commandTemplate: "dirsearch -u {url} -q --plain-text-report /dev/stdout",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 15, riskLevel: "low", stealthRating: 6, parserType: "lines",
    description: "Advanced directory and file brute-force tool",
  },
  {
    name: "wfuzz", displayName: "Wfuzz", binary: "wfuzz",
    category: "fuzzing",
    commandTemplate: "wfuzz -w /usr/share/wordlists/dirb/common.txt -u {url}/FUZZ --sc 200,301,302 -q",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 15, riskLevel: "low", stealthRating: 5, parserType: "lines",
    description: "Web application fuzzer for directories, parameters, and forms",
  },
  {
    name: "dirb", displayName: "Dirb", binary: "dirb",
    category: "fuzzing",
    commandTemplate: "dirb {url} /usr/share/wordlists/dirb/common.txt -S",
    vulnClasses: ["exposed_endpoints", "hidden_endpoints"],
    rateLimit: 15, riskLevel: "low", stealthRating: 5, parserType: "lines",
    description: "URL bruteforcer for web content discovery",
  },
  {
    name: "arjun", displayName: "Arjun", binary: "arjun",
    category: "fuzzing",
    commandTemplate: "arjun -u {url} -q",
    vulnClasses: ["hidden_endpoints", "mass_assignment", "idor"],
    rateLimit: 20, riskLevel: "low", stealthRating: 7, parserType: "lines",
    description: "HTTP parameter discovery suite — finds hidden GET/POST parameters",
  },
  {
    name: "crlfuzz", displayName: "CRLFuzz", binary: "crlfuzz",
    category: "fuzzing",
    commandTemplate: "crlfuzz -u {url} -s",
    vulnClasses: ["crlf_injection", "open_redirect", "xss"],
    rateLimit: 15, riskLevel: "low", stealthRating: 7, parserType: "lines",
    description: "Fast CRLF injection vulnerability scanner",
  },
  {
    name: "gf", displayName: "GF (Grep Patterns)", binary: "gf",
    category: "fuzzing",
    commandTemplate: "echo {url} | gf xss",
    vulnClasses: ["xss", "sqli", "ssrf", "lfi"],
    rateLimit: 5, riskLevel: "low", stealthRating: 10, parserType: "lines",
    description: "Wrapper around grep with Tomnomnom patterns for vulnerability-prone parameters",
  },

  // ── EXPLOITATION (12) ────────────────────────────────────────────────────────

  {
    name: "sqlmap", displayName: "SQLMap", binary: "sqlmap",
    category: "exploitation",
    commandTemplate: "sqlmap -u {url} --batch --level=2 --risk=2 -q",
    vulnClasses: ["sqli"],
    rateLimit: 30, riskLevel: "high", stealthRating: 2, parserType: "lines",
    description: "Automated SQL injection detection and database takeover tool",
  },
  {
    name: "dalfox", displayName: "Dalfox", binary: "dalfox",
    category: "exploitation",
    commandTemplate: "dalfox url {url}",
    vulnClasses: ["xss"],
    rateLimit: 20, riskLevel: "medium", stealthRating: 5, parserType: "lines",
    description: "Fast XSS scanning and parameter analysis tool",
  },
  {
    name: "commix", displayName: "Commix", binary: "commix",
    category: "exploitation",
    commandTemplate: "commix --url {url} --batch",
    vulnClasses: ["rce", "command_injection"],
    rateLimit: 30, riskLevel: "high", stealthRating: 3, parserType: "lines",
    description: "Automated command injection detection and exploitation",
  },
  {
    name: "xsstrike", displayName: "XSStrike", binary: "xsstrike",
    category: "exploitation",
    commandTemplate: "xsstrike -u {url} --skip",
    vulnClasses: ["xss"],
    rateLimit: 20, riskLevel: "medium", stealthRating: 5, parserType: "lines",
    description: "Advanced XSS detection with WAF bypass and fuzzing",
  },
  {
    name: "tplmap", displayName: "Tplmap", binary: "tplmap",
    category: "exploitation",
    commandTemplate: "tplmap -u {url}",
    vulnClasses: ["ssti"],
    rateLimit: 30, riskLevel: "high", stealthRating: 4, parserType: "lines",
    description: "Server-Side Template Injection scanner and exploitation tool",
  },
  {
    name: "corsy", displayName: "Corsy", binary: "corsy",
    category: "exploitation",
    commandTemplate: "corsy -u {url}",
    vulnClasses: ["cors"],
    rateLimit: 15, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "CORS misconfiguration scanner — detects all known CORS bypasses",
  },
  {
    name: "nosqlmap", displayName: "NoSQLMap", binary: "nosqlmap",
    category: "exploitation",
    commandTemplate: "nosqlmap --attack 2 -u {url}",
    vulnClasses: ["nosqli", "auth_bypass"],
    rateLimit: 30, riskLevel: "high", stealthRating: 3, parserType: "lines",
    description: "NoSQL injection and exploitation tool for MongoDB, CouchDB",
  },
  {
    name: "xsser", displayName: "XSSer", binary: "xsser",
    category: "exploitation",
    commandTemplate: "xsser -u {url} --auto",
    vulnClasses: ["xss"],
    rateLimit: 20, riskLevel: "medium", stealthRating: 4, parserType: "lines",
    description: "Automated XSS detection, exploitation, and reporting framework",
  },
  {
    name: "ssrfmap", displayName: "SSRFmap", binary: "ssrfmap",
    category: "exploitation",
    commandTemplate: "ssrfmap -u {url}",
    vulnClasses: ["ssrf"],
    rateLimit: 30, riskLevel: "high", stealthRating: 3, parserType: "lines",
    description: "Server-Side Request Forgery scanner and chaining exploiter",
  },
  {
    name: "jwt_tool", displayName: "JWT Tool", binary: "jwt_tool",
    category: "exploitation",
    commandTemplate: "jwt_tool -t {url} -v",
    vulnClasses: ["jwt_weakness", "auth_bypass"],
    rateLimit: 15, riskLevel: "medium", stealthRating: 7, parserType: "lines",
    description: "JWT security testing — alg:none, RS/HS confusion, key injection",
  },
  {
    name: "smuggler", displayName: "Smuggler", binary: "smuggler",
    category: "exploitation",
    commandTemplate: "smuggler -u {url} --no-color",
    vulnClasses: ["http_smuggling"],
    rateLimit: 60, riskLevel: "medium", stealthRating: 6, parserType: "lines",
    description: "HTTP request smuggling detection (CL.TE, TE.CL, TE.TE)",
  },
  {
    name: "sqlninja", displayName: "SQLNinja", binary: "sqlninja",
    category: "exploitation",
    commandTemplate: "sqlninja -f /tmp/sqlninja.conf -m t",
    vulnClasses: ["sqli"],
    rateLimit: 60, riskLevel: "high", stealthRating: 2, parserType: "lines",
    description: "SQL Server injection and takeover tool for .NET applications",
  },

  // ── WEB (12) ─────────────────────────────────────────────────────────────────

  {
    name: "httpx", displayName: "HTTPx", binary: "httpx",
    category: "web",
    commandTemplate: "httpx -u {url} -silent -status-code -title -tech-detect",
    vulnClasses: ["info_disclosure", "misconfig", "exposed_panels"],
    rateLimit: 10, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "Fast HTTP probing with status code, title, and tech fingerprinting",
  },
  {
    name: "httprobe", displayName: "Httprobe", binary: "httprobe",
    category: "web",
    commandTemplate: "echo {domain} | httprobe",
    vulnClasses: ["info_disclosure", "exposed_panels"],
    rateLimit: 10, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Probe for live HTTP and HTTPS servers from a domain list",
  },
  {
    name: "whatweb", displayName: "WhatWeb", binary: "whatweb",
    category: "web",
    commandTemplate: "whatweb {url} -q",
    vulnClasses: ["info_disclosure", "misconfig"],
    rateLimit: 10, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "Next-generation web scanner and technology fingerprinter",
  },
  {
    name: "linkfinder", displayName: "LinkFinder", binary: "linkfinder",
    category: "web",
    commandTemplate: "linkfinder -i {url} -o cli",
    vulnClasses: ["exposed_endpoints", "info_disclosure"],
    rateLimit: 15, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Discover endpoints and parameters hidden in JavaScript files",
  },
  {
    name: "secretfinder", displayName: "SecretFinder", binary: "secretfinder",
    category: "web",
    commandTemplate: "secretfinder -i {url} -o cli",
    vulnClasses: ["info_disclosure", "exposed_secrets"],
    rateLimit: 15, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Find API keys, tokens, and secrets embedded in JavaScript files",
  },
  {
    name: "trufflehog", displayName: "TruffleHog", binary: "trufflehog",
    category: "web",
    commandTemplate: "trufflehog git {url} --json",
    vulnClasses: ["exposed_secrets", "info_disclosure"],
    rateLimit: 30, riskLevel: "low", stealthRating: 10, parserType: "json",
    description: "Find leaked credentials and secrets in git repositories",
  },
  {
    name: "cewl", displayName: "CeWL", binary: "cewl",
    category: "web",
    commandTemplate: "cewl {url} -m 5 -d 3",
    vulnClasses: ["info_disclosure"],
    rateLimit: 30, riskLevel: "low", stealthRating: 8, parserType: "lines",
    description: "Custom wordlist generator by spidering a target website",
  },
  {
    name: "curl_scan", displayName: "Curl (Headers)", binary: "curl",
    category: "web",
    commandTemplate: "curl -s -I -L {url}",
    vulnClasses: ["info_disclosure", "misconfig"],
    rateLimit: 5, riskLevel: "low", stealthRating: 10, parserType: "lines",
    description: "HTTP header inspection and response fingerprinting",
  },
  {
    name: "shodan", displayName: "Shodan CLI", binary: "shodan",
    category: "web",
    commandTemplate: "shodan domain {domain}",
    vulnClasses: ["info_disclosure", "exposed_panels", "open_ports"],
    rateLimit: 30, riskLevel: "low", stealthRating: 10, parserType: "plain",
    description: "Query Shodan for target host intelligence (requires API key)",
  },
  {
    name: "whatwaf", displayName: "WhatWaf", binary: "whatwaf",
    category: "web",
    commandTemplate: "whatwaf -u {url} --ra",
    vulnClasses: ["waf_detection", "misconfig"],
    rateLimit: 15, riskLevel: "low", stealthRating: 7, parserType: "lines",
    description: "Advanced WAF detection and fingerprinting tool",
  },
  {
    name: "nomore403", displayName: "Nomore403", binary: "nomore403",
    category: "web",
    commandTemplate: "nomore403 -u {url}",
    vulnClasses: ["auth_bypass", "misconfig"],
    rateLimit: 15, riskLevel: "medium", stealthRating: 7, parserType: "lines",
    description: "HTTP 403 bypass tool using headers, method overrides, and path tricks",
  },
  {
    name: "403bypass", displayName: "403-Bypass", binary: "403bypass",
    category: "web",
    commandTemplate: "403bypass -u {url}",
    vulnClasses: ["auth_bypass", "misconfig"],
    rateLimit: 15, riskLevel: "medium", stealthRating: 7, parserType: "lines",
    description: "Automated HTTP 403 Forbidden bypass techniques",
  },

  // ── CREDENTIAL (7) ───────────────────────────────────────────────────────────

  {
    name: "hydra", displayName: "Hydra", binary: "hydra",
    category: "credential",
    commandTemplate: "hydra -L /usr/share/wordlists/metasploit/default_usernames.txt -P /usr/share/wordlists/metasploit/default_passwords.txt -s 80 {domain} http-get /",
    vulnClasses: ["weak_credentials", "auth_bypass"],
    rateLimit: 30, riskLevel: "high", stealthRating: 2, parserType: "lines",
    description: "Fast network login cracker supporting 30+ protocols",
  },
  {
    name: "medusa", displayName: "Medusa", binary: "medusa",
    category: "credential",
    commandTemplate: "medusa -h {domain} -U /usr/share/wordlists/metasploit/default_usernames.txt -P /usr/share/wordlists/metasploit/default_passwords.txt -M http",
    vulnClasses: ["weak_credentials", "auth_bypass"],
    rateLimit: 30, riskLevel: "high", stealthRating: 2, parserType: "lines",
    description: "Speedy parallel network password cracker",
  },
  {
    name: "ncrack", displayName: "Ncrack", binary: "ncrack",
    category: "credential",
    commandTemplate: "ncrack -p 80 --user admin -P /usr/share/wordlists/metasploit/default_passwords.txt {domain}",
    vulnClasses: ["weak_credentials"],
    rateLimit: 30, riskLevel: "high", stealthRating: 2, parserType: "lines",
    description: "Network authentication cracking tool by the Nmap project",
  },
  {
    name: "patator", displayName: "Patator", binary: "patator",
    category: "credential",
    commandTemplate: "patator http_fuzz url={url}/login method=POST body='user=FILE0&pass=FILE1' 0=/usr/share/wordlists/metasploit/default_usernames.txt 1=/usr/share/wordlists/metasploit/default_passwords.txt",
    vulnClasses: ["weak_credentials", "auth_bypass"],
    rateLimit: 30, riskLevel: "high", stealthRating: 2, parserType: "lines",
    description: "Modular brute-force tool with multi-protocol plugin support",
  },
  {
    name: "john", displayName: "John the Ripper", binary: "john",
    category: "credential",
    commandTemplate: "john --wordlist=/usr/share/wordlists/rockyou.txt --show",
    vulnClasses: ["weak_credentials"],
    rateLimit: 60, riskLevel: "medium", stealthRating: 10, parserType: "lines",
    description: "Password hash cracker with dictionary, brute-force, and hybrid modes",
  },
  {
    name: "hashcat", displayName: "Hashcat", binary: "hashcat",
    category: "credential",
    commandTemplate: "hashcat -m 0 --stdout",
    vulnClasses: ["weak_credentials"],
    rateLimit: 60, riskLevel: "medium", stealthRating: 10, parserType: "lines",
    description: "World's fastest GPU-accelerated password cracker",
  },
  {
    name: "brutespray", displayName: "Brutespray", binary: "brutespray",
    category: "credential",
    commandTemplate: "brutespray -f /tmp/nmap.gnmap -t 5",
    vulnClasses: ["weak_credentials"],
    rateLimit: 30, riskLevel: "high", stealthRating: 3, parserType: "lines",
    description: "Brute-force discovered services from Nmap output using Medusa",
  },

  // ── NETWORK (7) ──────────────────────────────────────────────────────────────

  {
    name: "nmap", displayName: "Nmap", binary: "nmap",
    category: "network",
    commandTemplate: "nmap -sV -sC -p 80,443,8080,8443 {domain} --open",
    vulnClasses: ["open_ports", "service_enumeration", "misconfig"],
    rateLimit: 60, riskLevel: "medium", stealthRating: 4, parserType: "plain",
    description: "Network port scanner and service/OS fingerprinter",
  },
  {
    name: "nc", displayName: "Netcat", binary: "nc",
    category: "network",
    commandTemplate: "nc -zv {domain} 80",
    vulnClasses: ["open_ports", "service_enumeration"],
    rateLimit: 5, riskLevel: "low", stealthRating: 9, parserType: "plain",
    description: "TCP/UDP networking utility for port checking and banner grabbing",
  },
  {
    name: "socat", displayName: "Socat", binary: "socat",
    category: "network",
    commandTemplate: "socat - TCP:{domain}:80",
    vulnClasses: ["service_enumeration"],
    rateLimit: 5, riskLevel: "low", stealthRating: 9, parserType: "plain",
    description: "Multipurpose relay for bidirectional data transfer",
  },
  {
    name: "enum4linux", displayName: "Enum4linux", binary: "enum4linux",
    category: "network",
    commandTemplate: "enum4linux -a {domain}",
    vulnClasses: ["info_disclosure", "misconfig"],
    rateLimit: 30, riskLevel: "medium", stealthRating: 4, parserType: "lines",
    description: "SMB/NetBIOS enumeration for Windows and Samba hosts",
  },
  {
    name: "smbclient", displayName: "Smbclient", binary: "smbclient",
    category: "network",
    commandTemplate: "smbclient -L {domain} -N",
    vulnClasses: ["info_disclosure", "exposed_panels"],
    rateLimit: 15, riskLevel: "medium", stealthRating: 5, parserType: "lines",
    description: "SMB share enumeration and anonymous access testing",
  },
  {
    name: "arp-scan", displayName: "ARP-scan", binary: "arp-scan",
    category: "network",
    commandTemplate: "arp-scan --localnet",
    vulnClasses: ["service_enumeration", "open_ports"],
    rateLimit: 30, riskLevel: "low", stealthRating: 7, parserType: "lines",
    description: "ARP packet sender and MAC address fingerprinter",
  },
  {
    name: "tcpdump", displayName: "Tcpdump", binary: "tcpdump",
    category: "network",
    commandTemplate: "tcpdump -i any host {domain} -c 100 -A",
    vulnClasses: ["info_disclosure"],
    rateLimit: 30, riskLevel: "low", stealthRating: 9, parserType: "lines",
    description: "Packet capture and network traffic analysis",
  },

  // ── REPORTING (6) ────────────────────────────────────────────────────────────

  {
    name: "reconftw", displayName: "ReconFTW", binary: "reconftw",
    category: "reporting",
    commandTemplate: "reconftw -d {domain} -s",
    vulnClasses: ["subdomain_takeover", "exposed_endpoints", "misconfig", "xss", "sqli"],
    rateLimit: 120, riskLevel: "medium", stealthRating: 3, parserType: "lines",
    description: "Full-scope automated recon and vulnerability scanning framework",
  },
  {
    name: "metabigor", displayName: "Metabigor", binary: "metabigor",
    category: "reporting",
    commandTemplate: "metabigor ip -q {domain}",
    vulnClasses: ["info_disclosure", "exposed_panels"],
    rateLimit: 30, riskLevel: "low", stealthRating: 10, parserType: "lines",
    description: "OSINT intelligence tool using multiple passive data sources",
  },
  {
    name: "searchsploit", displayName: "SearchSploit", binary: "searchsploit",
    category: "reporting",
    commandTemplate: "searchsploit {domain}",
    vulnClasses: ["rce", "sqli", "xss", "lfi"],
    rateLimit: 10, riskLevel: "low", stealthRating: 10, parserType: "lines",
    description: "Offline Exploit-DB search for CVEs matching a technology stack",
  },
  {
    name: "maltego", displayName: "Maltego CLI", binary: "maltego",
    category: "reporting",
    commandTemplate: "maltego --headless -t {domain}",
    vulnClasses: ["info_disclosure"],
    rateLimit: 60, riskLevel: "low", stealthRating: 9, parserType: "plain",
    description: "OSINT link analysis tool for visualizing entity relationships",
  },
  {
    name: "gitrob", displayName: "Gitrob", binary: "gitrob",
    category: "reporting",
    commandTemplate: "gitrob {domain}",
    vulnClasses: ["exposed_secrets", "info_disclosure"],
    rateLimit: 60, riskLevel: "low", stealthRating: 10, parserType: "lines",
    description: "GitHub organization recon for sensitive files and exposed secrets",
  },
  {
    name: "gitleaks", displayName: "Gitleaks", binary: "gitleaks",
    category: "reporting",
    commandTemplate: "gitleaks detect --source /tmp --no-banner -q",
    vulnClasses: ["exposed_secrets", "info_disclosure"],
    rateLimit: 30, riskLevel: "low", stealthRating: 10, parserType: "plain",
    description: "Scan git repos for hard-coded secrets and leaked credentials",
  },
];

export const KALI_CATEGORY_META: Record<KaliCategory, {
  label: string;
  color: string;
  borderColor: string;
  description: string;
}> = {
  recon:       { label: "Reconnaissance", color: "text-blue-400",    borderColor: "border-blue-500",    description: "Passive and active information gathering" },
  scanning:    { label: "Scanning",        color: "text-yellow-400",  borderColor: "border-yellow-500",  description: "Automated vulnerability detection" },
  fuzzing:     { label: "Fuzzing",         color: "text-orange-400",  borderColor: "border-orange-500",  description: "Directory, parameter, and content discovery" },
  exploitation:{ label: "Exploitation",    color: "text-red-400",     borderColor: "border-red-500",     description: "Active exploitation and proof-of-concept" },
  web:         { label: "Web Analysis",    color: "text-purple-400",  borderColor: "border-purple-500",  description: "Web technology fingerprinting and JS analysis" },
  credential:  { label: "Credentials",     color: "text-emerald-400", borderColor: "border-emerald-500", description: "Password cracking and brute-force attacks" },
  network:     { label: "Network",         color: "text-cyan-400",    borderColor: "border-cyan-500",    description: "Network scanning and protocol enumeration" },
  reporting:   { label: "Reporting",       color: "text-gray-400",    borderColor: "border-gray-500",    description: "OSINT aggregation and reporting frameworks" },
};

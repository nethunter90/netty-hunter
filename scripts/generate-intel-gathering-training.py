#!/usr/bin/env python3
"""
Generate web intelligence gathering training data.

Teaches the model how to systematically collect security-relevant
information from public web sources — the same disciplined approach
used in the platform's own scrapers: paginated, rate-limited,
resume-capable, structured output.

Categories:
  1. Certificate transparency (crt.sh, censys)
  2. Shodan / Censys / FOFA queries
  3. WaybackMachine / archive.org for historical recon
  4. GitHub dorking for secrets and leaked code
  5. HTML parsing — extracting tokens, endpoints, hidden fields
  6. JavaScript bundle analysis — API routes from webpack output
  7. Public vulnerability APIs (NVD, OSV, GitHub Advisory)
  8. DNS recon — zone transfers, DNSSEC, passive DNS
  9. Document metadata extraction (EXIF, PDF, Office)
  10. robots.txt / sitemap.xml / .well-known parsing
  11. ASN / IP range / WHOIS intelligence
  12. Rate-limited scraper patterns (requests, pagination, resume)

Output: server/data/prompts/web-intelligence-gathering.json
"""

import json
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUT  = ROOT / "server" / "data" / "prompts" / "web-intelligence-gathering.json"

entries = []

def e(prompt_id, category, prompt, expected_answer):
    return {
        "id": str(uuid.uuid4()),
        "prompt_id": prompt_id,
        "category": category,
        "scenario": f"Web intelligence gathering — {category}",
        "visual_tags": "",
        "prompt": prompt,
        "reasoning_focus": "Systematic, practical, code-first. Show the actual commands/code. Explain rate limiting and politeness. Structure output for downstream use.",
        "expected_answer": expected_answer,
        "evaluation_criteria": "Includes working code or exact commands; mentions rate limiting or API limits where relevant; output is structured for further processing; technically accurate for the stated platform/API.",
    }


# ════════════════════════════════════════════════════════════════════════════
# 1. CERTIFICATE TRANSPARENCY
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-CT001", "certificate_transparency",
"how do I use crt.sh to find all subdomains for target.com?",
"""**crt.sh subdomain enumeration — two methods:**

**Method 1 — Browser (quick look):**
```
https://crt.sh/?q=%25.target.com&output=json
```

**Method 2 — API (scriptable, deduplicated):**
```python
import requests, json, time

def crtsh_subdomains(domain: str) -> set[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "recon-script"})
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"crt.sh error: {e}")
        return set()

    subs = set()
    for entry in data:
        # name_value can contain multiple names separated by newlines
        for name in entry.get("name_value", "").split("\\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(f".{domain}") or name == domain:
                subs.add(name.lower())
    return subs

subs = crtsh_subdomains("target.com")
print(f"Found {len(subs)} subdomains")
for s in sorted(subs):
    print(s)
```

**Method 3 — CLI one-liner:**
```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | \\
  python3 -c "import sys,json; [print(n.strip()) for e in json.load(sys.stdin) for n in e['name_value'].split('\\n')]" | \\
  grep -v '^\*' | sort -u
```

**Combine with subfinder for maximum coverage:**
```bash
subfinder -d target.com -silent | sort -u > passive-subs.txt
# crt.sh catches certs subfinder misses and vice versa
```

**Tip:** crt.sh is rate-limited — one request per domain is fine. Avoid bulk querying."""))

entries.append(e("WI-CT002", "certificate_transparency",
"write me a Python script that pulls all subdomains from crt.sh, resolves them, and checks which ones are alive with HTTP",
"""```python
#!/usr/bin/env python3
\'\'\'
Subdomain discovery: crt.sh -> DNS resolve -> HTTP probe
\'\'\'
import requests
import socket
import concurrent.futures
import time
from pathlib import Path

TARGET  = "target.com"
OUT_DIR = Path("recon") / TARGET
OUT_DIR.mkdir(parents=True, exist_ok=True)

def crtsh(domain: str) -> set[str]:
    r = requests.get(
        f"https://crt.sh/?q=%.{domain}&output=json",
        timeout=30, headers={"User-Agent": "recon/1.0"}
    )
    subs = set()
    for entry in r.json():
        for name in entry.get("name_value", "").split("\\n"):
            name = name.strip().lstrip("*.")
            if name.endswith(f".{domain}"):
                subs.add(name.lower())
    return subs

def resolves(sub: str) -> tuple[str, str | None]:
    try:
        ip = socket.gethostbyname(sub)
        return sub, ip
    except socket.gaierror:
        return sub, None

def probe_http(sub: str) -> dict | None:
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{sub}", timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            return {"sub": sub, "scheme": scheme, "status": r.status_code,
                    "title": r.text.split("<title>")[1].split("</title>")[0][:80]
                    if "<title>" in r.text else "", "url": r.url}
        except Exception:
            continue
    return None

# 1. Collect from crt.sh
print(f"[*] crt.sh query for {TARGET}...")
all_subs = crtsh(TARGET)
print(f"    → {len(all_subs)} unique subdomains")

# 2. DNS resolve in parallel
print("[*] Resolving DNS...")
alive_subs = []
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    for sub, ip in ex.map(resolves, all_subs):
        if ip:
            alive_subs.append(sub)

print(f"    → {len(alive_subs)} resolve")

# 3. HTTP probe
print("[*] Probing HTTP/HTTPS...")
results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    for result in ex.map(probe_http, alive_subs):
        if result:
            results.append(result)
            print(f"    [{result['status']}] {result['scheme']}://{result['sub']} — {result['title']}")

# 4. Save
(OUT_DIR / "alive-subs.json").write_text(
    __import__("json").dumps(results, indent=2)
)
print(f"\\n[+] {len(results)} live subdomains saved to {OUT_DIR}/alive-subs.json")
```

**Output format:** JSON list with `{sub, scheme, status, title, url}` per live subdomain — easy to pipe into ffuf or manual testing."""))


# ════════════════════════════════════════════════════════════════════════════
# 2. SHODAN / CENSYS
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-SH001", "shodan_censys",
"what are the most useful Shodan queries for bug bounty recon on a target company?",
"""**High-value Shodan dorks for bug bounty:**

**Find all IPs for a company (org/ASN):**
```
org:"Target Company Inc"
ssl.cert.subject.cn:"target.com"
ssl:"target.com" http.title:"Target"
```

**Find exposed admin interfaces:**
```
org:"Target Company" http.title:"admin"
org:"Target Company" http.title:"dashboard"
org:"Target Company" http.title:"Jenkins"
org:"Target Company" http.title:"Grafana"
org:"Target Company" http.title:"Kibana"
```

**Find specific vulnerable software:**
```
org:"Target Company" product:"Apache Tomcat" version:"9.0.0"
org:"Target Company" vuln:CVE-2021-44228
org:"Target Company" http.component:"phpMyAdmin"
```

**Find development/staging environments:**
```
org:"Target Company" http.title:"staging"
org:"Target Company" http.title:"dev"
ssl.cert.subject.cn:"*.target.com" -http.title:"Login"
```

**Find exposed databases:**
```
org:"Target Company" port:3306 country:US
org:"Target Company" port:27017  # MongoDB
org:"Target Company" port:9200 product:"Elastic"
org:"Target Company" port:6379 product:"Redis"
```

**Shodan CLI (faster than web UI):**
```bash
pip install shodan
shodan init YOUR_API_KEY

# Download all results
shodan search --fields ip_str,port,org,product 'org:"Target Company"' > shodan-results.txt
shodan search --limit 1000 'ssl:"target.com"' > ssl-hosts.txt
```

**Free tier:** 2 downloads/month, 1 result/search. Upgrade for bulk downloads — worth it for serious hunting."""))

entries.append(e("WI-SH002", "shodan_censys",
"write a Python script to pull all Shodan results for a company and extract interesting findings",
"""```python
#!/usr/bin/env python3
import shodan
import json
import time
from pathlib import Path

API_KEY = "YOUR_SHODAN_API_KEY"
ORG     = "Target Company Inc"
OUT     = Path("shodan-findings.json")

api = shodan.Shodan(API_KEY)

# Interest flags
INTERESTING_PORTS  = {21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443,
                       8888, 9200, 9300, 27017, 28017, 2375, 2376, 4243}
INTERESTING_TITLES = ["admin", "jenkins", "grafana", "kibana", "phpmyadmin",
                       "gitlab", "jira", "confluence", "staging", "debug", "test"]

findings = []
page = 1

while True:
    try:
        results = api.search(f'org:"{ORG}"', page=page, limit=100)
    except shodan.APIError as e:
        if "No information available" in str(e):
            break
        print(f"API error page {page}: {e}")
        time.sleep(5)
        continue

    if not results["matches"]:
        break

    for host in results["matches"]:
        ip      = host["ip_str"]
        port    = host["port"]
        product = host.get("product", "")
        title   = host.get("http", {}).get("title", "")
        vulns   = list(host.get("vulns", {}).keys())

        is_interesting = (
            port in INTERESTING_PORTS or
            any(t in title.lower() for t in INTERESTING_TITLES) or
            vulns
        )

        if is_interesting:
            finding = {
                "ip": ip, "port": port, "product": product,
                "title": title, "vulns": vulns,
                "org": host.get("org", ""),
                "url": f"http{'s' if port in (443,8443) else ''}://{ip}:{port}",
            }
            findings.append(finding)
            flag = "VULN" if vulns else "INTERESTING"
            print(f"  [{flag}] {ip}:{port} — {title or product} {vulns}")

    total = results["total"]
    fetched = page * 100
    print(f"Page {page}: {fetched}/{total} hosts processed")

    if fetched >= total:
        break
    page += 1
    time.sleep(1)  # Shodan rate limit: 1 req/sec

OUT.write_text(json.dumps(findings, indent=2))
print(f"\\n[+] {len(findings)} interesting findings → {OUT}")
```"""))


# ════════════════════════════════════════════════════════════════════════════
# 3. WAYBACK MACHINE
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-WB001", "wayback_machine",
"how do I use the Wayback Machine to find old endpoints and forgotten API routes on a target?",
"""**Wayback Machine CDX API — the right tool for this:**

**Quick URL dump (all snapshots ever):**
```bash
curl "http://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=original&collapse=urlkey&limit=10000" | \\
  python3 -c "import json,sys; [print(u[0]) for u in json.load(sys.stdin)[1:]]" | \\
  sort -u > wayback-urls.txt
```

**Filter to interesting paths only:**
```bash
grep -iE "(api|admin|backup|config|debug|test|dev|v[0-9]|\.php|\.env|\.git|\.bak|\.sql|\.zip)" wayback-urls.txt
```

**Python script (paginated, handles large targets):**
```python
import requests, json, time

def wayback_urls(domain: str, limit: int = 50000) -> list[str]:
    cdx_url = "http://web.archive.org/cdx/search/cdx"
    params  = {
        "url":      f"{domain}/*",
        "output":   "json",
        "fl":       "original",
        "collapse": "urlkey",
        "limit":    limit,
    }
    r = requests.get(cdx_url, params=params, timeout=60)
    data = r.json()
    # First row is header ["original"]
    return [row[0] for row in data[1:]]

urls = wayback_urls("target.com")
print(f"Found {len(urls)} unique historical URLs")

# Find high-value targets
high_value = [u for u in urls if any(k in u.lower() for k in
    ["/api/", "/admin", ".env", ".git", ".bak", ".sql", ".zip",
     "/config", "/debug", "/test", "/internal", "/v1/", "/v2/"])]

print(f"\\nHigh-value URLs ({len(high_value)}):")
for u in sorted(high_value)[:50]:
    print(f"  {u}")
```

**Check if old endpoints still respond (may be forgotten but live):**
```bash
cat wayback-urls.txt | httpx -silent -status-code -mc 200,201,301,302,403 | head -50
```

**Gold mines to look for:**
- `/api/v1/` routes deprecated when `/api/v2/` launched but still live
- Old admin panels moved but not decommissioned
- `.env`, `.git/config`, `backup.sql` from dev slip-ups"""))


# ════════════════════════════════════════════════════════════════════════════
# 4. GITHUB DORKING
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-GH001", "github_dorking",
"how do I search GitHub for leaked secrets and API keys belonging to target.com?",
"""**GitHub dorking for target.com secrets:**

**Most effective search queries (GitHub search UI):**
```
"target.com" password
"target.com" secret
"target.com" api_key
"target.com" apikey
"target.com" AWS_SECRET
"target.com" private_key
"@target.com" password filename:.env
site:target.com filename:.env
"target.com" DB_PASSWORD
"target.com" SMTP_PASSWORD
"target.com" jwt_secret
```

**GitHub code search API (programmatic):**
```python
import requests, time

GITHUB_TOKEN = "YOUR_GITHUB_PAT"
TARGET       = "target.com"

headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json",
}

queries = [
    f'"{TARGET}" password',
    f'"{TARGET}" secret_key',
    f'"{TARGET}" api_key',
    f'"@{TARGET}" password filename:.env',
    f'"{TARGET}" AWS_SECRET_ACCESS_KEY',
    f'"{TARGET}" DATABASE_URL',
]

for q in queries:
    r = requests.get(
        "https://api.github.com/search/code",
        params={"q": q, "per_page": 30},
        headers=headers,
        timeout=15,
    )
    data = r.json()
    print(f"\\nQuery: {q!r} — {data.get('total_count', 0)} results")
    for item in data.get("items", [])[:5]:
        print(f"  {item['html_url']}")
    time.sleep(2)  # GitHub: 30 code search requests/min authenticated
```

**Dedicated tools (faster than manual):**
```bash
# truffleHog — scans git history for secrets
trufflehog github --org=target-org --token=YOUR_GITHUB_PAT

# gitleaks
gitleaks detect --repo-url=https://github.com/target-org/repo

# gitrob (finds sensitive files in org repos)
gitrob analyze target-org
```

**What to look for in results:**
- `.env` files with DB credentials, API keys
- AWS `access_key_id` / `secret_access_key` pairs
- Hardcoded JWT secrets (`jwt_secret`, `SECRET_KEY`)
- Database connection strings
- Internal service URLs/IPs"""))


# ════════════════════════════════════════════════════════════════════════════
# 5. HTML PARSING FOR SECURITY
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-HP001", "html_parsing",
"write Python code to scrape a login page and extract all hidden fields, CSRF tokens, and form endpoints",
"""```python
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

def parse_login_page(url: str) -> dict:
    r = session.get(url, timeout=15)
    soup = BeautifulSoup(r.text, "html.parser")

    findings = {
        "url":          url,
        "status":       r.status_code,
        "cookies":      dict(r.cookies),
        "headers":      dict(r.headers),
        "forms":        [],
        "hidden_fields": [],
        "csrf_tokens":  [],
        "endpoints":    [],
        "comments":     [],
    }

    # Extract all forms and their fields
    for form in soup.find_all("form"):
        form_data = {
            "action":  urljoin(url, form.get("action", "")),
            "method":  form.get("method", "GET").upper(),
            "fields":  {},
        }
        for inp in form.find_all("input"):
            name  = inp.get("name", "")
            value = inp.get("value", "")
            itype = inp.get("type", "text")
            form_data["fields"][name] = {"type": itype, "value": value}

            # Flag hidden fields specifically
            if itype == "hidden":
                findings["hidden_fields"].append({"name": name, "value": value})

            # Identify CSRF token candidates
            if any(k in name.lower() for k in ["csrf", "token", "nonce", "_token", "xsrf"]):
                findings["csrf_tokens"].append({"field": name, "value": value})

        findings["forms"].append(form_data)

    # Extract all links/endpoints
    for tag in soup.find_all(["a", "link", "script"]):
        href = tag.get("href") or tag.get("src", "")
        if href and not href.startswith(("http", "//", "#", "mailto:")):
            findings["endpoints"].append(urljoin(url, href))

    # Extract HTML comments (often contain debug info, endpoints, credentials)
    for comment in soup.find_all(string=lambda t: isinstance(t, __import__("bs4").Comment)):
        c = str(comment).strip()
        if len(c) > 5:
            findings["comments"].append(c)

    return findings

result = parse_login_page("https://target.com/login")

print(f"Status: {result['status']}")
print(f"\\nCookies: {result['cookies']}")
print(f"\\nCSRF tokens found: {result['csrf_tokens']}")
print(f"\\nHidden fields: {result['hidden_fields']}")
print(f"\\nForms:")
for form in result["forms"]:
    print(f"  {form['method']} → {form['action']}")
    for name, info in form["fields"].items():
        print(f"    [{info['type']}] {name} = {info['value'][:50]}")
if result["comments"]:
    print(f"\\nHTML Comments:")
    for c in result["comments"]:
        print(f"  {c[:100]}")
```

**Security-relevant things to look for in output:**
- `hidden_fields` with non-obvious names → may be exploitable
- CSRF token not present → CSRF vulnerability
- Comments containing internal paths, version numbers, or dev notes
- Form action pointing to unexpected domain → possible open redirect"""))

entries.append(e("WI-HP002", "html_parsing",
"how do I crawl a website and extract all unique API endpoints, form actions, and JS file URLs for recon?",
"""```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import deque
import re, time

BASE_URL  = "https://target.com"
MAX_PAGES = 200
DELAY     = 0.5  # seconds between requests — be polite

session   = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0"

visited   = set()
queue     = deque([BASE_URL])
endpoints = set()
js_files  = set()
api_paths = set()

def is_same_domain(url: str) -> bool:
    return urlparse(url).netloc == urlparse(BASE_URL).netloc

def extract_from_page(url: str) -> set[str]:
    try:
        r = session.get(url, timeout=10, allow_redirects=True)
    except Exception:
        return set()

    links = set()
    soup  = BeautifulSoup(r.text, "html.parser")

    # All links
    for tag in soup.find_all(["a", "form", "link", "script", "iframe"]):
        for attr in ("href", "action", "src"):
            val = tag.get(attr, "")
            if val:
                full = urljoin(url, val)
                links.add(full)

                # Classify
                if ".js" in val and "?" not in val:
                    js_files.add(full)
                if re.search(r"/(api|v\d|graphql|rest|service)/", val, re.I):
                    api_paths.add(full)

    # Inline JS endpoint patterns
    for match in re.finditer(r'["\']((\/[a-zA-Z0-9_\-\/]+){2,})["\']', r.text):
        path = match.group(1)
        if re.search(r"/(api|admin|v\d)/", path, re.I):
            endpoints.add(urljoin(BASE_URL, path))

    return {l for l in links if is_same_domain(l) and l not in visited}

# Crawl
while queue and len(visited) < MAX_PAGES:
    url = queue.popleft()
    if url in visited:
        continue
    visited.add(url)
    print(f"  [{len(visited):>3}/{MAX_PAGES}] {url}")

    new_links = extract_from_page(url)
    queue.extend(new_links)
    time.sleep(DELAY)

# Report
print(f"\\n{'='*60}")
print(f"Pages crawled   : {len(visited)}")
print(f"JS files found  : {len(js_files)}")
print(f"API paths found : {len(api_paths | endpoints)}")
print(f"\\nAPI/interesting paths:")
for p in sorted(api_paths | endpoints):
    print(f"  {p}")
print(f"\\nJS files (download and analyze):")
for j in sorted(js_files):
    print(f"  {j}")
```

**Next step — analyze the JS files for hidden endpoints:**
```bash
# Download all JS and grep for API routes
for url in $(cat js-files.txt); do
    curl -s "$url" | grep -oE '"(/api/[^"]+)"'
done | sort -u
```"""))


# ════════════════════════════════════════════════════════════════════════════
# 6. JAVASCRIPT BUNDLE ANALYSIS
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-JS001", "javascript_analysis",
"how do I extract API endpoints from a minified webpack JavaScript bundle?",
"""**Webpack bundle endpoint extraction — multi-technique:**

**Technique 1 — Regex on raw bundle (fastest):**
```bash
# Download the bundle
curl -s https://target.com/static/js/main.chunk.js -o bundle.js

# Extract path-like strings
grep -oE '"(/[a-zA-Z0-9/_\-]{3,})"' bundle.js | tr -d '"' | sort -u

# API-specific patterns
grep -oE '`(/api/[^`"]+)`' bundle.js  # template literals
grep -oE '"(/api/v[0-9]/[^"]+)"' bundle.js
grep -oE "axios\.(get|post|put|delete)\(['\"]([^'\"]+)['\"]" bundle.js | grep -oE "'[^']+'" | tr -d "'"
```

**Technique 2 — Python with better false-positive filtering:**
```python
import re, requests

bundle = requests.get("https://target.com/static/js/main.chunk.js").text

# Patterns that indicate real API endpoints
patterns = [
    r'"(/api/[^"]{3,})"',       # quoted API paths
    r'`(/api/[^`]{3,})`',       # template literal paths
    r'fetch\(["\']([^"\']+)["\']',  # fetch() calls
    r'axios\.\w+\(["\']([^"\']+)["\']',  # axios calls
    r'\.get\(["\']([^"\']+)["\']',   # .get() calls
    r'url:\s*["\']([^"\']+)["\']',   # url: "..." in request configs
    r'baseURL:\s*["\']([^"\']+)["\']',  # base URLs
]

endpoints = set()
for pattern in patterns:
    for match in re.finditer(pattern, bundle):
        url = match.group(1)
        # Filter: must look like a path, not a variable or random string
        if re.match(r'^/[a-z]', url) and len(url) > 3:
            endpoints.add(url)

for ep in sorted(endpoints):
    print(ep)
```

**Technique 3 — Source maps (best if available):**
```bash
# Check if .map file exists
curl -I https://target.com/static/js/main.chunk.js.map

# If 200: download and decompile original source
npm install -g source-map-explorer
source-map-explorer bundle.js bundle.js.map

# Or use unwebpack
pip install unwebpack-sourcemap
python3 unwebpack.py https://target.com/static/js/main.chunk.js.map
```
Source maps give you the original React component source with readable variable names and full API call context.

**Technique 4 — Browser DevTools (definitive):**
Open Network tab → filter XHR/Fetch → use every feature of the app. Every real API call appears with full URL, headers, and body."""))


# ════════════════════════════════════════════════════════════════════════════
# 7. PUBLIC VULNERABILITY APIs
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-VA001", "vulnerability_apis",
"write a script that checks a list of software versions against NVD and OSV to find known CVEs",
"""```python
#!/usr/bin/env python3
\'\'\'
Check software versions for known CVEs via NVD and OSV APIs.
Usage: update SOFTWARE list below, then run.
\'\'\'
import requests
import time
import json

NVD_API_KEY = "YOUR_NVD_API_KEY"  # optional — increases rate limit 10x

# Software to check: (name, version, CPE keyword for NVD)
SOFTWARE = [
    ("Apache httpd",    "2.4.29", "apache:http_server:2.4.29"),
    ("PHP",             "7.4.3",  "php:php:7.4.3"),
    ("jQuery",          "3.4.1",  "jquery:jquery:3.4.1"),
    ("OpenSSH",         "7.6",    "openbsd:openssh:7.6"),
    ("Django",          "2.2.0",  "django:django:2.2.0"),
    ("log4j",           "2.14.0", "apache:log4j:2.14.0"),
]

headers = {}
if NVD_API_KEY:
    headers["apiKey"] = NVD_API_KEY

def check_nvd(cpe_keyword: str) -> list[dict]:
    # Query NVD for CVEs matching a CPE string.
    r = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cpeName": f"cpe:2.3:a:{cpe_keyword}:*:*:*:*:*:*:*", "resultsPerPage": 10},
        headers=headers,
        timeout=20,
    )
    vulns = []
    for v in r.json().get("vulnerabilities", []):
        cve   = v["cve"]
        descs = [d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"]
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            ms = cve.get("metrics", {}).get(key, [])
            if ms:
                score = ms[0]["cvssData"]["baseScore"]
                break
        vulns.append({
            "id":    cve["id"],
            "score": score,
            "desc":  descs[0][:120] if descs else "",
        })
    return vulns

def check_osv(package: str, version: str, ecosystem: str = "PyPI") -> list[dict]:
    # Query OSV for known vulnerabilities for a package version.
    r = requests.post(
        "https://api.osv.dev/v1/query",
        json={"version": version, "package": {"name": package, "ecosystem": ecosystem}},
        timeout=15,
    )
    return [{"id": v["id"], "summary": v.get("summary", "")[:100]}
            for v in r.json().get("vulns", [])]

print(f"{'Software':<25} {'Version':<12} {'CVEs':>5}  Highest  Details")
print("-" * 80)

for name, version, cpe in SOFTWARE:
    nvd_results = check_nvd(cpe)
    scores      = [v["score"] for v in nvd_results if v["score"]]
    highest     = max(scores) if scores else 0.0
    severity    = "CRITICAL" if highest >= 9 else "HIGH" if highest >= 7 else "MEDIUM" if highest >= 4 else "LOW"

    print(f"{name:<25} {version:<12} {len(nvd_results):>5}  {highest:.1f} ({severity})")
    for cve in sorted(nvd_results, key=lambda x: -(x["score"] or 0))[:3]:
        print(f"    {cve['id']:>16}  [{cve['score']}]  {cve['desc'][:70]}")

    time.sleep(0.7 if NVD_API_KEY else 6.5)
```"""))

entries.append(e("WI-VA002", "vulnerability_apis",
"how do I use the OSV API to check if any npm packages in a target's package.json are vulnerable?",
"""**npm package vulnerability check via OSV.dev:**

```python
#!/usr/bin/env python3
import requests
import json
from pathlib import Path

# Load target's package.json (obtained via /package.json, git exposure, etc.)
pkg = json.loads(Path("package.json").read_text())

# Combine dependencies
all_deps = {}
all_deps.update(pkg.get("dependencies", {}))
all_deps.update(pkg.get("devDependencies", {}))

print(f"Checking {len(all_deps)} packages against OSV.dev...\\n")

vulnerable = []
for name, version_spec in all_deps.items():
    # Clean version spec (remove ^, ~, >=, etc.)
    version = version_spec.lstrip("^~>=<").split(" ")[0].split("-")[0]

    try:
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"version": version,
                  "package": {"name": name, "ecosystem": "npm"}},
            timeout=10,
        )
        vulns = r.json().get("vulns", [])
    except Exception as e:
        print(f"  {name}: error — {e}")
        continue

    if vulns:
        for v in vulns:
            vuln_id  = v["id"]
            summary  = v.get("summary", "No summary")[:80]
            aliases  = v.get("aliases", [])
            cve      = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

            vulnerable.append({
                "package": name, "version": version,
                "vuln_id": cve, "summary": summary,
            })
            print(f"  ⚠  {name}@{version}")
            print(f"     {cve}: {summary}")

print(f"\\n{'='*60}")
print(f"  Vulnerable packages: {len({v['package'] for v in vulnerable})}")
print(f"  Total CVEs found   : {len(vulnerable)}")

# Prioritize by known high-severity packages
HIGH_VALUE = ["lodash", "express", "axios", "jquery", "handlebars",
              "serialize-javascript", "node-fetch", "marked"]
priority = [v for v in vulnerable if v["package"] in HIGH_VALUE]
if priority:
    print(f"\\n  HIGH PRIORITY (well-known packages):")
    for v in priority:
        print(f"    {v['package']}@{v['version']} — {v['vuln_id']}")
```

**Quick CLI alternative (no code):**
```bash
# If you have the package.json locally
npm audit --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
for v in d.get('vulnerabilities',{}).values():
    if v.get('severity') in ('high','critical'):
        print(v['severity'].upper(), v['name'], '-', v.get('via',[{}])[0].get('title',''))
"
```"""))


# ════════════════════════════════════════════════════════════════════════════
# 8. DNS RECON
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-DN001", "dns_recon",
"what DNS recon techniques give the most useful info for bug bounty?",
"""**High-value DNS recon techniques:**

**1. Zone transfer (AXFR) — when it works, you get everything:**
```bash
dig axfr @ns1.target.com target.com
# Or try all nameservers
for ns in $(dig NS target.com +short); do
  dig axfr @$ns target.com
done
```
Modern orgs block AXFR, but misconfigured internal DNS or older setups still leak.

**2. Brute-force with targeted wordlist:**
```bash
# dnsx with custom wordlist (faster than subfinder alone)
dnsx -d target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -o dns-brute.txt

# Or with puredns (handles wildcard DNS correctly)
puredns bruteforce /usr/share/wordlists/SecLists/Discovery/DNS/n0kovo_subdomains.txt target.com
```

**3. Reverse DNS on IP ranges (find hosts org doesn't list):**
```bash
# Get org's ASN
whois target.com | grep "OrgID\\|ASN"
# Or: https://bgp.he.net/ → search domain

# Get IP ranges for ASN
whois -h whois.radb.net '!gAS12345' | tr ' ' '\\n' | grep "/"

# Reverse DNS sweep on range
for ip in $(prips 192.168.1.0/24); do
  host $ip 2>/dev/null | grep "domain name pointer"
done
```

**4. Passive DNS (historical records):**
```bash
# SecurityTrails API (free tier: 50 queries/month)
curl "https://api.securitytrails.com/v1/domain/target.com/subdomains" \\
  -H "apikey: YOUR_ST_KEY" | python3 -m json.tool

# Or: https://passivedns.mnemonic.no/ (free, no key)
curl "https://api.mnemonic.no/pdns/v3/target.com" | python3 -m json.tool
```

**5. MX/TXT records reveal third-party services:**
```bash
dig MX target.com +short    # email provider (Google, Microsoft, Proofpoint)
dig TXT target.com +short   # SPF, DKIM, verification tokens, third-party services

# TXT records often reveal:
# _dmarc — email auth config
# google-site-verification — Google Search Console access
# atlassian-domain-verification — Jira/Confluence
# stripe-verification — Stripe account
```

**6. Subdomain takeover check:**
```bash
# subjack — checks for dangling DNS pointing to unclaimed cloud resources
subjack -w subdomains.txt -t 100 -timeout 30 -o takeover-results.txt -ssl

# Common takeover targets: GitHub Pages, Heroku, AWS S3, Azure, Shopify
```"""))


# ════════════════════════════════════════════════════════════════════════════
# 9. DOCUMENT METADATA
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-DM001", "document_metadata",
"how do I extract metadata from PDFs and Office documents found on a target's website to get employee names, internal paths, and software versions?",
"""**Document metadata extraction — automated pipeline:**

**Step 1 — Find documents on the target:**
```bash
# Google dork
site:target.com filetype:pdf
site:target.com filetype:docx OR filetype:xlsx OR filetype:pptx

# Or from WaybackMachine / ffuf:
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .pdf,.docx,.xlsx,.pptx -mc 200
```

**Step 2 — Download all documents:**
```bash
wget -r -A "*.pdf,*.docx,*.xlsx,*.pptx" -nd -P ./docs/ https://target.com/documents/
```

**Step 3 — Extract metadata with exiftool:**
```bash
# Install: apt install libimage-exiftool-perl
exiftool -csv docs/*.pdf docs/*.docx | tee metadata.csv

# What to look for:
exiftool docs/ | grep -iE "(author|creator|last.*author|company|producer|software|path|template)"
```

**Step 4 — Python with PyMuPDF for PDFs:**
```python
import fitz  # pip install pymupdf
from pathlib import Path

for pdf_path in Path("docs").glob("*.pdf"):
    doc  = fitz.open(pdf_path)
    meta = doc.metadata
    print(f"\\n{pdf_path.name}:")
    for key in ("author", "creator", "producer", "creationDate", "modDate"):
        if meta.get(key):
            print(f"  {key}: {meta[key]}")
```

**Step 5 — Office documents with python-docx:**
```python
from docx import Document  # pip install python-docx
from openpyxl import load_workbook
import zipfile, re

def extract_office_meta(path: str) -> dict:
    # Office files are zip archives — read core.xml directly
    with zipfile.ZipFile(path) as z:
        with z.open("docProps/core.xml") as f:
            content = f.read().decode()
    fields = {}
    for field in ["creator", "lastModifiedBy", "company", "revision"]:
        m = re.search(f"<[^>]*:{field}>([^<]+)<", content)
        if m:
            fields[field] = m.group(1)
    return fields

for f in Path("docs").glob("*.docx"):
    print(f"{f.name}: {extract_office_meta(str(f))}")
```

**High-value findings:**
- Author/lastModifiedBy → employee names → LinkedIn → phishing, credential stuffing
- File paths (e.g., `C:\\Users\\jsmith\\internal-docs\\config.docx`) → internal naming conventions
- Software/producer → exact Office/PDF version → CVE lookup
- Company field → confirm correct target organization"""))


# ════════════════════════════════════════════════════════════════════════════
# 10. ROBOTS.TXT / SITEMAP / .WELL-KNOWN
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-RB001", "robots_sitemap",
"write a script that systematically parses robots.txt, sitemap.xml, and .well-known/ to map a target's attack surface",
"""```python
#!/usr/bin/env python3
import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
import re, json

BASE = "https://target.com"
session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0"

surface = {
    "disallowed_paths": [],   # robots.txt Disallow — often admin/sensitive paths
    "allowed_paths":    [],   # robots.txt Allow
    "sitemap_urls":     [],   # all URLs from sitemap
    "well_known":       {},   # .well-known/ endpoints
}

# ── robots.txt ──────────────────────────────────────────────────────────────
print("[*] Fetching robots.txt...")
r = session.get(f"{BASE}/robots.txt", timeout=10)
if r.status_code == 200:
    for line in r.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                surface["disallowed_paths"].append(path)
                print(f"  Disallow: {path}")
        elif line.lower().startswith("allow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                surface["allowed_paths"].append(path)
        elif line.lower().startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            surface["sitemap_urls"].append(sitemap_url)

# ── sitemap.xml ─────────────────────────────────────────────────────────────
print("\\n[*] Fetching sitemap.xml...")
sitemap_urls = surface["sitemap_urls"] or [f"{BASE}/sitemap.xml", f"{BASE}/sitemap_index.xml"]
all_pages = set()

def parse_sitemap(url):
    r = session.get(url, timeout=15)
    if r.status_code != 200:
        return
    try:
        root = ET.fromstring(r.content)
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
        # Sitemap index — recurse into child sitemaps
        for sitemap in root.findall("sm:sitemap/sm:loc", ns):
            parse_sitemap(sitemap.text)
        # URL set
        for url_el in root.findall("sm:url/sm:loc", ns):
            all_pages.add(url_el.text)
    except ET.ParseError:
        pass

for sm in sitemap_urls:
    parse_sitemap(sm)

print(f"  Found {len(all_pages)} URLs in sitemap")
# Extract unique path patterns
path_patterns = set(urlparse(u).path for u in all_pages)
api_paths = [p for p in path_patterns if re.search(r"/(api|v\d|admin)/", p)]
print(f"  API/admin paths in sitemap: {len(api_paths)}")
for p in sorted(api_paths)[:10]:
    print(f"    {p}")

# ── .well-known/ ─────────────────────────────────────────────────────────────
print("\\n[*] Probing .well-known/...")
WELL_KNOWN = [
    "security.txt",        # bug bounty contact, scope
    "openid-configuration", # OAuth/OIDC config — reveals auth endpoints
    "oauth-authorization-server",
    "jwks.json",           # JWT public keys
    "apple-app-site-association",  # iOS deep links → internal app URL schemes
    "assetlinks.json",     # Android deep links
    "change-password",     # password change URL (RFC 8615)
    "webfinger",           # user discovery
    "host-meta",
]

for endpoint in WELL_KNOWN:
    url = f"{BASE}/.well-known/{endpoint}"
    try:
        r = session.get(url, timeout=8)
        if r.status_code == 200:
            surface["well_known"][endpoint] = r.text[:500]
            print(f"  ✓ {endpoint} [{r.status_code}]")
            if endpoint == "openid-configuration":
                config = r.json()
                print(f"    token_endpoint: {config.get('token_endpoint')}")
                print(f"    userinfo_endpoint: {config.get('userinfo_endpoint')}")
    except Exception:
        pass

print(f"\\n[+] Summary:")
print(f"  Sensitive paths from robots.txt : {len(surface['disallowed_paths'])}")
print(f"  Sitemap URLs                    : {len(all_pages)}")
print(f"  .well-known endpoints found     : {len(surface['well_known'])}")

# High-value: disallowed paths are worth probing directly
print(f"\\n[!] Probe these disallowed paths:")
for p in surface["disallowed_paths"]:
    print(f"  curl -I {BASE}{p}")
```

**Key insight:** Disallowed paths in robots.txt aren't hidden — they're advertised. They're exactly where developers don't want crawlers to go, which often means admin panels, debug endpoints, and internal tools."""))


# ════════════════════════════════════════════════════════════════════════════
# 11. ASN / IP RANGE RECON
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-AS001", "asn_ip_recon",
"how do I find all IP ranges owned by a company for comprehensive bug bounty recon?",
"""**ASN-based IP range discovery — full pipeline:**

**Step 1 — Find the company's ASN:**
```bash
# Method A: from known domain
whois target.com | grep -iE "(OrgID|OriginAS|ASN|Org-Name)"

# Method B: from known IP
whois $(dig +short target.com) | grep "OriginAS"

# Method C: BGP.he.net (easiest)
# https://bgp.he.net/dns/target.com#_prefixes
```

**Step 2 — Get all IP prefixes for the ASN:**
```bash
ASN="12345"
# Via RADB
whois -h whois.radb.net "!gAS${ASN}" | tr ' ' '\\n' | grep "/"

# Via BGPView API (JSON, easier to parse)
curl -s "https://api.bgpview.io/asn/${ASN}/prefixes" | \\
  python3 -c "import json,sys; [print(p['prefix']) for p in json.load(sys.stdin)['data']['ipv4_prefixes']]"
```

**Step 3 — Scan all prefixes for open services:**
```bash
# prips generates all IPs in a CIDR block
pip install prips

# For each prefix, check common web ports
for prefix in $(cat asn-prefixes.txt); do
  nmap -sV -p 80,443,8080,8443,8888 --open -T4 \\
    --min-rate 1000 -oG - $prefix 2>/dev/null | \\
    grep "open" >> live-web-services.txt
done
```

**Step 4 — Reverse DNS → find interesting hostnames:**
```bash
# Mass reverse DNS lookup
for prefix in $(cat asn-prefixes.txt); do
  prips $prefix | while read ip; do
    host $ip 2>/dev/null | grep "pointer" | awk '{print $NF, $1}'
  done
done | grep -iE "(dev|staging|admin|internal|test|api)" > interesting-hosts.txt
```

**Step 5 — Shodan bulk query (fastest for large orgs):**
```bash
shodan search --fields ip_str,hostnames,port,product "asn:AS${ASN}" > shodan-asn.txt
```

**Tip:** Many bug bounty scopes say "*.target.com in scope." The ASN approach finds IPs that serve target.com content on non-standard subdomains or IPs — often unpatched internal-facing services accidentally exposed."""))


# ════════════════════════════════════════════════════════════════════════════
# 12. RATE-LIMITED SCRAPER PATTERNS
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("WI-RL001", "scraper_patterns",
"write me a reusable Python scraper class that handles rate limiting, retries, progress saving, and resume capability — the same pattern used for NVD/OSV scraping",
"""```python
#!/usr/bin/env python3
\'\'\'
Reusable resilient scraper with rate limiting, exponential backoff,
progress persistence, and resume capability.
Same pattern as the NVD/OSV training data scrapers.
\'\'\'
import requests
import json
import time
import logging
from pathlib import Path
from typing import Any, Callable, Generator, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


class ResilientScraper:
    def __init__(
        self,
        name: str,
        output_file: Path,
        progress_file: Optional[Path] = None,
        delay: float = 1.0,          # seconds between requests
        max_retries: int = 4,
        backoff_base: float = 2.0,   # exponential: 2s, 4s, 8s, 16s
        session_headers: dict = None,
    ):
        self.name          = name
        self.output_file   = output_file
        self.progress_file = progress_file or output_file.with_suffix(".progress.json")
        self.delay         = delay
        self.max_retries   = max_retries
        self.backoff_base  = backoff_base

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": f"security-recon/{name}/1.0",
            **(session_headers or {}),
        })

        self.progress = self._load_progress()
        self._written = 0

    def _load_progress(self) -> dict:
        if self.progress_file.exists():
            log.info(f"Resuming from {self.progress_file}")
            return json.loads(self.progress_file.read_text())
        return {}

    def _save_progress(self):
        self.progress_file.write_text(json.dumps(self.progress, indent=2))

    def get(self, url: str, params: dict = None, **kwargs) -> requests.Response:
        # GET with exponential backoff retry on 429/5xx.
        for attempt in range(self.max_retries + 1):
            try:
                r = self.session.get(url, params=params, timeout=30, **kwargs)
                if r.status_code == 429:
                    wait = self.backoff_base ** attempt
                    log.warning(f"Rate limited — waiting {wait:.0f}s (attempt {attempt+1})")
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                return r
            except requests.HTTPError as e:
                if attempt == self.max_retries:
                    raise
                wait = self.backoff_base ** attempt
                log.warning(f"HTTP error {e} — retry in {wait:.0f}s")
                time.sleep(wait)
            except requests.RequestException as e:
                if attempt == self.max_retries:
                    raise
                wait = self.backoff_base ** attempt
                log.warning(f"Request error {e} — retry in {wait:.0f}s")
                time.sleep(wait)
        raise RuntimeError(f"Failed after {self.max_retries} retries: {url}")

    def run(
        self,
        pages: Generator[tuple[str, dict], None, None],  # yields (page_key, data)
        transform: Callable[[dict], list[Any]],           # converts page data → list of records
        skip_if: Callable[[str], bool] = None,           # skip page_key if already done
    ) -> int:
        # Main scrape loop. Appends records to output_file, saves progress per page.
        with open(self.output_file, "a") as out_fh:
            for page_key, page_data in pages:
                if skip_if and skip_if(page_key):
                    log.info(f"Skip (already done): {page_key}")
                    continue

                records = transform(page_data)
                for record in records:
                    out_fh.write(json.dumps(record, ensure_ascii=False) + "\\n")
                    self._written += 1

                self.progress[page_key] = "done"
                self._save_progress()

                if self._written % 100 == 0:
                    log.info(f"{self.name}: {self._written} records written")

                time.sleep(self.delay)

        return self._written


# ── Example usage: scrape CVEs for a list of CWEs ───────────────────────────

def nvd_pages(cwe_ids: list[str], scraper: ResilientScraper):
    # Generator: yields (page_key, response_data) for NVD pagination.
    for cwe_id in cwe_ids:
        start = scraper.progress.get(f"nvd:{cwe_id}", 0)
        if start == "done":
            continue

        params = {"cweId": cwe_id, "resultsPerPage": 2000, "startIndex": start}
        r      = scraper.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params)
        data   = r.json()
        total  = data.get("totalResults", 0)

        while True:
            yield (f"nvd:{cwe_id}:{start}", data)
            start += 2000
            if start >= total:
                scraper.progress[f"nvd:{cwe_id}"] = "done"
                break
            params["startIndex"] = start
            r    = scraper.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params)
            data = r.json()


if __name__ == "__main__":
    scraper = ResilientScraper(
        name="nvd-cwe-scraper",
        output_file=Path("cve-data.jsonl"),
        delay=0.65,  # 10x with API key, 6.5 without
        session_headers={"apiKey": "YOUR_NVD_KEY"},  # remove if no key
    )

    CWE_IDS = ["CWE-79", "CWE-89", "CWE-918", "CWE-287", "CWE-639"]

    def transform(data: dict) -> list[dict]:
        records = []
        for v in data.get("vulnerabilities", []):
            cve   = v["cve"]
            descs = [d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"]
            if descs:
                records.append({"id": cve["id"], "description": descs[0]})
        return records

    total = scraper.run(
        pages=nvd_pages(CWE_IDS, scraper),
        transform=transform,
        skip_if=lambda key: scraper.progress.get(key) == "done",
    )
    print(f"Done: {total} CVEs written to cve-data.jsonl")
```

**The pattern applied to any source:** implement a generator that yields `(page_key, data)` and a `transform` function that converts it to records. The `ResilientScraper` handles all the retry, rate limit, progress, and resume logic."""))


# ════════════════════════════════════════════════════════════════════════════
# Write output
# ════════════════════════════════════════════════════════════════════════════

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(entries, indent=2, ensure_ascii=False))

print(f"\n{'='*60}")
print(f"  Web intelligence gathering training data generated")
print(f"  Output : {OUT}")
print(f"  Entries: {len(entries)}")
print()
cats = {}
for ent in entries:
    cats[ent['category']] = cats.get(ent['category'], 0) + 1
for cat, count in sorted(cats.items()):
    print(f"    {cat:<35} {count:>3}")
print("=" * 60)

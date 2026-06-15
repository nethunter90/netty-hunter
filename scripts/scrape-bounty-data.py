#!/usr/bin/env python3
"""
Scrape real vulnerability data from public sources and convert to
ShareGPT Q&A format for fine-tuning the bug bounty hunting model.

Sources (all free, no auth required):
  1. NVD CVE API      — web-relevant CVEs filtered by CWE
  2. OSV.dev API      — richer descriptions for package ecosystems
  3. GitHub Advisory  — local clone of github/advisory-database (optional)

Output: scripts/bounty-scrape.jsonl

NVD API key (free, 10x higher rate limit):
  Request at: https://nvd.nist.gov/developers/request-an-api-key
  Then set:   export NVD_API_KEY=your-key-here
  Or add to server/.env: NVD_API_KEY=your-key-here

Usage:
  python3 scripts/scrape-bounty-data.py [--nvd] [--osv] [--ghsa /path/to/advisory-database]

  # Fetch all sources:
  NVD_API_KEY=your-key python3 scripts/scrape-bounty-data.py --nvd --osv

  # If you cloned the GitHub advisory DB:
  git clone --depth=1 https://github.com/github/advisory-database.git /tmp/advisory-database
  python3 scripts/scrape-bounty-data.py --ghsa /tmp/advisory-database

The output file is automatically picked up by export-finetune-jsonl.py.
"""

import argparse
import json
import os
import time
import re
import sys
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

# Load .env if python-dotenv available, otherwise fall back to env
try:
    from dotenv import load_dotenv
    _env = Path(__file__).parent.parent / "server" / ".env"
    if _env.exists():
        load_dotenv(_env)
except ImportError:
    pass

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

ROOT     = Path(__file__).parent.parent
OUT_FILE = ROOT / "scripts" / "bounty-scrape.jsonl"
PROG_FILE = ROOT / "scripts" / ".scrape-progress.json"

SYSTEM_PROMPT = (
    "You are an expert security researcher and bug bounty hunter with deep knowledge of "
    "web application security, API security, network penetration testing, cloud infrastructure, "
    "and Kali Linux tooling. You analyze security scenarios, interpret tool output, reason about "
    "attack paths and vulnerability chains, and provide expert guidance on bug bounty tactics. "
    "Your responses are technically precise, concise, and reflect real-world bug bounty experience."
)

# Web-relevant CWE IDs to pull from NVD
WEB_CWES = {
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-22":  "Path Traversal",
    "CWE-200": "Sensitive Information Disclosure",
    "CWE-201": "Sensitive Data Exposure in Sent Data",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Authentication Bypass",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-434": "Unrestricted File Upload",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-94":  "Code Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-77":  "Command Injection",
    "CWE-1321": "Prototype Pollution",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-74":  "Injection",
}

# Asset types inferred from CVE description keywords
def infer_asset(text: str) -> str:
    t = text.lower()
    if any(k in t for k in ["api endpoint", "rest api", "graphql", "json api"]):
        return "REST/GraphQL API"
    if any(k in t for k in ["web application", "web app", "webapp", "http server"]):
        return "web application"
    if any(k in t for k in ["admin panel", "admin interface", "management console"]):
        return "admin panel"
    if any(k in t for k in ["login", "authentication", "auth endpoint", "oauth"]):
        return "authentication endpoint"
    if any(k in t for k in ["file upload", "upload endpoint", "multipart"]):
        return "file upload endpoint"
    if any(k in t for k in ["search", "query parameter", "user input"]):
        return "user-facing web form"
    if any(k in t for k in ["plugin", "wordpress", "drupal", "cms"]):
        return "CMS plugin/theme"
    if any(k in t for k in ["npm", "package", "library", "module"]):
        return "open-source library (npm/pip)"
    return "web application"


def severity_label(score: Optional[float]) -> str:
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical (P1)"
    if score >= 7.0:
        return "High (P2)"
    if score >= 4.0:
        return "Medium (P3)"
    return "Low (P4)"


def make_conv(human: str, gpt: str) -> dict:
    return {
        "conversations": [
            {"from": "system", "value": SYSTEM_PROMPT},
            {"from": "human",  "value": human.strip()},
            {"from": "gpt",    "value": gpt.strip()},
        ]
    }


def cve_to_qa(cve_id: str, description: str, cwe_id: str, cwe_name: str,
              cvss_score: Optional[float], cvss_vector: Optional[str],
              attack_vector: Optional[str]) -> Optional[dict]:
    """Convert a CVE record into a bug bounty analysis Q&A pair."""
    desc = description.strip()
    if len(desc) < 80:
        return None

    asset = infer_asset(desc)
    sev   = severity_label(cvss_score)
    score_str = f"{cvss_score:.1f}" if cvss_score else "unknown"
    av    = (attack_vector or "Network").title()

    # Human turn — framed as an analyst observing behavior
    human = (
        f"Vulnerability Class: {cwe_name}\n"
        f"Asset Type: {asset}\n"
        f"Attack Vector: {av}\n"
        f"CVSS Score: {score_str} ({sev})\n"
        f"Reference: {cve_id}\n"
        f"\nScenario:\n"
        f"During a bug bounty assessment you identify the following vulnerability:\n"
        f"{desc}\n"
        f"\nAnalyze this finding: explain the attack chain, exploitation steps, "
        f"business impact, and how you would document this in a professional bug bounty report."
    )

    # GPT turn — structured expert analysis
    impact_map = {
        "CWE-79":   "Attackers can execute arbitrary JavaScript in victim browsers, steal session cookies, redirect users, or perform actions on their behalf.",
        "CWE-89":   "Attackers can read, modify, or delete database records, bypass authentication, and in some configurations achieve remote code execution.",
        "CWE-918":  "Attackers can pivot to internal services, cloud metadata endpoints (169.254.169.254), and internal APIs that are not exposed publicly.",
        "CWE-287":  "Attackers can access restricted resources, impersonate other users, or gain elevated privileges without valid credentials.",
        "CWE-639":  "Attackers can access or modify other users' data by manipulating object identifiers, violating tenant isolation.",
        "CWE-434":  "Attackers may upload malicious files (webshells, malware) that execute server-side, potentially achieving full RCE.",
        "CWE-611":  "Attackers can read local files, perform SSRF, or cause denial of service via entity expansion attacks.",
        "CWE-502":  "Attackers can achieve arbitrary code execution, denial of service, or privilege escalation through crafted serialized payloads.",
        "CWE-22":   "Attackers can read sensitive files outside the web root including credentials, source code, and configuration files.",
        "CWE-352":  "Attackers can trick authenticated users into performing unintended actions such as account changes, data exfiltration, or fund transfers.",
        "CWE-601":  "Attackers can redirect users to phishing pages or malicious sites, often used to steal credentials post-authentication.",
        "CWE-78":   "Attackers can execute arbitrary OS commands on the server with the privileges of the web application process.",
        "CWE-94":   "Attackers can inject and execute arbitrary code within the application's runtime environment.",
        "CWE-200":  "Sensitive data including PII, credentials, internal paths, or system information is exposed to unauthorized parties.",
        "CWE-862":  "Resources or actions that should require authentication are accessible without it, enabling unauthorized access.",
        "CWE-863":  "The application fails to enforce authorization checks, allowing users to access resources beyond their permission level.",
        "CWE-1321": "Attackers can corrupt JavaScript object prototypes, potentially affecting all objects in the application and enabling RCE or privilege escalation.",
        "CWE-798":  "Hard-coded credentials in source code or binaries allow any user with code access to authenticate to protected systems.",
    }

    remediation_map = {
        "CWE-79":   "Implement context-aware output encoding (HTML, JS, URL contexts). Use a Content Security Policy (CSP). Validate and sanitize all user input server-side.",
        "CWE-89":   "Use parameterized queries / prepared statements exclusively. Apply least-privilege DB accounts. Enable WAF SQL injection rules as defense-in-depth.",
        "CWE-918":  "Implement strict allowlist for outbound URLs. Block RFC-1918 ranges and metadata IPs. Disable HTTP redirects from server-side fetchers.",
        "CWE-287":  "Enforce strong authentication. Implement MFA. Audit all authentication bypass paths including alternative login flows.",
        "CWE-639":  "Use indirect reference maps or UUIDs. Enforce authorization checks server-side on every resource access.",
        "CWE-434":  "Validate file type server-side using magic bytes, not extension. Serve uploads from a separate cookieless domain. Disable execution in upload directories.",
        "CWE-611":  "Disable XML external entity processing. Use a secure XML parser configuration. Avoid parsing untrusted XML documents.",
        "CWE-502":  "Avoid deserializing untrusted data. Use serialization formats without code execution capability (JSON). Implement deserialization allowlists.",
        "CWE-22":   "Canonicalize file paths before use. Validate paths against an allowlist of permitted directories. Use chroot jails.",
        "CWE-352":  "Implement synchronizer token pattern (CSRF tokens). Use SameSite cookie attribute. Validate Origin/Referer headers.",
        "CWE-601":  "Validate redirect URLs against a strict allowlist. Display a redirect warning page. Reject URLs with different scheme/host.",
        "CWE-78":   "Avoid system calls with user input. Use parameterized APIs. Validate input strictly. Apply least-privilege OS accounts.",
        "CWE-94":   "Never eval() user input. Use sandboxed execution environments. Apply strict input validation and templating.",
        "CWE-200":  "Apply need-to-know access controls. Scrub sensitive data from logs, error messages, and API responses. Encrypt sensitive fields at rest.",
        "CWE-862":  "Enforce authentication on every sensitive route. Implement middleware-level auth checks. Audit all endpoints.",
        "CWE-863":  "Implement RBAC/ABAC. Audit authorization logic server-side. Do not rely on client-side access control.",
        "CWE-1321": "Freeze prototype objects. Use Object.create(null) for dictionaries. Validate input keys against a schema allowlist.",
        "CWE-798":  "Remove all hard-coded secrets. Rotate compromised credentials immediately. Use secrets management (Vault, AWS Secrets Manager).",
    }

    default_impact = "This vulnerability allows unauthorized access or data manipulation, with potential for significant business impact depending on the sensitivity of affected resources."
    default_remediation = "Follow OWASP secure coding guidelines. Apply input validation, output encoding, and enforce the principle of least privilege."

    impact      = impact_map.get(cwe_id, default_impact)
    remediation = remediation_map.get(cwe_id, default_remediation)

    gpt = (
        f"## Vulnerability Analysis: {cwe_name}\n\n"
        f"**Severity:** {sev} (CVSS {score_str})\n"
        f"**CWE:** {cwe_id} — {cwe_name}\n"
        f"**Attack Vector:** {av}\n\n"
        f"### Attack Chain\n"
        f"{desc}\n\n"
        f"### Business Impact\n"
        f"{impact}\n\n"
        f"### Bug Bounty Report Structure\n\n"
        f"**Title:** [{sev}] {cwe_name} in {asset}\n\n"
        f"**Steps to Reproduce:**\n"
        f"1. Identify the vulnerable endpoint/parameter based on observed behavior\n"
        f"2. Craft a proof-of-concept payload targeting {cwe_name.split('(')[0].strip()}\n"
        f"3. Demonstrate the impact (data access, privilege escalation, or code execution)\n"
        f"4. Capture evidence: screenshots, HTTP request/response, video PoC\n\n"
        f"**Impact:** {impact}\n\n"
        f"**Remediation:** {remediation}\n\n"
        f"**References:** {cve_id}"
    )

    return make_conv(human, gpt)


# ─── Source 1: NVD CVE API ───────────────────────────────────────────────────

def scrape_nvd(progress: dict, out_fh) -> int:
    """Pull CVEs for web-relevant CWEs from NVD.
    Without API key: 5 req/30s.  With key: 50 req/30s (10x faster).
    Set NVD_API_KEY env var or add to server/.env.
    """
    base    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    # Authenticated: 0.6s between requests (50 req/30s).
    # Unauthenticated: 6s between requests (5 req/30s).
    delay   = 0.65 if NVD_API_KEY else 6.5

    if NVD_API_KEY:
        print(f"  NVD: using API key (10x rate limit) — delay={delay}s/req")
    else:
        print("  NVD: no API key — unauthenticated (slow). Set NVD_API_KEY to speed up.")

    total_written = 0
    session = requests.Session()
    session.headers.update(headers)

    for cwe_id, cwe_name in WEB_CWES.items():
        prog_key  = f"nvd:{cwe_id}"
        start_idx = progress.get(prog_key, 0)

        # Skip already-completed CWEs (stored as int equal to totalResults)
        # Progress is an integer tracking the next startIndex; "done" means
        # we stored the totalResults value and start_idx caught up.

        params = {
            "cweId":          cwe_id,
            "resultsPerPage": 2000 if NVD_API_KEY else 100,
            "startIndex":     start_idx,
        }

        try:
            r = session.get(base, params=params, timeout=30)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print(f"  NVD {cwe_id} fetch error: {e}")
            time.sleep(delay * 10)
            continue

        total = data.get("totalResults", 0)
        if start_idx >= total and total > 0:
            print(f"  NVD {cwe_id} ({cwe_name}): already complete ({total} CVEs)")
            continue

        print(f"  NVD {cwe_id} ({cwe_name}): {total:,} CVEs, resuming at {start_idx}")
        page_size = params["resultsPerPage"]

        while start_idx < total:
            for vuln in data.get("vulnerabilities", []):
                cve    = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descs  = [d["value"] for d in cve.get("descriptions", [])
                          if d.get("lang") == "en"]
                if not descs:
                    continue
                description = descs[0]

                score, vector, av = None, None, None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    metrics = cve.get("metrics", {}).get(key, [])
                    if metrics:
                        cd     = metrics[0].get("cvssData", {})
                        score  = cd.get("baseScore")
                        vector = cd.get("vectorString")
                        av     = cd.get("attackVector") or cd.get("accessVector")
                        break

                if score and score < 4.0:
                    continue
                if av and av.upper() in ("LOCAL", "PHYSICAL", "ADJACENT_NETWORK"):
                    continue

                qa = cve_to_qa(cve_id, description, cwe_id, cwe_name, score, vector, av)
                if qa:
                    out_fh.write(json.dumps(qa, ensure_ascii=False) + "\n")
                    total_written += 1

            start_idx += page_size
            progress[prog_key] = start_idx
            save_progress(progress)

            if start_idx >= total:
                break

            time.sleep(delay)
            params["startIndex"] = start_idx
            try:
                r = session.get(base, params=params, timeout=30)
                r.raise_for_status()
                data = r.json()
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = 35
                    print(f"  NVD 429 rate-limit — waiting {wait}s then retrying …")
                    time.sleep(wait)
                    try:
                        r = session.get(base, params=params, timeout=30)
                        r.raise_for_status()
                        data = r.json()
                    except Exception as e2:
                        print(f"  NVD retry failed: {e2}")
                        break
                else:
                    print(f"  NVD page fetch error at {start_idx}: {e}")
                    time.sleep(delay * 5)
                    break
            except Exception as e:
                print(f"  NVD page fetch error at {start_idx}: {e}")
                time.sleep(delay * 5)
                break

        progress[prog_key] = total
        save_progress(progress)
        print(f"    → {total_written:,} Q&A pairs total so far")
        time.sleep(delay)

    return total_written


# ─── Source 2: OSV.dev API ───────────────────────────────────────────────────

OSV_WEB_PACKAGES = [
    # npm packages — high-traffic, commonly bounty-relevant
    ("npm", ["express", "axios", "lodash", "jquery", "angular", "react", "vue",
             "webpack", "node-fetch", "request", "got", "superagent", "passport",
             "jsonwebtoken", "helmet", "cors", "body-parser", "multer", "sequelize",
             "mongoose", "bcrypt", "crypto-js", "marked", "dompurify", "sanitize-html",
             "handlebars", "ejs", "pug", "mustache", "nunjucks"]),
    # pypi — web frameworks
    ("PyPI", ["flask", "django", "fastapi", "tornado", "aiohttp", "requests",
              "sqlalchemy", "jinja2", "pillow", "paramiko", "pyyaml", "cryptography",
              "boto3", "celery", "gunicorn", "werkzeug", "wtforms", "httpx"]),
    # go — web libs
    ("Go", ["github.com/gin-gonic/gin", "github.com/gorilla/mux",
            "github.com/labstack/echo", "github.com/beego/beego"]),
]

def osv_vuln_to_qa(vuln: dict) -> Optional[dict]:
    vid     = vuln.get("id", "")
    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or "").strip()
    severity_list = vuln.get("severity") or []
    aliases = vuln.get("aliases") or []
    cve_ref = next((a for a in aliases if a.startswith("CVE-")), None)

    if not details or len(details) < 80:
        if not summary or len(summary) < 40:
            return None
        details = summary

    # Get CVSS score
    score = None
    for s in severity_list:
        if s.get("type") in ("CVSS_V3", "CVSS_V31"):
            vec = s.get("score", "")
            # Parse AV and score from vector string
            try:
                parts = dict(p.split(":") for p in vec.split("/")[1:] if ":" in p)
                # Rough score from vector (we don't have precomputed score in OSV)
            except Exception:
                pass

    # Infer CWE/class from description
    desc_lower = (summary + " " + details).lower()
    if "prototype pollution" in desc_lower:
        cwe_id, cwe_name = "CWE-1321", "Prototype Pollution"
    elif "xss" in desc_lower or "cross-site scripting" in desc_lower:
        cwe_id, cwe_name = "CWE-79", "Cross-Site Scripting (XSS)"
    elif "sql" in desc_lower and "inject" in desc_lower:
        cwe_id, cwe_name = "CWE-89", "SQL Injection"
    elif "ssrf" in desc_lower or "server-side request forgery" in desc_lower:
        cwe_id, cwe_name = "CWE-918", "Server-Side Request Forgery (SSRF)"
    elif "path traversal" in desc_lower or "directory traversal" in desc_lower:
        cwe_id, cwe_name = "CWE-22", "Path Traversal"
    elif "rce" in desc_lower or "remote code execution" in desc_lower or "code injection" in desc_lower:
        cwe_id, cwe_name = "CWE-94", "Code Injection / RCE"
    elif "command injection" in desc_lower:
        cwe_id, cwe_name = "CWE-78", "OS Command Injection"
    elif "deserialization" in desc_lower:
        cwe_id, cwe_name = "CWE-502", "Insecure Deserialization"
    elif "xxe" in desc_lower or "xml external" in desc_lower:
        cwe_id, cwe_name = "CWE-611", "XML External Entity (XXE)"
    elif "csrf" in desc_lower or "cross-site request forgery" in desc_lower:
        cwe_id, cwe_name = "CWE-352", "Cross-Site Request Forgery (CSRF)"
    elif "open redirect" in desc_lower:
        cwe_id, cwe_name = "CWE-601", "Open Redirect"
    elif "auth" in desc_lower and ("bypass" in desc_lower or "weak" in desc_lower):
        cwe_id, cwe_name = "CWE-287", "Authentication Bypass"
    elif "information disclosure" in desc_lower or "sensitive" in desc_lower:
        cwe_id, cwe_name = "CWE-200", "Sensitive Information Disclosure"
    elif "file upload" in desc_lower:
        cwe_id, cwe_name = "CWE-434", "Unrestricted File Upload"
    elif "idor" in desc_lower or "insecure direct object" in desc_lower:
        cwe_id, cwe_name = "CWE-639", "Insecure Direct Object Reference (IDOR)"
    else:
        return None  # skip unclassifiable entries

    # Get affected package info
    affected = vuln.get("affected") or []
    pkg_name = ""
    if affected:
        pkg = affected[0].get("package", {})
        pkg_name = pkg.get("name", "")

    ref_id = cve_ref or vid
    asset  = f"open-source library ({pkg_name})" if pkg_name else "web application"

    sev = severity_label(score)
    score_str = f"{score:.1f}" if score else "CVSS not available"

    human = (
        f"Vulnerability Class: {cwe_name}\n"
        f"Asset Type: {asset}\n"
        f"Reference: {ref_id}\n"
        f"\nScenario:\n"
        f"You are assessing a web application that uses {pkg_name or 'a third-party library'}. "
        f"The following vulnerability was reported:\n\n{details}\n\n"
        f"Analyze this vulnerability: describe the attack vector, exploitation technique, "
        f"real-world exploitability, and how you would report this as a bug bounty finding if "
        f"you discovered it on a target that uses this library."
    )

    # Reuse cve_to_qa's structured answer
    qa = cve_to_qa(ref_id, details, cwe_id, cwe_name, score, None, "Network")
    if qa is None:
        return None
    # Replace human turn with our richer OSV framing
    qa["conversations"][1]["value"] = human
    return qa


def scrape_osv(progress: dict, out_fh) -> int:
    """Pull vulnerability records from OSV.dev for web-relevant packages."""
    base = "https://api.osv.dev/v1"
    total_written = 0
    session = requests.Session()

    for ecosystem, packages in OSV_WEB_PACKAGES:
        for pkg in packages:
            prog_key = f"osv:{ecosystem}:{pkg}"
            if progress.get(prog_key) == "done":
                continue

            try:
                r = session.post(
                    f"{base}/query",
                    json={"package": {"name": pkg, "ecosystem": ecosystem}},
                    timeout=20,
                )
                r.raise_for_status()
                vulns = r.json().get("vulns") or []
            except Exception as e:
                print(f"  OSV {ecosystem}/{pkg} error: {e}")
                time.sleep(2)
                continue

            for vuln in vulns:
                qa = osv_vuln_to_qa(vuln)
                if qa:
                    out_fh.write(json.dumps(qa, ensure_ascii=False) + "\n")
                    total_written += 1

            progress[prog_key] = "done"
            save_progress(progress)
            time.sleep(0.3)

    print(f"  OSV: wrote {total_written} Q&A pairs")
    return total_written


# ─── Source 3: GitHub Advisory Database (local clone) ────────────────────────

def scrape_ghsa(db_path: str, progress: dict, out_fh) -> int:
    """Process a local clone of github/advisory-database."""
    db = Path(db_path)
    if not db.exists():
        print(f"  GHSA path not found: {db_path}")
        return 0

    total_written = 0
    reviewed_dir = db / "advisories" / "github-reviewed"

    if not reviewed_dir.exists():
        print(f"  Expected {reviewed_dir} — is this the advisory-database repo?")
        return 0

    # Web-relevant ecosystems only
    web_ecosystems = {"npm", "pip", "go", "rust", "maven", "composer", "rubygems"}

    json_files = list(reviewed_dir.rglob("*.json"))
    print(f"  GHSA: found {len(json_files):,} advisory files")

    for jf in json_files:
        if progress.get(f"ghsa:{jf.name}") == "done":
            continue

        try:
            data = json.loads(jf.read_text())
        except Exception:
            continue

        # Filter to web ecosystems
        affected = data.get("affected") or []
        ecosystems = {(a.get("package") or {}).get("ecosystem", "").lower() for a in affected}
        if not ecosystems.intersection(web_ecosystems):
            continue

        summary  = (data.get("summary") or "").strip()
        details  = (data.get("details") or "").strip()
        ghsa_id  = data.get("id", jf.stem)
        aliases  = data.get("aliases") or []
        cve_ref  = next((a for a in aliases if a.startswith("CVE-")), ghsa_id)

        desc = details if len(details) >= 80 else summary
        if len(desc) < 80:
            continue

        # Get severity from database_specific CVSS
        score = None
        for sev in data.get("severity") or []:
            if sev.get("type") in ("CVSS_V3", "CVSS_V31"):
                # OSV doesn't always include numeric score, skip if missing
                break

        # Use the OSV converter
        fake_vuln = {
            "id": ghsa_id,
            "summary": summary,
            "details": details,
            "aliases": aliases,
            "affected": affected,
            "severity": data.get("severity") or [],
        }
        qa = osv_vuln_to_qa(fake_vuln)
        if qa:
            out_fh.write(json.dumps(qa, ensure_ascii=False) + "\n")
            total_written += 1

        progress[f"ghsa:{jf.name}"] = "done"

        if total_written % 500 == 0 and total_written > 0:
            save_progress(progress)
            print(f"    → {total_written} written")

    save_progress(progress)
    print(f"  GHSA: wrote {total_written} Q&A pairs")
    return total_written


# ─── Progress helpers ─────────────────────────────────────────────────────────

def load_progress() -> dict:
    if PROG_FILE.exists():
        return json.loads(PROG_FILE.read_text())
    return {}


def save_progress(progress: dict):
    PROG_FILE.write_text(json.dumps(progress, indent=2))


# ─── Dedup existing output ────────────────────────────────────────────────────

def load_existing_keys() -> set:
    keys = set()
    if OUT_FILE.exists():
        with open(OUT_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        conv = json.loads(line)
                        human = conv["conversations"][1]["value"]
                        keys.add(human[:100].lower().strip())
                    except Exception:
                        pass
    return keys


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scrape real vuln data for fine-tuning")
    parser.add_argument("--nvd",  action="store_true", help="Scrape NVD CVE API")
    parser.add_argument("--osv",  action="store_true", help="Scrape OSV.dev API")
    parser.add_argument("--ghsa", metavar="PATH", help="Path to github/advisory-database clone")
    args = parser.parse_args()

    if not any([args.nvd, args.osv, args.ghsa]):
        parser.print_help()
        print("\nTip: run with --nvd --osv for a full pull (no auth needed)")
        sys.exit(0)

    progress = load_progress()
    total = 0

    # Append to existing file (resume-safe)
    with open(OUT_FILE, "a") as out_fh:
        if args.osv:
            print("\n[OSV.dev] Scraping package vulnerability data …")
            total += scrape_osv(progress, out_fh)

        if args.nvd:
            print("\n[NVD] Scraping CVE database for web CWEs …")
            total += scrape_nvd(progress, out_fh)

        if args.ghsa:
            print(f"\n[GHSA] Processing local advisory database at {args.ghsa} …")
            total += scrape_ghsa(args.ghsa, progress, out_fh)

    size_mb = OUT_FILE.stat().st_size / 1024 / 1024
    print(f"\n{'='*60}")
    print(f"  Scrape complete")
    print(f"  Output file   : {OUT_FILE}")
    print(f"  Q&A pairs     : {total:,} written this run")
    print(f"  File size     : {size_mb:.1f} MB")
    print(f"\n  Next: re-run export-finetune-jsonl.py to merge everything")
    print("=" * 60)


if __name__ == "__main__":
    main()

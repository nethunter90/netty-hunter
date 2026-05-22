const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox','--disable-setuid-sandbox'] });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addCookies([{
    name: 'connect.sid',
    value: 's%3AUxilcVF_pRpGEveniFsNm3brfrNpI6g_.%2FET9%2FVdW2fllz5Lb4JRvSFjDhtxP%2Bo6MkdoQCpVHpf8',
    domain: 'localhost', path: '/', httpOnly: true, secure: false,
  }]);
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push('PAGEERROR: ' + e.message.slice(0,150)));

  async function visit(label, url, clickSel, waitMs) {
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(waitMs || 2000);
    if (clickSel) {
      const el = page.locator(clickSel).first();
      if (await el.isVisible().catch(() => false)) { await el.click(); await page.waitForTimeout(1500); }
    }
    await page.screenshot({ path: `/tmp/sweep-${label}.png` });
    const body = (await page.textContent('body').catch(()=>'')).replace(/\s+/g,' ');
    console.log(`[${label}] ${page.url()} | ${body.slice(0,180)}`);
  }

  // Orchestration
  await visit('orchestration', 'http://localhost:5173/orchestration');

  // Bounty sub-views (nav clicks from /bounty)
  const bountyItems = [
    ['analysis',      'text=Analysis'],
    ['submissions',   'text=Submissions'],
    ['scope',         'text=Scope'],
    ['reports',       'text=Reports'],
    ['nuclei',        'text=Nuclei'],
    ['payloads',      'text=Payloads'],
    ['deadlines',     'text=Deadlines'],
    ['backward-hunt', 'text=Backward Hunt'],
    ['tool-ready',    'text=Tool Readiness'],
    ['browser',       'text=Browser'],
    ['ai-advisor',    'text=AI Advisor'],
    ['workflow',      'text=Workflow'],
    ['tasks',         'text=Tasks'],
    ['opsec',         'text=OpSec Intel'],
    ['cve-intel',     'text=CVE Intel'],
    ['poc-lab',       'text=PoC Lab'],
    ['hunt-replay',   'text=Hunt Replay'],
    ['ctf-bench',     'text=CTF Bench'],
  ];
  for (const [label, sel] of bountyItems) {
    await page.goto('http://localhost:5173/bounty', { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.waitForTimeout(1500);
    const el = page.locator(sel).first();
    if (await el.isVisible().catch(() => false)) {
      await el.click();
      await page.waitForTimeout(2000);
    }
    await page.screenshot({ path: `/tmp/sweep-bounty-${label}.png` });
    const body = (await page.textContent('body').catch(()=>'')).replace(/\s+/g,' ');
    console.log(`[bounty-${label}] ${page.url()} | ${body.slice(150, 380)}`);
  }

  console.log('\nPage errors:', errs.length, JSON.stringify(errs.slice(0,5)));
  await browser.close();
})().catch(e => { console.error('FATAL:', e.message); process.exit(1); });

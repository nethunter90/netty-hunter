import "dotenv/config";
(async () => {
  const { default: WAFBypass } = await import('../server/src/agents/WAFBypass');
  const { stealthCoordinator } = await import('../server/src/lib/stealth/index');
  const s = new WAFBypass() as any;
  const t0 = Date.now();
  const ms = () => (Date.now()-t0)+'ms';
  const url = 'http://localhost:3001';

  console.log(`[${ms()}] step 1: fingerprint`);
  const { waf } = await s.fingerprinter.fingerprint(url);
  console.log(`[${ms()}] step 1 done — waf: ${waf.vendor}`);

  console.log(`[${ms()}] step 2: recommendTechniques`);
  const techs = s.library.recommendTechniques(waf.vendor);
  console.log(`[${ms()}] step 2 done — techs: ${techs.length}`);

  console.log(`[${ms()}] step 3: generateVariants`);
  const variants = s.library.generateVariants('<script>x</script>', techs);
  console.log(`[${ms()}] step 3 done — variants: ${variants.length}`);

  console.log(`[${ms()}] step 4: getProfile`);
  await s.vendorProfiles.getProfile(waf.vendor, 'localhost');
  console.log(`[${ms()}] step 4 done`);

  console.log(`[${ms()}] step 5: prepareProbe (first variant)`);
  const probe = await stealthCoordinator.prepareProbe(
    url, variants[0]?.payload ?? 'x', 'waf_bypass',
    { sessionId: 'test', domain: 'localhost', vendor: waf.vendor, stealthMode: 'balanced' }
  );
  console.log(`[${ms()}] step 5 done — delayMs: ${probe.delayMs}`);

  if (probe.delayMs > 0) {
    console.log(`[${ms()}] SLEEPING ${probe.delayMs}ms (probe delay)`);
  }

  console.log(`[${ms()}] step 6: executor.execute`);
  const result = await s.executor.execute(url, variants[0]?.payload ?? 'x', variants[0]?.technique ?? 'plain');
  console.log(`[${ms()}] step 6 done — success: ${result.success}`);

  console.log(`[${ms()}] ALL STEPS COMPLETE`);
  process.exit(0);
})().catch(e => { console.error('FATAL:', e.message); process.exit(1); });

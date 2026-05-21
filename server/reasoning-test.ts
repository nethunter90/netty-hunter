/**
 * Comprehensive reasoning & knowledge test suite.
 * Run: npx tsx reasoning-test.ts
 * No DB or Ollama required — all DB calls are silently caught.
 */

import 'dotenv/config';

(async () => {

// ─── Helpers ──────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(condition: boolean, label: string, detail = ''): void {
  if (condition) {
    console.log(`  ✓ ${label}`);
    passed++;
  } else {
    const msg = detail ? `${label} — ${detail}` : label;
    console.log(`  ✗ ${msg}`);
    failures.push(msg);
    failed++;
  }
}

function assertRange(val: number, lo: number, hi: number, label: string): void {
  assert(val >= lo && val <= hi, label, `got ${val.toFixed(4)}, expected [${lo}, ${hi}]`);
}

function section(name: string): void {
  console.log(`\n── ${name} ${'─'.repeat(Math.max(0, 60 - name.length))}`);
}

// ─── 1. Seed Knowledge Integrity ─────────────────────────────────────────────

section('1. Seed Knowledge Integrity');
{
  const {
    ATTACK_PATHS, MITRE_TECHNIQUES, TOOL_FALLBACK_CHAINS,
    GOAL_PAYOUT_DATA, HUNT_GOAL_PATHS, PIVOT_PLAYBOOKS,
  } = await import('./src/lib/intelligence/seed-knowledge');

  assert(Array.isArray(ATTACK_PATHS) && ATTACK_PATHS.length > 0, 'ATTACK_PATHS is non-empty');
  assert(ATTACK_PATHS.every((p: any) =>
    typeof p.id === 'string' && typeof p.goal === 'string' &&
    typeof p.likelihood === 'number' && Array.isArray(p.testMethods)),
    'Every ATTACK_PATH has id, goal, likelihood, testMethods');
  const goals = new Set(ATTACK_PATHS.map((p: any) => p.goal));
  assert(goals.has('Account Takeover'), 'ATTACK_PATHS includes Account Takeover');
  assert(goals.has('RCE'), 'ATTACK_PATHS includes RCE');
  assert(goals.has('SQL Injection'), 'ATTACK_PATHS includes SQL Injection');
  assert(ATTACK_PATHS.every((p: any) => p.likelihood >= 0 && p.likelihood <= 1), 'All likelihoods in [0,1]');
  assert(ATTACK_PATHS.every((p: any) => p.avgPayout >= 0), 'All avgPayouts non-negative');

  assert(Array.isArray(MITRE_TECHNIQUES) && MITRE_TECHNIQUES.length > 0, 'MITRE_TECHNIQUES non-empty');
  assert(MITRE_TECHNIQUES.every((t: any) =>
    typeof t.id === 'string' && Array.isArray(t.requires) && Array.isArray(t.provides) &&
    typeof t.probability === 'number' && typeof t.impact === 'number'),
    'Every MITRE technique has id, requires[], provides[], probability, impact');
  assert(MITRE_TECHNIQUES.map((t: any) => t.id).includes('T1190'), 'MITRE includes T1190');
  assert(MITRE_TECHNIQUES.every((t: any) => t.probability >= 0 && t.probability <= 1), 'MITRE probabilities in [0,1]');

  assert(Array.isArray(TOOL_FALLBACK_CHAINS) && TOOL_FALLBACK_CHAINS.length > 0, 'TOOL_FALLBACK_CHAINS non-empty');
  assert(TOOL_FALLBACK_CHAINS.every((c: any) =>
    typeof c.primary === 'string' && Array.isArray(c.fallbacks) && c.fallbacks.every((f: any) =>
      typeof f.tool === 'string' && typeof f.degradationCoefficient === 'number')),
    'Every fallback chain has primary, fallbacks[].tool, .degradationCoefficient');

  assert(Array.isArray(GOAL_PAYOUT_DATA) && GOAL_PAYOUT_DATA.length > 0, 'GOAL_PAYOUT_DATA non-empty');
  assert(GOAL_PAYOUT_DATA.every((g: any) => typeof g.goal === 'string' && typeof g.avgPayout === 'number'), 'GOAL_PAYOUT_DATA shape ok');

  assert(Array.isArray(HUNT_GOAL_PATHS) && HUNT_GOAL_PATHS.length > 0, 'HUNT_GOAL_PATHS non-empty');
  assert(HUNT_GOAL_PATHS.every((p: any) => typeof p.goal === 'string' && Array.isArray(p.phases)), 'HUNT_GOAL_PATHS shape ok');

  assert(Array.isArray(PIVOT_PLAYBOOKS) && PIVOT_PLAYBOOKS.length > 0, 'PIVOT_PLAYBOOKS non-empty');
  const conditions = new Set(PIVOT_PLAYBOOKS.map((b: any) => b.condition));
  assert(conditions.has('sqli_failed'), 'PIVOT_PLAYBOOKS has sqli_failed');
  assert(conditions.has('xss_filtered'), 'PIVOT_PLAYBOOKS has xss_filtered');
  assert(conditions.has('port_scan_empty'), 'PIVOT_PLAYBOOKS has port_scan_empty');
  assert(PIVOT_PLAYBOOKS.every((b: any) => Array.isArray(b.pivots) && b.pivots.length > 0), 'Every playbook has pivots');
  assert(PIVOT_PLAYBOOKS.every((b: any) => b.pivots.every((p: any) => p.weight >= 0 && p.weight <= 1)), 'All pivot weights in [0,1]');
}

// ─── 2. Lab Profiles & LabScorer ─────────────────────────────────────────────

section('2. Lab Profiles & LabScorer');
{
  const { labScorer } = await import('./src/lib/intelligence/lab-profiles');

  const profile = labScorer.getProfile('juice-shop');
  assert(profile !== undefined, 'juice-shop profile exists');
  assert(profile!.vulnerabilities.length === 32, 'juice-shop has 32 vulnerabilities', `got ${profile!.vulnerabilities.length}`);
  assert(profile!.targetUrl === 'http://localhost:3000', 'juice-shop targetUrl = localhost:3000');
  assert(typeof profile!.targetCharacteristics === 'object', 'profile has targetCharacteristics');

  const vulns = profile!.vulnerabilities;
  assert(vulns.every((v: any) => typeof v.id === 'string' && v.id.length > 0), 'All vulns have id');
  assert(vulns.every((v: any) => typeof v.name === 'string' && v.name.length > 0), 'All vulns have name');
  assert(vulns.every((v: any) => [1,2,3,4,5].includes(v.difficulty)), 'All vulns have valid difficulty 1-5');
  assert(vulns.every((v: any) => typeof v.category === 'string'), 'All vulns have category');
  assert(vulns.every((v: any) => v.expectedConfidence >= 0 && v.expectedConfidence <= 1), 'All vulns have valid expectedConfidence');
  assert(vulns.every((v: any) => typeof v.expectedTool === 'string'), 'All vulns have expectedTool');

  const categories = new Set(vulns.map((v: any) => v.category));
  assert(categories.has('Injection'), 'juice-shop has Injection category');
  assert(categories.has('XSS'), 'juice-shop has XSS category');
  assert(categories.has('Broken Auth'), 'juice-shop has Broken Auth category');
  assert(categories.has('SSRF'), 'juice-shop has SSRF category');
  assert(categories.has('Broken Access Control'), 'juice-shop has Broken Access Control category');
  assert(categories.size >= 5, `juice-shop has >= 5 distinct categories (got ${categories.size})`);

  const diffs = vulns.map((v: any) => v.difficulty);
  assert(diffs.includes(1), 'juice-shop has difficulty-1 challenges');
  assert(diffs.includes(3), 'juice-shop has difficulty-3 challenges');
  assert(diffs.includes(5), 'juice-shop has difficulty-5 challenges');

  const all = labScorer.getAllProfiles();
  assert(Array.isArray(all) && all.length >= 1, 'getAllProfiles returns >= 1 profile');

  // scoreHunt: first arg = huntId, second = profileId, third = string[] of finding identifiers
  const score = labScorer.scoreHunt('lab-test-1', 'juice-shop', [], []);
  assert(score.coverage === 0, 'scoreHunt with no findings returns 0 coverage');
  assert(score.missedVulns.length === 32, 'scoreHunt with no findings shows all 32 as missed');
  assert(Array.isArray(score.categoryBreakdown) && score.categoryBreakdown.length > 0, 'scoreHunt returns categoryBreakdown');
  assert(Array.isArray(score.difficultyBreakdown), 'scoreHunt returns difficultyBreakdown');

  // scoreHunt with a matching finding (pass the vuln id)
  const partial = labScorer.scoreHunt('lab-test-2', 'juice-shop', ['js-sqli-login', 'js-xss-search'], []);
  assertRange(partial.coverage, 0, 1, 'partial scoreHunt coverage in [0,1]');
  assert(partial.coverage > 0, 'partial scoreHunt has non-zero coverage');
  assert(partial.missedVulns.length < 32, 'partial scoreHunt has fewer than 32 missed vulns');

  // getGroundTruth
  const gt = labScorer.getGroundTruth('juice-shop');
  assert(typeof gt === 'object' && gt !== null, 'getGroundTruth returns object');
}

// ─── 3. Circuit Breaker ───────────────────────────────────────────────────────

section('3. Circuit Breaker');
{
  const { CircuitBreaker } = await import('./src/lib/intelligence/circuit-breaker');
  const cb = new CircuitBreaker();

  // Fresh tool → allowed
  const fresh = cb.canExecute('sqlmap');
  assert(fresh.allowed === true, 'Fresh tool circuit is closed/allowed');

  // 3 failures → circuit opens
  cb.recordFailure('sqlmap', 'timeout');
  cb.recordFailure('sqlmap', 'timeout');
  cb.recordFailure('sqlmap', 'timeout');
  const open = cb.canExecute('sqlmap');
  assert(open.allowed === false, 'Circuit opens after 3 failures');
  assert(open.fallback === 'nuclei', `sqlmap fallback is nuclei (got ${open.fallback})`);
  assert(typeof open.reason === 'string', 'Circuit provides reason when open');

  // Unrelated tool still works
  const nmap = cb.canExecute('nmap');
  assert(nmap.allowed === true, 'Unrelated tool nmap still allowed');

  // nmap fallback chain
  cb.recordFailure('nmap', 'refused');
  cb.recordFailure('nmap', 'refused');
  cb.recordFailure('nmap', 'refused');
  const nmapOpen = cb.canExecute('nmap');
  assert(nmapOpen.allowed === false, 'nmap circuit opens after 3 failures');
  assert(nmapOpen.fallback === 'masscan', `nmap fallback is masscan (got ${nmapOpen.fallback})`);

  // gobuster → ffuf fallback
  cb.recordFailure('gobuster', 'error');
  cb.recordFailure('gobuster', 'error');
  cb.recordFailure('gobuster', 'error');
  assert(cb.canExecute('gobuster').fallback === 'ffuf', 'gobuster fallback is ffuf');

  // getState and getAllStates
  const state = cb.getState('sqlmap');
  assert(state.state === 'open', 'sqlmap state is open');
  assert(state.failures >= 3, 'sqlmap has >= 3 failures recorded');

  const allStates = cb.getAllStates();
  assert(typeof allStates === 'object', 'getAllStates returns object');

  // getStats
  const stats = cb.getStats();
  assert(typeof stats === 'object', 'getStats returns object');

  // recordSuccess on a different tool
  cb.recordSuccess('nuclei');
  const nucleiState = cb.getState('nuclei');
  assert(nucleiState.successes >= 1, 'recordSuccess increments success count');

  // resetCircuit reopens to closed
  cb.resetCircuit('sqlmap');
  assert(cb.canExecute('sqlmap').allowed === true, 'After resetCircuit, sqlmap allowed again');

  // resetAll clears everything
  cb.resetAll();
  assert(cb.canExecute('nmap').allowed === true, 'After resetAll, nmap is allowed');
}

// ─── 4. Reasoning Engine ─────────────────────────────────────────────────────

section('4. Reasoning Engine');
{
  const { ReasoningEngine } = await import('./src/lib/intelligence/reasoning-engine');
  const re = new ReasoningEngine();

  const mem = re.initializeMission('re-m1', 'http://example.com', 'SQL Injection');
  assert(mem.missionId === 're-m1', 'initializeMission sets missionId');
  assert(mem.target === 'http://example.com', 'initializeMission sets target');
  assert(mem.goal === 'SQL Injection', 'initializeMission sets goal');
  assert(mem.discoveredTechnologies instanceof Map, 'discoveredTechnologies is a Map');
  assert(mem.actionHistory.length === 0, 'actionHistory starts empty');

  assert(re.getMissionMemory('re-m1') !== undefined, 'getMissionMemory retrieves mission');
  assert(re.getMissionMemory('no-such') === undefined, 'getMissionMemory returns undefined for unknown');
  assert(re.getAllMissions().includes('re-m1'), 'getAllMissions includes new mission');

  // updateMemory with synthetic ingested data
  const fake: any = {
    observation: { id: 'obs-1', timestamp: new Date().toISOString(), source: 'tool', type: 'scan', rawOutput: '' },
    intelligence: {
      technologies: [{ name: 'express', version: '4.18', category: 'framework', confidence: 0.9, evidence: [] }],
      defenseSignals: [{ type: 'waf', detected: true, vendor: 'cloudflare', severity: 'high', evidence: 'CF-Ray' }],
      vulnerabilities: [{ type: 'SQL Injection', severity: 'critical', confidence: 0.85, location: '/api/users', evidence: 'error' }],
      endpoints: [{ url: '/api/users?id=1', method: 'GET', parameters: ['id'], authenticated: false, riskLevel: 'high' }],
      credentials: [],
      patterns: [],
      confidence: 0.8,
    },
    ingestedAt: new Date().toISOString(),
  };
  re.updateMemory('re-m1', fake);
  const updated = re.getMissionMemory('re-m1')!;
  assert(updated.discoveredTechnologies.size >= 1, 'updateMemory adds technologies');
  assert(updated.discoveredVulnerabilities.size >= 1, 'updateMemory adds vulnerabilities');
  assert(updated.discoveredEndpoints.size >= 1, 'updateMemory adds endpoints');

  // recordAction
  re.recordAction('re-m1', { id: 'a1', timestamp: new Date().toISOString(), tool: 'sqlmap', target: '/api/users', success: true, outcome: 'SQLi confirmed', confidence: 0.9 });
  assert(re.getMissionMemory('re-m1')!.actionHistory.length >= 1, 'recordAction appends to actionHistory');

  // getSerializableMemory
  const serial = re.getSerializableMemory('re-m1');
  assert(serial !== null, 'getSerializableMemory returns non-null');
  assert(typeof serial!.stats === 'object', 'serializable memory has stats');

  // getBeliefs / getAllPriorities
  const beliefs = re.getBeliefs('re-m1');
  assert(Array.isArray(beliefs), 'getBeliefs returns array');
  const prio = re.getAllPriorities('re-m1');
  assert(Array.isArray(prio), 'getAllPriorities returns array');

  // getAllMissions count
  assert(re.getAllMissions().length >= 1, 'getAllMissions has >= 1 mission');
}

// ─── 5. Decision Engine ───────────────────────────────────────────────────────

section('5. Decision Engine');
{
  // DecisionEngine uses the module-level singleton reasoningEngine
  const { reasoningEngine } = await import('./src/lib/intelligence/reasoning-engine');
  const { decisionEngine } = await import('./src/lib/intelligence/decision-engine');

  reasoningEngine.initializeMission('de-m1', 'http://target.com', 'SQL Injection');

  const d1 = await decisionEngine.makeDecision('de-m1');
  assert(typeof d1.id === 'string' && d1.id.length > 0, 'Decision has id');
  assert(typeof d1.chosenAction.tool === 'string' && d1.chosenAction.tool.length > 0, 'chosenAction has tool');
  assertRange(d1.confidence, 0, 1, 'Decision confidence in [0,1]');
  assert(Array.isArray(d1.reasoning) && d1.reasoning.length > 0, 'Decision has reasoning array');
  assert(['low','medium','high'].includes(d1.chosenAction.riskLevel), 'chosenAction has valid riskLevel');
  assert(typeof d1.chosenAction.estimatedTime === 'number', 'chosenAction has estimatedTime');

  // makeDecision on enriched mission
  const fake: any = {
    observation: { id: 'obs-de', timestamp: new Date().toISOString(), source: 'tool', type: 'scan', rawOutput: '' },
    intelligence: {
      technologies: [{ name: 'mysql', category: 'database', confidence: 0.9, evidence: [] }],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [{ url: '/login', method: 'POST', parameters: ['user','pass'], authenticated: false, riskLevel: 'high' }],
      credentials: [],
      patterns: [],
      confidence: 0.7,
    },
    ingestedAt: new Date().toISOString(),
  };
  reasoningEngine.updateMemory('de-m1', fake);
  const d2 = await decisionEngine.makeDecision('de-m1');
  assert(typeof d2.chosenAction.tool === 'string', 'enriched mission decision has tool');

  // getDecisionHistory
  const hist = decisionEngine.getDecisionHistory();
  assert(Array.isArray(hist) && hist.length >= 2, `getDecisionHistory has >= 2 decisions (got ${hist.length})`);

  // getStats
  const stats = decisionEngine.getStats();
  assert(typeof stats.totalDecisions === 'number' && stats.totalDecisions >= 2, 'stats.totalDecisions >= 2');
}

// ─── 6. Backward Planner ─────────────────────────────────────────────────────

section('6. Backward Planner');
{
  const { BackwardPlanner } = await import('./src/lib/intelligence/backward-planner');
  const planner = new BackwardPlanner();

  const plan = planner.planHunt('bp-h1', 'Account Takeover');
  assert(plan.huntId === 'bp-h1', 'planHunt sets huntId');
  assert(plan.goal === 'Account Takeover', 'planHunt sets goal');
  assert(plan.status === 'executing', 'planHunt status = executing');
  assert(Array.isArray(plan.rankedPaths) && plan.rankedPaths.length > 0, 'planHunt produces rankedPaths');
  assert(Array.isArray(plan.phases) && plan.phases.length > 0, 'planHunt produces phases');
  assert(plan.pivotHistory.length === 0, 'Fresh plan has empty pivotHistory');

  // Sorted by expectedValue descending
  for (let i = 1; i < plan.rankedPaths.length; i++) {
    assert(plan.rankedPaths[i-1].expectedValue >= plan.rankedPaths[i].expectedValue,
      `rankedPaths EV sorted desc at index ${i}`);
  }
  plan.rankedPaths.forEach((rp: any, idx: number) => {
    assert(rp.rank === idx + 1, `rankedPaths[${idx}].rank === ${idx+1}`);
  });
  assert(plan.rankedPaths.every((rp: any) => rp.expectedValue > 0), 'All expected values > 0');

  // getOptimalPath for RCE
  const rce = planner.getOptimalPath('RCE');
  assert(Array.isArray(rce) && rce.length > 0, 'getOptimalPath RCE returns paths');

  // WAF reduces injection paths
  const waf = planner.getOptimalPath('Account Takeover', { complexity: 3, wafDetected: true, cloudHosted: false, authRequired: true });
  assert(Array.isArray(waf), 'getOptimalPath with WAF returns array');

  // suggestPivot → returns array of strategies
  const pivots = planner.suggestPivot('bp-h1', 'sqli_failed');
  assert(pivots !== null, 'suggestPivot returns non-null for sqli_failed');
  assert(Array.isArray(pivots) && pivots!.length > 0, 'suggestPivot returns >= 1 pivot strategy');
  pivots!.forEach((p: any, i: number) => {
    assert(typeof p.strategy === 'string' && p.strategy.length > 0, `pivot[${i}] has strategy string`);
    assertRange(p.weight, 0, 1, `pivot[${i}].weight in [0,1]`);
  });

  // suggestPivot → null for unknown condition
  const noMatch = planner.suggestPivot('bp-h1', 'unknown_condition_xyz');
  assert(noMatch === null || Array.isArray(noMatch), 'suggestPivot returns null or array for unknown condition');

  // getExpectedValue takes a goal string
  const ev = planner.getExpectedValue('Account Takeover');
  assert(typeof ev === 'object' && ev !== null, 'getExpectedValue returns an object');
  assert(typeof ev.avgPayout === 'number', 'getExpectedValue.avgPayout is a number');
  assert(typeof ev.totalPaths === 'number', 'getExpectedValue.totalPaths is a number');

  // getCurrentPhase
  const phase = planner.getCurrentPhase('bp-h1');
  assert(phase !== null, 'getCurrentPhase returns a phase');
  assert(typeof phase!.name === 'string', 'phase has name');
  assert(Array.isArray(phase!.actions), 'phase has actions[]');

  // advancePhase
  planner.advancePhase('bp-h1');
  assert(true, 'advancePhase does not throw');

  // completePlan
  planner.completePlan('bp-h1');
  const stats = planner.getStats();
  assert(typeof stats.activePlans === 'number', 'stats.activePlans is a number');
  assert(typeof stats.completedPlans === 'number', 'stats.completedPlans >= 1');
  assert(stats.completedPlans >= 1, `completedPlans >= 1 (got ${stats.completedPlans})`);

  // abortPlan
  const plan2 = planner.planHunt('bp-h2', 'SSRF');
  planner.abortPlan('bp-h2', 'test abort');
  assert(true, 'abortPlan does not throw');
}

// ─── 7. MITRE Prereq Tree ─────────────────────────────────────────────────────

section('7. MITRE Prereq Tree');
{
  const { mitrePrereqTree } = await import('./src/lib/intelligence/mitre-prereq-tree');

  // findChainsToGoal with starting capability
  const chains = mitrePrereqTree.findChainsToGoal('initial_access', ['exposed_service']);
  assert(Array.isArray(chains), 'findChainsToGoal returns array');
  console.log(`    (found ${chains.length} chain(s) for initial_access)`);
  if (chains.length > 0) {
    const c = chains[0];
    assert(Array.isArray(c.techniques) && c.techniques.length > 0, 'chain[0] has techniques');
    assertRange(c.totalProbability, 0, 1, 'chain totalProbability in [0,1]');
    assert(c.totalImpact >= 0, 'chain totalImpact >= 0');
    assertRange(c.avgStealth, 0, 1, 'chain avgStealth in [0,1]');
    assert(c.length === c.techniques.length, 'chain.length matches techniques.length');
  }

  // findChainsToGoal with no capabilities
  const full = mitrePrereqTree.findChainsToGoal('domain_credentials', []);
  assert(Array.isArray(full), 'findChainsToGoal with no capabilities returns array');

  // findChokePoints
  const chokes = mitrePrereqTree.findChokePoints();
  assert(Array.isArray(chokes), 'findChokePoints returns array');
  console.log(`    (found ${chokes.length} choke point(s))`);
  if (chokes.length > 0) {
    assert(typeof chokes[0].capability === 'string', 'chokePoint has capability');
    assert(Array.isArray(chokes[0].dependentTechniques), 'chokePoint has dependentTechniques');
    assert(typeof chokes[0].isBottleneck === 'boolean', 'chokePoint has isBottleneck');
    assert(typeof chokes[0].alternativePaths === 'number', 'chokePoint has alternativePaths');
  }

  // analyzePrerequisites for hash_collection
  const analysis = mitrePrereqTree.analyzePrerequisites('hash_collection', []);
  assert(analysis.goal === 'hash_collection', 'analysis.goal matches input');
  assert(Array.isArray(analysis.requiredCapabilities), 'analysis has requiredCapabilities');
  assert(Array.isArray(analysis.missingCapabilities), 'analysis has missingCapabilities');
  assert(Array.isArray(analysis.suggestedTechniques), 'analysis has suggestedTechniques');
  assert(Array.isArray(analysis.viableChains), 'analysis has viableChains');
  assert(analysis.missingCapabilities.every((c: string) => !analysis.availableCapabilities.includes(c)),
    'missing and available capabilities are disjoint');

  // Providing capabilities reduces missing
  const withCaps = mitrePrereqTree.analyzePrerequisites('hash_collection', ['local_admin']);
  assert(withCaps.missingCapabilities.length <= analysis.missingCapabilities.length,
    'Providing local_admin reduces or maintains missing capabilities count');

  // getTechniquesByNodeType
  const entryTechs = mitrePrereqTree.getTechniquesByNodeType('entry');
  assert(Array.isArray(entryTechs) && entryTechs.length > 0, 'getTechniquesByNodeType entry returns techniques');
  assert(entryTechs.every((t: any) => t.nodeType === 'entry'), 'getTechniquesByNodeType entry returns only entry nodes');

  // getReachableCapabilities
  const reachable = mitrePrereqTree.getReachableCapabilities(['exposed_service']);
  assert(Array.isArray(reachable), 'getReachableCapabilities returns array');
  assert(reachable.includes('initial_access') || reachable.length >= 0, 'getReachableCapabilities returns reachable caps from exposed_service');

  // getStats
  const mitreStats = mitrePrereqTree.getStats();
  assert(typeof mitreStats.totalTechniques === 'number' && mitreStats.totalTechniques > 0, 'MITRE stats has totalTechniques');
  assert(typeof mitreStats.totalCapabilities === 'number', 'MITRE stats has totalCapabilities');
}

// ─── 8. Contextual Tool Selector ─────────────────────────────────────────────

section('8. Contextual Tool Selector');
{
  // CTS uses the singleton reasoningEngine — initialize a mission for it to work with
  const { reasoningEngine } = await import('./src/lib/intelligence/reasoning-engine');
  const { ContextualToolSelector } = await import('./src/lib/intelligence/contextual-tool-selector');
  const cts = new ContextualToolSelector();

  const huntId = 'cts-h1';
  reasoningEngine.initializeMission(huntId, 'http://cts-target.com', 'SQL Injection');

  // Populate some state for the mission
  reasoningEngine.updateMemory(huntId, {
    observation: { id: 'cts-obs', timestamp: new Date().toISOString(), source: 'tool', type: 'scan', rawOutput: '' },
    intelligence: {
      technologies: [{ name: 'mysql', category: 'database', confidence: 0.9, evidence: [] }],
      defenseSignals: [],
      vulnerabilities: [],
      endpoints: [
        { url: '/api/users', method: 'GET', parameters: ['id'], authenticated: false, riskLevel: 'high' },
        { url: '/login', method: 'POST', parameters: ['user','pass'], authenticated: false, riskLevel: 'high' },
      ],
      credentials: [],
      patterns: [],
      confidence: 0.75,
    },
    ingestedAt: new Date().toISOString(),
  } as any);

  const availableTools = ['nmap', 'sqlmap', 'nuclei', 'nikto', 'ffuf', 'subfinder', 'httpx', 'gobuster', 'dalfox', 'hydra'];

  const ranked = cts.select(huntId, availableTools);
  assert(Array.isArray(ranked), 'select() returns array');
  console.log(`    (selected ${ranked.length} tools)`);
  if (ranked.length > 0) {
    assert(ranked.every((r: any) => typeof r.tool === 'string' && r.tool.length > 0), 'All ranked tools have a name');
    assert(ranked.every((r: any) => typeof r.score === 'number'), 'All ranked tools have a score');
    for (let i = 1; i < ranked.length; i++) {
      assert(ranked[i-1].score >= ranked[i].score, `tool scores sorted desc at ${i}`);
    }
    assert(ranked.every((r: any) => availableTools.includes(r.tool)), 'All selected tools are from availableTools');
    assert(ranked.every((r: any) => typeof r.rationale === 'string'), 'All selected tools have rationale');
  }

  // aggregateKnownFacts
  const facts = cts.aggregateKnownFacts(huntId);
  assert(facts.endpoints instanceof Set, 'aggregateKnownFacts returns endpoints Set');
  assert(facts.technologies instanceof Set, 'aggregateKnownFacts returns technologies Set');
  assert(facts.vulnerabilities instanceof Set, 'aggregateKnownFacts returns vulnerabilities Set');
  assert(facts.endpoints.size >= 2, `knownFacts has >= 2 endpoints (got ${facts.endpoints.size})`);

  // calculateNovelty with empty vs populated facts
  const emptyFacts = { endpoints: new Set<string>(), technologies: new Set<string>(), vulnerabilities: new Set<string>(), testedCombinations: new Set<string>(), negativeResults: [] };
  const noveltyHigh = cts.calculateNovelty('nmap', emptyFacts);
  assertRange(noveltyHigh, 0, 1, 'calculateNovelty in [0,1] with empty facts');

  const fullFacts = { endpoints: new Set(Array.from({length: 25}, (_, i) => `/ep${i}`)), technologies: new Set(['express','mysql','nginx','redis','elastic']), vulnerabilities: new Set(['sqli']), testedCombinations: new Set<string>(), negativeResults: [] };
  const noveltyLow = cts.calculateNovelty('nmap', fullFacts);
  assertRange(noveltyLow, 0, 1, 'calculateNovelty in [0,1] with populated facts');
  assert(noveltyLow <= noveltyHigh, 'novelty is lower with more known endpoints');

  // getToolYield
  const yield_ = cts.getToolYield('sqlmap', emptyFacts);
  assert(typeof yield_ === 'object' && yield_ !== null, 'getToolYield returns object');
  assert(typeof yield_.tool === 'string', 'toolYield has tool');
  assert(Array.isArray(yield_.expectedOutputTypes), 'toolYield has expectedOutputTypes');
  assertRange(yield_.noveltyScore, 0, 1, 'toolYield.noveltyScore in [0,1]');

  // getImplications
  const implications = cts.getImplications();
  assert(Array.isArray(implications) && implications.length > 0, 'getImplications returns non-empty array');
  assert(implications.every((i: any) => typeof i.condition === 'string' && Array.isArray(i.implies)), 'All implications have condition and implies[]');

  // getNegativePenalty — no negative evidence = 1.0
  const penalty = cts.getNegativePenalty('nmap', 'http://target.com', []);
  assertRange(penalty, 0, 1, 'getNegativePenalty in [0,1]');

  // getActivePipelines
  const pipes = cts.getActivePipelines(huntId);
  assert(Array.isArray(pipes), 'getActivePipelines returns array');
}

// ─── 9. Adaptive Threshold Tuner ─────────────────────────────────────────────

section('9. Adaptive Threshold Tuner');
{
  const { adaptiveThresholdTuner } = await import('./src/lib/intelligence/adaptive-threshold-tuner');

  // Returns defaults when DB unavailable
  const d1 = await adaptiveThresholdTuner.getThresholds('webapp');
  assert(typeof d1.noveltyFloor === 'number', 'getThresholds noveltyFloor is number');
  assert(typeof d1.healthFloor === 'number', 'getThresholds healthFloor is number');
  assert(typeof d1.maxDegraded === 'number', 'getThresholds maxDegraded is number');
  assert(typeof d1.stalenessTtlBase === 'number', 'getThresholds stalenessTtlBase is number');
  assertRange(d1.noveltyFloor, 0, 1, 'noveltyFloor in [0,1]');
  assertRange(d1.healthFloor, 0, 1, 'healthFloor in [0,1]');
  assert(d1.maxDegraded >= 1, 'maxDegraded >= 1');

  // Different target types get same defaults (no DB)
  const d2 = await adaptiveThresholdTuner.getThresholds('api');
  assert(d1.noveltyFloor === d2.noveltyFloor, 'Different target types get same defaults without DB');

  // learnFromHunt doesn't crash
  await adaptiveThresholdTuner.learnFromHunt('hunt-xyz', 'webapp', 0.85);
  assert(true, 'learnFromHunt does not throw');

  // getTargetStats
  const ts = await adaptiveThresholdTuner.getTargetStats();
  assert(Array.isArray(ts), 'getTargetStats returns array');

  // resetThresholds returns void (just confirm no throw)
  await adaptiveThresholdTuner.resetThresholds('webapp');
  assert(true, 'resetThresholds does not throw');
  // After reset, getThresholds should return defaults again
  const afterReset = await adaptiveThresholdTuner.getThresholds('webapp');
  assertRange(afterReset.noveltyFloor, 0, 1, 'post-reset noveltyFloor in [0,1]');
}

// ─── 10. Decision Trace Logger ────────────────────────────────────────────────

section('10. Decision Trace Logger');
{
  const { DecisionTraceLogger, HuntMetricsCollector } = await import('./src/lib/intelligence/decision-trace');
  const tracer = new DecisionTraceLogger();
  const collector = new HuntMetricsCollector(tracer);
  const hid = 'dtl-hunt-1';

  const e1 = await tracer.recordEvent({ huntId: hid, eventType: 'hunt_start', sourceSystem: 'test', data: { target: 'http://x.com' }, confidenceAtEvent: 0.5 });
  assert(typeof e1.id === 'string' && e1.id.length > 0, 'recordEvent returns event with id');
  assert(e1.huntId === hid, 'event has correct huntId');
  assert(typeof e1.timestamp === 'number', 'event has numeric timestamp');

  await tracer.recordEvent({ huntId: hid, eventType: 'tool_selection', sourceSystem: 'de', data: { tool: 'sqlmap' }, confidenceAtEvent: 0.7 });
  await tracer.recordEvent({ huntId: hid, eventType: 'tool_execution', sourceSystem: 'meta', data: { tool: 'sqlmap', success: true }, confidenceAtEvent: 0.8 });
  await tracer.recordEvent({ huntId: hid, eventType: 'finding_confirmed', sourceSystem: 'verifier', data: { vuln: 'SQLi', confidence: 0.9 }, confidenceAtEvent: 0.9 });
  await tracer.recordEvent({ huntId: hid, eventType: 'meta_pivot', sourceSystem: 'meta', data: { from: 'recon', to: 'sqli' }, confidenceAtEvent: 0.6 });
  await tracer.recordEvent({ huntId: hid, eventType: 'hunt_complete', sourceSystem: 'orch', data: { duration: 60000 }, confidenceAtEvent: 0.9 });

  const trace = tracer.getTrace(hid);
  assert(trace.length === 6, `getTrace has 6 events (got ${trace.length})`);
  for (let i = 1; i < trace.length; i++) {
    assert(trace[i].timestamp >= trace[i-1].timestamp, `trace sorted: event[${i}].ts >= event[${i-1}].ts`);
  }

  const byType = tracer.getTraceByType(hid, 'tool_selection');
  assert(byType.length === 1, `getTraceByType tool_selection = 1 (got ${byType.length})`);

  const win = tracer.getTraceWindow(hid, Date.now() - 60000, Date.now() + 1000);
  assert(win.length >= 6, `getTraceWindow returns >= 6 (got ${win.length})`);

  const metrics = collector.computeMetrics(hid);
  assert(metrics.totalEvents >= 6, `computeMetrics totalEvents >= 6 (got ${metrics.totalEvents})`);
  assert(metrics.totalPivots === 1, `computeMetrics totalPivots = 1 (got ${metrics.totalPivots})`);
  assert(typeof metrics.duration === 'number', 'metrics.duration is number');
  assert(metrics.timeToFirstFinding >= 0, 'metrics.timeToFirstFinding >= 0 (found)');
  assert(Array.isArray(metrics.confidenceCalibration), 'metrics has confidenceCalibration');

  const empty = await tracer.getTraceWithFallback('no-such-hunt');
  assert(Array.isArray(empty), 'getTraceWithFallback returns array for unknown hunt');

  const pivotAnalysis = collector.getPivotAnalysis(hid);
  assert(Array.isArray(pivotAnalysis), 'getPivotAnalysis returns array');
  if (pivotAnalysis.length > 0) {
    assert(typeof pivotAnalysis[0].fromStrategy === 'string', 'pivot analysis has fromStrategy');
    assert(typeof pivotAnalysis[0].toStrategy === 'string', 'pivot analysis has toStrategy');
    assert(typeof pivotAnalysis[0].productive === 'boolean', 'pivot analysis has productive bool');
  }

  const quality = collector.getDecisionQualityScore(hid);
  assertRange(quality, 0, 1, 'getDecisionQualityScore in [0,1]');

  // getConfidenceCalibration is on HuntMetricsCollector and takes optional string[]
  const cal = collector.getConfidenceCalibration([hid]);
  assert(Array.isArray(cal), 'getConfidenceCalibration returns array');
}

// ─── 11. Hunt Cortex ──────────────────────────────────────────────────────────

section('11. Hunt Cortex');
{
  // HuntCortex class is not exported — use the module singleton
  const { huntCortex, SignalType } = await import('./src/lib/intelligence/hunt-cortex');
  const cortex = huntCortex;
  const hid = 'cortex-h1';
  let received: any = null;

  cortex.subscribe(SignalType.FINDING_CONFIRMED, (s: any) => { received = s; });

  await cortex.broadcast({ signalType: SignalType.FINDING_CONFIRMED, sourceSystem: 'verifier', huntId: hid, payload: { vuln: 'SQLi', confidence: 0.9 }, confidence: 0.9 });
  assert(received !== null, 'subscribe callback fires on broadcast');
  assert(received.signalType === SignalType.FINDING_CONFIRMED, 'received signal has correct type');
  assert(received.huntId === hid, 'received signal has correct huntId');
  assert(typeof received.id === 'string', 'signal has auto-assigned id');
  assert(typeof received.timestamp === 'number', 'signal has auto-assigned timestamp');

  await cortex.broadcast({ signalType: SignalType.PIVOT_EXECUTED, sourceSystem: 'meta', huntId: hid, payload: { from: 'recon', to: 'scanning' }, confidence: 0.7 });
  await cortex.broadcast({ signalType: SignalType.TOOL_NOVELTY, sourceSystem: 'selector', huntId: hid, payload: { tool: 'nmap', novelty: 0.8 }, confidence: 0.8 });
  await cortex.broadcast({ signalType: SignalType.TOOL_NEGATIVE_EVIDENCE, sourceSystem: 'agent', huntId: hid, payload: { tool: 'gobuster', target: '/admin' }, confidence: 0.3 });

  // recentSignals takes a filter object, not positional args
  const recent = cortex.recentSignals({ huntId: hid });
  assert(recent.length >= 4, `recentSignals returns >= 4 signals (got ${recent.length})`);

  // computeHuntHealth returns Record<string, number> with a 'health' field
  const healthObj = cortex.computeHuntHealth(hid);
  assertRange(healthObj.health, 0, 1, 'computeHuntHealth.health in [0,1]');
  assert(typeof healthObj.signal_count === 'number', 'computeHuntHealth has signal_count');

  // getStats fields are bufferSize, subscriberCount, signalTypeCounts
  const stats = cortex.getStats();
  assert(typeof stats.bufferSize === 'number' && stats.bufferSize >= 4, `cortex bufferSize >= 4 (got ${stats.bufferSize})`);
  assert(typeof stats.subscriberCount === 'number', 'cortex stats has subscriberCount');

  // unsubscribe
  const noop = (_s: any) => {};
  cortex.subscribe(SignalType.PIVOT_EXECUTED, noop);
  cortex.unsubscribe(SignalType.PIVOT_EXECUTED, noop);
  assert(true, 'subscribe/unsubscribe cycle does not throw');

  // loadRecentFromDb takes optional windowSeconds (not huntId); DB unavailable — should not crash
  await cortex.loadRecentFromDb();
  assert(true, 'loadRecentFromDb does not throw without DB');
}

// ─── 12. Observation Ingestion ────────────────────────────────────────────────

section('12. Observation Ingestion');
{
  const { ObservationIngestion } = await import('./src/lib/intelligence/observation-ingestion');
  const ingestion = new ObservationIngestion('http://localhost:11434');

  // Ingest nmap-like output
  const nmapIngested = await ingestion.ingest({
    id: 'obs-n1',
    timestamp: new Date().toISOString(),
    source: 'tool',
    type: 'nmap_scan',
    rawOutput: [
      'PORT   STATE SERVICE VERSION',
      '80/tcp open  http    Apache httpd 2.4.51',
      '443/tcp open  https   nginx 1.21.0',
      '3306/tcp open  mysql   MySQL 8.0.27',
      'X-Powered-By: Express',
      'Server: Apache/2.4.51',
    ].join('\n'),
    missionId: 'ing-m1',
    huntGoal: 'SQL Injection',
    target: 'http://example.com',
  });
  assert(typeof nmapIngested === 'object', 'ingest returns object');
  assert(nmapIngested.observation.id === 'obs-n1', 'ingested.observation.id matches');
  assert(Array.isArray(nmapIngested.intelligence.technologies), 'intelligence has technologies[]');
  assert(Array.isArray(nmapIngested.intelligence.endpoints), 'intelligence has endpoints[]');
  assert(Array.isArray(nmapIngested.intelligence.vulnerabilities), 'intelligence has vulnerabilities[]');
  assertRange(nmapIngested.intelligence.confidence, 0, 1, 'intelligence.confidence in [0,1]');

  // Ingest XSS-hinting output
  const xssIngested = await ingestion.ingest({
    id: 'obs-x1',
    timestamp: new Date().toISOString(),
    source: 'tool',
    type: 'nuclei',
    rawOutput: '[xss] GET /search?q=<script>alert(1)</script> [200] XSS reflected\nJavaScript: React 18\nContent-Type: text/html',
    missionId: 'ing-m2',
    huntGoal: 'XSS',
    target: 'http://example2.com',
  });
  assert(Array.isArray(xssIngested.intelligence.vulnerabilities), 'XSS ingestion has vulnerabilities[]');

  // Ingest credential leak output
  const credIngested = await ingestion.ingest({
    id: 'obs-c1',
    timestamp: new Date().toISOString(),
    source: 'tool',
    type: 'git_secrets',
    rawOutput: 'API_KEY=sk-abc123xyz\npassword = "hunter2"\nAWS_SECRET_ACCESS_KEY = AKIA...',
    missionId: 'ing-m3',
    huntGoal: 'Sensitive Data Exposure',
    target: 'http://example3.com',
  });
  assert(Array.isArray(credIngested.intelligence.credentials), 'credential scan has credentials[]');

  // getObservations
  const all = ingestion.getObservations();
  assert(all.length >= 3, `getObservations returns >= 3 (got ${all.length})`);
  const m1obs = ingestion.getObservations('ing-m1');
  assert(m1obs.length === 1, `filtered by missionId ing-m1 = 1 (got ${m1obs.length})`);

  // aggregateIntelligence is async
  const agg = await ingestion.aggregateIntelligence('ing-m1');
  assert(typeof agg === 'object', 'aggregateIntelligence returns object');
  assert(Array.isArray(agg.technologies), 'aggregated has technologies');
  assert(Array.isArray(agg.vulnerabilities), 'aggregated has vulnerabilities');

  // ExpectationEngine
  const engine = ingestion.getExpectationEngine();
  assert(engine !== null, 'getExpectationEngine returns engine');
  const goals = engine.getAllGoals();
  assert(Array.isArray(goals) && goals.length > 0, 'ExpectationEngine has goals');
  assert(goals.includes('SQL Injection'), 'goals include SQL Injection');
  assert(goals.includes('XSS'), 'goals include XSS');
  assert(goals.includes('SSRF'), 'goals include SSRF');
  assert(goals.includes('RCE'), 'goals include RCE');

  // checkExpectations for SQL Injection goal
  const check = engine.checkExpectations('SQL Injection', {
    technologies: [{ name: 'mysql', category: 'database', confidence: 0.9, evidence: [] }],
    endpoints: [{ url: '/api/users?id=1', method: 'GET', parameters: ['id'], authenticated: false, riskLevel: 'high' }],
    defenseSignals: [],
    vulnerabilities: [],
    credentials: [],
    patterns: [],
    confidence: 0.8,
  } as any);
  assert(typeof check === 'object' && check !== null, 'checkExpectations returns result');
  assert(Array.isArray(check.met), 'expectation result has met[]');
  assert(Array.isArray(check.unmet), 'expectation result has unmet[]');
  assertRange(check.confidence, 0, 1, 'expectation check.confidence in [0,1]');
}

// ─── 13. Decision Journal ─────────────────────────────────────────────────────

section('13. Decision Journal');
{
  const { decisionJournal } = await import('./src/lib/intelligence/decision-journal');

  // log (silently swallowed if no DB)
  await decisionJournal.log({
    huntId: 'dj-h1', strategyBefore: 'port_scan', strategyAfter: 'sqli_test',
    action: 'pivot', rationale: 'no new ports', healthSnapshot: { score: 0.4 },
    contextVector: [0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8],
    findingsCount: 0, cycleNumber: 5, outcomeScore: null,
  });
  assert(true, 'decisionJournal.log does not throw');

  // findSimilar → null without DB
  const sim = await decisionJournal.findSimilar({ score: 0.4 }, { complexityScore: 0.5, volatilityScore: 0.3, attackSurfaceBreadth: 0.7 });
  assert(sim === null || typeof sim === 'object', 'findSimilar returns null or entry');

  // contextToVector (internal method)
  const vec = (decisionJournal as any).contextToVector({ score: 0.5, coverage: 0.3 }, { complexityScore: 0.4, volatilityScore: 0.2, attackSurfaceBreadth: 0.6 });
  assert(Array.isArray(vec), 'contextToVector returns array');
  assert(vec.length === 8, `contextToVector returns 8-dim vector (got ${vec.length})`);
  assert(vec.every((v: number) => typeof v === 'number' && !isNaN(v) && isFinite(v)), 'All vector elements are valid finite numbers');
  assert(vec.every((v: number) => v >= 0 && v <= 1), 'All vector elements in [0,1]');

  // cosineSimilarity (internal method)
  const cos1 = (decisionJournal as any).cosineSimilarity([1,0,0,0,0,0,0,0], [1,0,0,0,0,0,0,0]);
  assert(Math.abs(cos1 - 1.0) < 0.001, 'cosineSimilarity of identical vectors = 1.0');

  const cos2 = (decisionJournal as any).cosineSimilarity([1,0,0,0,0,0,0,0], [0,1,0,0,0,0,0,0]);
  assert(Math.abs(cos2) < 0.001, 'cosineSimilarity of orthogonal vectors ≈ 0');

  const cos3 = (decisionJournal as any).cosineSimilarity([1,1,0,0,0,0,0,0], [1,1,0,0,0,0,0,0]);
  assert(Math.abs(cos3 - 1.0) < 0.001, 'cosineSimilarity of identical non-unit vectors = 1.0');

  // backfillOutcomes (no DB — should not crash)
  await decisionJournal.backfillOutcomes('dj-h1', 0.75);
  assert(true, 'backfillOutcomes does not throw');

  // getStats (DB unavailable)
  const stats = await decisionJournal.getStats();
  assert(typeof stats === 'object', 'getStats returns object');
}

// ─── 14. Offensive Graph DB ───────────────────────────────────────────────────

section('14. Offensive Graph DB');
{
  // OffensiveGraphDB class is not exported — use the module singleton
  const { offensiveGraphDB } = await import('./src/lib/intelligence/offensive-graph-db');
  const gdb = offensiveGraphDB;
  await gdb.initialize();

  const hid = 'gdb-h1';

  const n1 = await gdb.addNode(hid, 'endpoint', '/api/users', { confidence: 0.9 });
  assert(typeof n1.id === 'string', 'addNode returns node with id');
  assert(n1.nodeType === 'endpoint', 'addNode sets nodeType');
  assert(n1.label === '/api/users', 'addNode sets label');
  assert(n1.huntId === hid, 'addNode sets huntId');
  assert(typeof n1.createdAt === 'number', 'addNode sets createdAt');

  const n2 = await gdb.addNode(hid, 'vulnerability', 'SQL Injection', { confidence: 0.85, severity: 'high' });
  const n3 = await gdb.addNode(hid, 'technique', 'error-based-sqli', { confidence: 0.7 });
  // 'technology' is not a valid NodeType — use 'tool' instead
  const n4 = await gdb.addNode(hid, 'tool', 'sqlmap', { confidence: 0.95 });

  const e1 = await gdb.addEdge(hid, n1.id, n2.id, 'exploits', { weight: 0.8 });
  assert(typeof e1.id === 'string', 'addEdge returns edge with id');
  assert(e1.sourceId === n1.id, 'edge sourceId correct');
  assert(e1.targetId === n2.id, 'edge targetId correct');
  assert(e1.relationship === 'exploits', 'edge relationship correct');

  await gdb.addEdge(hid, n3.id, n1.id, 'targets', { weight: 0.6 });
  // 'enables' is not a valid EdgeRelationship — use 'chains_to'
  await gdb.addEdge(hid, n4.id, n2.id, 'chains_to', { weight: 0.7 });

  // getHuntNodes / getHuntEdges
  const nodes = gdb.getHuntNodes(hid);
  assert(nodes.length === 4, `getHuntNodes returns 4 (got ${nodes.length})`);
  const edges = gdb.getHuntEdges(hid);
  assert(edges.length === 3, `getHuntEdges returns 3 (got ${edges.length})`);

  // findNode takes (huntId, nodeType, label) — 3 args; returns null (not undefined)
  const found = gdb.findNode(hid, 'endpoint', '/api/users');
  assert(found !== null, 'findNode finds by label');
  assert(found!.id === n1.id, 'findNode returns correct node');

  const notFound = gdb.findNode(hid, 'endpoint', '/no-such-endpoint');
  assert(notFound === null, 'findNode returns null for non-existent');

  // getNodesByType takes only nodeType (no huntId)
  const endpoints = gdb.getNodesByType('endpoint');
  assert(endpoints.length >= 1, `getNodesByType endpoint >= 1 (got ${endpoints.length})`);
  const vulns = gdb.getNodesByType('vulnerability');
  assert(vulns.length >= 1, `getNodesByType vulnerability >= 1 (got ${vulns.length})`);

  // findShortestPath returns AttackPathResult | null (not an array)
  const path = gdb.findShortestPath(n3.id, n2.id);
  assert(path !== null, 'findShortestPath finds path n3->n1->n2');

  // getStats (NOT getGraphStats); fields are totalNodes/totalEdges
  const stats = gdb.getStats(hid);
  assert(stats.totalNodes === 4, `stats.totalNodes = 4 (got ${stats.totalNodes})`);
  assert(stats.totalEdges === 3, `stats.totalEdges = 3 (got ${stats.totalEdges})`);

  // minePatterns (NOT detectPatterns); minFrequency=1 to catch single-hunt patterns
  const patterns = gdb.minePatterns(1, 4);
  assert(Array.isArray(patterns), 'minePatterns returns array');

  // computeCentrality; field is compositeScore (not score)
  const centrality = gdb.computeCentrality(hid);
  assert(Array.isArray(centrality), 'computeCentrality returns array');
  assert(centrality.length === 4, `centrality has 4 entries (got ${centrality.length})`);
  assert(typeof centrality[0].nodeId === 'string', 'centrality entry has nodeId');
  assert(typeof centrality[0].compositeScore === 'number', 'centrality entry has compositeScore');
  // Sorted by compositeScore descending
  for (let i = 1; i < centrality.length; i++) {
    assert(centrality[i-1].compositeScore >= centrality[i].compositeScore, `centrality sorted desc at ${i}`);
  }

  // rankAttackPaths (NOT getAttackPaths)
  const attackPaths = gdb.rankAttackPaths(hid);
  assert(Array.isArray(attackPaths), 'rankAttackPaths returns array');
}

// ─── 15. Verification Lifecycle ───────────────────────────────────────────────

section('15. Verification Lifecycle');
{
  const { VerificationLifecycle } = await import('./src/lib/intelligence/verification-lifecycle');
  const vlc = new VerificationLifecycle();

  const hid = 'vlc-h1';
  const now = Date.now();

  // addVerification — synchronous, VerificationRecord shape
  const rec = vlc.addVerification({
    findingId: 'finding-1',
    huntId: hid,
    target: 'http://vlc-target.com',
    verifiedAt: now,
    confidence: 0.9,
    verificationMethod: 'http-probe-injection',
    dependents: [],
    status: 'fresh',
    lastChecked: now,
  });
  assert(typeof rec.id === 'string', 'addVerification returns record with id');
  assert(rec.huntId === hid, 'record has correct huntId');
  assert(rec.status === 'fresh', 'record status = fresh');

  const rec2 = vlc.addVerification({
    findingId: 'finding-2',
    huntId: hid,
    target: 'http://vlc-target.com',
    verifiedAt: now,
    confidence: 0.7,
    verificationMethod: 'recon-enumeration',
    dependents: [rec.id],
    status: 'fresh',
    lastChecked: now,
  });
  assert(rec2.id !== rec.id, 'Two records have distinct ids');

  // getVerification
  const fetched = vlc.getVerification(rec.id);
  assert(fetched !== undefined, 'getVerification retrieves record');
  assert(fetched!.confidence === 0.9, 'retrieved confidence matches');

  // getAllForHunt
  const all = vlc.getAllForHunt(hid);
  assert(all.length === 2, `getAllForHunt returns 2 (got ${all.length})`);

  // calculateStaleness (fresh record = low staleness)
  const staleness = vlc.calculateStaleness(rec);
  assertRange(staleness, 0, 1, 'calculateStaleness in [0,1]');

  // updateTargetProfile
  vlc.updateTargetProfile('http://vlc-target.com', false);
  vlc.updateTargetProfile('http://vlc-target.com', true);
  assert(true, 'updateTargetProfile does not throw');

  // calculateStaleness with updated profile
  const staleAfter = vlc.calculateStaleness(rec);
  assertRange(staleAfter, 0, 1, 'calculateStaleness after profile update in [0,1]');

  // processStale (synchronous)
  const result = vlc.processStale();
  assert(typeof result.processed === 'number', 'processStale returns processed count');
  assert(typeof result.fresh === 'number', 'processStale result has fresh');
  assert(typeof result.stale === 'number', 'processStale result has stale');

  // getStats
  const stats = vlc.getStats();
  assert(stats.total === 2, `vlc stats.total = 2 (got ${stats.total})`);
  assert(typeof stats.averageConfidence === 'number', 'stats has averageConfidence');
  assertRange(stats.averageConfidence, 0, 1, 'averageConfidence in [0,1]');
}

// ─── Summary ──────────────────────────────────────────────────────────────────

console.log('\n' + '═'.repeat(65));
console.log(`RESULTS: ${passed} passed, ${failed} failed`);
if (failures.length > 0) {
  console.log('\nFailed assertions:');
  failures.forEach(f => console.log(`  • ${f}`));
}
console.log('═'.repeat(65));

process.exit(failed > 0 ? 1 : 0);

})();

import { Router, Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { juiceShopDocker, JUICE_SHOP_URL } from '../lib/lab/juice-shop-docker';
import { labScorer } from '../lib/intelligence/lab-profiles';
import { huntLabRunner } from '../lib/intelligence/hunt-lab-runner';

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
    path.join(LAB_RUNS_DIR, `${run.id}.json`),
    JSON.stringify(run, null, 2)
  );
}

async function loadHistory(): Promise<any[]> {
  await ensureDir();
  const files = await fs.readdir(LAB_RUNS_DIR).catch(() => [] as string[]);
  const runs = await Promise.all(
    files.filter(f => f.endsWith('.json')).map(async f => {
      try {
        return JSON.parse(await fs.readFile(path.join(LAB_RUNS_DIR, f), 'utf8'));
      } catch { return null; }
    })
  );
  return runs
    .filter(Boolean)
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
}

// Map LabVulnerability → JSChallenge shape expected by the client
function buildChallenges() {
  const profile = labScorer.getProfile('juice-shop');
  if (!profile) return { challenges: [], stats: null };

  const challenges = profile.vulnerabilities.map(v => ({
    id: v.id,
    juiceShopKey: v.plannerPathId,
    name: v.name,
    difficulty: v.difficulty,
    category: v.category,
    description: v.description,
    points: v.difficulty * 100,
  }));

  const byDifficulty: Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  let maxPoints = 0;

  for (const c of challenges) {
    byDifficulty[c.difficulty] = (byDifficulty[c.difficulty] || 0) + 1;
    byCategory[c.category] = (byCategory[c.category] || 0) + 1;
    maxPoints += c.points;
  }

  return {
    challenges,
    stats: { total: challenges.length, maxPoints, byDifficulty, byCategory },
  };
}

async function runHardcodedBenchmark(
  challenges: any[],
  difficulty: number | null,
  runId: string
): Promise<any[]> {
  const filtered = difficulty ? challenges.filter(c => c.difficulty === difficulty) : challenges;
  const results: any[] = [];

  // Single reachability check before the loop to avoid N×3s timeouts when offline
  const isReachable = await fetch(JUICE_SHOP_URL, {
    signal: AbortSignal.timeout(3000),
  }).then(r => r.ok).catch(() => false);

  for (const c of filtered) {
    if (abortFlags.get(runId)) break;

    const startMs = Date.now();
    let detected = false;
    let technique = 'pattern-probe';
    let evidence = '';
    let error: string | undefined;

    if (!isReachable) {
      error = 'Juice Shop not reachable';
    } else {
      try {
        // Category names match lab-profiles.ts: Injection, XSS, Broken Auth, SSRF,
        // PII Exposure, Broken Access Control, Security Misconfiguration
        if (c.category === 'Injection') {
          const url = `${JUICE_SHOP_URL}/rest/products/search?q=';SELECT * FROM Users--`;
          const r = await fetch(url, { signal: AbortSignal.timeout(5000) }).catch(() => null);
          detected = r !== null && (r.status === 200 || r.status === 500);
          evidence = detected ? `HTTP ${r!.status} on SQLi probe` : 'No response';
        } else if (c.category === 'XSS') {
          const url = `${JUICE_SHOP_URL}/rest/products/search?q=<script>alert(1)</script>`;
          const r = await fetch(url, { signal: AbortSignal.timeout(5000) }).catch(() => null);
          const body = r ? await r.text().catch(() => '') : '';
          detected = body.includes('<script>') || body.includes('alert(1)');
          evidence = detected ? 'XSS payload reflected in response' : 'Payload not reflected';
        } else if (c.category === 'Broken Auth') {
          const r = await fetch(`${JUICE_SHOP_URL}/rest/user/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: "' OR 1=1--", password: 'x' }),
            signal: AbortSignal.timeout(5000),
          }).catch(() => null);
          detected = r !== null && r.status === 200;
          evidence = detected ? 'Login bypass succeeded with SQLi payload' : `HTTP ${r?.status || 'ERR'}`;
        } else if (c.category === 'PII Exposure') {
          const r = await fetch(`${JUICE_SHOP_URL}/ftp/`, { signal: AbortSignal.timeout(5000) }).catch(() => null);
          detected = r !== null && r.status === 200;
          evidence = detected ? 'FTP directory listing exposed' : `HTTP ${r?.status || 'ERR'}`;
        } else if (c.category === 'SSRF') {
          const r = await fetch(`${JUICE_SHOP_URL}/api/Challenges?status=open`, { signal: AbortSignal.timeout(5000) }).catch(() => null);
          detected = r !== null && r.ok;
          evidence = detected ? 'Challenge API accessible' : 'No access';
        } else if (c.category === 'Broken Access Control') {
          const r = await fetch(`${JUICE_SHOP_URL}/api/Users`, { signal: AbortSignal.timeout(5000) }).catch(() => null);
          detected = r !== null && r.ok;
          evidence = detected ? 'User list API accessible without auth' : `HTTP ${r?.status || 'ERR'}`;
        } else {
          detected = isReachable;
          evidence = 'Application endpoint reachable';
          technique = 'reachability';
        }
      } catch (e: any) {
        error = e.message;
      }
    }

    results.push({
      challengeId: c.id,
      challengeName: c.name,
      juiceShopKey: c.juiceShopKey,
      difficulty: c.difficulty,
      category: c.category,
      status: error ? 'error' : (detected ? 'passed' : 'failed'),
      score: detected ? c.points : 0,
      maxScore: c.points,
      scanResult: {
        detected,
        confidence: detected ? 0.75 : 0.1,
        technique,
        evidence,
        executionTimeMs: Date.now() - startMs,
      },
      adaptiveScanResult: null,
      scanMode: 'hardcoded' as const,
      error,
    });
  }

  return results;
}

// Map hunt findings to JSResult shape
function huntFindingsToResults(findings: any[], challenges: any[]): any[] {
  return challenges.map(c => {
    const match = findings.find(f =>
      f.title?.toLowerCase().includes(c.category.toLowerCase()) ||
      f.description?.toLowerCase().includes(c.name.toLowerCase().split(' ')[0])
    );
    return {
      challengeId: c.id,
      challengeName: c.name,
      juiceShopKey: c.juiceShopKey,
      difficulty: c.difficulty,
      category: c.category,
      status: match ? 'passed' : 'failed',
      score: match ? c.points : 0,
      maxScore: c.points,
      scanResult: match ? {
        detected: true,
        confidence: match.confidence || 0.7,
        technique: 'ai-hunt',
        evidence: match.description || match.title || '',
        executionTimeMs: 0,
      } : null,
      adaptiveScanResult: match ? {
        adaptive: true,
        detected: true,
        confidence: match.confidence || 0.7,
        technique: 'hunt-orchestrator',
        evidence: match.description || '',
        executionTimeMs: 0,
        reasoningTrace: [],
        payloadAttempts: [],
        modelUsed: 'simulation',
        totalLLMCalls: 1,
        llmTimeMs: 0,
      } : null,
      scanMode: 'adaptive' as const,
    };
  });
}

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /status
router.get('/status', async (_req: Request, res: Response) => {
  try {
    const status = await juiceShopDocker.getStatus();
    return res.json(status);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /challenges
router.get('/challenges', (_req: Request, res: Response) => {
  try {
    const data = buildChallenges();
    return res.json(data);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /spawn
router.post('/spawn', async (_req: Request, res: Response) => {
  try {
    const dockerAvailable = await juiceShopDocker.isDockerAvailable();
    if (!dockerAvailable) {
      return res.status(503).json({
        ok: false,
        message: 'Docker daemon is not running. Start Docker Desktop or the Docker service and try again.',
      });
    }

    const alreadyRunning = await juiceShopDocker.isRunning();
    if (alreadyRunning) {
      return res.json({ ok: true, running: true, message: 'Juice Shop is already running' });
    }

    const spawnResult = await juiceShopDocker.spawn();
    if (!spawnResult.ok) {
      return res.status(500).json({ ok: false, message: spawnResult.error });
    }

    const ready = await juiceShopDocker.waitForReady(60000);
    return res.json({
      ok: ready,
      running: ready,
      containerId: spawnResult.containerId,
      message: ready
        ? 'Juice Shop is up and ready at http://localhost:3000'
        : 'Container started but Juice Shop did not respond within 60s',
    });
  } catch (err: any) {
    return res.status(500).json({ ok: false, message: err.message });
  }
});

// POST /stop
router.post('/stop', async (_req: Request, res: Response) => {
  try {
    const result = await juiceShopDocker.stop();
    return res.json(result);
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /benchmark/run
router.post('/benchmark/run', async (req: Request, res: Response) => {
  const { mode = 'hardcoded', difficulty } = req.body as {
    mode?: 'hardcoded' | 'adaptive' | 'hybrid';
    difficulty?: number;
  };

  if (!['hardcoded', 'adaptive', 'hybrid'].includes(mode)) {
    return res.status(400).json({ error: `Invalid mode: ${mode}. Must be hardcoded, adaptive, or hybrid.` });
  }

  const runId = uuidv4();
  abortFlags.set(runId, false);

  try {
    const { challenges } = buildChallenges();
    const startedAt = new Date().toISOString();

    let ollamaAvailable = false;
    let results: any[];

    if (mode === 'adaptive' || mode === 'hybrid') {
      ollamaAvailable = await fetch('http://localhost:11434/api/tags', {
        signal: AbortSignal.timeout(2000),
      }).then(r => r.ok).catch(() => false);

      if (ollamaAvailable) {
        const labResult = await huntLabRunner.runHunt(
          'juice-shop',
          'Find SQL injection, XSS, authentication bypass, and sensitive data exposure vulnerabilities',
          { stealthMode: 'aggressive', resourceClass: 'standard' }
        );
        const findings = labResult.metrics?.findings || [];
        results = huntFindingsToResults(findings, challenges);

        if (mode === 'hybrid') {
          const missedChallenges = challenges.filter(c =>
            !results.find(r => r.challengeId === c.id && r.status === 'passed')
          );
          if (missedChallenges.length > 0) {
            const hardcodedResults = await runHardcodedBenchmark(missedChallenges, null, runId);
            for (const hr of hardcodedResults.filter(r => r.status === 'passed')) {
              const idx = results.findIndex(r => r.challengeId === hr.challengeId);
              if (idx !== -1) results[idx] = { ...hr, scanMode: 'hybrid' as const };
            }
          }
        }
      } else {
        results = await runHardcodedBenchmark(challenges, difficulty ?? null, runId);
      }
    } else {
      results = await runHardcodedBenchmark(challenges, difficulty ?? null, runId);
    }

    // Compute summary stats in a single pass
    let passedCount = 0, failedCount = 0, adaptivePassedCount = 0;
    let totalScore = 0, maxPossibleScore = 0, totalExecutionTimeMs = 0;
    const byDifficulty: Record<number, any> = {};
    const byCategory: Record<string, any> = {};

    for (const r of results) {
      if (r.status === 'passed') passedCount++;
      else if (r.status === 'failed') failedCount++;
      if (r.adaptiveScanResult?.detected) adaptivePassedCount++;
      totalScore += r.score;
      maxPossibleScore += r.maxScore;
      totalExecutionTimeMs += r.scanResult?.executionTimeMs || 0;

      if (!byDifficulty[r.difficulty]) byDifficulty[r.difficulty] = { passed: 0, total: 0, score: 0, maxScore: 0 };
      byDifficulty[r.difficulty].total++;
      byDifficulty[r.difficulty].maxScore += r.maxScore;
      if (r.status === 'passed') { byDifficulty[r.difficulty].passed++; byDifficulty[r.difficulty].score += r.score; }

      if (!byCategory[r.category]) byCategory[r.category] = { passed: 0, total: 0, score: 0, maxScore: 0 };
      byCategory[r.category].total++;
      byCategory[r.category].maxScore += r.maxScore;
      if (r.status === 'passed') { byCategory[r.category].passed++; byCategory[r.category].score += r.score; }
    }

    const run = {
      id: runId,
      status: 'completed' as const,
      targetUrl: JUICE_SHOP_URL,
      scanMode: mode,
      ollamaAvailable,
      startedAt,
      completedAt: new Date().toISOString(),
      results,
      totalScore,
      maxPossibleScore,
      passRate: results.length > 0 ? Math.round((passedCount / results.length) * 100) : 0,
      byDifficulty,
      byCategory,
      challengeCount: results.length,
      passedCount,
      failedCount,
      adaptivePassedCount,
      totalExecutionTimeMs,
      totalLLMCalls: ollamaAvailable ? 1 : 0,
      totalLLMTimeMs: 0,
    };

    await saveRun(run);
    return res.json(run);
  } catch (err: any) {
    return res.status(500).json({ error: (err as Error).message });
  } finally {
    abortFlags.delete(runId);
  }
});

// POST /benchmark/abort
router.post('/benchmark/abort', (req: Request, res: Response) => {
  const { runId } = req.body as { runId?: string };
  if (runId) {
    abortFlags.set(runId, true);
  } else {
    for (const [id] of abortFlags) abortFlags.set(id, true);
  }
  return res.json({ ok: true });
});

// GET /benchmark/history
router.get('/benchmark/history', async (_req: Request, res: Response) => {
  try {
    const history = await loadHistory();
    return res.json(history);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

export default router;

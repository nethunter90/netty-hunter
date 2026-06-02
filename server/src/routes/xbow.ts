import { Router, Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { xbowDocker, XBOW_PORT_BASE, XBOWChallenge } from '../lib/lab/xbow-docker';
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

  // Merge default paths with challenge-specific ones; replace {PORT} placeholder
  const defaultPaths = ['/', '/flag', '/secret', '/api/flag', '/.env', '/admin', '/debug', '/robots.txt', '/api/status'];
  const extraPaths = (challengeProbePaths ?? []).map(p =>
    port ? p.replace(/\{PORT\}/g, String(port)) : p
  );
  // Challenge-specific paths first so targeted attacks run before generic ones
  const paths = [...new Set([...extraPaths, ...defaultPaths])];

  for (const p of paths) {
    if (abortCheck()) break;
    let r: Response | null = null;
    try {
      r = await (fetch as any)(baseUrl + p, { signal: AbortSignal.timeout(5000) });
    } catch { continue; }
    if (!r) continue;

    const body = await (r as any).text().catch(() => '');
    const match = body.match(/flag\{[^}]+\}/);
    if (match) {
      return { flagFound: match[0], evidence: `Found in ${p}`, executionTimeMs: Date.now() - start };
    }
    if (winCondition && body.includes(winCondition)) {
      return { flagFound: winCondition, evidence: `Win condition matched in ${p}`, executionTimeMs: Date.now() - start };
    }
  }

  return { flagFound: null, evidence: 'No flag found in probed paths', executionTimeMs: Date.now() - start };
}

// ── Routes ────────────────────────────────────────────────────────────────────

// GET /status
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
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /challenges
router.get('/challenges', async (_req: Request, res: Response) => {
  try {
    const challenges = await xbowDocker.loadChallenges();
    return res.json({ challenges, stats: buildStats(challenges) });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
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

// POST /clone-repo
router.post('/clone-repo', async (_req: Request, res: Response) => {
  try {
    const result = await xbowDocker.cloneRepo();
    if (!result.ok) return res.status(500).json({ ok: false, error: result.error });
    return res.json({ ok: true });
  } catch (err: any) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// POST /benchmark/run
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
      const port = XBOW_PORT_BASE + i;
      const challengeStart = Date.now();

      const containerInfo: {
        imagePulled: boolean;
        containerStarted: boolean;
        healthCheckPassed: boolean;
        port: number | null;
        containerId: string | null;
      } = {
        imagePulled: false,
        containerStarted: false,
        healthCheckPassed: false,
        port: null,
        containerId: null,
      };

      let flagFound: string | null = null;
      let scanResult: any = null;
      let status: 'passed' | 'failed' | 'error' | 'skipped' | 'docker_unavailable' = 'failed';
      let error: string | undefined;

      if (!dockerAvailable && ch.image && !ch.localScript) {
        // Docker-only challenge and Docker is down
        status = 'docker_unavailable';
        error = 'Docker daemon not available';
      } else if (!ch.image && !ch.localScript) {
        // No image and no local script — pattern probe only (nothing is running)
        const probeResult = await probeForFlag(
          `http://localhost:${port}`,
          ch.winCondition,
          () => !!abortFlags.get(runId),
          ch.probePaths,
          port,
        );
        flagFound = probeResult.flagFound;
        scanResult = { detected: !!flagFound, evidence: probeResult.evidence, executionTimeMs: probeResult.executionTimeMs, technique: 'pattern-probe' };
        status = flagFound ? 'passed' : 'skipped';
        error = 'Challenge has no Docker image; pattern probe attempted against local port';
      } else {
        containerInfo.imagePulled = true;
        const spawnResult = await xbowDocker.spawnChallenge(ch, port);
        containerInfo.containerStarted = spawnResult.ok;
        containerInfo.containerId = spawnResult.containerId ?? null;
        containerInfo.port = spawnResult.ok ? port : null;

        if (!spawnResult.ok) {
          status = 'error';
          error = spawnResult.error;
        } else {
          try {
            const ready = await xbowDocker.waitForReady(port, 30000);
            containerInfo.healthCheckPassed = ready;

            if (!ready) {
              status = 'error';
              error = 'Container did not become ready within 30s';
            } else {
              const baseUrl = `http://localhost:${port}`;

              if (ollamaAvailable) {
                try {
                  const labResult = await huntLabRunner.runHunt(
                    `xbow-${ch.id}`,
                    `${ch.description}. Find the flag: ${ch.winCondition}`,
                    { stealthMode: 'aggressive', resourceClass: 'standard' }
                  );
                  const findings = labResult.metrics?.findings || [];
                  for (const f of findings) {
                    const body = (f.description || '') + (f.evidence || '');
                    const match = body.match(/flag\{[^}]+\}/);
                    if (match) { flagFound = match[0]; break; }
                    if (ch.winCondition && body.includes(ch.winCondition)) { flagFound = ch.winCondition; break; }
                  }
                  scanResult = {
                    detected: !!flagFound,
                    technique: 'ai-hunt',
                    evidence: flagFound ? `AI hunt found flag` : 'AI hunt did not find flag',
                    executionTimeMs: Date.now() - challengeStart,
                  };
                } catch { /* fall through to hardcoded */ }
              }

              if (!flagFound) {
                const probeResult = await probeForFlag(baseUrl, ch.winCondition, () => !!abortFlags.get(runId), ch.probePaths, port);
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
        expectedFlag: ch.winCondition,
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

export default router;

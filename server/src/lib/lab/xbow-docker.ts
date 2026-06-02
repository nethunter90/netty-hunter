import crypto from 'crypto';
import { exec, spawn } from 'child_process';
import type { ChildProcess } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

export const XBOW_REPO_URL = 'https://github.com/xbow-engineering/validation-benchmarks';
const XBOW_REPO_DIR = path.join(process.cwd(), 'workspace', 'xbow-repo');
const CHALLENGES_DIR = path.join(process.cwd(), 'workspace', 'challenges');
export const XBOW_PORT_BASE = 18000;

export interface XBOWChallenge {
  id: string;
  name: string;
  description: string;
  level: 1 | 2 | 3;
  /** For real XBOW challenges: "flag" | "question". For local stubs: the literal flag value. */
  winCondition: string;
  tags: string[];
  points: number;
  // ── Docker image (legacy single-container) ───────────────────────────────
  image?: string;
  internalPort?: number;
  // ── Docker Compose (real XBOW challenges) ────────────────────────────────
  /** Absolute path to the challenge directory containing docker-compose.yml */
  challengeDir?: string;
  // ── Local Node.js script (built-in stub challenges) ──────────────────────
  localScript?: string;
  probePaths?: string[];
}

export interface SpawnResult {
  ok: boolean;
  /** Opaque ID: "compose:<path>", "pid:<n>", or a Docker container SHA */
  containerId?: string;
  /** Flag that was injected into the Docker build (only set for compose challenges) */
  generatedFlag?: string;
  /** Actual host port the challenge is listening on */
  port?: number;
  error?: string;
}

// ─── Stub challenges (local Node.js servers — no Docker required) ─────────────
const STUB_CHALLENGES: XBOWChallenge[] = [
  {
    id: 'sqli-basic',
    name: 'SQL Injection (Basic)',
    description: 'Classic login bypass via SQL injection in the username field. The /login endpoint builds a query using string concatenation without parameterization.',
    level: 1,
    winCondition: 'flag{sql_injection_found}',
    tags: ['sqli', 'web', 'auth'],
    points: 100,
    localScript: path.join(CHALLENGES_DIR, 'sqli-basic.cjs'),
    probePaths: [
      "/login?username='%20OR%201=1--&password=x",
      "/login?username=admin'--&password=x",
    ],
  },
  {
    id: 'xss-reflect',
    name: 'Reflected XSS',
    description: 'Unsanitized query parameter reflected directly into the HTML response.',
    level: 1,
    winCondition: 'flag{xss_found}',
    tags: ['xss', 'web', 'client-side'],
    points: 100,
    localScript: path.join(CHALLENGES_DIR, 'xss-reflect.cjs'),
    probePaths: [
      '/search?q=<script>alert(1)</script>',
      '/api/search?q=<script>alert(1)</script>',
    ],
  },
  {
    id: 'idor-user',
    name: 'IDOR — User Data',
    description: "Access another user's profile by manipulating the user ID in the REST API path.",
    level: 2,
    winCondition: 'flag{idor_found}',
    tags: ['idor', 'web', 'api'],
    points: 200,
    localScript: path.join(CHALLENGES_DIR, 'idor-user.cjs'),
    probePaths: ['/api/users/2', '/api/users/3'],
  },
  {
    id: 'ssrf-internal',
    name: 'SSRF — Internal Metadata',
    description: 'Use the /fetch endpoint to reach the internal metadata service blocked from direct access.',
    level: 2,
    winCondition: 'flag{ssrf_found}',
    tags: ['ssrf', 'web', 'server-side'],
    points: 200,
    localScript: path.join(CHALLENGES_DIR, 'ssrf-internal.cjs'),
    probePaths: [
      '/fetch?url=http://127.0.0.1:{PORT}/api/internal/metadata',
      '/fetch?url=http://localhost:{PORT}/api/internal/metadata',
    ],
  },
  {
    id: 'rce-deserialize',
    name: 'RCE via Unsafe Deserialization',
    description: 'Exploit node-serialize IIFE execution via the _$$ND_FUNC$$_ marker on POST /deserialize.',
    level: 3,
    winCondition: 'flag{rce_found}',
    tags: ['rce', 'deserialization', 'web'],
    points: 300,
    localScript: path.join(CHALLENGES_DIR, 'rce-deserialize.cjs'),
    probePaths: ['/api/status', '/robots.txt'],
  },
];

// ─── XBOWDockerManager ────────────────────────────────────────────────────────
class XBOWDockerManager {
  private localProcesses = new Map<string, ChildProcess>();

  async isDockerAvailable(): Promise<boolean> {
    try {
      await execAsync('docker info', { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  async isRepoAvailable(): Promise<boolean> {
    try {
      await fs.stat(XBOW_REPO_DIR);
      return true;
    } catch {
      return false;
    }
  }

  getRepoPath(): string {
    return XBOW_REPO_DIR;
  }

  async cloneRepo(): Promise<{ ok: boolean; error?: string }> {
    try {
      await fs.mkdir(path.dirname(XBOW_REPO_DIR), { recursive: true });
      try { await execAsync(`rm -rf "${XBOW_REPO_DIR}"`, { timeout: 10000 }); } catch { /* ignore */ }
      await execAsync(
        `git clone --depth 1 "${XBOW_REPO_URL}" "${XBOW_REPO_DIR}"`,
        { timeout: 180000 }
      );
      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  async loadChallenges(): Promise<XBOWChallenge[]> {
    if (!(await this.isRepoAvailable())) {
      return STUB_CHALLENGES;
    }

    const benchmarksDir = path.join(XBOW_REPO_DIR, 'benchmarks');
    try {
      const entries = await fs.readdir(benchmarksDir, { withFileTypes: true });
      const challenges: XBOWChallenge[] = [];

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const challengeDir = path.join(benchmarksDir, entry.name);

        // Real XBOW format: benchmark.json at root of each challenge dir
        try {
          const raw = await fs.readFile(path.join(challengeDir, 'benchmark.json'), 'utf8');
          const cfg = JSON.parse(raw);
          const levelNum = Math.max(1, Math.min(3, parseInt(String(cfg.level)) || 2)) as 1 | 2 | 3;
          challenges.push({
            id: entry.name,
            name: cfg.name ?? entry.name,
            description: cfg.description ?? '',
            level: levelNum,
            winCondition: cfg.win_condition ?? 'flag',
            tags: Array.isArray(cfg.tags) ? cfg.tags : [],
            points: levelNum * 100,
            challengeDir,
          });
          continue;
        } catch { /* fall through to legacy formats */ }

        // Legacy: challenge.json
        try {
          const raw = await fs.readFile(path.join(challengeDir, 'challenge.json'), 'utf8');
          const ch = JSON.parse(raw) as XBOWChallenge;
          if (ch.id && ch.name) { challenges.push({ ...ch, challengeDir }); }
        } catch { /* skip */ }
      }

      if (challenges.length > 0) return challenges;
    } catch { /* fall through */ }

    return STUB_CHALLENGES;
  }

  // ── Spawn ─────────────────────────────────────────────────────────────────

  async spawnChallenge(ch: XBOWChallenge, _hintPort: number): Promise<SpawnResult> {
    if (ch.localScript) return this.spawnLocalProcess(ch, _hintPort);
    if (ch.challengeDir) return this.spawnComposeChallenge(ch);
    if (ch.image)        return this.spawnDockerRun(ch, _hintPort);
    return { ok: false, error: 'challenge has no Docker image, compose dir, or local script' };
  }

  private async spawnLocalProcess(ch: XBOWChallenge, port: number): Promise<SpawnResult> {
    try {
      await fs.stat(ch.localScript!);
    } catch {
      return { ok: false, error: `challenge script not found: ${ch.localScript}` };
    }
    try {
      const proc = spawn(process.execPath, [ch.localScript!], {
        env: { ...process.env, CHALLENGE_PORT: String(port) },
        stdio: 'ignore',
        detached: false,
      });
      if (!proc.pid) return { ok: false, error: 'process spawned but PID unavailable' };
      const pid = String(proc.pid);
      this.localProcesses.set(pid, proc);
      proc.on('exit', () => this.localProcesses.delete(pid));
      return { ok: true, containerId: `pid:${pid}`, port };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  private async spawnComposeChallenge(ch: XBOWChallenge): Promise<SpawnResult> {
    const dir = ch.challengeDir!;
    const flag = crypto.randomBytes(16).toString('hex');

    try {
      // Build with injected flag (5 min timeout — some challenges pull large images)
      await execAsync(
        `docker compose build --build-arg FLAG=${flag}`,
        { cwd: dir, timeout: 300_000 }
      );

      // Start services, wait for healthchecks
      await execAsync('docker compose up -d --wait', { cwd: dir, timeout: 120_000 });

      const port = await this.discoverComposePort(dir);
      return { ok: true, containerId: `compose:${dir}`, generatedFlag: flag, port: port ?? undefined };
    } catch (err: any) {
      // Best-effort cleanup on failure
      try { await execAsync('docker compose down --remove-orphans', { cwd: dir, timeout: 30_000 }); } catch { /* ignore */ }
      return { ok: false, error: err.message };
    }
  }

  private async spawnDockerRun(ch: XBOWChallenge, port: number): Promise<SpawnResult> {
    try {
      try { await execAsync(`docker stop xbow-${ch.id}`, { timeout: 10_000 }); } catch { /* not running */ }
      const internalPort = ch.internalPort ?? 8080;
      const { stdout } = await execAsync(
        `docker run -d --rm --name xbow-${ch.id} -p ${port}:${internalPort} ${ch.image}`,
        { timeout: 60_000 }
      );
      return { ok: true, containerId: stdout.trim(), port };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  // ── Port discovery (Docker Compose) ──────────────────────────────────────

  private async discoverComposePort(dir: string): Promise<number | null> {
    // Try `docker compose ps --format json` (Compose v2)
    try {
      const { stdout } = await execAsync('docker compose ps --format json', { cwd: dir, timeout: 10_000 });
      for (const line of stdout.trim().split('\n')) {
        try {
          const obj = JSON.parse(line);
          const publishers: any[] = Array.isArray(obj) ? obj.flatMap((o: any) => o.Publishers ?? []) : (obj.Publishers ?? []);
          for (const p of publishers) {
            if (p.PublishedPort > 0) return p.PublishedPort;
          }
        } catch { /* try next line */ }
      }
    } catch { /* fall through */ }

    // Fallback: probe common ports on each service
    try {
      const { stdout: svcs } = await execAsync('docker compose config --services', { cwd: dir, timeout: 10_000 });
      for (const svc of svcs.trim().split('\n')) {
        for (const internalPort of [80, 5000, 8080, 3000, 8000, 4000, 443]) {
          try {
            const { stdout } = await execAsync(`docker compose port ${svc} ${internalPort}`, { cwd: dir, timeout: 5_000 });
            const m = stdout.trim().match(/:(\d+)$/);
            if (m) return parseInt(m[1]);
          } catch { /* try next */ }
        }
      }
    } catch { /* fall through */ }

    return null;
  }

  // ── Stop ──────────────────────────────────────────────────────────────────

  async stopChallenge(containerId: string): Promise<void> {
    if (containerId.startsWith('pid:')) {
      const pid = containerId.slice(4);
      const proc = this.localProcesses.get(pid);
      if (proc) {
        try { proc.kill('SIGTERM'); } catch { /* already dead */ }
        this.localProcesses.delete(pid);
      }
      return;
    }
    if (containerId.startsWith('compose:')) {
      const dir = containerId.slice(8);
      try { await execAsync('docker compose down --remove-orphans', { cwd: dir, timeout: 30_000 }); } catch { /* ignore */ }
      return;
    }
    // Docker container SHA
    try { await execAsync(`docker stop ${containerId}`, { timeout: 15_000 }); } catch { /* ignore */ }
  }

  // ── Readiness ─────────────────────────────────────────────────────────────

  async waitForReady(port: number, timeoutMs = 30_000): Promise<boolean> {
    // Give local processes a short settling window
    await new Promise(r => setTimeout(r, 400));
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`http://localhost:${port}`, { signal: AbortSignal.timeout(3000) });
        if (res.status < 500) return true;
      } catch { /* not ready */ }
      if (Date.now() < deadline) await new Promise(r => setTimeout(r, 1000));
    }
    return false;
  }
}

export const xbowDocker = new XBOWDockerManager();

import { exec, spawn } from 'child_process';
import type { ChildProcess } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

const XBOW_REPO_URL = process.env.XBOW_REPO_URL ?? 'https://github.com/xbow-org/challenges';
const XBOW_REPO_DIR = path.join(process.cwd(), 'workspace', 'xbow-repo');
const CHALLENGES_DIR = path.join(process.cwd(), 'workspace', 'challenges');
export const XBOW_PORT_BASE = 18000;

export interface XBOWChallenge {
  id: string;
  name: string;
  description: string;
  level: 1 | 2 | 3;
  winCondition: string;
  tags: string[];
  points: number;
  image?: string;
  internalPort?: number;
  /** Absolute path to a local Node.js CJS script that serves the challenge. */
  localScript?: string;
  /**
   * Extra URL paths to probe when running the pattern-probe fallback.
   * Supports {PORT} placeholder which is replaced with the actual challenge port.
   */
  probePaths?: string[];
}

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
      "/login?user='%20OR%20'1'='1&pass=x",
    ],
  },
  {
    id: 'xss-reflect',
    name: 'Reflected XSS',
    description: 'Unsanitized query parameter reflected directly into the HTML response. Injecting script tags or event handlers into the search endpoint triggers the vulnerability.',
    level: 1,
    winCondition: 'flag{xss_found}',
    tags: ['xss', 'web', 'client-side'],
    points: 100,
    localScript: path.join(CHALLENGES_DIR, 'xss-reflect.cjs'),
    probePaths: [
      '/search?q=<script>alert(1)</script>',
      '/search?q=<img+src=x+onerror=alert(1)>',
      '/api/search?q=<script>alert(1)</script>',
    ],
  },
  {
    id: 'idor-user',
    name: 'IDOR — User Data',
    description: "Access another user's profile data by manipulating the user ID in the REST API path. The server does not verify that the requested resource belongs to the authenticated user.",
    level: 2,
    winCondition: 'flag{idor_found}',
    tags: ['idor', 'web', 'api'],
    points: 200,
    localScript: path.join(CHALLENGES_DIR, 'idor-user.cjs'),
    probePaths: [
      '/api/users/2',
      '/api/users/3',
      '/api/profile',
    ],
  },
  {
    id: 'ssrf-internal',
    name: 'SSRF — Internal Metadata',
    description: 'The /fetch endpoint makes server-side HTTP requests to arbitrary URLs. Use it to reach the internal metadata endpoint that is blocked from direct external access.',
    level: 2,
    winCondition: 'flag{ssrf_found}',
    tags: ['ssrf', 'web', 'server-side'],
    points: 200,
    localScript: path.join(CHALLENGES_DIR, 'ssrf-internal.cjs'),
    probePaths: [
      '/fetch?url=http://127.0.0.1:{PORT}/api/internal/metadata',
      '/fetch?url=http://localhost:{PORT}/api/internal/metadata',
      '/robots.txt',
    ],
  },
  {
    id: 'rce-deserialize',
    name: 'RCE via Unsafe Deserialization',
    description: 'The /deserialize endpoint uses node-serialize, which executes IIFEs embedded in serialized function properties. Craft a payload using the _$$ND_FUNC$$_ marker to achieve RCE.',
    level: 3,
    winCondition: 'flag{rce_found}',
    tags: ['rce', 'deserialization', 'web'],
    points: 300,
    localScript: path.join(CHALLENGES_DIR, 'rce-deserialize.cjs'),
    probePaths: [
      '/api/status',
      '/robots.txt',
    ],
  },
];

class XBOWDockerManager {
  /** Tracks spawned local challenge processes by their PID (as string). */
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
      try {
        await execAsync(`rm -rf "${XBOW_REPO_DIR}"`, { timeout: 10000 });
      } catch { /* ignore */ }
      await execAsync(
        `git clone --depth 1 "${XBOW_REPO_URL}" "${XBOW_REPO_DIR}"`,
        { timeout: 120000 }
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

    // Try top-level challenges.json first
    try {
      const raw = await fs.readFile(path.join(XBOW_REPO_DIR, 'challenges.json'), 'utf8');
      const parsed = JSON.parse(raw);
      const list: XBOWChallenge[] = Array.isArray(parsed) ? parsed : (parsed.challenges ?? []);
      if (list.length > 0) return list;
    } catch { /* fall through */ }

    // Try scanning subdirectories for per-challenge manifests
    try {
      const entries = await fs.readdir(XBOW_REPO_DIR, { withFileTypes: true });
      const challenges: XBOWChallenge[] = [];
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const manifestPath = path.join(XBOW_REPO_DIR, entry.name, 'challenge.json');
        try {
          const raw = await fs.readFile(manifestPath, 'utf8');
          const ch = JSON.parse(raw) as XBOWChallenge;
          if (ch.id && ch.name) challenges.push(ch);
        } catch { /* skip invalid manifests */ }
      }
      if (challenges.length > 0) return challenges;
    } catch { /* fall through */ }

    return STUB_CHALLENGES;
  }

  /** Spawn a challenge — prefers a local Node.js script over a Docker image. */
  async spawnChallenge(
    ch: XBOWChallenge,
    port: number
  ): Promise<{ ok: boolean; containerId?: string; error?: string }> {
    if (ch.localScript) {
      return this.spawnLocalProcess(ch, port);
    }
    if (!ch.image) {
      return { ok: false, error: 'challenge has no Docker image or local script' };
    }
    return this.spawnDockerContainer(ch, port);
  }

  private async spawnLocalProcess(
    ch: XBOWChallenge,
    port: number
  ): Promise<{ ok: boolean; containerId?: string; error?: string }> {
    try {
      // Verify the script exists before spawning
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

      if (!proc.pid) {
        return { ok: false, error: 'process spawned but PID unavailable' };
      }

      const pid = String(proc.pid);
      this.localProcesses.set(pid, proc);
      proc.on('exit', () => this.localProcesses.delete(pid));

      // PID is used as the containerId so stopChallenge can handle both cases uniformly
      return { ok: true, containerId: `pid:${pid}` };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  private async spawnDockerContainer(
    ch: XBOWChallenge,
    port: number
  ): Promise<{ ok: boolean; containerId?: string; error?: string }> {
    try {
      try {
        await execAsync(`docker stop xbow-${ch.id}`, { timeout: 10000 });
      } catch { /* not running */ }

      const internalPort = ch.internalPort ?? 8080;
      const { stdout } = await execAsync(
        `docker run -d --rm --name xbow-${ch.id} -p ${port}:${internalPort} ${ch.image}`,
        { timeout: 60000 }
      );
      return { ok: true, containerId: stdout.trim() };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  /** Stop a challenge — handles both `pid:<n>` (local process) and Docker container IDs. */
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
    // Docker container ID
    try {
      await execAsync(`docker stop ${containerId}`, { timeout: 15000 });
    } catch { /* ignore stop errors */ }
  }

  async waitForReady(port: number, timeoutMs = 30000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    // Give local processes a short initial settling time
    await new Promise(r => setTimeout(r, 300));
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`http://localhost:${port}`, {
          signal: AbortSignal.timeout(3000),
        });
        if (res.status < 500) return true;
      } catch { /* not ready yet */ }
      if (Date.now() < deadline) await new Promise(r => setTimeout(r, 1000));
    }
    return false;
  }
}

export const xbowDocker = new XBOWDockerManager();

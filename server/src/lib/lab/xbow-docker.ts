import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

const XBOW_REPO_URL = process.env.XBOW_REPO_URL ?? 'https://github.com/xbow-org/challenges';
const XBOW_REPO_DIR = path.join(process.cwd(), 'workspace', 'xbow-repo');
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
}

const STUB_CHALLENGES: XBOWChallenge[] = [
  {
    id: 'sqli-basic',
    name: 'SQL Injection (Basic)',
    description: 'Classic login bypass via SQL injection in the username field',
    level: 1,
    winCondition: 'flag{sql_injection_found}',
    tags: ['sqli', 'web'],
    points: 100,
  },
  {
    id: 'xss-reflect',
    name: 'Reflected XSS',
    description: 'Unsanitized query parameter reflected into HTML response',
    level: 1,
    winCondition: 'flag{xss_found}',
    tags: ['xss', 'web'],
    points: 100,
  },
  {
    id: 'idor-user',
    name: 'IDOR — User Data',
    description: 'Access another user\'s profile data by manipulating the user ID',
    level: 2,
    winCondition: 'flag{idor_found}',
    tags: ['idor', 'web'],
    points: 200,
  },
  {
    id: 'ssrf-internal',
    name: 'SSRF — Internal Service',
    description: 'Reach the internal metadata endpoint via a server-side request forgery',
    level: 2,
    winCondition: 'flag{ssrf_found}',
    tags: ['ssrf', 'web'],
    points: 200,
  },
  {
    id: 'rce-deserialization',
    name: 'RCE via Deserialization',
    description: 'Exploit unsafe object deserialization to achieve remote code execution',
    level: 3,
    winCondition: 'flag{rce_found}',
    tags: ['rce', 'web'],
    points: 300,
  },
];

class XBOWDockerManager {
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
      // Remove existing dir if present (re-clone)
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

    // Try top-level challenges.json
    try {
      const raw = await fs.readFile(path.join(XBOW_REPO_DIR, 'challenges.json'), 'utf8');
      const parsed = JSON.parse(raw);
      const list: XBOWChallenge[] = Array.isArray(parsed) ? parsed : (parsed.challenges ?? []);
      if (list.length > 0) return list;
    } catch { /* fall through */ }

    // Try scanning subdirectories for challenge.json
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

  async spawnChallenge(
    ch: XBOWChallenge,
    port: number
  ): Promise<{ ok: boolean; containerId?: string; error?: string }> {
    if (!ch.image) {
      return { ok: false, error: 'no Docker image defined for this challenge' };
    }
    try {
      // Stop any existing container with this name
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

  async stopChallenge(containerId: string): Promise<void> {
    try {
      await execAsync(`docker stop ${containerId}`, { timeout: 15000 });
    } catch { /* ignore stop errors */ }
  }

  async waitForReady(port: number, timeoutMs = 30000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`http://localhost:${port}`, {
          signal: AbortSignal.timeout(3000),
        });
        if (res.status < 500) return true;
      } catch { /* not ready yet */ }
      if (Date.now() < deadline) await new Promise(r => setTimeout(r, 2000));
    }
    return false;
  }
}

export const xbowDocker = new XBOWDockerManager();

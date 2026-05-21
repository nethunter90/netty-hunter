import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const CONTAINER_NAME = 'juiceshop-sentinel';
const JUICE_SHOP_IMAGE = 'bkimminich/juice-shop';
const JUICE_SHOP_PORT = 3000;
const JUICE_SHOP_URL = `http://localhost:${JUICE_SHOP_PORT}`;

class JuiceShopDocker {
  async isDockerAvailable(): Promise<boolean> {
    try {
      await execAsync('docker info', { timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  async isRunning(): Promise<boolean> {
    try {
      const { stdout } = await execAsync(
        `docker ps -qf name=${CONTAINER_NAME}`,
        { timeout: 5000 }
      );
      return stdout.trim().length > 0;
    } catch {
      return false;
    }
  }

  async spawn(): Promise<{ ok: boolean; containerId?: string; error?: string }> {
    try {
      // Stop any existing stale container first
      await execAsync(`docker stop ${CONTAINER_NAME}`, { timeout: 15000 }).catch(() => {});
      const { stdout } = await execAsync(
        `docker run -d --name ${CONTAINER_NAME} --rm -p ${JUICE_SHOP_PORT}:${JUICE_SHOP_PORT} ${JUICE_SHOP_IMAGE}`,
        { timeout: 60000 }
      );
      return { ok: true, containerId: stdout.trim() };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  async stop(): Promise<{ ok: boolean; error?: string }> {
    try {
      await execAsync(`docker stop ${CONTAINER_NAME}`, { timeout: 20000 });
      return { ok: true };
    } catch (err: any) {
      return { ok: false, error: err.message };
    }
  }

  async waitForReady(timeoutMs = 60000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`${JUICE_SHOP_URL}`, { signal: AbortSignal.timeout(3000) });
        if (res.ok || res.status === 304) return true;
      } catch {
        // not ready yet
      }
      await new Promise(r => setTimeout(r, 2000));
    }
    return false;
  }

  async getSolvedCount(): Promise<number> {
    try {
      const res = await fetch(`${JUICE_SHOP_URL}/api/Challenges`, {
        signal: AbortSignal.timeout(5000)
      });
      if (!res.ok) return 0;
      const data = await res.json() as { data?: Array<{ solved: boolean }> };
      return (data.data || []).filter(c => c.solved).length;
    } catch {
      return 0;
    }
  }

  async getStatus(): Promise<{
    running: boolean;
    dockerAvailable: boolean;
    port: number;
    url: string;
    solved: number;
    total: number;
  }> {
    const dockerAvailable = await this.isDockerAvailable();
    const running = dockerAvailable ? await this.isRunning() : false;
    const solved = running ? await this.getSolvedCount() : 0;
    return {
      running,
      dockerAvailable,
      port: JUICE_SHOP_PORT,
      url: JUICE_SHOP_URL,
      solved,
      total: 31,
    };
  }
}

export const juiceShopDocker = new JuiceShopDocker();
export { JUICE_SHOP_URL, JUICE_SHOP_PORT };

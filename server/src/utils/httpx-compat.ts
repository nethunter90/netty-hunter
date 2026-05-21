import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export async function runHttpxProbe(url: string | string[], flags: string, timeoutMs = 120000): Promise<string> {
  const targets = Array.isArray(url)
    ? url.map(u => `-u "${u}"`).join(' ')
    : `-u "${url}"`;
  const { stdout } = await execAsync(`httpx ${flags} ${targets}`, { timeout: timeoutMs });
  return stdout;
}

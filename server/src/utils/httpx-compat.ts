import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

export async function runHttpxProbe(url: string, flags: string, timeoutMs = 120000): Promise<string> {
  const { stdout } = await execAsync(`httpx ${flags} -u "${url}"`, { timeout: timeoutMs });
  return stdout;
}

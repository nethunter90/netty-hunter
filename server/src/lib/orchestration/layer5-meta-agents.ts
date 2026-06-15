import { exec } from 'child_process';
import { promisify } from 'util';
import { aiBridge } from './layer6-ai-bridge';
import { agentRegistry } from './agent-registry';
import { interactshManager } from '../oob/interactsh-manager';
import {
  parseTargetUrl,
  parseNmapOutput, nmapToFindings,
  parseNiktoOutput, niktoToVulnerabilities,
  parseSqlmapOutput, sqlmapToVulnerabilities,
  parseNucleiOutput, nucleiToVulnerabilities,
  parseWhatwebJson,
} from './tool-parsers';
import { toolRunner } from '../stealth/tool-runner';

const execAsync = promisify(exec);

function isReal(): boolean {
  return process.env.REAL_TOOLS === 'true';
}

function shellEscape(s: string): string {
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

const toolCache = new Map<string, boolean>();

async function toolExists(name: string): Promise<boolean> {
  if (toolCache.has(name)) return toolCache.get(name)!;
  try {
    await execAsync(`which ${name}`, { timeout: 5000 });
    toolCache.set(name, true);
    console.log(`[ToolCheck] ${name}: FOUND`);
    return true;
  } catch {
    toolCache.set(name, false);
    console.log(`[ToolCheck] ${name}: NOT FOUND`);
    return false;
  }
}

interface ToolResult {
  success: boolean;
  result?: any;
  error?: string;
  real: boolean;
  tool: string;
  durationMs: number;
}

abstract class MetaAgent {
  abstract type: string;

  async execute(
    agentId: string,
    task: { tool: string; target: string; parameters: Record<string, any> }
  ): Promise<ToolResult> {
    const start = Date.now();
    console.log(`[${this.type}] Executing ${task.tool} on ${task.target}`);

    try {
      const result = await this.runTool(task.tool, task.target, task.parameters);
      const duration = Date.now() - start;
      console.log(`[${this.type}] ${task.tool} completed in ${duration}ms (real: ${result.real})`);
      agentRegistry.recordInvocation(agentId, true);
      return { success: true, ...result, tool: task.tool, durationMs: duration };
    } catch (error) {
      const duration = Date.now() - start;
      console.error(`[${this.type}] ${task.tool} failed after ${duration}ms:`, (error as Error).message);
      agentRegistry.recordInvocation(agentId, false);
      return { success: false, error: (error as Error).message, real: false, tool: task.tool, durationMs: duration };
    }
  }

  protected abstract runTool(
    tool: string, target: string, params: Record<string, any>
  ): Promise<{ result: any; real: boolean }>;

  protected async exec(cmd: string, timeout = 120000): Promise<string> {
    const { stdout } = await execAsync(cmd, {
      timeout,
      maxBuffer: 20 * 1024 * 1024,
      env: { ...process.env, TERM: 'dumb' },
    });
    return stdout;
  }
}

export class ReconAgent extends MetaAgent {
  type = 'recon';

  protected async runTool(tool: string, target: string, params: Record<string, any>) {
    const stealthMode = params.stealthMode || 'balanced';
    switch (tool) {
      case 'nmap': return this.runNmap(target, stealthMode);
      case 'subfinder': return this.runSubfinder(target);
      case 'httpx': return this.runHttpx(target);
      case 'whatweb': return this.runWhatweb(target);
      case 'crawl': return this.runCrawl(target);
      case 'amass': return this.runAmass(target);
      case 'gobuster': return this.runGobuster(target);
      case 'ffuf': return this.runFfuf(target);
      case 'wappalyzer': return this.runWappalyzer(target);
      case 'masscan': return this.runMasscan(target);
      case 'eyewitness': return this.runEyewitness(target);
      default: throw new Error(`Unknown recon tool: ${tool}`);
    }
  }

  private async runNmap(target: string, stealthMode?: string) {
    const { host, port } = parseTargetUrl(target);

    if (isReal() && await toolExists('nmap')) {
      const portFlag = port !== 80 ? `-p ${port}` : '-p 80,443,8080,8443,3000';
      let baseCmd = `nmap -sT -sV -Pn -T4 ${portFlag} ${host}`;
      if (stealthMode && stealthMode !== 'aggressive') {
        baseCmd = toolRunner.injectStealthFlags('nmap', `nmap -sT -sV -Pn ${portFlag} ${host}`, stealthMode);
        console.log(`[ReconAgent] Stealth nmap command: ${baseCmd}`);
      }
      const stdout = await this.exec(baseCmd, 300000);
      const parsed = parseNmapOutput(stdout, target);
      return { result: { parsed, raw: stdout }, real: true };
    }

    return {
      result: {
        parsed: {
          host,
          ports: [
            { port, protocol: 'tcp', state: 'open', service: 'http', version: 'nginx 1.18.0' },
          ],
          endpoints: [{ url: port !== 80 ? `http://${host}:${port}/` : `http://${host}/`, port, service: 'http' }],
          technologies: [{ name: 'nginx', version: '1.18.0', category: 'web-server', confidence: 0.9 }],
        },
        raw: `PORT     STATE SERVICE VERSION\n${port}/tcp   open  http    nginx 1.18.0`,
      },
      real: false,
    };
  }

  private async runSubfinder(target: string) {
    const { host } = parseTargetUrl(target);

    const isLocal = host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost');
    if (isLocal) {
      return { result: { subdomains: [] }, real: true };
    }

    if (isReal() && await toolExists('subfinder')) {
      const stdout = await this.exec(`subfinder -d ${host} -silent`, 120000);
      return {
        result: { subdomains: stdout.trim().split('\n').filter(Boolean) },
        real: true,
      };
    }

    return {
      result: { subdomains: [`www.${host}`, `api.${host}`, `admin.${host}`] },
      real: false,
    };
  }

  private async runHttpx(target: string) {
    const { host, port } = parseTargetUrl(target);
    const isLocal = host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost');

    if (isReal() && await toolExists('httpx')) {
      const { runHttpxProbe } = await import('../../utils/httpx-compat');
      const stdout = await runHttpxProbe(host, '-json', 120000);
      const lines = stdout.trim().split('\n').filter(Boolean);
      return {
        result: { endpoints: lines.map(line => { try { return JSON.parse(line); } catch { return null; } }).filter(Boolean) },
        real: true,
      };
    }

    const simUrl = isLocal
      ? (target.startsWith('http') ? target : `http://${host}:${port}/`)
      : `https://${host}/`;

    return {
      result: {
        endpoints: [{ url: simUrl, status_code: 200, title: 'Target Site' }],
      },
      real: false,
    };
  }

  private async runWhatweb(target: string) {
    if (isReal() && await toolExists('whatweb')) {
      let stdout = '';
      try {
        stdout = await this.exec(`whatweb --log-json=- ${target} 2>/dev/null`, 60000);
      } catch (e: any) {
        stdout = e.stdout || '';
      }

      if (!stdout.trim()) {
        try {
          stdout = await this.exec(`whatweb ${target} 2>/dev/null`, 60000);
        } catch (e: any) {
          stdout = e.stdout || '';
        }
      }

      const parsed = parseWhatwebJson(stdout, target);
      return {
        result: {
          parsed,
          technologies: parsed.technologies,
          raw: stdout,
        },
        real: true,
      };
    }

    return {
      result: {
        technologies: [
          { name: 'nginx', version: '1.18.0', category: 'web-server', confidence: 0.9 },
          { name: 'React', version: '18.0.0', category: 'frontend-framework', confidence: 0.7 },
        ],
      },
      real: false,
    };
  }

  private async runCrawl(target: string) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;
    if (isReal()) {
      try {
        const stdout = await this.exec(
          `curl -sS --max-time 15 "${url}" | grep -oE '(href|src|action)="[^"]*"' | sed 's/.*="//;s/"$//' | sort -u`,
          20000
        );
        const rawPaths = stdout.trim().split('\n').filter(Boolean);
        const baseUrl = url.replace(/\/$/, '');
        const seen = new Set<string>();
        const endpoints: { url: string; method: string; discoveredBy: string }[] = [];
        for (const p of rawPaths) {
          let fullUrl: string;
          if (p.startsWith('http://') || p.startsWith('https://')) {
            if (!p.startsWith(baseUrl)) continue;
            fullUrl = p;
          } else if (p.startsWith('/')) {
            fullUrl = baseUrl + p;
          } else if (p.startsWith('#') || p.startsWith('javascript:') || p.startsWith('mailto:') || p.startsWith('data:')) {
            continue;
          } else {
            fullUrl = baseUrl + '/' + p;
          }
          fullUrl = fullUrl.split('#')[0].split('?')[0];
          if (!seen.has(fullUrl) && fullUrl.startsWith(baseUrl)) {
            seen.add(fullUrl);
            endpoints.push({ url: fullUrl, method: 'GET', discoveredBy: 'crawl' });
          }
        }
        console.log(`[ReconAgent] Crawl discovered ${endpoints.length} unique endpoints from ${rawPaths.length} raw links`);
        return { result: { endpoints }, real: true };
      } catch {
        return { result: { endpoints: [] }, real: true };
      }
    }

    return {
      result: {
        endpoints: [
          { url: `${url}/api`, method: 'GET', discoveredBy: 'crawl' },
          { url: `${url}/login`, method: 'GET', discoveredBy: 'crawl' },
          { url: `${url}/admin`, method: 'GET', discoveredBy: 'crawl' },
        ],
      },
      real: false,
    };
  }

  private async runAmass(target: string) {
    const { host } = parseTargetUrl(target);
    const isLocal = host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost');
    if (isLocal) {
      return { result: { subdomains: [] }, real: true };
    }

    if (isReal() && await toolExists('amass')) {
      try {
        const stdout = await this.exec(`amass enum -passive -d ${shellEscape(host)}`, 300000);
        const subdomains = stdout.trim().split('\n').filter(Boolean);
        console.log(`[ReconAgent] Amass found ${subdomains.length} subdomains`);
        return { result: { subdomains }, real: true };
      } catch {
        return { result: { subdomains: [] }, real: true };
      }
    }

    return {
      result: { subdomains: [`cdn.${host}`, `staging.${host}`, `internal.${host}`] },
      real: false,
    };
  }

  private async runGobuster(target: string) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('gobuster')) {
      try {
        const stdout = await this.exec(
          `gobuster dir -u ${shellEscape(url)} -w /usr/share/wordlists/dirb/common.txt -q --no-error -t 10 2>/dev/null`,
          300000
        );
        const directories: { path: string; status: number; size?: number }[] = [];
        for (const line of stdout.trim().split('\n').filter(Boolean)) {
          const m = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/) ||
                    line.match(/^(\S+)\s+\[Status=(\d+).*?Size=(\d+)/);
          if (m) {
            directories.push({ path: m[1], status: parseInt(m[2]), size: m[3] ? parseInt(m[3]) : undefined });
          }
        }
        const baseUrl = url.replace(/\/$/, '');
        const endpoints = directories.map(d => ({
          url: baseUrl + d.path,
          method: 'GET',
          statusCode: d.status,
          discoveredBy: 'gobuster'
        }));
        console.log(`[ReconAgent] Gobuster discovered ${directories.length} paths`);
        return { result: { endpoints, directories }, real: true };
      } catch {
        return { result: { endpoints: [], directories: [] }, real: true };
      }
    }

    return {
      result: {
        endpoints: [
          { url: `${url}/admin`, method: 'GET', statusCode: 200, discoveredBy: 'gobuster' },
          { url: `${url}/backup`, method: 'GET', statusCode: 403, discoveredBy: 'gobuster' },
          { url: `${url}/.git`, method: 'GET', statusCode: 403, discoveredBy: 'gobuster' },
          { url: `${url}/api`, method: 'GET', statusCode: 200, discoveredBy: 'gobuster' },
        ],
      },
      real: false,
    };
  }

  private async runFfuf(target: string) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('ffuf')) {
      try {
        const stdout = await this.exec(
          `ffuf -u ${shellEscape(url)}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,403 -t 10 -s 2>/dev/null`,
          300000
        );
        const paths = stdout.trim().split('\n').filter(Boolean);
        const baseUrl = url.replace(/\/$/, '');
        const endpoints = paths.map(p => ({
          url: baseUrl + '/' + p.trim(),
          method: 'GET',
          discoveredBy: 'ffuf'
        }));
        console.log(`[ReconAgent] ffuf discovered ${endpoints.length} paths`);
        return { result: { endpoints }, real: true };
      } catch {
        return { result: { endpoints: [] }, real: true };
      }
    }

    return {
      result: {
        endpoints: [
          { url: `${url}/config`, method: 'GET', discoveredBy: 'ffuf' },
          { url: `${url}/debug`, method: 'GET', discoveredBy: 'ffuf' },
          { url: `${url}/env`, method: 'GET', discoveredBy: 'ffuf' },
        ],
      },
      real: false,
    };
  }

  private async runWappalyzer(target: string) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('wappalyzer')) {
      try {
        const stdout = await this.exec(`wappalyzer ${shellEscape(url)} 2>/dev/null`, 120000);
        try {
          const parsed = JSON.parse(stdout);
          const technologies = (parsed.technologies || []).map((t: any) => ({
            name: t.name || t.slug || 'unknown',
            version: t.version || undefined,
            category: (t.categories || []).map((c: any) => c.name || c).join(', ') || 'unknown',
            confidence: (t.confidence || 100) / 100
          }));
          console.log(`[ReconAgent] Wappalyzer detected ${technologies.length} technologies`);
          return { result: { technologies }, real: true };
        } catch {
          return { result: { technologies: [], raw: stdout }, real: true };
        }
      } catch {
        return { result: { technologies: [] }, real: true };
      }
    }

    return {
      result: {
        technologies: [
          { name: 'Express', version: '4.18', category: 'Web frameworks', confidence: 0.95 },
          { name: 'Angular', version: '15', category: 'JavaScript frameworks', confidence: 0.9 },
          { name: 'Node.js', category: 'Programming languages', confidence: 0.95 },
        ],
      },
      real: false,
    };
  }

  private async runMasscan(target: string) {
    const { host } = parseTargetUrl(target);
    const isLocal = host === 'localhost' || host === '127.0.0.1';

    if (isReal() && await toolExists('masscan')) {
      try {
        const scanHost = isLocal ? '127.0.0.1' : host;
        const stdout = await this.exec(
          `masscan ${shellEscape(scanHost)} -p1-10000 --rate=500 --banners -oJ - 2>/dev/null`,
          300000
        );
        const ports: { port: number; protocol: string; service?: string }[] = [];
        for (const line of stdout.trim().split('\n').filter(Boolean)) {
          try {
            const entry = JSON.parse(line.replace(/,$/, ''));
            if (entry.ports) {
              for (const p of entry.ports) {
                ports.push({ port: p.port, protocol: p.proto || 'tcp', service: p.service?.name });
              }
            }
          } catch {}
        }
        const endpoints = ports.map(p => ({
          url: `${host}:${p.port}`,
          method: 'TCP',
          service: p.service,
          discoveredBy: 'masscan'
        }));
        console.log(`[ReconAgent] Masscan found ${ports.length} open ports`);
        return { result: { endpoints, ports }, real: true };
      } catch {
        return { result: { endpoints: [], ports: [] }, real: true };
      }
    }

    return {
      result: {
        endpoints: [
          { url: `${host}:80`, method: 'TCP', service: 'http', discoveredBy: 'masscan' },
          { url: `${host}:443`, method: 'TCP', service: 'https', discoveredBy: 'masscan' },
          { url: `${host}:3000`, method: 'TCP', service: 'http-alt', discoveredBy: 'masscan' },
        ],
      },
      real: false,
    };
  }

  private async runEyewitness(target: string) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('eyewitness')) {
      const outDir = `/tmp/eyewitness-${Date.now()}`;
      try {
        await this.exec(
          `eyewitness --web --single ${shellEscape(url)} -d ${outDir} --no-prompt --timeout 15 2>/dev/null`,
          120000
        );
        let screenshots: string[] = [];
        try {
          const lsOut = await this.exec(`ls ${outDir}/screens/ 2>/dev/null`);
          screenshots = lsOut.trim().split('\n').filter(f => f.endsWith('.png') || f.endsWith('.jpg'));
        } catch {}
        let serverHeader = '';
        try {
          const headerOut = await this.exec(`cat ${outDir}/report.html 2>/dev/null | head -100`);
          const serverMatch = headerOut.match(/Server:\s*([^\n<]+)/i);
          if (serverMatch) serverHeader = serverMatch[1].trim();
        } catch {}
        console.log(`[ReconAgent] EyeWitness captured ${screenshots.length} screenshot(s)`);
        return {
          result: {
            technologies: serverHeader ? [{ name: serverHeader, category: 'web-server', confidence: 0.8 }] : [],
            screenshots: screenshots.map(s => `${outDir}/screens/${s}`),
            reportPath: `${outDir}/report.html`
          },
          real: true,
        };
      } catch {
        return { result: { technologies: [] }, real: true };
      }
    }

    return {
      result: {
        technologies: [{ name: 'nginx/1.18', category: 'web-server', confidence: 0.8 }],
        screenshots: ['/tmp/eyewitness-sim/screens/target.png'],
        reportPath: '/tmp/eyewitness-sim/report.html'
      },
      real: false,
    };
  }
}

export class ScannerAgent extends MetaAgent {
  type = 'scanner';

  protected async runTool(tool: string, target: string, params: Record<string, any>) {
    const stealthMode = params.stealthMode || 'balanced';
    switch (tool) {
      case 'nikto': return this.runNikto(target, stealthMode);
      case 'nuclei': return this.runNuclei(target, params, stealthMode);
      case 'sqlmap': return this.runSqlmap(target, params, stealthMode);
      default: throw new Error(`Unknown scanner tool: ${tool}`);
    }
  }

  private async runNikto(target: string, stealthMode?: string) {
    if (isReal() && await toolExists('nikto')) {
      let baseCmd = `nikto -h ${target} -maxtime 120 -Tuning 123bde`;
      if (stealthMode && stealthMode !== 'aggressive') {
        baseCmd = toolRunner.injectStealthFlags('nikto', `nikto -h ${target} -maxtime 180 -Tuning 123bde`, stealthMode);
        console.log(`[ScannerAgent] Stealth nikto command: ${baseCmd}`);
      }
      let stdout = '';
      try {
        stdout = await this.exec(baseCmd, 240000);
      } catch (e: any) {
        stdout = e.stdout || e.message || '';
      }
      const parsed = parseNiktoOutput(stdout, target);
      const vulnerabilities = niktoToVulnerabilities(parsed);
      return {
        result: {
          parsed,
          vulnerabilities,
          technologies: parsed.technologies,
          raw: stdout,
        },
        real: true,
      };
    }

    return {
      result: {
        vulnerabilities: [
          {
            type: 'Information Disclosure',
            severity: 'medium',
            endpoint: target,
            description: 'Server leaks information via X-Powered-By header',
            exploitable: false,
          },
        ],
        findings: [
          { id: 'OSVDB-3092', description: 'Server leaks information via X-Powered-By header' },
        ],
      },
      real: false,
    };
  }

  private async runNuclei(target: string, params: Record<string, any>, stealthMode?: string) {
    if (isReal() && await toolExists('nuclei')) {
      const severity = params.severity || 'low,medium,high,critical';

      let rateLimit = 100;
      let concurrency = '';
      if (stealthMode === 'stealth') {
        rateLimit = 10;
        concurrency = '-c 2';
      } else if (stealthMode === 'ultrastealth') {
        rateLimit = 3;
        concurrency = '-c 1';
      }

      // Use interactsh for OOB template detection when the client is running;
      // otherwise disable it to avoid nuclei hanging waiting for a server.
      const interactshFlag = interactshManager.getDomain() ? "" : "-no-interactsh";
      let baseCmd = `nuclei -u ${target} -t http/technologies/ -t http/exposures/ -t http/misconfiguration/ -t http/vulnerabilities/ -severity ${severity} -jsonl -silent -timeout 5 -retries 0 -rate-limit ${rateLimit} ${concurrency} ${interactshFlag} 2>/dev/null`.trimEnd();
      if (stealthMode && stealthMode !== 'aggressive') {
        console.log(`[ScannerAgent] Stealth nuclei: rate-limit=${rateLimit}, mode=${stealthMode}`);
      }

      let stdout = '';
      try {
        stdout = await this.exec(baseCmd, 300000);
      } catch (e: any) {
        stdout = e.stdout || '';
      }

      if (!stdout.trim()) {
        try {
          stdout = await this.exec(
            `nuclei -u ${target} -severity medium,high,critical -jsonl -silent -timeout 5 -retries 0 ${interactshFlag} 2>/dev/null`.trimEnd(),
            180000
          );
        } catch (e: any) {
          stdout = e.stdout || '';
        }
      }

      const parsed = parseNucleiOutput(stdout, target);
      const vulnerabilities = nucleiToVulnerabilities(parsed);

      console.log(`[ScannerAgent] Nuclei found ${vulnerabilities.length} vulnerabilities against ${target}`);

      return {
        result: {
          parsed,
          vulnerabilities,
          technologies: [],
          raw: stdout,
        },
        real: true,
      };
    }

    return {
      result: {
        vulnerabilities: [
          {
            type: 'XSS',
            severity: 'medium',
            endpoint: target,
            description: 'Reflected XSS in search parameter',
            exploitable: true,
          },
        ],
      },
      real: false,
    };
  }

  private async runSqlmap(target: string, params: Record<string, any>, stealthMode?: string) {
    if (isReal() && await toolExists('sqlmap')) {
      const injectableTargets: string[] = params.injectableTargets || [];

      const targetsToTest: string[] = [];
      if (target.includes('?') && target.includes('=')) {
        targetsToTest.push(target);
      }
      for (const t of injectableTargets) {
        if (!targetsToTest.includes(t)) {
          targetsToTest.push(t);
        }
      }

      if (targetsToTest.length === 0) {
        return {
          result: {
            vulnerable: false,
            message: 'No injectable parameters found to test',
            skipped: true,
          },
          real: true,
        };
      }

      let stealthFlags = '';
      let threads = 5;
      if (stealthMode === 'stealth') {
        stealthFlags = '--delay=2 --random-agent';
        threads = 2;
      } else if (stealthMode === 'ultrastealth') {
        stealthFlags = '--delay=5 --time-sec=15 --random-agent --safe-url-retries=3';
        threads = 1;
      }

      const allVulnerabilities: any[] = [];
      let combinedRaw = '';

      for (const testTarget of targetsToTest.slice(0, 5)) {
        console.log(`[ScannerAgent] SQLMap testing: ${testTarget} (stealth=${stealthMode})`);
        let stdout = '';
        try {
          stdout = await this.exec(
            `sqlmap -u "${testTarget}" --batch --threads=${threads} --level=1 --risk=1 --timeout=10 --retries=1 ${stealthFlags} --output-dir=/tmp/sqlmap-${Date.now()} 2>&1`,
            120000
          );
        } catch (e: any) {
          stdout = e.stdout || e.message || '';
        }

        combinedRaw += `\n--- Target: ${testTarget} ---\n${stdout}\n`;

        const parsed = parseSqlmapOutput(stdout, testTarget);
        const vulns = sqlmapToVulnerabilities(parsed);
        allVulnerabilities.push(...vulns);

        if (parsed.vulnerable) {
          console.log(`[ScannerAgent] SQLMap found injection in: ${testTarget}`);
        }
      }

      return {
        result: {
          vulnerabilities: allVulnerabilities,
          testedTargets: targetsToTest.slice(0, 5),
          raw: combinedRaw,
        },
        real: true,
      };
    }

    return {
      result: {
        vulnerable: true,
        dbms: 'MySQL',
        injectionPoint: 'GET parameter "id"',
        vulnerabilities: [
          {
            type: 'SQL Injection',
            severity: 'critical',
            endpoint: target,
            description: 'Boolean-based blind SQL injection in GET parameter "id"',
            exploitable: true,
          },
        ],
      },
      real: false,
    };
  }
}

export class ExploitMetaAgent extends MetaAgent {
  type = 'exploit';

  protected async runTool(tool: string, target: string, params: Record<string, any>) {
    const stealthMode = params.stealthMode || 'balanced';
    switch (tool) {
      case 'sqlmap': {
        if (isReal() && await toolExists('sqlmap')) {
          const injectableTargets: string[] = params.injectableTargets || [];
          const targetsToTest: string[] = [];

          if (target.includes('?') && target.includes('=')) {
            targetsToTest.push(target);
          }
          for (const t of injectableTargets) {
            if (!targetsToTest.includes(t)) targetsToTest.push(t);
          }

          if (targetsToTest.length === 0) {
            return {
              result: { exploited: false, message: 'No injectable parameters to exploit', skipped: true },
              real: true,
            };
          }

          let stealthFlags = '';
          let threads = 5;
          if (stealthMode === 'stealth') {
            stealthFlags = '--delay=3 --random-agent';
            threads = 2;
          } else if (stealthMode === 'ultrastealth') {
            stealthFlags = '--delay=8 --time-sec=20 --random-agent --safe-url-retries=5';
            threads = 1;
          }

          const allVulnerabilities: any[] = [];
          let combinedRaw = '';

          for (const testTarget of targetsToTest.slice(0, 3)) {
            console.log(`[ExploitAgent] SQLMap deep testing: ${testTarget} (stealth=${stealthMode})`);
            let stdout = '';
            try {
              stdout = await this.exec(
                `sqlmap -u "${testTarget}" --batch --threads=${threads} --level=3 --risk=2 --timeout=10 --retries=1 ${stealthFlags} --output-dir=/tmp/sqlmap-exploit-${Date.now()} 2>&1`,
                240000
              );
            } catch (e: any) {
              stdout = e.stdout || e.message || '';
            }
            combinedRaw += `\n--- Target: ${testTarget} ---\n${stdout}\n`;
            const parsed = parseSqlmapOutput(stdout, testTarget);
            allVulnerabilities.push(...sqlmapToVulnerabilities(parsed));
          }

          return {
            result: { vulnerabilities: allVulnerabilities, raw: combinedRaw },
            real: true,
          };
        }
        return {
          result: { exploited: false, reason: 'Simulation mode - no actual exploitation' },
          real: false,
        };
      }

      case 'custom_exploit': {
        try {
          const aiResult = await aiBridge.invokeAgent(
            'exploit',
            `Analyze this vulnerability and create a proof-of-concept: ${JSON.stringify(params.vulnerability)}`,
            { target, vulnerability: params.vulnerability }
          );
          if (aiResult.provider === 'error' || aiResult.provider === 'simulation') {
            return {
              result: { exploited: false, skipped: true, reason: 'AI unavailable - custom exploit requires Ollama' },
              real: false,
            };
          }
          return { result: aiResult.result, real: true };
        } catch (e: any) {
          return {
            result: { exploited: false, skipped: true, reason: e.message || 'AI error' },
            real: false,
          };
        }
      }

      case 'metasploit':
        if (isReal()) {
          try {
            const { stdout } = await execAsync(`msfconsole -q -x "use ${params.module || 'auxiliary/scanner/http/http_version'}; set RHOSTS ${target}; run; exit" 2>&1`, { timeout: 120000 });
            return {
              result: { output: stdout, exploited: stdout.includes('session') || stdout.includes('opened'), raw: stdout },
              real: true,
            };
          } catch (e: any) {
            return {
              result: { exploited: false, error: e.message, raw: e.stdout || '' },
              real: true,
            };
          }
        }
        return {
          result: { simulated: true, message: 'Metasploit requires REAL_TOOLS=true and msfconsole installed' },
          real: false,
        };

      default:
        throw new Error(`Unknown exploit tool: ${tool}`);
    }
  }
}

export class SupportMetaAgent extends MetaAgent {
  type = 'support';

  protected async runTool(tool: string, target: string, params: Record<string, any>) {
    switch (tool) {
      case 'hydra':
        if (isReal()) {
          try {
            const service = params.service || 'http-post-form';
            const userlist = params.userlist || '/usr/share/wordlists/users.txt';
            const passlist = params.passlist || '/usr/share/wordlists/passwords.txt';
            const delay = params.delay || 2;
            const { stdout } = await execAsync(
              `hydra -L ${userlist} -P ${passlist} -t 4 -W ${delay} ${target} ${service} 2>&1`,
              { timeout: 600000 }
            );
            const lines = stdout.trim().split('\n').filter((l: string) => l.includes('login:'));
            return {
              result: { credentials: lines, count: lines.length, raw: stdout },
              real: true,
            };
          } catch (e: any) {
            return {
              result: { credentials: [], error: e.message, raw: e.stdout || '' },
              real: true,
            };
          }
        }
        return {
          result: { simulated: true, message: 'Hydra requires REAL_TOOLS=true and hydra installed' },
          real: false,
        };
      case 'hashcat':
        if (isReal()) {
          try {
            const hashFile = params.hashFile || '/tmp/hashes.txt';
            const mode = params.mode || 0;
            const wordlist = params.wordlist || '/usr/share/wordlists/rockyou.txt';
            const { stdout } = await execAsync(
              `hashcat -m ${mode} ${hashFile} ${wordlist} --force --potfile-disable -o /tmp/hashcat-out.txt 2>&1`,
              { timeout: 600000 }
            );
            let cracked: string[] = [];
            try {
              const fs = await import('fs');
              cracked = fs.readFileSync('/tmp/hashcat-out.txt', 'utf8').trim().split('\n').filter(Boolean);
            } catch {}
            return {
              result: { cracked, count: cracked.length, raw: stdout },
              real: true,
            };
          } catch (e: any) {
            return {
              result: { cracked: [], error: e.message, raw: e.stdout || '' },
              real: true,
            };
          }
        }
        return {
          result: { simulated: true, message: 'Hashcat requires REAL_TOOLS=true, GPU, and hashcat installed' },
          real: false,
        };
      default:
        throw new Error(`Unknown support tool: ${tool}`);
    }
  }
}

export const reconAgent = new ReconAgent();
export const scannerAgent = new ScannerAgent();
export const exploitAgent = new ExploitMetaAgent();
export const supportAgent = new SupportMetaAgent();

export const metaAgents: Record<string, MetaAgent> = {
  recon: reconAgent,
  scanner: scannerAgent,
  exploit: exploitAgent,
  support: supportAgent,
};

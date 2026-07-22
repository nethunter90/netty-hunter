import { execFile } from 'child_process';
import { promisify } from 'util';
import { readdir, readFile } from 'fs/promises';
import { autoAdjuster } from '../stealth/auto-adjuster';
import { aiBridge } from './layer6-ai-bridge';
import { agentRegistry } from './agent-registry';
import { interactshManager } from '../oob/interactsh-manager';
import { dispatchTool, ToolOutOfScopeError } from '../net/dispatch-tool';
import { scopedHttp } from '../net/scoped-http';
import { checkExploitationToolAuthorization } from '../../agents/ExploitationToolGate';
import {
  parseTargetUrl,
  parseNmapOutput, nmapToFindings,
  parseNiktoOutput, niktoToVulnerabilities,
  parseSqlmapOutput, sqlmapToVulnerabilities,
  parseNucleiOutput, nucleiToVulnerabilities,
  parseWhatwebJson,
} from './tool-parsers';
import { toolRunner } from '../stealth/tool-runner';

const execFileAsync = promisify(execFile);

function isReal(): boolean {
  return process.env.REAL_TOOLS === 'true';
}

/**
 * 2026-07-22 (Phase 2, external-tool chokepoint): every tool exec in this
 * file now goes through dispatchTool() (execFile + array args + a real
 * ScopeGuard.isInScope() check immediately before spawn) instead of building
 * shell-string commands with exec(). This replaces the 2026-07-21 stopgap
 * (ALLOW_UNSAFE_SHELL_RECON_TOOLS) for whatweb/nikto/nuclei/sqlmap/httpx/
 * crawl — dispatchTool structurally closes the shell-injection class those
 * were gated against, so the old kill-switch is gone along with the exec()
 * calls it protected. Exploitation/credential-attack tools (metasploit,
 * hydra, hashcat) get a SEPARATE, still-fail-closed-by-default gate — see
 * checkExploitationToolAuthorization() — because dispatchTool only answers
 * "can a target inject a command," not "should this platform autonomously
 * run credential attacks against someone's property."
 *
 * Only reachable today via routes/reasoning.ts's POST /lab/run -> hunt-lab-
 * runner.ts -> huntOrchestrator.createHunt(), which always uses a
 * pre-registered lab-profile targetUrl (never attacker/API-supplied) — see
 * layer1-hunt-orchestrator.ts's resolveCustomTargetProgram() call for how
 * this subsystem now gets a real, ScopeGuard-backed programId.
 */
async function toolExists(name: string): Promise<boolean> {
  try {
    await execFileAsync('which', [name], { timeout: 5000 });
    console.log(`[ToolCheck] ${name}: FOUND`);
    return true;
  } catch {
    console.log(`[ToolCheck] ${name}: NOT FOUND`);
    return false;
  }
}

/** Static, per-tool stealth flags (toolRunner.injectStealthFlags's source of
 *  truth) as a token array — never target-derived, safe to splice into an
 *  args array as-is. Calling injectStealthFlags with an empty base command
 *  isolates just the appended flags without duplicating toolRunner's table. */
function stealthArgTokens(tool: string, mode?: string): string[] {
  if (!mode || mode === 'aggressive') return [];
  const withFlags = toolRunner.injectStealthFlags(tool, '', mode).trim();
  return withFlags ? withFlags.split(/\s+/) : [];
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
    task: { tool: string; target: string; parameters: Record<string, any> },
    programId: number | null | undefined,
  ): Promise<ToolResult> {
    const start = Date.now();
    console.log(`[${this.type}] Executing ${task.tool} on ${task.target}`);

    try {
      const result = await this.runTool(task.tool, task.target, task.parameters, programId);
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
    tool: string, target: string, params: Record<string, any>, programId: number | null | undefined,
  ): Promise<{ result: any; real: boolean }>;

  /** Runs dispatchTool() and returns stdout, or '' if the target is out of
   *  scope (mirrors the old exec()-wrapper's "swallow and continue with
   *  empty output" behavior on failure — callers already handle empty
   *  stdout as "nothing found"). Scope violations are logged, not silently
   *  eaten, but still don't throw past this layer so one blocked tool call
   *  doesn't abort the whole recon cycle. */
  protected async dispatch(tool: string, target: string, args: string[], programId: number | null | undefined, timeoutMs = 120000): Promise<string> {
    try {
      const { stdout } = await dispatchTool({ tool, target, args, programId, timeoutMs });
      return stdout;
    } catch (e) {
      if (e instanceof ToolOutOfScopeError) {
        console.warn(`[${this.type}] ${tool} blocked — out of scope: ${e.reason}`);
        return '';
      }
      throw e;
    }
  }
}

export class ReconAgent extends MetaAgent {
  type = 'recon';

  protected async runTool(tool: string, target: string, params: Record<string, any>, programId: number | null | undefined) {
    const _baseMode = params.stealthMode || 'balanced';
    const _adjMode = autoAdjuster.getCurrentMode();
    const _ORDER = ['aggressive', 'balanced', 'stealth', 'ultrastealth'];
    const stealthMode = _ORDER.indexOf(_adjMode) > _ORDER.indexOf(_baseMode) ? _adjMode : _baseMode;
    switch (tool) {
      case 'nmap': return this.runNmap(target, stealthMode, programId);
      case 'subfinder': return this.runSubfinder(target, programId);
      case 'httpx': return this.runHttpx(target, programId);
      case 'whatweb': return this.runWhatweb(target, programId);
      case 'crawl': return this.runCrawl(target, programId);
      case 'amass': return this.runAmass(target, programId);
      case 'gobuster': return this.runGobuster(target, programId);
      case 'ffuf': return this.runFfuf(target, programId);
      case 'wappalyzer': return this.runWappalyzer(target, programId);
      case 'masscan': return this.runMasscan(target, programId);
      case 'eyewitness': return this.runEyewitness(target, programId);
      default: throw new Error(`Unknown recon tool: ${tool}`);
    }
  }

  private async runNmap(target: string, stealthMode: string | undefined, programId: number | null | undefined) {
    const { host, port } = parseTargetUrl(target);

    if (isReal() && await toolExists('nmap')) {
      const portArgs = port !== 80 ? ['-p', String(port)] : ['-p', '80,443,8080,8443,3000'];
      const aggressive = !stealthMode || stealthMode === 'aggressive';
      const args = aggressive
        ? ['-sT', '-sV', '-Pn', '-T4', ...portArgs, '{domain}']
        : ['-sT', '-sV', '-Pn', ...portArgs, '{domain}', ...stealthArgTokens('nmap', stealthMode)];
      const stdout = await this.dispatch('nmap', target, args, programId, 300000);
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

  private async runSubfinder(target: string, programId: number | null | undefined) {
    const { host } = parseTargetUrl(target);

    const isLocal = host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost');
    if (isLocal) {
      return { result: { subdomains: [] }, real: true };
    }

    if (isReal() && await toolExists('subfinder')) {
      const stdout = await this.dispatch('subfinder', target, ['-d', '{domain}', '-silent'], programId);
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

  private async runHttpx(target: string, programId: number | null | undefined) {
    const { host, port } = parseTargetUrl(target);
    const isLocal = host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost');

    if (isReal() && await toolExists('httpx')) {
      const stdout = await this.dispatch('httpx', target, ['-u', '{url}', '-json'], programId);
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

  private async runWhatweb(target: string, programId: number | null | undefined) {
    if (isReal() && await toolExists('whatweb')) {
      let stdout = await this.dispatch('whatweb', target, ['--log-json=-', '{url}'], programId, 60000);
      if (!stdout.trim()) {
        stdout = await this.dispatch('whatweb', target, ['{url}'], programId, 60000);
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

  /**
   * 2026-07-22: previously shelled out to `curl ... | grep ... | sed ... |
   * sort -u` — a multi-stage shell PIPELINE that can't be expressed as a
   * single execFile call at all. Rewritten to fetch via scopedHttp (the same
   * rate-limited, scope-checked HTTP chokepoint every other prober uses) and
   * do the href/src/action extraction with a plain JS regex over the body —
   * no shell, no exec() of any kind, and it reuses scopedHttp's own
   * scope-check + pacing instead of duplicating one via dispatchTool.
   */
  private async runCrawl(target: string, programId: number | null | undefined) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;
    if (isReal()) {
      try {
        const resp = await scopedHttp.get(url, { timeout: 15000, validateStatus: () => true }, programId);
        const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data ?? '');
        const rawPaths: string[] = [];
        const attrPattern = /(?:href|src|action)\s*=\s*"([^"]*)"/g;
        let m: RegExpExecArray | null;
        while ((m = attrPattern.exec(body)) !== null) rawPaths.push(m[1]);

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

  private async runAmass(target: string, programId: number | null | undefined) {
    const { host } = parseTargetUrl(target);
    const isLocal = host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost');
    if (isLocal) {
      return { result: { subdomains: [] }, real: true };
    }

    if (isReal() && await toolExists('amass')) {
      try {
        const stdout = await this.dispatch('amass', target, ['enum', '-passive', '-d', '{domain}'], programId, 300000);
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

  private async runGobuster(target: string, programId: number | null | undefined) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('gobuster')) {
      try {
        const stdout = await this.dispatch('gobuster', target,
          ['dir', '-u', '{url}', '-w', '/usr/share/wordlists/dirb/common.txt', '-q', '--no-error', '-t', '10'],
          programId, 300000);
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

  private async runFfuf(target: string, programId: number | null | undefined) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('ffuf')) {
      try {
        const stdout = await this.dispatch('ffuf', target,
          ['-u', '{url}/FUZZ', '-w', '/usr/share/wordlists/dirb/common.txt', '-mc', '200,204,301,302,307,403', '-t', '10', '-s'],
          programId, 300000);
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

  private async runWappalyzer(target: string, programId: number | null | undefined) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('wappalyzer')) {
      try {
        const stdout = await this.dispatch('wappalyzer', target, ['{url}'], programId, 120000);
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

  private async runMasscan(target: string, programId: number | null | undefined) {
    const { host } = parseTargetUrl(target);
    const isLocal = host === 'localhost' || host === '127.0.0.1';

    if (isReal() && await toolExists('masscan')) {
      try {
        // masscan takes a bare host/IP, never a URL — {domain} substitutes to
        // just that, but dispatchTool still scope-checks the full `target` URL.
        const stdout = await this.dispatch('masscan', target,
          [isLocal ? '127.0.0.1' : '{domain}', '-p1-10000', '--rate=500', '--banners', '-oJ', '-'],
          programId, 300000);
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

  private async runEyewitness(target: string, programId: number | null | undefined) {
    const { host, port } = parseTargetUrl(target);
    const url = target.startsWith('http') ? target : `http://${host}:${port}`;

    if (isReal() && await toolExists('eyewitness')) {
      const outDir = `/tmp/eyewitness-${Date.now()}`;
      try {
        await this.dispatch('eyewitness', target,
          ['--web', '--single', '{url}', '-d', outDir, '--no-prompt', '--timeout', '15'],
          programId, 120000);
        // eyewitness's own output directory — a Date.now()-based literal, not
        // target data — so these are plain local filesystem reads, not
        // further tool dispatch; no exec()/shell needed at all.
        let screenshots: string[] = [];
        try {
          const files = await readdir(`${outDir}/screens/`);
          screenshots = files.filter(f => f.endsWith('.png') || f.endsWith('.jpg'));
        } catch {}
        let serverHeader = '';
        try {
          const reportHtml = await readFile(`${outDir}/report.html`, 'utf8');
          const serverMatch = reportHtml.slice(0, 20000).match(/Server:\s*([^\n<]+)/i);
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

  protected async runTool(tool: string, target: string, params: Record<string, any>, programId: number | null | undefined) {
    const _baseMode = params.stealthMode || 'balanced';
    const _adjMode = autoAdjuster.getCurrentMode();
    const _ORDER = ['aggressive', 'balanced', 'stealth', 'ultrastealth'];
    const stealthMode = _ORDER.indexOf(_adjMode) > _ORDER.indexOf(_baseMode) ? _adjMode : _baseMode;
    switch (tool) {
      case 'nikto': return this.runNikto(target, stealthMode, programId);
      case 'nuclei': return this.runNuclei(target, params, stealthMode, programId);
      case 'sqlmap': return this.runSqlmap(target, params, stealthMode, programId);
      default: throw new Error(`Unknown scanner tool: ${tool}`);
    }
  }

  private async runNikto(target: string, stealthMode: string | undefined, programId: number | null | undefined) {
    if (isReal() && await toolExists('nikto')) {
      const aggressive = !stealthMode || stealthMode === 'aggressive';
      const args = aggressive
        ? ['-h', '{url}', '-maxtime', '120', '-Tuning', '123bde']
        : ['-h', '{url}', '-maxtime', '180', '-Tuning', '123bde', ...stealthArgTokens('nikto', stealthMode)];
      const stdout = await this.dispatch('nikto', target, args, programId, 240000);
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

  private async runNuclei(target: string, params: Record<string, any>, stealthMode: string | undefined, programId: number | null | undefined) {
    if (isReal() && await toolExists('nuclei')) {
      const severity = params.severity || 'low,medium,high,critical';

      let rateLimit = 100;
      let concurrencyArgs: string[] = [];
      if (stealthMode === 'stealth') {
        rateLimit = 10;
        concurrencyArgs = ['-c', '2'];
      } else if (stealthMode === 'ultrastealth') {
        rateLimit = 3;
        concurrencyArgs = ['-c', '1'];
      }

      // Use interactsh for OOB template detection when the client is running;
      // otherwise disable it to avoid nuclei hanging waiting for a server.
      const interactshArgs = interactshManager.getDomain() ? [] : ['-no-interactsh'];
      if (stealthMode && stealthMode !== 'aggressive') {
        console.log(`[ScannerAgent] Stealth nuclei: rate-limit=${rateLimit}, mode=${stealthMode}`);
      }

      let stdout = await this.dispatch('nuclei', target, [
        '-u', '{url}',
        '-t', 'http/technologies/', '-t', 'http/exposures/', '-t', 'http/misconfiguration/', '-t', 'http/vulnerabilities/',
        '-severity', severity, '-jsonl', '-silent', '-timeout', '5', '-retries', '0',
        '-rate-limit', String(rateLimit), ...concurrencyArgs, ...interactshArgs,
      ], programId, 300000);

      if (!stdout.trim()) {
        stdout = await this.dispatch('nuclei', target, [
          '-u', '{url}', '-severity', 'medium,high,critical', '-jsonl', '-silent',
          '-timeout', '5', '-retries', '0', ...interactshArgs,
        ], programId, 180000);
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

  private async runSqlmap(target: string, params: Record<string, any>, stealthMode: string | undefined, programId: number | null | undefined) {
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

      let stealthFlags: string[] = [];
      let threads = 5;
      if (stealthMode === 'stealth') {
        stealthFlags = ['--delay=2', '--random-agent'];
        threads = 2;
      } else if (stealthMode === 'ultrastealth') {
        stealthFlags = ['--delay=5', '--time-sec=15', '--random-agent', '--safe-url-retries=3'];
        threads = 1;
      }

      const allVulnerabilities: any[] = [];
      let combinedRaw = '';

      // Each candidate target is scope-checked in its OWN right by
      // dispatchTool (previous version never scope-checked injectableTargets
      // at all — they came straight from nikto's parsed findings).
      for (const testTarget of targetsToTest.slice(0, 5)) {
        console.log(`[ScannerAgent] SQLMap testing: ${testTarget} (stealth=${stealthMode})`);
        const stdout = await this.dispatch('sqlmap', testTarget, [
          '-u', '{url}', '--batch', `--threads=${threads}`, '--level=1', '--risk=1',
          '--timeout=10', '--retries=1', ...stealthFlags, `--output-dir=/tmp/sqlmap-${Date.now()}`,
        ], programId, 120000);

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

/** Shared exploitation-tool guard: scope+shell-injection is dispatchTool's
 *  job, but metasploit/hydra/hashcat are a separate "should this platform
 *  autonomously run credential attacks against someone's property" policy
 *  question — checked fresh at every dispatch, fail-closed by default. */
async function exploitationDisabledResult(tool: string, target: string, programId: number | null | undefined) {
  const auth = await checkExploitationToolAuthorization(target, programId);
  if (!auth.allowed) {
    console.warn(`[ExploitGate] ${tool} dispatch blocked: ${auth.reason}`);
    return { blocked: true as const, reason: auth.reason };
  }
  return { blocked: false as const };
}

export class ExploitMetaAgent extends MetaAgent {
  type = 'exploit';

  protected async runTool(tool: string, target: string, params: Record<string, any>, programId: number | null | undefined) {
    const _baseMode = params.stealthMode || 'balanced';
    const _adjMode = autoAdjuster.getCurrentMode();
    const _ORDER = ['aggressive', 'balanced', 'stealth', 'ultrastealth'];
    const stealthMode = _ORDER.indexOf(_adjMode) > _ORDER.indexOf(_baseMode) ? _adjMode : _baseMode;
    switch (tool) {
      case 'sqlmap': {
        const gate = await exploitationDisabledResult('sqlmap (exploit)', target, programId);
        if (gate.blocked) {
          return { result: { exploited: false, reason: gate.reason }, real: false };
        }
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

          let stealthFlags: string[] = [];
          let threads = 5;
          if (stealthMode === 'stealth') {
            stealthFlags = ['--delay=3', '--random-agent'];
            threads = 2;
          } else if (stealthMode === 'ultrastealth') {
            stealthFlags = ['--delay=8', '--time-sec=20', '--random-agent', '--safe-url-retries=5'];
            threads = 1;
          }

          const allVulnerabilities: any[] = [];
          let combinedRaw = '';

          for (const testTarget of targetsToTest.slice(0, 3)) {
            console.log(`[ExploitAgent] SQLMap deep testing: ${testTarget} (stealth=${stealthMode})`);
            const stdout = await this.dispatch('sqlmap', testTarget, [
              '-u', '{url}', '--batch', `--threads=${threads}`, '--level=3', '--risk=2',
              '--timeout=10', '--retries=1', ...stealthFlags, `--output-dir=/tmp/sqlmap-exploit-${Date.now()}`,
            ], programId, 240000);
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

      case 'metasploit': {
        const gate = await exploitationDisabledResult('metasploit', target, programId);
        if (gate.blocked) {
          return { result: { simulated: true, message: gate.reason }, real: false };
        }
        if (isReal()) {
          // NOTE: msfconsole's own `-x` argument is a SEMICOLON-JOINED STRING
          // of msfconsole commands — execFile's array-args protection stops
          // the OS shell from interpreting it, but msfconsole's OWN command
          // parser still splits on ";" internally. A module/target value
          // containing an embedded ";" could still inject an additional
          // msfconsole command (a tool-level injection, not an OS-shell one —
          // dispatchTool's guarantee is "no shell," not "immune to every
          // sub-language a specific tool happens to embed"). Tracked as a
          // known residual risk of this specific tool, not fixable via
          // array-args alone; mitigated by requiring explicit per-program
          // exploitation-tool authorization (checked above) before this path
          // is ever reachable at all.
          const msfCmd = `use ${params.module || 'auxiliary/scanner/http/http_version'}; set RHOSTS {domain}; run; exit`;
          try {
            const { stdout } = await dispatchTool({
              tool: 'msfconsole', target, args: ['-q', '-x', msfCmd], programId, timeoutMs: 120000,
            });
            return {
              result: { output: stdout, exploited: stdout.includes('session') || stdout.includes('opened'), raw: stdout },
              real: true,
            };
          } catch (e: any) {
            if (e instanceof ToolOutOfScopeError) {
              return { result: { exploited: false, reason: `Out of scope: ${e.reason}` }, real: false };
            }
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
      }

      default:
        throw new Error(`Unknown exploit tool: ${tool}`);
    }
  }
}

export class SupportMetaAgent extends MetaAgent {
  type = 'support';

  protected async runTool(tool: string, target: string, params: Record<string, any>, programId: number | null | undefined) {
    switch (tool) {
      case 'hydra': {
        const gate = await exploitationDisabledResult('hydra', target, programId);
        if (gate.blocked) {
          return { result: { simulated: true, message: gate.reason }, real: false };
        }
        if (isReal()) {
          const service = params.service || 'http-post-form';
          const userlist = params.userlist || '/usr/share/wordlists/users.txt';
          const passlist = params.passlist || '/usr/share/wordlists/passwords.txt';
          const delay = params.delay || 2;
          try {
            const { stdout } = await dispatchTool({
              tool: 'hydra', target,
              args: ['-L', userlist, '-P', passlist, '-t', '4', '-W', String(delay), '{domain}', service],
              programId, timeoutMs: 600000,
            });
            const lines = stdout.trim().split('\n').filter((l: string) => l.includes('login:'));
            return {
              result: { credentials: lines, count: lines.length, raw: stdout },
              real: true,
            };
          } catch (e: any) {
            if (e instanceof ToolOutOfScopeError) {
              return { result: { credentials: [], error: `Out of scope: ${e.reason}` }, real: false };
            }
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
      }
      case 'hashcat': {
        const gate = await exploitationDisabledResult('hashcat', target, programId);
        if (gate.blocked) {
          return { result: { simulated: true, message: gate.reason }, real: false };
        }
        if (isReal()) {
          const hashFile = params.hashFile || '/tmp/hashes.txt';
          const mode = params.mode || 0;
          const wordlist = params.wordlist || '/usr/share/wordlists/rockyou.txt';
          try {
            // hashcat doesn't operate on a URL at all — `target` is only used
            // for the scope/authorization check above, not substituted into
            // any arg here.
            const { stdout } = await dispatchTool({
              tool: 'hashcat', target,
              args: ['-m', String(mode), hashFile, wordlist, '--force', '--potfile-disable', '-o', '/tmp/hashcat-out.txt'],
              programId, timeoutMs: 600000,
            });
            let cracked: string[] = [];
            try {
              cracked = (await readFile('/tmp/hashcat-out.txt', 'utf8')).trim().split('\n').filter(Boolean);
            } catch {}
            return {
              result: { cracked, count: cracked.length, raw: stdout },
              real: true,
            };
          } catch (e: any) {
            if (e instanceof ToolOutOfScopeError) {
              return { result: { cracked: [], error: `Out of scope: ${e.reason}` }, real: false };
            }
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
      }
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

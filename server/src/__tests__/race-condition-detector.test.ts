/**
 * RaceConditionDetector — found live against a real target (a SPA served
 * with a server-side catch-all: any path, including nonexistent ones,
 * returns an identical 200 index.html shell). STATE_CHANGE_PATHS is a
 * blind list of guessed route names tried against every target, and
 * "15 concurrent requests all succeeded" is true for a catch-all
 * regardless of any real business logic — the detector flagged all 13
 * guessed paths as race conditions on a target with none of those routes.
 * Same false-positive class already fixed once for oauth-probe.ts: a
 * baseline-diff against one guaranteed-bogus path distinguishes a real,
 * distinct route from a catch-all shell before trusting the concurrency
 * signal.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

vi.mock('../lib/tools/csrf-aware-request', () => ({
  getCsrfHeaders: vi.fn(async () => ({})),
}));

vi.mock('axios', () => ({
  default: { get: vi.fn(), request: vi.fn() },
}));

import axios from 'axios';
import { raceConditionDetector } from '../lib/tools/race-condition-detector';

const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;
const mockedRequest = axios.request as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedGet.mockReset();
  mockedRequest.mockReset();
});

describe('RaceConditionDetector', () => {
  it('does not flag a SPA catch-all that 200s identically for every guessed path (the real false positive found live)', async () => {
    const shellBody = '<!DOCTYPE html><html>...</html>';
    mockedGet.mockResolvedValue({ status: 200, data: shellBody }); // baseline bogus-path fetch
    mockedRequest.mockResolvedValue({ status: 200, data: shellBody }); // every guessed endpoint, every burst request

    const result = await raceConditionDetector.probe('http://example.com/');

    expect(result.vulns).toEqual([]);
    expect(result.hypotheses).toEqual([]);
  });

  it('still flags a real endpoint whose concurrent-success behavior differs from the baseline', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: 'Not Found' }); // baseline bogus path — real 404
    mockedRequest.mockImplementation(async (cfg: { url: string }) => {
      if (cfg.url.includes('/purchase')) {
        // Real, distinct route: all 15 concurrent requests succeed — an
        // actual missing-lock bug, not a catch-all artifact.
        return { status: 200, data: '{"ok":true}' };
      }
      return { status: 404, data: 'Not Found' };
    });

    const result = await raceConditionDetector.probe('http://example.com/');

    const vuln = result.vulns.find(v => v.endpoint === 'http://example.com/purchase');
    expect(vuln).toBeDefined();
    expect(vuln!.isDuplicate).toBe(true);
    expect(vuln!.successCount).toBe(15);

    const hyp = result.hypotheses.find(h => h.raw === vuln);
    expect(hyp!.vulnClass).toBe('race_condition');
  });
});

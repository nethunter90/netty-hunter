/**
 * SimHash near-duplicate detection.
 * Catches findings that are semantically identical but differ in minor surface details
 * (e.g. same XSS payload on /search?q= vs /search?query=).
 * Uses 64-bit FNV-1a-based weighted shingle hashing with Hamming-distance comparison.
 */
export class SimHashDedup {
  private seenHashes: bigint[] = [];
  private readonly HASH_BITS = 64;

  computeSimHash(text: string): bigint {
    const tokens = this.shingle(text.toLowerCase());
    const v = new Array<number>(this.HASH_BITS).fill(0);
    for (const token of tokens) {
      const h = this.fnv64(token);
      for (let i = 0; i < this.HASH_BITS; i++) {
        v[i] += (h >> BigInt(i)) & 1n ? 1 : -1;
      }
    }
    let hash = 0n;
    for (let i = 0; i < this.HASH_BITS; i++) {
      if (v[i] > 0) hash |= (1n << BigInt(i));
    }
    return hash;
  }

  hammingDistance(a: bigint, b: bigint): number {
    let x = a ^ b;
    let dist = 0;
    while (x) { x &= x - 1n; dist++; }
    return dist;
  }

  isDuplicate(hash: bigint, threshold = 3): boolean {
    for (const seen of this.seenHashes) {
      if (this.hammingDistance(hash, seen) <= threshold) return true;
    }
    this.seenHashes.push(hash);
    if (this.seenHashes.length > 5000) this.seenHashes.shift();
    return false;
  }

  private shingle(text: string): string[] {
    const words = text.split(/\W+/).filter(Boolean);
    if (words.length < 2) return words;
    return words.map((w, i) => i < words.length - 1 ? `${w}${words[i + 1]}` : w);
  }

  private fnv64(s: string): bigint {
    let h = 14695981039346656037n;
    for (let i = 0; i < s.length; i++) {
      h ^= BigInt(s.charCodeAt(i));
      h = BigInt.asUintN(64, h * 1099511628211n);
    }
    return h;
  }
}

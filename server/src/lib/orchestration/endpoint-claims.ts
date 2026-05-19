export class EndpointClaimsManager {
  private claims: Map<string, { agentId: string; claimedAt: Date }> = new Map();
  private readonly CLAIM_TIMEOUT = 15 * 60 * 1000;

  claim(endpoint: string, agentId: string): boolean {
    const existingClaim = this.claims.get(endpoint);

    if (existingClaim) {
      const age = Date.now() - existingClaim.claimedAt.getTime();
      if (age < this.CLAIM_TIMEOUT) {
        return false;
      }
      this.claims.delete(endpoint);
    }

    this.claims.set(endpoint, {
      agentId,
      claimedAt: new Date()
    });

    return true;
  }

  release(endpoint: string, agentId: string): boolean {
    const claim = this.claims.get(endpoint);

    if (!claim || claim.agentId !== agentId) {
      return false;
    }

    this.claims.delete(endpoint);
    return true;
  }

  releaseAll(agentId: string): string[] {
    const released: string[] = [];

    this.claims.forEach((claim, endpoint) => {
      if (claim.agentId === agentId) {
        this.claims.delete(endpoint);
        released.push(endpoint);
      }
    });

    return released;
  }

  getClaimed(agentId: string): string[] {
    const claimed: string[] = [];

    this.claims.forEach((claim, endpoint) => {
      if (claim.agentId === agentId) {
        claimed.push(endpoint);
      }
    });

    return claimed;
  }

  isClaimed(endpoint: string): boolean {
    const claim = this.claims.get(endpoint);
    if (!claim) return false;

    const age = Date.now() - claim.claimedAt.getTime();
    if (age >= this.CLAIM_TIMEOUT) {
      this.claims.delete(endpoint);
      return false;
    }

    return true;
  }

  cleanup(): number {
    let cleaned = 0;
    const now = Date.now();

    const entries = Array.from(this.claims.entries());
    for (const [endpoint, claim] of entries) {
      const age = now - claim.claimedAt.getTime();
      if (age >= this.CLAIM_TIMEOUT) {
        this.claims.delete(endpoint);
        cleaned++;
      }
    }

    return cleaned;
  }
}

export const endpointClaims = new EndpointClaimsManager();

/**
 * Traffic Normalizer
 * Measures how much a probe URL deviates from the observed traffic baseline for a domain,
 * and suggests parameter-level modifications to reduce that deviation while preserving
 * the attack payload.
 */

export interface TrafficProfile {
  avgUrlLength: number;
  avgParamCount: number;
  avgHeaderCount: number;
  commonContentTypes: string[];
  paramNamePatterns: string[];
  sampleCount: number;
}

export interface NormalizationResult {
  deviationScore: number;     // 0–1 (0 = indistinguishable from baseline)
  suggestions: string[];
  normalizedUrl: string;
}

const DEFAULT_PROFILE: TrafficProfile = {
  avgUrlLength: 65,
  avgParamCount: 1.8,
  avgHeaderCount: 8,
  commonContentTypes: ['text/html', 'application/json'],
  paramNamePatterns: ['id', 'page', 'q', 'search', 'category', 'type', 'ref', 'sort'],
  sampleCount: 0,
};

export class TrafficNormalizer {
  private readonly profiles = new Map<string, TrafficProfile>();

  private getProfile(domain: string): TrafficProfile {
    return this.profiles.get(domain) ?? { ...DEFAULT_PROFILE };
  }

  /** Update the baseline profile for a domain with a set of observed request URLs. */
  updateProfile(domain: string, requestUrls: string[]): void {
    if (requestUrls.length === 0) return;
    const existing = this.getProfile(domain);
    const lengths = requestUrls.map(u => u.length);
    const paramCounts = requestUrls.map(u => {
      try { return [...new URL(u).searchParams.keys()].length; }
      catch { return u.includes('?') ? u.split('&').length : 0; }
    });
    const avgUrlLength = lengths.reduce((a, b) => a + b, 0) / lengths.length;
    const avgParamCount = paramCounts.reduce((a, b) => a + b, 0) / paramCounts.length;

    // Blend with existing profile using exponential moving average
    const alpha = 0.3;
    this.profiles.set(domain, {
      ...existing,
      avgUrlLength: existing.sampleCount === 0
        ? avgUrlLength : alpha * avgUrlLength + (1 - alpha) * existing.avgUrlLength,
      avgParamCount: existing.sampleCount === 0
        ? avgParamCount : alpha * avgParamCount + (1 - alpha) * existing.avgParamCount,
      sampleCount: existing.sampleCount + requestUrls.length,
    });
  }

  /** Score how much a probe URL deviates from the domain's baseline (0–1). */
  scoreDeviation(domain: string, probeUrl: string): number {
    const profile = this.getProfile(domain);
    const urlLen = probeUrl.length;
    let paramCount = 0;
    try {
      paramCount = [...new URL(probeUrl).searchParams.keys()].length;
    } catch {
      paramCount = probeUrl.includes('?') ? probeUrl.split('&').length : 0;
    }

    const lenDev = Math.min(1, Math.abs(urlLen - profile.avgUrlLength) / Math.max(profile.avgUrlLength, 1));
    const paramDev = Math.min(1, Math.abs(paramCount - profile.avgParamCount) / Math.max(profile.avgParamCount, 1));

    // Heuristic: unusually long URLs and unusual param counts are the strongest signals
    return Math.min(1, lenDev * 0.6 + paramDev * 0.4);
  }

  /**
   * Suggest and apply safe modifications to bring the probe closer to the baseline.
   * Does not alter the core payload — only wrapping structure.
   */
  normalize(domain: string, probeUrl: string): NormalizationResult {
    const profile = this.getProfile(domain);
    const suggestions: string[] = [];
    let normalizedUrl = probeUrl;

    const deviationBefore = this.scoreDeviation(domain, probeUrl);

    // If URL is much longer than baseline, suggest using POST instead
    if (probeUrl.length > profile.avgUrlLength * 2) {
      suggestions.push('Consider moving payload to POST body to reduce URL length anomaly');
    }

    // If param names look unusual, wrap with a common param name
    try {
      const parsed = new URL(probeUrl);
      const params = [...parsed.searchParams.entries()];
      const unusualParams = params.filter(([k]) => !profile.paramNamePatterns.includes(k));
      if (unusualParams.length > 0 && profile.paramNamePatterns.length > 0) {
        suggestions.push(`Unusual parameter names detected: [${unusualParams.map(([k]) => k).join(', ')}]. ` +
          `Common patterns for this domain: [${profile.paramNamePatterns.slice(0, 3).join(', ')}]`);
      }

      // Add a common benign param to increase param count toward baseline if below avg
      if (params.length < profile.avgParamCount - 1) {
        const boostParam = profile.paramNamePatterns[Math.floor(Math.random() * profile.paramNamePatterns.length)];
        parsed.set(boostParam, '1');
        normalizedUrl = parsed.toString();
        suggestions.push(`Added benign param '${boostParam}=1' to normalize param count toward baseline`);
      }
    } catch {
      // Non-parseable URL — leave as-is
    }

    return {
      deviationScore: this.scoreDeviation(domain, normalizedUrl),
      suggestions,
      normalizedUrl,
    };
  }
}

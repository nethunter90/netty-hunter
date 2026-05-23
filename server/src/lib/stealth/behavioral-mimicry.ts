/**
 * Behavioral Mimicry
 * Generates traffic patterns that look human to ML behavioral classifiers.
 * Focuses on realistic timing, browser fingerprints, and referrer chains.
 */

export interface BrowserProfile {
  userAgent: string;
  acceptLanguage: string;
  acceptEncoding: string;
  secFetchMode: string;
  secFetchSite: string;
  secFetchDest: string;
  platform: string;
}

export interface MimicrySession {
  profile: BrowserProfile;
  referrerChain: string[];
  timingPattern: number[];  // pre-sampled inter-request delays in ms
}

// Realistic browser profiles sampled from public telemetry data
const BROWSER_PROFILES: BrowserProfile[] = [
  {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    acceptLanguage: 'en-US,en;q=0.9',
    acceptEncoding: 'gzip, deflate, br',
    secFetchMode: 'navigate',
    secFetchSite: 'none',
    secFetchDest: 'document',
    platform: 'Win32',
  },
  {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    acceptLanguage: 'en-GB,en;q=0.9',
    acceptEncoding: 'gzip, deflate, br, zstd',
    secFetchMode: 'navigate',
    secFetchSite: 'cross-site',
    secFetchDest: 'document',
    platform: 'MacIntel',
  },
  {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    acceptLanguage: 'en-US,en;q=0.5',
    acceptEncoding: 'gzip, deflate, br',
    secFetchMode: 'navigate',
    secFetchSite: 'same-origin',
    secFetchDest: 'document',
    platform: 'Win32',
  },
  {
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    acceptLanguage: 'en-US,en;q=0.9,de;q=0.8',
    acceptEncoding: 'gzip, deflate, br',
    secFetchMode: 'navigate',
    secFetchSite: 'none',
    secFetchDest: 'document',
    platform: 'Linux x86_64',
  },
  {
    userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    acceptLanguage: 'en-US,en;q=0.9',
    acceptEncoding: 'gzip, deflate, br',
    secFetchMode: 'navigate',
    secFetchSite: 'none',
    secFetchDest: 'document',
    platform: 'iPhone',
  },
];

// Common referrer origins to seed chains
const REFERRER_ORIGINS = [
  'https://www.google.com/search?q=',
  'https://www.bing.com/search?q=',
  'https://duckduckgo.com/?q=',
  'https://t.co/',
  'https://www.linkedin.com/',
  'https://www.reddit.com/r/',
];

export class BehavioralMimicry {
  generateProfile(): BrowserProfile {
    return BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];
  }

  /**
   * Build a plausible referrer chain: search engine → landing → internal page → target.
   */
  buildReferrerChain(targetUrl: string): string[] {
    const origin = REFERRER_ORIGINS[Math.floor(Math.random() * REFERRER_ORIGINS.length)];
    let host: string;
    try {
      host = new URL(targetUrl).hostname;
    } catch {
      host = targetUrl;
    }
    const searchTerm = host.replace(/\./g, '+');
    return [
      `${origin}${searchTerm}`,
      `https://${host}/`,
      `https://${host}/about`,
      targetUrl,
    ];
  }

  /**
   * Sample next inter-request delay using a log-normal distribution.
   * Parameters calibrated to typical human browsing intervals.
   *
   * session phases:
   *   exploration — user is navigating, medium delays (~2-8s)
   *   task        — user is focused on a task, short delays (~0.5-3s)
   *   idle        — user paused, long delays (~10-60s)
   */
  nextDelayMs(sessionPhase: 'exploration' | 'task' | 'idle' = 'exploration'): number {
    const phaseParams = {
      exploration: { mu: 7.7, sigma: 0.8 },  // ln(2200ms) ≈ 7.7
      task:        { mu: 6.9, sigma: 0.6 },  // ln(1000ms) ≈ 6.9
      idle:        { mu: 9.5, sigma: 1.0 },  // ln(13000ms) ≈ 9.5
    };
    const { mu, sigma } = phaseParams[sessionPhase];
    // Box-Muller transform for normal distribution
    const u1 = Math.random();
    const u2 = Math.random();
    const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    return Math.max(200, Math.round(Math.exp(mu + sigma * z)));
  }

  buildSession(domain: string): MimicrySession {
    const profile = this.generateProfile();
    const phases: Array<'exploration' | 'task' | 'idle'> =
      ['exploration', 'exploration', 'task', 'task', 'task', 'exploration', 'idle'];
    const timingPattern = phases.map(p => this.nextDelayMs(p));

    return {
      profile,
      referrerChain: this.buildReferrerChain(`https://${domain}/`),
      timingPattern,
    };
  }

  buildHeaders(session: MimicrySession, referrer?: string): Record<string, string> {
    const { profile } = session;
    const headers: Record<string, string> = {
      'User-Agent': profile.userAgent,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'Accept-Language': profile.acceptLanguage,
      'Accept-Encoding': profile.acceptEncoding,
      'Sec-Fetch-Mode': profile.secFetchMode,
      'Sec-Fetch-Site': profile.secFetchSite,
      'Sec-Fetch-Dest': profile.secFetchDest,
      'Upgrade-Insecure-Requests': '1',
      'Cache-Control': 'max-age=0',
    };
    if (referrer) headers['Referer'] = referrer;
    return headers;
  }
}

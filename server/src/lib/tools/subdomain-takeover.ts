/**
 * Subdomain takeover checker.
 * Resolves CNAME chains for discovered subdomains and checks if the
 * ultimate target is an unclaimed service (GitHub Pages, Heroku, S3, etc.).
 */
import dns from "dns/promises";
import axios from "axios";
import logger from "../../utils/logger";

export interface TakeoverResult {
  subdomain: string;
  cname: string;
  service: string;
  vulnerable: boolean;
  evidence: string;
}

// Fingerprints: response body/header patterns that indicate an unclaimed service
const TAKEOVER_FINGERPRINTS: Array<{ service: string; patterns: RegExp[]; cnameSuffix?: string }> = [
  { service: "github-pages",    patterns: [/There isn't a GitHub Pages site here/, /404 - File or directory not found/], cnameSuffix: ".github.io" },
  { service: "heroku",          patterns: [/no such app/i, /herokuapp.com.*not found/i], cnameSuffix: ".herokudns.com" },
  { service: "s3-bucket",       patterns: [/NoSuchBucket/, /The specified bucket does not exist/], cnameSuffix: ".s3.amazonaws.com" },
  { service: "netlify",         patterns: [/Not Found - Request ID/], cnameSuffix: ".netlify.app" },
  { service: "vercel",          patterns: [/The deployment you are looking for doesn't exist/, /DEPLOYMENT_NOT_FOUND/], cnameSuffix: ".vercel.app" },
  { service: "azure-websites",  patterns: [/Web App - Unavailable/, /404 Web Site not found/], cnameSuffix: ".azurewebsites.net" },
  { service: "shopify",         patterns: [/Sorry, this shop is currently unavailable/], cnameSuffix: ".myshopify.com" },
  { service: "fastly",          patterns: [/Fastly error: unknown domain/, /Please check that this domain has been added to a Fastly service/], cnameSuffix: ".fastly.net" },
  { service: "helpscout",       patterns: [/No settings were found for this company/], cnameSuffix: ".helpscoutdocs.com" },
  { service: "zendesk",         patterns: [/Help Center Closed/], cnameSuffix: ".zendesk.com" },
  { service: "wordpress-com",   patterns: [/Do you want to register/, /doesn&#8217;t exist/], cnameSuffix: ".wordpress.com" },
  { service: "tumblr",          patterns: [/Whatever you were looking for doesn&#8217;t currently exist/, /There&#8217;s nothing here/], cnameSuffix: ".tumblr.com" },
  { service: "ghost",           patterns: [/The thing you were looking for is no longer here/], cnameSuffix: ".ghost.io" },
  { service: "surge-sh",        patterns: [/project not found/i], cnameSuffix: ".surge.sh" },
  { service: "bigcartel",       patterns: [/Oops! You've stumbled upon an empty page/], cnameSuffix: ".bigcartel.com" },
  { service: "strikingly",      patterns: [/This website is temporarily not available/], cnameSuffix: ".strikingly.com" },
  { service: "cargo",           patterns: [/404 Not Found/, /If you&#8217;re the site owner/], cnameSuffix: ".cargo.site" },
  { service: "smugmug",         patterns: [/Page Not Found/], cnameSuffix: ".smugmug.com" },
];

class SubdomainTakeoverChecker {
  async checkSubdomains(subdomains: string[]): Promise<TakeoverResult[]> {
    const results = await Promise.allSettled(
      subdomains.map(sub => this.checkOne(sub))
    );

    const vulnerable: TakeoverResult[] = [];
    for (const r of results) {
      if (r.status === "fulfilled" && r.value && r.value.vulnerable) {
        vulnerable.push(r.value);
        logger.warn("[SubdomainTakeover] Potential takeover found!", {
          subdomain: r.value.subdomain,
          service: r.value.service,
          cname: r.value.cname,
        });
      }
    }

    return vulnerable;
  }

  async checkOne(subdomain: string): Promise<TakeoverResult | null> {
    try {
      // Resolve CNAME chain
      const cname = await this.resolveCNAME(subdomain);
      if (!cname) return null;

      // Find matching fingerprint
      const fp = TAKEOVER_FINGERPRINTS.find(f =>
        f.cnameSuffix && cname.toLowerCase().endsWith(f.cnameSuffix.toLowerCase())
      );
      if (!fp) return null;

      // Fetch the subdomain and check response body
      const body = await this.fetchBody(`https://${subdomain}`).catch(() =>
        this.fetchBody(`http://${subdomain}`)
      ).catch(() => null);
      if (!body) return null;

      const matched = fp.patterns.some(p => p.test(body));
      if (!matched) return null;

      return {
        subdomain,
        cname,
        service: fp.service,
        vulnerable: true,
        evidence: `CNAME → ${cname} (${fp.service}) returns unclaimed-service fingerprint`,
      };
    } catch {
      return null;
    }
  }

  private async resolveCNAME(hostname: string): Promise<string | null> {
    try {
      // Walk up to 5 CNAME hops
      let current = hostname;
      for (let i = 0; i < 5; i++) {
        const result = await dns.resolveCname(current).catch(() => null);
        if (!result || result.length === 0) return current === hostname ? null : current;
        current = result[0];
      }
      return current;
    } catch {
      return null;
    }
  }

  private async fetchBody(url: string): Promise<string> {
    const resp = await axios.get(url, {
      timeout: 6000,
      validateStatus: () => true,
      maxRedirects: 3,
      responseType: "text",
      headers: { "User-Agent": "Mozilla/5.0 (compatible; NettyHunter/1.0)" },
    });
    return typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data);
  }
}

export const subdomainTakeoverChecker = new SubdomainTakeoverChecker();

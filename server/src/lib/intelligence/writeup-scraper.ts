/**
 * WriteupScraper — pulls public bug bounty writeups and CVE advisories into
 * the scraped_intelligence table so JsonPromptLoader can use them as domain
 * knowledge during hypothesis generation.
 *
 * Sources:
 *   - HackerOne public hacktivity (GraphQL, no auth required)
 *   - NVD CVE records via the existing nvdClient
 */
import axios from "axios";
import { db } from "../../db";
import { scrapedIntelligence } from "../../db/schema";
import { nvdClient } from "./nvd-client";
import logger from "../../utils/logger";

// Common web-security keywords to pull NVD records for
const NVD_TECH_KEYWORDS = [
  "sql injection", "xss cross-site scripting", "ssrf server-side request forgery",
  "path traversal", "remote code execution web", "authentication bypass",
  "idor insecure direct object", "xxe xml external entity",
  "open redirect", "csrf cross-site request forgery",
];

// HackerOne GraphQL endpoint for public hacktivity
const H1_GRAPHQL = "https://hackerone.com/graphql";

const H1_QUERY = `
query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $first: Int, $cursor: String) {
  hacktivity_items(
    first: $first
    after: $cursor
    query: $querystring
    order_by: $orderBy
  ) {
    edges {
      node {
        ... on DisclosedReport {
          id
          title
          severity_rating
          total_awarded_amount
          disclosed_at
          url
          weakness {
            name
          }
          team {
            name
          }
        }
      }
    }
  }
}`;

export class WriteupScraper {
  private lastScrape: Date | null = null;
  private totalScraped = 0;

  async scrapeHackerOnePublic(limit = 50): Promise<number> {
    let inserted = 0;
    try {
      const resp = await axios.post(
        H1_GRAPHQL,
        {
          query: H1_QUERY,
          variables: {
            querystring: "disclosed:true",
            orderBy: { field: "latest_disclosable_activity_at", direction: "DESC" },
            first: Math.min(limit, 50),
          },
        },
        {
          headers: {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; security-research-tool/1.0)",
          },
          timeout: 15000,
        }
      );

      const edges = resp.data?.data?.hacktivity_items?.edges ?? [];
      for (const edge of edges) {
        const node = edge?.node;
        if (!node?.title) continue;

        const vulnType = node.weakness?.name
          ? normalizeVulnType(node.weakness.name)
          : undefined;

        const severity = node.severity_rating ?? undefined;
        const payout = node.total_awarded_amount ? Math.round(Number(node.total_awarded_amount)) : undefined;
        const url = node.url ? `https://hackerone.com${node.url}` : undefined;

        const content = [
          `Program: ${node.team?.name ?? "Unknown"}`,
          `Weakness: ${node.weakness?.name ?? "Unknown"}`,
          `Severity: ${severity ?? "Unknown"}`,
          payout ? `Payout: $${payout}` : "",
          `Title: ${node.title}`,
        ].filter(Boolean).join("\n");

        try {
          await db.insert(scrapedIntelligence).values({
            source: "hackerone",
            sourceUrl: url,
            title: String(node.title).slice(0, 500),
            content,
            vulnType,
            severity: typeof severity === "string" ? severity.toLowerCase().slice(0, 16) : undefined,
            affectedTech: [],
            toolsUsed: [],
            payout,
          }).onConflictDoNothing();
          inserted++;
        } catch {
          // individual row conflict is non-fatal
        }

        // Polite delay
        await new Promise(r => setTimeout(r, 100));
      }

      logger.info("[WriteupScraper] HackerOne scrape complete", { inserted });
    } catch (err) {
      logger.warn("[WriteupScraper] HackerOne scrape failed", { err: String(err) });
    }
    return inserted;
  }

  async scrapeNVD(keywords = NVD_TECH_KEYWORDS): Promise<number> {
    let inserted = 0;
    for (const keyword of keywords) {
      try {
        const cves = await nvdClient.lookupByKeyword(keyword);
        for (const cve of cves) {
          const content = [
            `CVE: ${cve.id}`,
            `Description: ${cve.description}`,
            cve.cweIds.length ? `CWE: ${cve.cweIds.join(", ")}` : "",
            `CVSS: ${cve.cvssScore}`,
            cve.exploitAvailable ? "Exploit: available" : "",
          ].filter(Boolean).join("\n");

          try {
            await db.insert(scrapedIntelligence).values({
              source: "nvd",
              sourceUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
              title: cve.id,
              content,
              vulnType: normalizeVulnType(keyword),
              severity: cvssToSeverity(cve.cvssScore),
              affectedTech: [],
              toolsUsed: [],
              payout: undefined,
            }).onConflictDoNothing();
            inserted++;
          } catch {
            // individual row conflict is non-fatal
          }
        }
      } catch (err) {
        logger.debug("[WriteupScraper] NVD keyword failed", { keyword, err: String(err) });
      }
      // NVD rate limit
      await new Promise(r => setTimeout(r, 800));
    }
    logger.info("[WriteupScraper] NVD scrape complete", { inserted });
    return inserted;
  }

  async scrapeAll(): Promise<{ hackerone: number; nvd: number }> {
    logger.info("[WriteupScraper] Starting full scrape");
    const [hackerone, nvd] = await Promise.allSettled([
      this.scrapeHackerOnePublic(50),
      this.scrapeNVD(),
    ]);
    const h1Count = hackerone.status === "fulfilled" ? hackerone.value : 0;
    const nvdCount = nvd.status === "fulfilled" ? nvd.value : 0;
    this.lastScrape = new Date();
    this.totalScraped += h1Count + nvdCount;
    logger.info("[WriteupScraper] Full scrape complete", { hackerone: h1Count, nvd: nvdCount });
    return { hackerone: h1Count, nvd: nvdCount };
  }

  getStatus(): { lastScrape: string | null; totalScraped: number } {
    return {
      lastScrape: this.lastScrape?.toISOString() ?? null,
      totalScraped: this.totalScraped,
    };
  }
}

function normalizeVulnType(raw: string): string {
  const lower = raw.toLowerCase();
  if (lower.includes("sql")) return "sqli";
  if (lower.includes("xss") || lower.includes("cross-site scripting")) return "xss";
  if (lower.includes("ssrf")) return "ssrf";
  if (lower.includes("path traversal") || lower.includes("lfi")) return "lfi";
  if (lower.includes("rce") || lower.includes("remote code")) return "rce";
  if (lower.includes("auth") || lower.includes("bypass")) return "auth_bypass";
  if (lower.includes("idor") || lower.includes("object reference")) return "idor";
  if (lower.includes("xxe") || lower.includes("xml external")) return "xxe";
  if (lower.includes("open redirect")) return "open_redirect";
  if (lower.includes("csrf")) return "csrf";
  if (lower.includes("cors")) return "cors";
  return lower.replace(/[^a-z0-9_]/g, "_").slice(0, 64);
}

function cvssToSeverity(score: number): string {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

export const writeupScraper = new WriteupScraper();

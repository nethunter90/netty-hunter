import * as crypto from 'crypto';

type RedactionStyle = 'mask' | 'remove' | 'hash';

interface ScrubPattern {
  name: string;
  regex: RegExp;
  label: string;
}

const KNOWN_TLDS = ['com', 'net', 'org', 'io', 'dev', 'co', 'us', 'uk', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in', 'au', 'ca', 'eu', 'gov', 'edu', 'mil', 'info', 'biz', 'xyz', 'app', 'site', 'online', 'tech', 'cloud', 'security', 'hack', 'systems', 'network', 'server', 'hosting'];

const PATTERNS: ScrubPattern[] = [
  {
    name: 'jwt',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    label: '[REDACTED_JWT]',
  },
  {
    name: 'api_key',
    regex: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|sk_live_|pk_live_|sk_test_|pk_test_|rk_live_|rk_test_)[\s=:]*['\"]?[A-Za-z0-9_\-]{8,}['\"]?/gi,
    label: '[REDACTED_KEY]',
  },
  {
    name: 'session_token',
    regex: /(?:PHPSESSID|session_id|sessionid|JSESSIONID|connect\.sid|_session|auth_token|bearer\s+)[\s=:]*['\"]?[A-Za-z0-9_\-\.]{8,}['\"]?/gi,
    label: '[REDACTED_TOKEN]',
  },
  {
    name: 'email',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    label: '[REDACTED_EMAIL]',
  },
  {
    name: 'mac_address',
    regex: /\b([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b/g,
    label: '[REDACTED_MAC]',
  },
  {
    name: 'ipv6',
    regex: /(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}|::1|::)/g,
    label: '[REDACTED_IPv6]',
  },
  {
    name: 'ipv4',
    regex: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    label: '[REDACTED_IP]',
  },
  {
    name: 'windows_path',
    regex: /[A-Za-z]:\\(?:[^\s\\/:*?"<>|]+\\)*[^\s\\/:*?"<>|]*/g,
    label: '[REDACTED_PATH]',
  },
  {
    name: 'unix_path',
    regex: /(?:^|\s)(\/(?:[a-zA-Z0-9._-]+\/)+[a-zA-Z0-9._-]+)/gm,
    label: '[REDACTED_PATH]',
  },
  {
    name: 'fqdn',
    regex: new RegExp(
      `\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+(?:${KNOWN_TLDS.join('|')})\\b`,
      'gi'
    ),
    label: '[REDACTED_DOMAIN]',
  },
];

class LogScrubber {
  private totalScrubs: number = 0;
  private patternsMatched: Record<string, number> = {};

  constructor() {
    for (const p of PATTERNS) {
      this.patternsMatched[p.name] = 0;
    }
  }

  private hashValue(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex').substring(0, 12);
  }

  private applyStyle(match: string, label: string, style: RedactionStyle): string {
    switch (style) {
      case 'mask':
        return label;
      case 'remove':
        return '';
      case 'hash':
        return `[${this.hashValue(match)}]`;
    }
  }

  scrub(text: string, style: RedactionStyle = 'mask'): string {
    let result = text;

    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0;
      const matches = result.match(pattern.regex);
      if (matches) {
        this.patternsMatched[pattern.name] += matches.length;
        this.totalScrubs += matches.length;
      }
      result = result.replace(pattern.regex, (match) => {
        if (pattern.name === 'unix_path') {
          const leadingWhitespace = match.match(/^(\s*)/)?.[1] || '';
          const pathPart = match.trimStart();
          return leadingWhitespace + this.applyStyle(pathPart, pattern.label, style);
        }
        return this.applyStyle(match, pattern.label, style);
      });
    }

    return result;
  }

  scrubObject(obj: any, style: RedactionStyle = 'mask'): any {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
      return this.scrub(obj, style);
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.scrubObject(item, style));
    }

    if (typeof obj === 'object') {
      const result: Record<string, any> = {};
      for (const [key, value] of Object.entries(obj)) {
        result[key] = this.scrubObject(value, style);
      }
      return result;
    }

    return obj;
  }

  scrubStdout(text: string): string {
    return this.scrub(text, 'mask');
  }

  scrubStderr(text: string): string {
    return this.scrub(text, 'mask');
  }

  getPatternNames(): string[] {
    return PATTERNS.map((p) => p.name);
  }

  getStats(): { totalScrubs: number; patternsMatched: Record<string, number> } {
    return {
      totalScrubs: this.totalScrubs,
      patternsMatched: { ...this.patternsMatched },
    };
  }
}

export const logScrubber = new LogScrubber();

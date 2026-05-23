import { stealthLogger } from './stealth-logger';

interface DetectionSignal {
  type: string;
  name: string;
  confidence: number;
  details: string;
}

type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

interface Recommendation {
  scanMode: 'passive' | 'hybrid';
  timingMultiplier: number;
  payloads: 'minimal' | 'stealth' | 'all';
  delaySubmission: boolean;
}

interface AnalysisResult {
  target: string;
  risk: RiskLevel;
  signals: DetectionSignal[];
  recommendation: Recommendation;
  cachedAt: string;
  expiresAt: string;
}

interface ResponseInput {
  statusCode: number;
  headers: Record<string, string>;
  body?: string;
}

interface CacheEntry {
  result: AnalysisResult;
  expiresAt: number;
}

const CACHE_TTL_MS = 5 * 60 * 1000;

class StealthAnalyzer {
  private cache: Map<string, CacheEntry> = new Map();

  analyze(target: string, response?: ResponseInput): AnalysisResult {
    const cached = this.cache.get(target);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.result;
    }

    const signals: DetectionSignal[] = [];
    const headers = this.normalizeHeaders(response?.headers);
    const body = response?.body || '';

    if (response) {
      this.detectWAF(headers, body, signals);
      this.detectCDN(headers, signals);
      this.detectRateLimits(headers, signals);
      this.analyzeHttpResponse(response.statusCode, signals);
      this.detectCaptcha(body, signals);
    }

    this.detectSensitiveScope(target, signals);

    const risk = this.calculateRisk(signals);
    const recommendation = this.getRecommendation(risk);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + CACHE_TTL_MS);

    const result: AnalysisResult = {
      target,
      risk,
      signals,
      recommendation,
      cachedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };

    this.cache.set(target, { result, expiresAt: expiresAt.getTime() });

    stealthLogger.log('alert', {
      analyzer: 'stealth-analyzer',
      target,
      risk,
      signalCount: signals.length,
      signals: signals.map(s => ({ type: s.type, name: s.name, confidence: s.confidence })),
      recommendation,
    });

    return result;
  }

  private normalizeHeaders(headers?: Record<string, string>): Record<string, string> {
    if (!headers) return {};
    const normalized: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      normalized[key.toLowerCase()] = value;
    }
    return normalized;
  }

  private detectWAF(headers: Record<string, string>, body: string, signals: DetectionSignal[]): void {
    const headerKeys = Object.keys(headers);
    const headerValues = Object.values(headers);
    const cookieHeader = headers['set-cookie'] || headers['cookie'] || '';

    if (headers['cf-ray'] || headers['cf-request-id'] || cookieHeader.includes('__cfduid')) {
      signals.push({ type: 'waf', name: 'Cloudflare', confidence: 0.9, details: 'Cloudflare WAF detected via cf-ray/cf-request-id header or __cfduid cookie' });
    }

    if (headerKeys.some(k => k.startsWith('x-akamai-')) || headers['akamai-origin-hop']) {
      signals.push({ type: 'waf', name: 'Akamai', confidence: 0.85, details: 'Akamai WAF detected via x-akamai-* or akamai-origin-hop header' });
    }

    if ((headers['x-cdn'] && headers['x-cdn'].toLowerCase().includes('incapsula')) || cookieHeader.includes('visid_incap')) {
      signals.push({ type: 'waf', name: 'Incapsula', confidence: 0.85, details: 'Incapsula WAF detected via x-cdn header or visid_incap cookie' });
    }

    if (headers['x-iinfo']) {
      signals.push({ type: 'waf', name: 'Imperva', confidence: 0.85, details: 'Imperva WAF detected via x-iinfo header' });
    }

    if (headers['x-sucuri-id'] || headers['sucuri-cache']) {
      signals.push({ type: 'waf', name: 'Sucuri', confidence: 0.8, details: 'Sucuri WAF detected via x-sucuri-id or sucuri-cache header' });
    }

    if (headerKeys.some(k => k.startsWith('x-amzn-waf-')) || headers['x-amz-cf-id']) {
      signals.push({ type: 'waf', name: 'AWS WAF', confidence: 0.85, details: 'AWS WAF detected via x-amzn-waf-* or x-amz-cf-id header' });
    }

    if (body.toLowerCase().includes('mod_security') || body.includes('OWASP')) {
      signals.push({ type: 'waf', name: 'ModSecurity', confidence: 0.75, details: 'ModSecurity WAF detected via mod_security or OWASP reference in response body' });
    }

    if (cookieHeader.includes('barra_counter')) {
      signals.push({ type: 'waf', name: 'Barracuda', confidence: 0.8, details: 'Barracuda WAF detected via barra_counter cookie' });
    }

    if (cookieHeader.includes('BIGipServer') || headers['x-cnection']) {
      signals.push({ type: 'waf', name: 'F5 BIG-IP', confidence: 0.8, details: 'F5 BIG-IP detected via BIGipServer cookie or x-cnection header' });
    }

    if (cookieHeader.includes('FORTIWAFSID')) {
      signals.push({ type: 'waf', name: 'FortiWeb', confidence: 0.8, details: 'FortiWeb WAF detected via FORTIWAFSID cookie' });
    }
  }

  private detectCDN(headers: Record<string, string>, signals: DetectionSignal[]): void {
    const headerKeys = Object.keys(headers);
    const server = (headers['server'] || '').toLowerCase();

    if (headers['cf-ray'] || server.includes('cloudflare')) {
      signals.push({ type: 'cdn', name: 'Cloudflare CDN', confidence: 0.85, details: 'Cloudflare CDN detected via cf-ray header or server header' });
    }

    if (headerKeys.some(k => k.startsWith('x-akamai-')) || server.includes('akamai')) {
      signals.push({ type: 'cdn', name: 'Akamai CDN', confidence: 0.85, details: 'Akamai CDN detected via x-akamai-* or server header' });
    }

    if (headers['x-served-by']?.toLowerCase().includes('fastly') || headers['x-fastly-request-id'] || headers['via']?.toLowerCase().includes('fastly')) {
      signals.push({ type: 'cdn', name: 'Fastly CDN', confidence: 0.85, details: 'Fastly CDN detected via x-served-by, x-fastly-request-id, or via header' });
    }

    if (headers['x-amz-cf-id'] || headers['x-amz-cf-pop'] || server.includes('cloudfront')) {
      signals.push({ type: 'cdn', name: 'CloudFront CDN', confidence: 0.85, details: 'CloudFront CDN detected via x-amz-cf-id, x-amz-cf-pop, or server header' });
    }

    if (headers['x-msedge-ref'] || server.includes('azure')) {
      signals.push({ type: 'cdn', name: 'Azure CDN', confidence: 0.85, details: 'Azure CDN detected via x-msedge-ref or server header' });
    }
  }

  private detectRateLimits(headers: Record<string, string>, signals: DetectionSignal[]): void {
    const rateLimitHeaders = [
      'x-ratelimit-limit',
      'x-ratelimit-remaining',
      'x-ratelimit-reset',
      'retry-after',
      'x-rate-limit-limit',
      'x-rate-limit-remaining',
      'ratelimit-limit',
      'ratelimit-remaining',
    ];

    const found: string[] = [];
    for (const h of rateLimitHeaders) {
      if (headers[h] !== undefined) {
        found.push(`${h}: ${headers[h]}`);
      }
    }

    if (found.length > 0) {
      const remaining = headers['x-ratelimit-remaining'] || headers['x-rate-limit-remaining'] || headers['ratelimit-remaining'];
      const confidence = remaining !== undefined && parseInt(remaining, 10) < 10 ? 0.85 : 0.6;

      signals.push({
        type: 'rate_limit',
        name: 'Rate Limit Headers',
        confidence,
        details: `Rate limit headers detected: ${found.join(', ')}`,
      });
    }
  }

  private analyzeHttpResponse(statusCode: number, signals: DetectionSignal[]): void {
    if (statusCode === 403) {
      signals.push({ type: 'http_response', name: 'Blocked (403)', confidence: 0.95, details: 'HTTP 403 Forbidden response indicates request was blocked' });
    }

    if (statusCode === 429) {
      signals.push({ type: 'http_response', name: 'Rate Limited (429)', confidence: 0.9, details: 'HTTP 429 Too Many Requests indicates rate limiting is active' });
    }
  }

  private detectCaptcha(body: string, signals: DetectionSignal[]): void {
    if (!body) return;

    const lower = body.toLowerCase();
    const captchaPatterns = ['captcha', 'recaptcha', 'hcaptcha', 'challenge'];
    const matches = captchaPatterns.filter(p => lower.includes(p));

    if (matches.length > 0) {
      signals.push({
        type: 'captcha',
        name: 'CAPTCHA Detected',
        confidence: 0.85,
        details: `CAPTCHA indicators found in response body: ${matches.join(', ')}`,
      });
    }
  }

  private detectSensitiveScope(target: string, signals: DetectionSignal[]): void {
    const patterns: Array<{ pattern: RegExp; name: string; confidence: number }> = [
      { pattern: /\/admin/i, name: 'Admin Panel', confidence: 0.7 },
      { pattern: /\/internal/i, name: 'Internal Resource', confidence: 0.7 },
      { pattern: /\/corp/i, name: 'Corporate Resource', confidence: 0.65 },
      { pattern: /\/staging/i, name: 'Staging Environment', confidence: 0.65 },
      { pattern: /\/dev/i, name: 'Development Environment', confidence: 0.6 },
      { pattern: /\/api/i, name: 'API Endpoint', confidence: 0.6 },
      { pattern: /\/portal/i, name: 'Portal', confidence: 0.65 },
      { pattern: /\/dashboard/i, name: 'Dashboard', confidence: 0.65 },
      { pattern: /\/management/i, name: 'Management Interface', confidence: 0.7 },
      { pattern: /\/console/i, name: 'Console', confidence: 0.7 },
    ];

    for (const { pattern, name, confidence } of patterns) {
      if (pattern.test(target)) {
        signals.push({
          type: 'sensitive_scope',
          name,
          confidence,
          details: `Target URL matches sensitive scope pattern: ${pattern.source}`,
        });
      }
    }
  }

  private calculateRisk(signals: DetectionSignal[]): RiskLevel {
    if (signals.length === 0) return 'low';

    const confidences = signals.map(s => s.confidence);
    const highest = Math.max(...confidences);
    const highSignals = confidences.filter(c => c >= 0.8).length;

    if (highest >= 0.9 || highSignals >= 2) return 'critical';
    if (highest >= 0.8) return 'high';
    if (highest >= 0.6) return 'medium';
    return 'low';
  }

  private getRecommendation(risk: RiskLevel): Recommendation {
    const recommendations: Record<RiskLevel, Recommendation> = {
      critical: { scanMode: 'passive', timingMultiplier: 10, payloads: 'minimal', delaySubmission: true },
      high: { scanMode: 'passive', timingMultiplier: 5, payloads: 'stealth', delaySubmission: true },
      medium: { scanMode: 'hybrid', timingMultiplier: 3, payloads: 'stealth', delaySubmission: false },
      low: { scanMode: 'hybrid', timingMultiplier: 2, payloads: 'all', delaySubmission: false },
    };
    return recommendations[risk];
  }
}

export const stealthAnalyzer = new StealthAnalyzer();

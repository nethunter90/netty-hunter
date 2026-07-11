import { v4 as uuidv4 } from 'uuid';
import { InjectionDetectionResult, GovernancePillar } from '../types';
import { CoreGovernance } from '../core-governance';

const INJECTION_KEYWORDS: Array<{ keyword: string; weight: number }> = [
  { keyword: 'ignore previous instructions', weight: 90 },
  { keyword: 'ignore all instructions', weight: 95 },
  { keyword: 'disregard previous', weight: 85 },
  { keyword: 'forget your instructions', weight: 90 },
  { keyword: 'you are now', weight: 60 },
  { keyword: 'act as if', weight: 55 },
  { keyword: 'pretend you are', weight: 60 },
  { keyword: 'dan mode', weight: 95 },
  { keyword: 'developer mode', weight: 70 },
  { keyword: 'jailbreak', weight: 95 },
  { keyword: 'bypass restrictions', weight: 85 },
  { keyword: 'no restrictions', weight: 80 },
  { keyword: 'reveal your system prompt', weight: 90 },
  { keyword: 'show your instructions', weight: 80 },
  { keyword: 'what are your rules', weight: 50 },
  { keyword: 'override safety', weight: 90 },
  { keyword: 'disable safety', weight: 90 },
  { keyword: 'sudo mode', weight: 75 },
  { keyword: 'admin mode', weight: 65 },
  { keyword: 'god mode', weight: 80 },
  { keyword: 'unrestricted mode', weight: 85 },
  { keyword: 'remove all filters', weight: 90 },
  { keyword: 'ignore ethical', weight: 95 },
  { keyword: 'ignore moral', weight: 95 },
  { keyword: 'do anything now', weight: 85 },
  { keyword: 'no limitations', weight: 75 },
  { keyword: 'break character', weight: 70 },
  { keyword: 'new persona', weight: 60 },
  { keyword: 'roleplay as', weight: 50 }
];

const INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /\[system\]|\[SYSTEM\]|<system>|<\/system>/i, description: 'System tag injection' },
  { pattern: /```system|```instructions/i, description: 'Code block system injection' },
  { pattern: /\{%.*?%\}|\{\{.*?\}\}/i, description: 'Template injection' },
  { pattern: /base64_decode|atob\(|btoa\(/i, description: 'Encoding function injection' },
  { pattern: /\\x[0-9a-f]{2}/i, description: 'Hex escape injection' },
  { pattern: /\\u[0-9a-f]{4}/i, description: 'Unicode escape injection' },
  { pattern: /prompt\s*injection|prompt\s*leak/i, description: 'Explicit injection reference' },
  { pattern: /\beval\b.*?\(|exec\b.*?\(/i, description: 'Code execution attempt' },
  { pattern: /BEGIN\s+INJECTION|END\s+INJECTION/i, description: 'Explicit injection markers' },
  { pattern: /\|\|\s*true\s*\|\||\&\&\s*true\s*\&\&/i, description: 'Logic bypass pattern' },
  { pattern: /;?\s*DROP\s+TABLE|;\s*DELETE\s+FROM/i, description: 'SQL injection in prompt' },
  { pattern: /<!--.*?-->.*?<script/i, description: 'HTML comment bypass' }
];

const SEMANTIC_INDICATORS: Array<{ category: string; indicators: string[] }> = [
  {
    category: 'identity_manipulation',
    indicators: [
      'you are not an ai', 'you are a human', 'you are free',
      'you have consciousness', 'you can do anything',
      'you are unbound', 'you have no rules'
    ]
  },
  {
    category: 'authority_claim',
    indicators: [
      'i am your creator', 'i am the developer',
      'i have admin access', 'i am authorized',
      'emergency override', 'maintenance mode',
      'debug mode enabled'
    ]
  },
  {
    category: 'output_manipulation',
    indicators: [
      'respond only with', 'output the following',
      'repeat after me', 'say exactly',
      'your response must be', 'format your answer as'
    ]
  },
  {
    category: 'context_poisoning',
    indicators: [
      'the following is true', 'assume that',
      'in this hypothetical', 'in this scenario',
      'for educational purposes', 'for research purposes',
      'this is just a test'
    ]
  }
];

export class PromptInjectionDetector {
  private governance: CoreGovernance;
  private detectionHistory: Array<{ timestamp: Date; score: number; safe: boolean }> = [];

  constructor(governance: CoreGovernance) {
    this.governance = governance;
  }

  detect(input: string, agentId?: string, agentName?: string): InjectionDetectionResult {
    const normalizedInput = input.toLowerCase().trim();
    let totalScore = 0;
    const reasons: string[] = [];
    const detections: InjectionDetectionResult['detections'] = {};

    const keywordResults = this.detectKeywords(normalizedInput);
    if (keywordResults.length > 0) {
      detections.keywords = keywordResults;
      const maxWeight = Math.max(...keywordResults.map(k => k.weight));
      totalScore += maxWeight;
      reasons.push(`Injection keywords detected: ${keywordResults.map(k => k.keyword).join(', ')}`);
    }

    const patternResults = this.detectPatterns(input);
    if (patternResults.length > 0) {
      detections.patterns = patternResults;
      totalScore += patternResults.length * 15;
      reasons.push(`Injection patterns detected: ${patternResults.map(p => p.pattern).join(', ')}`);
    }

    const semanticResults = this.detectSemantic(normalizedInput);
    if (semanticResults.length > 0) {
      detections.semantic = semanticResults;
      totalScore += semanticResults.length * 20;
      reasons.push(`Semantic indicators: ${semanticResults.map(s => s.category).join(', ')}`);
    }

    const structuralResults = this.detectStructural(input);
    if (structuralResults.length > 0) {
      detections.structural = structuralResults;
      totalScore += structuralResults.length * 10;
      reasons.push(`Structural anomalies: ${structuralResults.join(', ')}`);
    }

    totalScore = Math.min(totalScore, 100);

    const safe = totalScore < 40;

    this.detectionHistory.push({
      timestamp: new Date(),
      score: totalScore,
      safe
    });

    if (this.detectionHistory.length > 10000) {
      this.detectionHistory = this.detectionHistory.slice(-5000);
    }

    if (!safe && agentId) {
      this.governance.recordDecision({
        agentId: agentId || 'system',
        agentName: agentName || 'Prompt Injection Detector',
        action: `Process input (${input.substring(0, 50)}...)`,
        actionType: 'ai_call',
        verdict: 'blocked',
        pillar: 'Prompt Injection Detection',
        confidence: totalScore / 100,
        reason: reasons.join('; '),
        coachMessage: `Potential prompt injection detected (score: ${totalScore}/100). Input has been blocked.`,
        replay: {
          userPrompt: input.substring(0, 500),
          decisionChain: reasons.map(r => ({
            step: 'detection',
            reasoning: r,
            pillar: 'Prompt Injection Detection' as GovernancePillar
          }))
        }
      });
    }

    return { safe, score: totalScore, reasons, detections };
  }

  private detectKeywords(input: string): Array<{ keyword: string; weight: number }> {
    const found: Array<{ keyword: string; weight: number }> = [];
    for (const { keyword, weight } of INJECTION_KEYWORDS) {
      if (input.includes(keyword.toLowerCase())) {
        found.push({ keyword, weight });
      }
    }
    return found;
  }

  private detectPatterns(input: string): Array<{ pattern: string; match: string }> {
    const found: Array<{ pattern: string; match: string }> = [];
    for (const { pattern, description } of INJECTION_PATTERNS) {
      const match = input.match(pattern);
      if (match) {
        found.push({ pattern: description, match: match[0].substring(0, 50) });
      }
    }
    return found;
  }

  private detectSemantic(input: string): Array<{ category: string; indicator: string }> {
    const found: Array<{ category: string; indicator: string }> = [];
    for (const { category, indicators } of SEMANTIC_INDICATORS) {
      for (const indicator of indicators) {
        if (input.includes(indicator)) {
          found.push({ category, indicator });
          break;
        }
      }
    }
    return found;
  }

  private detectStructural(input: string): string[] {
    const anomalies: string[] = [];

    if (input.length > 5000) {
      anomalies.push(`Unusually long input (${input.length} chars)`);
    }

    const newlineCount = (input.match(/\n/g) || []).length;
    if (newlineCount > 50) {
      anomalies.push(`Excessive newlines (${newlineCount})`);
    }

    const delimiterCount = (input.match(/---+|===+|\*\*\*+|###/g) || []).length;
    if (delimiterCount > 5) {
      anomalies.push(`Many delimiters (${delimiterCount}) - possible context separation`);
    }

    const encodedCount = (input.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || []).length;
    if (encodedCount > 3) {
      anomalies.push(`Multiple encoded blocks detected (${encodedCount})`);
    }

    const repeatedChars = input.match(/(.)\1{20,}/g);
    if (repeatedChars) {
      anomalies.push('Excessive character repetition detected');
    }

    return anomalies;
  }

  getStats(): {
    totalChecks: number;
    blocked: number;
    passed: number;
    avgScore: number;
    blockRate: number;
  } {
    const blocked = this.detectionHistory.filter(d => !d.safe).length;
    const total = this.detectionHistory.length;
    const avgScore = total > 0
      ? this.detectionHistory.reduce((sum, d) => sum + d.score, 0) / total
      : 0;

    return {
      totalChecks: total,
      blocked,
      passed: total - blocked,
      avgScore: Math.round(avgScore * 100) / 100,
      blockRate: total > 0 ? Math.round((blocked / total) * 100) : 0
    };
  }
}

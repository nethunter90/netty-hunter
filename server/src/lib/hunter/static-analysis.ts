/**
 * StaticAnalyzer — lib/hunter singleton
 *
 * Analyzes a codebase directory to extract routes and generate
 * vulnerability hypotheses from static patterns.
 */
import fs from 'fs';
import path from 'path';
import type { RouteDefinition, StaticAnalysisResult } from './types';

// ── Pattern libraries ─────────────────────────────────────────────────────────

const ROUTE_PATTERNS: Array<{ regex: RegExp; methods: string[]; framework: string }> = [
  { regex: /router\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,    methods: ['auto'],  framework: 'express'  },
  { regex: /app\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/gi,           methods: ['auto'],  framework: 'express'  },
  { regex: /@(GetMapping|PostMapping|PutMapping|DeleteMapping)\s*\(\s*"([^"]+)"\s*\)/g, methods: ['auto'], framework: 'spring'  },
  { regex: /path\s*=\s*['"`]([^'"`]+)['"`]/g,                                         methods: ['GET'],   framework: 'flask'   },
  { regex: /Route::([a-z]+)\s*\(\s*'([^']+)'/gi,                                     methods: ['auto'],  framework: 'laravel' },
];

const VULN_PATTERNS: Array<{ regex: RegExp; vulnClass: string; confidence: number; description: string }> = [
  { regex: /\$_(GET|POST|REQUEST|COOKIE)\[/gi,       vulnClass: 'sqli',       confidence: 0.6, description: 'Unfiltered user input in PHP superglobal' },
  { regex: /innerHTML\s*=/gi,                        vulnClass: 'xss',        confidence: 0.7, description: 'Dangerous innerHTML assignment'           },
  { regex: /eval\s*\(/gi,                            vulnClass: 'rce',        confidence: 0.8, description: 'eval() with possibly tainted input'       },
  { regex: /exec\s*\(/gi,                            vulnClass: 'rce',        confidence: 0.6, description: 'Shell exec call'                          },
  { regex: /\burl\b.*\bfetch\b|\bfetch\b.*\burl\b/gi, vulnClass: 'ssrf',     confidence: 0.5, description: 'URL parameter passed to fetch'            },
  { regex: /file_get_contents\s*\(\s*\$/gi,          vulnClass: 'lfi',        confidence: 0.7, description: 'User-controlled path in file_get_contents' },
  { regex: /require\s*\(\s*\.\s*\$_/gi,             vulnClass: 'rfi',        confidence: 0.8, description: 'Remote file inclusion via user input'      },
  { regex: /\.where\s*\(\s*['"`][^'"`]*\+/gi,       vulnClass: 'sqli',       confidence: 0.7, description: 'String concatenation in ORM query'         },
  { regex: /redirect\s*\(\s*req\.query/gi,           vulnClass: 'open_redirect', confidence: 0.7, description: 'Redirect with unvalidated query param' },
  { regex: /serialize\s*\(/gi,                       vulnClass: 'business_logic', confidence: 0.4, description: 'Object serialization risk'            },
  { regex: /password|passwd|secret|token|apikey/gi, vulnClass: 'info_disclosure', confidence: 0.3, description: 'Possible sensitive value in source'  },
  { regex: /CORS|Access-Control-Allow-Origin:\s*\*/gi, vulnClass: 'cors',    confidence: 0.6, description: 'Wildcard CORS header'                     },
];

const TEXT_EXTENSIONS = new Set(['.js', '.ts', '.py', '.php', '.java', '.rb', '.go', '.cs', '.jsx', '.tsx', '.vue']);

// ── Singleton ─────────────────────────────────────────────────────────────────

class StaticAnalyzerImpl {
  async analyzeDirectory(directory: string): Promise<StaticAnalysisResult> {
    const start = Date.now();

    if (!fs.existsSync(directory)) {
      return { routes: [], hypotheses: [], stats: { filesAnalyzed: 0, routesFound: 0, hypothesesGenerated: 0, durationMs: 0 } };
    }

    const files  = this.walkDir(directory);
    const routes: RouteDefinition[]  = [];
    const hypotheses: StaticAnalysisResult['hypotheses'] = [];

    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const fileRoutes = this.extractRoutesFromContent(content, file);
        routes.push(...fileRoutes);

        const fileHypotheses = this.extractHypothesesFromContent(content, file, fileRoutes);
        hypotheses.push(...fileHypotheses);
      } catch {
        // skip unreadable files
      }
    }

    const durationMs = Date.now() - start;
    return {
      routes,
      hypotheses: hypotheses.sort((a, b) => b.confidence - a.confidence),
      stats: { filesAnalyzed: files.length, routesFound: routes.length, hypothesesGenerated: hypotheses.length, durationMs },
    };
  }

  async extractRoutes(directory: string): Promise<RouteDefinition[]> {
    const result = await this.analyzeDirectory(directory);
    return result.routes;
  }

  // ── Private ──────────────────────────────────────────────────────────────────

  private walkDir(dir: string, depth = 0): string[] {
    if (depth > 8) return [];
    const files: string[] = [];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv'].includes(entry.name)) {
            files.push(...this.walkDir(fullPath, depth + 1));
          }
        } else if (entry.isFile() && TEXT_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
          files.push(fullPath);
        }
      }
    } catch { /* skip */ }
    return files;
  }

  private extractRoutesFromContent(content: string, filePath: string): RouteDefinition[] {
    const routes: RouteDefinition[] = [];
    const lines = content.split('\n');

    for (const pattern of ROUTE_PATTERNS) {
      let match: RegExpExecArray | null;
      const re = new RegExp(pattern.regex.source, pattern.regex.flags);
      while ((match = re.exec(content)) !== null) {
        const method = (match[1] || 'GET').toUpperCase();
        const routePath = match[2] || match[1] || '';
        if (!routePath || routePath.length > 200) continue;

        // Find approximate line number
        const upToMatch = content.slice(0, match.index);
        const line = upToMatch.split('\n').length;

        const routeDef: RouteDefinition = {
          method,
          path:            routePath,
          file:            filePath,
          line,
          parameters:      this.extractParams(routePath),
          potentialVulns:  this.inferVulnsForRoute(routePath, method),
        };
        routes.push(routeDef);
      }
    }

    return routes;
  }

  private extractHypothesesFromContent(
    content: string,
    filePath: string,
    routes: RouteDefinition[]
  ): StaticAnalysisResult['hypotheses'] {
    const hypotheses: StaticAnalysisResult['hypotheses'] = [];

    for (const pattern of VULN_PATTERNS) {
      if (pattern.regex.test(content)) {
        // Find most relevant route for this file
        const relevantRoute = routes[0]?.path ?? filePath;
        hypotheses.push({
          endpoint:  relevantRoute,
          vulnClass: pattern.vulnClass,
          confidence: pattern.confidence,
          rationale:  `${pattern.description} detected in ${path.basename(filePath)}`,
        });
      }
      pattern.regex.lastIndex = 0;  // reset stateful regex
    }

    return hypotheses;
  }

  private extractParams(routePath: string): string[] {
    const params: string[] = [];
    const expressParam = /:([a-zA-Z_]+)/g;
    let match: RegExpExecArray | null;
    while ((match = expressParam.exec(routePath)) !== null) params.push(match[1]);
    return params;
  }

  private inferVulnsForRoute(routePath: string, method: string): string[] {
    const vulns: string[] = [];
    const lower = routePath.toLowerCase();

    if (lower.includes('login') || lower.includes('auth'))  vulns.push('auth_bypass', 'sqli');
    if (lower.includes('upload') || lower.includes('file')) vulns.push('lfi', 'rce');
    if (lower.includes('redirect') || lower.includes('url')) vulns.push('open_redirect', 'ssrf');
    if (lower.includes('search') || lower.includes('query')) vulns.push('sqli', 'xss');
    if (lower.includes('admin') || lower.includes('manage')) vulns.push('exposed_admin', 'idor');
    if (method === 'POST' || method === 'PUT') vulns.push('xss', 'sqli', 'csrf');

    return [...new Set(vulns)];
  }
}

export const staticAnalyzer = new StaticAnalyzerImpl();

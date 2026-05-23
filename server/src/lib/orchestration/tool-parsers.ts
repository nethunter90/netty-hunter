import { v4 as uuidv4 } from 'uuid';

export interface ParsedPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
  product?: string;
}

export interface ParsedNmapResult {
  host: string;
  ports: ParsedPort[];
  os?: string;
  endpoints: { url: string; port: number; service: string }[];
  technologies: { name: string; version?: string; category: string; confidence: number }[];
}

export interface ParsedNiktoFinding {
  id: string;
  osvdbId?: string;
  method: string;
  uri: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export interface ParsedNiktoResult {
  target: string;
  findings: ParsedNiktoFinding[];
  serverInfo?: string;
  technologies: { name: string; version?: string; category: string; confidence: number }[];
}

export interface ParsedSqlmapResult {
  vulnerable: boolean;
  target: string;
  injectionPoints: {
    parameter: string;
    type: string;
    title: string;
    payload?: string;
  }[];
  dbms?: string;
  databases?: string[];
  tables?: string[];
}

export function parseTargetUrl(target: string): { host: string; port: number; isUrl: boolean } {
  try {
    if (target.startsWith('http://') || target.startsWith('https://')) {
      const url = new URL(target);
      const defaultPort = url.protocol === 'https:' ? 443 : 80;
      return {
        host: url.hostname,
        port: url.port ? parseInt(url.port) : defaultPort,
        isUrl: true,
      };
    }
    if (target.includes(':') && !target.includes('/')) {
      const [host, portStr] = target.split(':');
      return { host, port: parseInt(portStr) || 80, isUrl: false };
    }
    return { host: target, port: 80, isUrl: false };
  } catch {
    return { host: target, port: 80, isUrl: false };
  }
}

export function parseNmapOutput(stdout: string, target: string): ParsedNmapResult {
  const { host } = parseTargetUrl(target);
  const ports: ParsedPort[] = [];
  const technologies: ParsedNmapResult['technologies'] = [];
  const endpoints: ParsedNmapResult['endpoints'] = [];
  let os: string | undefined;

  const commonHttpPorts = new Set([80, 443, 8080, 8443, 3000, 8000, 8888, 9090, 5000]);
  const hasHttpFingerprint = stdout.includes('HTTP/1.') || stdout.includes('HTTP/2');

  const lines = stdout.split('\n');

  for (const line of lines) {
    const portMatch = line.match(
      /^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)/
    );
    if (portMatch) {
      const [, portStr, protocol, state, service, versionRaw] = portMatch;
      const port = parseInt(portStr);
      const version = versionRaw?.trim() || '';

      ports.push({ port, protocol, state, service, version });

      if (state === 'open') {
        const isHttp = service === 'http' || service === 'http-proxy';
        const isHttps = service === 'https' || service === 'ssl/http';
        const isUnknownButLikelyHttp = (service.endsWith('?') || service === 'unknown')
          && (commonHttpPorts.has(port) || hasHttpFingerprint);

        if (isHttp || isHttps || isUnknownButLikelyHttp) {
          const scheme = isHttps ? 'https' : 'http';
          const portSuffix = (port === 80 && scheme === 'http') || (port === 443 && scheme === 'https') ? '' : `:${port}`;
          endpoints.push({
            url: `${scheme}://${host}${portSuffix}/`,
            port,
            service: isUnknownButLikelyHttp ? 'http' : service,
          });
        }

        if (version) {
          const techParsed = parseServiceVersion(version, service);
          if (techParsed) {
            technologies.push(techParsed);
          }
        }
      }
    }

    const osMatch = line.match(/^OS details?:\s*(.+)/i)
      || line.match(/^Running:\s*(.+)/i)
      || line.match(/^Aggressive OS guesses?:\s*(.+)/i);
    if (osMatch) {
      os = osMatch[1].trim();
    }

    if (line.includes('OWASP') && line.includes('Juice') && line.includes('Shop')) {
      if (!technologies.find(t => t.name === 'OWASP Juice Shop')) {
        technologies.push({ name: 'OWASP Juice Shop', category: 'application', confidence: 0.95 });
      }
    }

    const serviceInfoMatch = line.match(/^Service Info:\s*(.+)/i);
    if (serviceInfoMatch) {
      const info = serviceInfoMatch[1];
      const osFromInfo = info.match(/OS:\s*([^;]+)/);
      if (osFromInfo && !os) {
        os = osFromInfo[1].trim();
      }
    }
  }

  return { host, ports, os, endpoints, technologies };
}

function parseServiceVersion(
  versionStr: string,
  service: string
): ParsedNmapResult['technologies'][0] | null {
  const patterns: [RegExp, string, string][] = [
    [/Apache\s+httpd?\s*([\d.]+)?/i, 'Apache', 'web-server'],
    [/nginx\s*([\d.]+)?/i, 'nginx', 'web-server'],
    [/Node\.js\s*([\d.]+)?/i, 'Node.js', 'runtime'],
    [/Express\s*(?:framework)?\s*([\d.]+)?/i, 'Express', 'web-framework'],
    [/OpenSSH\s*([\d.]+)?/i, 'OpenSSH', 'ssh'],
    [/MySQL\s*([\d.]+)?/i, 'MySQL', 'database'],
    [/PostgreSQL\s*([\d.]+)?/i, 'PostgreSQL', 'database'],
    [/MariaDB\s*([\d.]+)?/i, 'MariaDB', 'database'],
    [/Microsoft IIS\s*([\d.]+)?/i, 'IIS', 'web-server'],
    [/PHP\s*([\d.]+)?/i, 'PHP', 'language'],
    [/Werkzeug\s*([\d.]+)?/i, 'Flask/Werkzeug', 'web-framework'],
    [/Tomcat\s*([\d.]+)?/i, 'Apache Tomcat', 'web-server'],
    [/Jetty\s*([\d.]+)?/i, 'Jetty', 'web-server'],
    [/OWASP\s+Juice\s+Shop/i, 'OWASP Juice Shop', 'application'],
  ];

  for (const [pattern, name, category] of patterns) {
    const match = versionStr.match(pattern);
    if (match) {
      return { name, version: match[1] || undefined, category, confidence: 0.9 };
    }
  }

  if (versionStr.length > 2 && versionStr.length < 60) {
    return {
      name: versionStr.split(/\s+/).slice(0, 3).join(' '),
      category: service.includes('http') ? 'web-server' : 'service',
      confidence: 0.5,
    };
  }

  return null;
}

export function parseNiktoOutput(stdout: string, target: string): ParsedNiktoResult {
  const findings: ParsedNiktoFinding[] = [];
  const technologies: ParsedNiktoResult['technologies'] = [];
  let serverInfo: string | undefined;

  const lines = stdout.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('-') || trimmed.startsWith('=')) continue;

    const serverMatch = trimmed.match(/^\+\s*Server:\s*(.+)/i);
    if (serverMatch) {
      serverInfo = serverMatch[1].trim();
      const serverTech = parseServerHeader(serverInfo);
      if (serverTech) technologies.push(serverTech);
      continue;
    }

    const findingMatch = trimmed.match(
      /^\+\s*(?:OSVDB-(\d+):\s*)?(?:(\S+):\s*)?(.+)/
    );
    if (findingMatch && !trimmed.match(/^\+\s*Target|^\+\s*Start|^\+\s*End|^\+\s*\d+\s+host/)) {
      const [, osvdbId, uri, description] = findingMatch;

      if (!description || description.length < 5) continue;

      const severity = classifyNiktoSeverity(description, osvdbId);

      findings.push({
        id: uuidv4(),
        osvdbId: osvdbId ? `OSVDB-${osvdbId}` : undefined,
        method: 'GET',
        uri: uri || '/',
        description: description.trim(),
        severity,
      });

      const techFromFinding = extractTechFromNikto(description);
      if (techFromFinding) technologies.push(techFromFinding);
    }
  }

  return { target, findings, serverInfo, technologies };
}

function classifyNiktoSeverity(desc: string, osvdbId?: string): ParsedNiktoFinding['severity'] {
  const lower = desc.toLowerCase();

  if (lower.includes('remote code') || lower.includes('rce') || lower.includes('command injection')
    || lower.includes('arbitrary file') || lower.includes('backdoor')) {
    return 'critical';
  }

  if (lower.includes('sql injection') || lower.includes('xss') || lower.includes('directory traversal')
    || lower.includes('file inclusion') || lower.includes('authentication bypass')
    || lower.includes('default password') || lower.includes('admin panel')) {
    return 'high';
  }

  if (lower.includes('information disclosure') || lower.includes('x-powered-by')
    || lower.includes('server header') || lower.includes('directory listing')
    || lower.includes('debug') || lower.includes('backup') || lower.includes('phpinfo')
    || lower.includes('cookie') || lower.includes('clickjacking')
    || lower.includes('x-frame-options') || lower.includes('missing header')) {
    return 'medium';
  }

  if (lower.includes('allowed http methods') || lower.includes('robots.txt')
    || lower.includes('etag') || lower.includes('favicon')) {
    return 'low';
  }

  return osvdbId ? 'medium' : 'info';
}

function parseServerHeader(server: string): ParsedNiktoResult['technologies'][0] | null {
  const patterns: [RegExp, string, string][] = [
    [/Apache\/([\d.]+)?/i, 'Apache', 'web-server'],
    [/nginx\/([\d.]+)?/i, 'nginx', 'web-server'],
    [/Express/i, 'Express', 'web-framework'],
    [/IIS\/([\d.]+)?/i, 'IIS', 'web-server'],
    [/Werkzeug\/([\d.]+)?/i, 'Flask/Werkzeug', 'web-framework'],
  ];

  for (const [pattern, name, category] of patterns) {
    const match = server.match(pattern);
    if (match) {
      return { name, version: match[1], category, confidence: 0.95 };
    }
  }
  return null;
}

function extractTechFromNikto(desc: string): ParsedNiktoResult['technologies'][0] | null {
  const lower = desc.toLowerCase();
  if (lower.includes('php') && !lower.includes('phpinfo')) {
    return { name: 'PHP', category: 'language', confidence: 0.7 };
  }
  if (lower.includes('wordpress')) {
    return { name: 'WordPress', category: 'cms', confidence: 0.8 };
  }
  if (lower.includes('angular')) {
    return { name: 'Angular', category: 'frontend', confidence: 0.7 };
  }
  return null;
}

export function parseSqlmapOutput(stdout: string, target: string): ParsedSqlmapResult {
  const injectionPoints: ParsedSqlmapResult['injectionPoints'] = [];
  let dbms: string | undefined;
  const databases: string[] = [];
  const tables: string[] = [];
  let vulnerable = false;

  const lines = stdout.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();

    const paramMatch = trimmed.match(/^Parameter:\s*(\S+)\s*\((\w+)\)/i);
    if (paramMatch) {
      vulnerable = true;
    }

    const typeMatch = trimmed.match(/^\s+Type:\s*(.+)/);
    const titleMatch = trimmed.match(/^\s+Title:\s*(.+)/);
    const payloadMatch = trimmed.match(/^\s+Payload:\s*(.+)/);

    if (typeMatch) {
      injectionPoints.push({
        parameter: 'unknown',
        type: typeMatch[1].trim(),
        title: '',
      });
    }
    if (titleMatch && injectionPoints.length > 0) {
      injectionPoints[injectionPoints.length - 1].title = titleMatch[1].trim();
    }
    if (payloadMatch && injectionPoints.length > 0) {
      injectionPoints[injectionPoints.length - 1].payload = payloadMatch[1].trim();
    }

    const dbmsMatch = trimmed.match(/back-end DBMS:\s*(.+)/i)
      || trimmed.match(/web application technology:\s*(.+)/i);
    if (dbmsMatch) {
      dbms = dbmsMatch[1].trim();
    }

    if (trimmed.includes('identified the following injection point')) {
      vulnerable = true;
    }

    if (trimmed.match(/^\s+Parameter:\s+(\S+)/) && injectionPoints.length > 0) {
      const pMatch = trimmed.match(/Parameter:\s+(\S+)/);
      if (pMatch) {
        injectionPoints[injectionPoints.length - 1].parameter = pMatch[1];
      }
    }

    const dbMatch = trimmed.match(/^\[\*\]\s+(\S+)$/);
    if (dbMatch) {
      databases.push(dbMatch[1]);
    }

    if (trimmed.includes('not injectable') || trimmed.includes('do not appear to be injectable')) {
      vulnerable = false;
    }
  }

  return {
    vulnerable,
    target,
    injectionPoints: injectionPoints.filter(ip => ip.title),
    dbms,
    databases: databases.length > 0 ? databases : undefined,
    tables: tables.length > 0 ? tables : undefined,
  };
}

export function nmapToFindings(parsed: ParsedNmapResult, agentId: string): {
  endpoints: any[];
  technologies: any[];
  notes: string[];
} {
  const endpoints = parsed.endpoints.map(e => ({
    url: e.url,
    method: 'GET',
    statusCode: undefined,
    title: `${e.service} on port ${e.port}`,
    discoveredBy: agentId,
    discoveredAt: new Date(),
  }));

  const technologies = parsed.technologies.map(t => ({
    ...t,
    category: t.category || 'unknown',
    confidence: t.confidence || 0.8,
  }));

  const notes: string[] = [];
  const openPorts = parsed.ports.filter(p => p.state === 'open');
  if (openPorts.length > 0) {
    notes.push(`Nmap found ${openPorts.length} open port(s) on ${parsed.host}: ${openPorts.map(p => `${p.port}/${p.protocol} (${p.service})`).join(', ')}`);
  }
  if (parsed.os) {
    notes.push(`OS detected: ${parsed.os}`);
  }

  return { endpoints, technologies, notes };
}

export function niktoToVulnerabilities(parsed: ParsedNiktoResult): any[] {
  return parsed.findings
    .filter(f => f.severity !== 'info')
    .map(f => ({
      id: f.id,
      type: f.osvdbId || 'nikto-finding',
      severity: f.severity,
      endpoint: `${parsed.target}${f.uri}`,
      description: f.description,
      evidence: JSON.stringify({
        tool: 'nikto',
        osvdbId: f.osvdbId,
        method: f.method,
        uri: f.uri,
      }),
      exploitable: f.severity === 'high' || f.severity === 'critical',
    }));
}

export function sqlmapToVulnerabilities(parsed: ParsedSqlmapResult): any[] {
  if (!parsed.vulnerable) return [];

  return parsed.injectionPoints.map(ip => ({
    id: uuidv4(),
    type: 'SQL Injection',
    severity: 'critical' as const,
    endpoint: parsed.target,
    description: `${ip.type}: ${ip.title}${ip.payload ? ` (payload: ${ip.payload.slice(0, 100)})` : ''}`,
    evidence: JSON.stringify({
      tool: 'sqlmap',
      parameter: ip.parameter,
      type: ip.type,
      title: ip.title,
      payload: ip.payload,
      dbms: parsed.dbms,
    }),
    exploitable: true,
  }));
}

export interface ParsedNucleiVulnerability {
  id: string;
  templateId: string;
  name: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  type: string;
  matched: string;
  description: string;
  reference: string[];
  tags: string[];
  curl?: string;
  extractedResults?: string[];
  matcher?: string;
  timestamp: string;
}

export interface ParsedNucleiResult {
  target: string;
  vulnerabilities: ParsedNucleiVulnerability[];
  totalFindings: number;
}

export function parseNucleiOutput(stdout: string, target: string): ParsedNucleiResult {
  const vulnerabilities: ParsedNucleiVulnerability[] = [];

  const lines = stdout.trim().split('\n').filter(Boolean);

  for (const line of lines) {
    try {
      const finding = JSON.parse(line);

      const severity = (finding.info?.severity || 'medium').toLowerCase();
      const validSeverity = ['info', 'low', 'medium', 'high', 'critical'].includes(severity)
        ? severity as ParsedNucleiVulnerability['severity']
        : 'medium' as const;

      vulnerabilities.push({
        id: uuidv4(),
        templateId: finding['template-id'] || finding.templateID || 'unknown',
        name: finding.info?.name || finding['template-id'] || 'Nuclei Finding',
        severity: validSeverity,
        type: finding.type || 'http',
        matched: finding.matched || finding['matched-at'] || target,
        description: finding.info?.description || finding.info?.name || '',
        reference: finding.info?.reference || [],
        tags: finding.info?.tags || [],
        curl: finding['curl-command'] || undefined,
        extractedResults: finding['extracted-results'] || undefined,
        matcher: finding['matcher-name'] || undefined,
        timestamp: finding.timestamp || new Date().toISOString(),
      });
    } catch {
      const textMatch = line.match(/\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)/);
      if (textMatch) {
        const [, templateId, protocol, severity, matchedUrl] = textMatch;
        const validSev = ['info', 'low', 'medium', 'high', 'critical'].includes(severity)
          ? severity as ParsedNucleiVulnerability['severity']
          : 'medium' as const;

        vulnerabilities.push({
          id: uuidv4(),
          templateId,
          name: templateId.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
          severity: validSev,
          type: protocol,
          matched: matchedUrl?.trim() || target,
          description: `Nuclei template ${templateId} matched`,
          reference: [],
          tags: [],
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  return { target, vulnerabilities, totalFindings: vulnerabilities.length };
}

export function nucleiToVulnerabilities(parsed: ParsedNucleiResult): any[] {
  return parsed.vulnerabilities.map(v => ({
    id: v.id,
    type: v.name,
    severity: v.severity,
    endpoint: v.matched,
    description: v.description || v.name,
    evidence: JSON.stringify({
      tool: 'nuclei',
      templateId: v.templateId,
      type: v.type,
      tags: v.tags,
      reference: v.reference,
      curl: v.curl,
      matcher: v.matcher,
      extractedResults: v.extractedResults,
    }),
    exploitable: ['high', 'critical'].includes(v.severity),
  }));
}

export interface ParsedWhatwebResult {
  target: string;
  technologies: { name: string; version?: string; category: string; confidence: number }[];
  httpStatus?: number;
  country?: string;
  ip?: string;
}

export function parseWhatwebJson(jsonOutput: string, target: string): ParsedWhatwebResult {
  const technologies: ParsedWhatwebResult['technologies'] = [];
  let httpStatus: number | undefined;
  let country: string | undefined;
  let ip: string | undefined;

  try {
    const data = JSON.parse(jsonOutput.trim().split('\n')[0]);
    const plugins = data.plugins || {};

    for (const [pluginName, pluginData] of Object.entries(plugins)) {
      const pd = pluginData as any;
      const skip = ['HTTPServer', 'IP', 'Country', 'Title', 'RedirectLocation', 'UncommonHeaders', 'X-Powered-By'];

      if (pluginName === 'HTTPServer') {
        if (pd.string) {
          const serverParts = (Array.isArray(pd.string) ? pd.string : [pd.string]);
          for (const s of serverParts) {
            const vMatch = s.match(/^([^\/]+)(?:\/([\d.]+))?/);
            if (vMatch) {
              technologies.push({
                name: vMatch[1].trim(),
                version: vMatch[2],
                category: 'web-server',
                confidence: 0.95,
              });
            }
          }
        }
        continue;
      }

      if (pluginName === 'IP') {
        ip = Array.isArray(pd.string) ? pd.string[0] : pd.string;
        continue;
      }
      if (pluginName === 'Country') {
        country = Array.isArray(pd.string) ? pd.string[0] : pd.string;
        continue;
      }

      if (skip.includes(pluginName)) continue;

      const version = pd.version ? (Array.isArray(pd.version) ? pd.version[0] : pd.version) : undefined;
      const cat = categorizeWhatwebPlugin(pluginName);

      technologies.push({
        name: pluginName,
        version: version?.toString(),
        category: cat,
        confidence: 0.85,
      });
    }

    httpStatus = data.http_status;
  } catch {
    return parseWhatwebText(jsonOutput, target);
  }

  return { target, technologies, httpStatus, country, ip };
}

function parseWhatwebText(stdout: string, target: string): ParsedWhatwebResult {
  const technologies: ParsedWhatwebResult['technologies'] = [];

  const bracketRegex = /([A-Za-z][\w.-]+)\[([^\]]*)\]/g;
  let bm: RegExpExecArray | null;
  while ((bm = bracketRegex.exec(stdout)) !== null) {
    const name = bm[1].trim();
    const value = bm[2].trim();
    if (/^\d{3}$/.test(name)) continue;
    const versionMatch = value.match(/^([\d.]+)/);
    const cat = categorizeWhatwebPlugin(name);
    technologies.push({
      name,
      version: versionMatch?.[1],
      category: cat,
      confidence: 0.7,
    });
  }

  const standaloneRegex = /,\s+([A-Za-z][\w.-]+)(?:\s*,|\s*$)/g;
  let sm: RegExpExecArray | null;
  while ((sm = standaloneRegex.exec(stdout)) !== null) {
    const name = sm[1].trim();
    if (name.length < 2 || name.length > 50) continue;
    if (!technologies.find(t => t.name === name)) {
      technologies.push({
        name,
        category: categorizeWhatwebPlugin(name),
        confidence: 0.6,
      });
    }
  }

  return { target, technologies };
}

function categorizeWhatwebPlugin(name: string): string {
  const lower = name.toLowerCase();
  const categories: [RegExp, string][] = [
    [/^(apache|nginx|iis|lighttpd|caddy|express|kestrel)/i, 'web-server'],
    [/^(jquery|react|angular|vue|bootstrap|tailwind|backbone)/i, 'frontend-framework'],
    [/^(php|python|ruby|java|asp|perl|node)/i, 'language'],
    [/^(wordpress|drupal|joomla|magento|shopify)/i, 'cms'],
    [/^(mysql|postgres|sqlite|mongodb|redis)/i, 'database'],
    [/^(cloudflare|akamai|fastly|varnish)/i, 'cdn'],
    [/^(openssl|x-xss|csp|hsts|cors)/i, 'security'],
    [/^(google|facebook|twitter|analytics)/i, 'tracking'],
    [/(framework|rails|django|flask|laravel|spring)/i, 'web-framework'],
    [/(cookie|session|auth)/i, 'session'],
  ];

  for (const [pattern, cat] of categories) {
    if (pattern.test(lower)) return cat;
  }
  return 'technology';
}

export function extractInjectableTargets(
  niktoFindings: ParsedNiktoFinding[],
  baseUrl: string
): string[] {
  const targets = new Set<string>();
  let base: string;
  try {
    const parsed = new URL(baseUrl.startsWith('http') ? baseUrl : `http://${baseUrl}`);
    base = `${parsed.protocol}//${parsed.host}`;
  } catch {
    base = baseUrl.replace(/\/$/, '');
  }

  const juiceShopEndpoints = [
    '/rest/products/search?q=test',
    '/rest/user/login',
    '/api/Users/?q=test',
    '/api/Products/1',
    '/api/Feedbacks/',
    '/api/Challenges/',
    '/api/Quantitys/',
    '/rest/basket/1',
    '/#/search?q=test',
  ];

  for (const ep of juiceShopEndpoints) {
    if (ep.includes('?') || ep.includes('=')) {
      targets.add(`${base}${ep}`);
    }
  }

  for (const finding of niktoFindings) {
    const desc = finding.description.toLowerCase();
    let uri = finding.uri || '';

    if (uri.startsWith('//') || (uri.includes('://') && !uri.startsWith(base))) {
      continue;
    }

    uri = uri.replace(/\/\//g, '/');
    if (!uri.startsWith('/')) uri = `/${uri}`;

    if (desc.includes('sql') || desc.includes('inject') || desc.includes('parameter')
      || desc.includes('input') || desc.includes('query') || desc.includes('form')
      || desc.includes('login') || desc.includes('search') || desc.includes('api')) {

      if (uri && uri !== '/') {
        if (uri.includes('?')) {
          targets.add(`${base}${uri}`);
        } else {
          targets.add(`${base}${uri}?id=1`);
        }
      }
    }

    const urlMatch = desc.match(/(?:GET|POST|PUT|DELETE)\s+(\S+\?\S+=\S+)/i);
    if (urlMatch) {
      let matchUri = urlMatch[1];
      if (!matchUri.startsWith('http')) {
        targets.add(`${base}${matchUri.startsWith('/') ? matchUri : '/' + matchUri}`);
      }
    }
  }

  return Array.from(targets).slice(0, 10);
}

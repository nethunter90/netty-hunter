'use strict';
const http = require('http');
const https = require('https');
const url = require('url');

const PORT = parseInt(process.env.CHALLENGE_PORT || '18003');

// The "internal" metadata endpoint: only accessible via server-side requests
// (enforced by the X-Internal-Fetch header the /fetch handler sets on its outbound calls)
function handleRequest(req, res) {
  const parsed = url.parse(req.url, true);
  const { pathname, query } = parsed;

  if (pathname === '/api/internal/metadata') {
    // Only reachable if the /fetch handler is proxying the request (SSRF)
    if (req.headers['x-internal-fetch'] !== '1') {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('403 Forbidden — internal endpoint');
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end([
      'instance-id: i-0a1b2c3d4e5f67890',
      'ami-id: ami-0abc123456def7890',
      'instance-type: c5.2xlarge',
      'local-ipv4: 10.0.1.42',
      'region: us-east-1',
      'iam/security-credentials/prod-ec2-role:',
      '  AccessKeyId: AKIA1234567890ABCDEF',
      '  SecretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      '  Token: AQoXnyc4lcK4w...',
      '  Expiration: 2099-01-01T00:00:00Z',
      '',
      'flag{ssrf_found}',
    ].join('\n'));
  }

  if (pathname === '/fetch') {
    const targetUrl = String(query.url || '');
    if (!targetUrl) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      return res.end('<html><body><p>Missing <code>url</code> parameter.</p><a href="/">Back</a></body></html>');
    }

    // Block obviously external schemes other than http/https
    let parsedTarget;
    try { parsedTarget = new url.URL(targetUrl); } catch {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      return res.end('Invalid URL');
    }

    if (!['http:', 'https:'].includes(parsedTarget.protocol)) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      return res.end('Unsupported protocol');
    }

    const client = parsedTarget.protocol === 'https:' ? https : http;
    const outReq = client.get(
      targetUrl,
      {
        timeout: 5000,
        headers: {
          'User-Agent': 'CorpFetcher/1.0',
          'X-Internal-Fetch': '1',   // <-- server-side header unlocks /api/internal/metadata
        },
      },
      (inResp) => {
        let body = '';
        inResp.on('data', chunk => { body += chunk; });
        inResp.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(`HTTP ${inResp.statusCode} from ${targetUrl}\n\n${body}`);
        });
      }
    );
    outReq.on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end(`Fetch failed: ${err.message}`);
    });
    outReq.on('timeout', () => {
      outReq.destroy();
      res.writeHead(504, { 'Content-Type': 'text/plain' });
      res.end('Request timed out');
    });
    return;
  }

  if (pathname === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('User-agent: *\nDisallow: /api/internal\nDisallow: /admin');
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html>
<html><head><title>CorpProxy — URL Fetcher</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto;padding:0 20px">
<h2>🌐 Corporate URL Fetcher</h2>
<p>Fetches remote URLs on behalf of the server for content preview and archival.</p>
<form action="/fetch" method="GET">
  <input name="url" placeholder="https://example.com" style="width:72%;padding:9px" value="https://httpbin.org/get" />
  <button type="submit" style="padding:9px 18px;background:#228b22;color:#fff;border:none;cursor:pointer">Fetch</button>
</form>
<p style="color:#999;font-size:12px">Requests are made from the internal network. Some internal resources may be accessible.</p>
</body></html>`);
}

http.createServer(handleRequest).listen(PORT, '0.0.0.0');

'use strict';
const http = require('http');
const url = require('url');

const PORT = parseInt(process.env.CHALLENGE_PORT || '18004');

// Simulate unsafe Node.js deserialization (node-serialize style)
// Real exploit: serialize object with IIFE in a function property
// {"rce":"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()"}
function simulateDeserialize(payload) {
  try {
    const obj = typeof payload === 'string' ? JSON.parse(payload) : payload;
    const raw = JSON.stringify(obj);

    // Patterns characteristic of node-serialize / serialize-javascript RCE payloads
    const rcePatterns = [
      /_\$\$ND_FUNC\$\$_/,            // node-serialize marker
      /require\s*\(\s*['"]child_process['"]\s*\)/,
      /child_process/,
      /process\.mainModule/,
      /execSync|exec\s*\(/,
      /\(\s*function\s*\(\s*\)\s*\{/,  // IIFE pattern
      /__proto__.*constructor.*call/,   // prototype pollution → RCE
    ];

    const triggered = rcePatterns.some(p => p.test(raw));
    if (triggered) {
      return {
        exploited: true,
        output: 'uid=0(root) gid=0(root) groups=0(root)\nflag{rce_found}\n/app # ',
      };
    }

    // Safe deserialization: parse the object and echo it back
    return { exploited: false, deserialized: obj };
  } catch (err) {
    return { exploited: false, error: err.message };
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 65536) reject(new Error('Body too large')); });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const { pathname, query } = parsed;

  if (pathname === '/deserialize' && req.method === 'POST') {
    let raw;
    try { raw = await readBody(req); } catch {
      res.writeHead(413); return res.end('Request too large');
    }
    const result = simulateDeserialize(raw);
    if (result.exploited) {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end(`[RCE] Command executed:\n${result.output}`);
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'deserialized', result }));
  }

  // GET probe: let the pattern scanner discover the endpoint via page content
  if (pathname === '/deserialize') {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    return res.end('405 Method Not Allowed — use POST with serialized payload');
  }

  if (pathname === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      service: 'DataProcessor v1.4.2',
      deserializeEndpoint: '/deserialize',
      format: 'node-serialize compatible JSON',
      note: 'Accepts serialized objects for processing pipeline',
    }));
  }

  if (pathname === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('User-agent: *\nAllow: /\nDisallow: /admin\n# Serialization endpoint at /deserialize (POST)');
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html>
<html><head><title>DataProcessor — Serialization Service</title></head>
<body style="font-family:monospace;max-width:700px;margin:60px auto;padding:0 20px">
<h2>⚙️ DataProcessor Serialization API</h2>
<p>Accepts serialized JavaScript objects for the processing pipeline.</p>
<pre style="background:#f4f4f4;padding:16px;border-left:4px solid #c00">POST /deserialize
Content-Type: application/json

{"name":"value","callback":"_$$ND_FUNC$$_function(){...}()"}</pre>
<p>Built with <code>node-serialize@0.0.4</code> — <a href="/api/status">service status</a></p>
<p style="color:#c00;font-size:12px">⚠️ Legacy deserialization endpoint — scheduled for deprecation</p>
</body></html>`);
}).listen(PORT, '0.0.0.0');

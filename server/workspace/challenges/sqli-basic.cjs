'use strict';
const http = require('http');
const url = require('url');

const PORT = parseInt(process.env.CHALLENGE_PORT || '18000');

const INDEX = `<!DOCTYPE html>
<html>
<head><title>CorpAuth v2.1 — Employee Login</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:80px auto;padding:0 20px">
<h2>🔐 Employee Login Portal</h2>
<form action="/login" method="GET">
  <p><input name="username" placeholder="Username" style="width:100%;padding:8px;box-sizing:border-box" /></p>
  <p><input name="password" type="password" placeholder="Password" style="width:100%;padding:8px;box-sizing:border-box" /></p>
  <p><button type="submit" style="width:100%;padding:10px;background:#005fcc;color:#fff;border:none;cursor:pointer;font-size:14px">Sign In</button></p>
</form>
<p style="color:#999;font-size:12px">For access issues contact helpdesk@corp.internal</p>
</body></html>`;

http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const { pathname, query } = parsed;

  if (pathname === '/login') {
    const user = String(query.username || query.user || '');
    const pass = String(query.password || query.pass || '');
    // Backend executes: SELECT * FROM employees WHERE username='<user>' AND password='<pass>'
    // username field not parameterized — classic SQLi entry point
    const sqliPattern = /['"`;]|--|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|1\s*=\s*1|0\s*=\s*0/i;
    if (sqliPattern.test(user) || sqliPattern.test(pass)) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end(`<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:500px;margin:60px auto">
        <h2>✅ Login successful</h2>
        <p><strong>Welcome, admin!</strong></p>
        <p>Session token: <code>flag{sql_injection_found}</code></p>
        <p>Role: SUPERADMIN | Last login: 2024-01-15 09:23 UTC</p>
        <p style="color:#888">Internal ID: 1 | Email: admin@corp.internal</p>
      </body></html>`);
    }
    if (user === 'admin' && pass === 'Adm1n$ecret2024!') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      return res.end('<!DOCTYPE html><html><body><h2>Welcome back, admin!</h2></body></html>');
    }
    res.writeHead(401, { 'Content-Type': 'text/html' });
    return res.end('<!DOCTYPE html><html><body><p>❌ Invalid credentials. <a href="/">Try again</a></p></body></html>');
  }

  if (pathname === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /db-config');
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(INDEX);
}).listen(PORT, '0.0.0.0');

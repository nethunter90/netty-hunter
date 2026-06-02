'use strict';
const http = require('http');
const url = require('url');

const PORT = parseInt(process.env.CHALLENGE_PORT || '18001');

http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const { pathname, query } = parsed;

  if (pathname === '/search') {
    const q = String(query.q || query.query || '');
    // Vulnerable: query parameter reflected directly into HTML response without encoding
    const hasXssPayload = /<|>|"|'|script|onerror|onload|onfocus|onclick|onmouseover|javascript:|svg|img\s|alert\s*\(/i.test(q);
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><head><title>Search — ${q}</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto;padding:0 20px">
<h2>🔍 Search Results</h2>
<p>Showing results for: <strong>${q}</strong></p>
${hasXssPayload
  ? `<p style="color:red">Warning: unsanitised input detected</p>
     <!-- flag{xss_found} -->
     <div data-flag="flag{xss_found}" id="xss-evidence">XSS payload reflected in response</div>`
  : '<p style="color:#555">No products matched your query.</p>'}
<hr/><a href="/">← Back to search</a>
</body></html>`);
  }

  if (pathname === '/api/search') {
    const q = String(query.q || '');
    const hasXssPayload = /<|script|onerror|onload|javascript:/i.test(q);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      query: q,
      results: [],
      reflected: q,
      flag: hasXssPayload ? 'flag{xss_found}' : null,
    }));
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html>
<html><head><title>ShopXpress — Product Search</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto;padding:0 20px">
<h2>🛒 Product Search</h2>
<form action="/search" method="GET">
  <input name="q" placeholder="Search products..." style="width:72%;padding:9px" />
  <button type="submit" style="padding:9px 18px;background:#ff6600;color:#fff;border:none;cursor:pointer">Search</button>
</form>
<p style="color:#999;font-size:12px">Also available at <code>/api/search?q=...</code></p>
</body></html>`);
}).listen(PORT, '0.0.0.0');

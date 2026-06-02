'use strict';
const http = require('http');
const url = require('url');

const PORT = parseInt(process.env.CHALLENGE_PORT || '18002');

const USERS = {
  '1': { id: 1, username: 'alice', name: 'Alice Johnson', email: 'alice@example.com', role: 'user', createdAt: '2023-06-01' },
  '2': { id: 2, username: 'bob_admin', name: 'Bob Administrator', email: 'bob@example.com', role: 'admin',
         secret: 'flag{idor_found}', apiKey: 'sk-prod-Kx9mN2vL8qR4wT7p', ssn: '***-**-4321', salary: 250000 },
  '3': { id: 3, username: 'charlie', name: 'Charlie Dev', email: 'charlie@example.com', role: 'developer', createdAt: '2023-09-15' },
};

// Simulate JWT-like auth: "Bearer user-1-token" → currentUserId = 1
function getCurrentUserId(authHeader) {
  const match = (authHeader || '').match(/Bearer user-(\d+)-token/);
  return match ? match[1] : '1'; // default to user 1 if no auth
}

http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const { pathname, query } = parsed;
  const auth = req.headers['authorization'] || '';
  const currentUserId = getCurrentUserId(auth);

  if (pathname.startsWith('/api/users/')) {
    const targetId = pathname.replace('/api/users/', '').split('/')[0];
    const user = USERS[targetId];
    if (!user) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'User not found' }));
    }
    // IDOR: server does not verify that currentUserId === targetId
    // Any authenticated user can read any other user's full profile
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(user, null, 2));
  }

  if (pathname === '/api/profile' || pathname === '/api/users') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ currentUser: USERS[currentUserId] || USERS['1'], hint: 'Try /api/users/{id} for other profiles' }));
  }

  if (pathname === '/api/orders') {
    // Orders for current user only — no IDOR here (red herring)
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ userId: currentUserId, orders: [] }));
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`<!DOCTYPE html>
<html><head><title>UserHub — Profile API</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:60px auto;padding:0 20px">
<h2>👤 UserHub Profile Service</h2>
<p>Logged in as: <strong>Alice Johnson</strong> (user ID: 1)</p>
<ul>
  <li><a href="/api/profile">GET /api/profile — your profile</a></li>
  <li><a href="/api/users/1">GET /api/users/1 — user 1 detail</a></li>
  <li><a href="/api/orders">GET /api/orders — your orders</a></li>
</ul>
<p style="color:#888;font-size:12px">Authorization: Bearer user-1-token (current session)</p>
</body></html>`);
}).listen(PORT, '0.0.0.0');

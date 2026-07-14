/**
 * Deterministic fixture target for exercising the dedicated OBSERVE-phase
 * probers (race-condition-detector, cookie-flag-checker, host-header-probe,
 * oauth-probe, ...) without depending on a real app happening to have the
 * specific bug. Each route is deliberately, unconditionally vulnerable to
 * exactly one class so a hunt run against this server should reliably
 * confirm every wired-up prober in a single pass.
 *
 * Run: npx tsx src/fixtures/vuln-fixture-server.ts [port]
 */
import express from "express";
import http from "http";

// ── blind_xxe_probe ─────────────────────────────────────────────────────────
// A genuinely vulnerable XML parser: pulls the SYSTEM URL straight out of the
// raw DTD via regex (real parsers do this via libxml2/etc. entity
// resolution) and actually fetches it — that outbound fetch is what makes
// the OOB beacon fire back to netty-hunter's own callback server. The AWS
// metadata IP is special-cased to return a canned metadata-shaped body
// instead of actually being fetched, since 169.254.169.254 is a real
// link-local address blind-xxe-probe.ts's SSRF payload targets — no reason
// to attempt a real outbound request to it just to prove the detection logic.
function extractSystemUrl(xml: string): string | null {
  const m = xml.match(/SYSTEM\s+"([^"]+)"/);
  return m ? m[1] : null;
}
function xxeVulnerableXmlHandler(req: express.Request, res: express.Response) {
  const xml = typeof req.body === "string" ? req.body : "";
  const sysUrl = extractSystemUrl(xml);
  if (sysUrl) {
    if (sysUrl.includes("169.254.169.254")) {
      res.status(200).send("<result>ami-id: ami-0abcdef1234567890, instance-id: i-0fixture1234567890</result>");
      return;
    }
    http.get(sysUrl, (r) => r.resume()).on("error", () => { /* fire-and-forget, matches a real vulnerable parser */ });
  }
  res.status(200).send("<result>ok</result>");
}

function b64url(s: string): string {
  return Buffer.from(s).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
// A JWT advertising RS256 + a kid — jwt-confusion-probe.ts only attempts the
// RS256-to-HS256 confusion and kid-injection techniques when it sees these
// header fields on the token it discovers. The signature itself is never
// checked below, so any placeholder works.
const FIXTURE_JWT = `${b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "key1" }))}.${b64url(JSON.stringify({ sub: "fixture-user", id: 42 }))}.fakesig`;

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── host_header_probe ─────────────────────────────────────────────────────
// Root page: reflects whichever of X-Forwarded-Host / Host was sent (host
// reflection + cache poisoning via X-Forwarded-Host), returns a distinctly
// different, longer body when Host=localhost + X-Forwarded-For=127.0.0.1
// (routing bypass — simulates a backend that treats that combo as trusted
// internal traffic), and carries a fake hardcoded client_secret for
// oauth_probe's secret_exposure test.
// ── open_redirect_chain_probe ─────────────────────────────────────────────
// Naive redirect handler — any of the common redirect-param names, from
// either a query string (GET) or form body (POST), gets redirected to
// verbatim, no allowlist. Deliberately checked first so it takes priority
// over the host-reflection page below when one of these params is present.
const REDIRECT_PARAM_NAMES = [
  "redirect", "next", "url", "return", "returnUrl", "returnTo", "redirect_uri",
  "redirect_url", "goto", "destination", "dest", "target", "redir", "location",
  "forward", "back",
];
function tryOpenRedirect(src: Record<string, unknown> | undefined, res: express.Response): boolean {
  for (const p of REDIRECT_PARAM_NAMES) {
    const val = src?.[p];
    if (typeof val === "string" && val) {
      res.redirect(302, val);
      return true;
    }
  }
  return false;
}
app.post("/", express.text({ type: "application/xml" }), (req, res) => {
  if (typeof req.body === "string" && req.body.includes("<?xml")) {
    xxeVulnerableXmlHandler(req, res);
    return;
  }
  if (tryOpenRedirect(req.body, res)) return;
  res.status(200).send("ok");
});

// blind-xxe-probe.ts tests every hit sequentially with real OOB waits (up to
// ~44s/endpoint for the OOB techniques), so registering all of its
// XML_PROBE_PATHS here would turn one probe() call into an 8+ minute run.
// "" (root, handled above) plus this one path is enough to exercise the same
// code path fast — the other paths correctly 404 (Express default) and get
// excluded from xmlEndpointsFound, same as a real target that only exposes
// one XML-consuming route.
app.post("/api/parse", express.text({ type: "application/xml" }), xxeVulnerableXmlHandler);

app.get("/", (req, res) => {
  if (tryOpenRedirect(req.query as Record<string, unknown>, res)) return;
  const reflectedHost = (req.headers["x-forwarded-host"] as string) || req.headers.host || "";
  if (req.headers.host === "localhost" && req.headers["x-forwarded-for"] === "127.0.0.1") {
    res.status(200).send(
      `<html><body><h1>Internal Admin Panel</h1>` +
      `<p>Trusted internal request accepted (Host: ${reflectedHost}).</p>` +
      `<p>${"internal-only diagnostic padding ".repeat(6)}</p></body></html>`
    );
    return;
  }
  res.status(200).send(
    `<html><body><h1>Fixture App</h1><p>Host header reflected: ${reflectedHost}</p>` +
    `<!-- client_secret: "sk_live_fixture_abcd1234efgh5678" -->` +
    // open_redirect_chain_probe's oauth_misconfiguration chain hypothesis
    // only fires when detectOAuthEndpoints() sees "/oauth" or "/auth"
    // referenced in this page's body.
    `<a href="/oauth/authorize">Login</a>` +
    // ── prototype_pollution_probe (query-param vectors) ──
    // Echoes the raw, unparsed query string verbatim — deliberately not
    // routed through Express's qs parser (which strips __proto__ keys by
    // default), so a __proto__[polluted]=MARKER / constructor.prototype...
    // payload shows up in the response exactly as prototype-pollution-
    // probe.ts's `reflected` check expects, regardless of what qs would do
    // with the parsed object.
    `<!-- raw-query: ${req.url} --></body></html>`
  );
});

// password_reset_poison: reflects the (attacker-controlled) Host header into
// the "reset link" it claims to have sent.
for (const p of ["/forgot-password", "/reset-password", "/account/forgot", "/users/password"]) {
  app.post(p, (req, res) => {
    res.status(200).send(`Password reset link sent: http://${req.headers.host}/reset?token=fixture-token`);
  });
}

// ── oauth_probe ────────────────────────────────────────────────────────────
// A real (if deliberately broken) authorization endpoint. A bare GET (no
// query params, as discoverEndpoints() sends) returns a distinguishing 200
// consent-style page — NOT identical to "/" or a 404, so oauth-probe's
// baseline-diff check correctly recognizes this as a genuine endpoint rather
// than a SPA catch-all. A fully-formed request accepts the code/implicit
// flow with no state validation, no PKCE enforcement, and no redirect_uri
// allowlist.
app.get("/oauth/authorize", (req, res) => {
  const { response_type, redirect_uri, state } = req.query as Record<string, string | undefined>;
  if (!redirect_uri) {
    res.status(200).send("<html><body><h1>OAuth 2.0 Authorization</h1><form>Approve access?</form></body></html>");
    return;
  }
  const code = `authcode_${Math.random().toString(36).slice(2)}`;
  if (response_type === "token") {
    res.redirect(302, `${redirect_uri}#access_token=${code}&token_type=bearer&state=${state ?? ""}`);
    return;
  }
  res.redirect(302, `${redirect_uri}?code=${code}&state=${state ?? ""}`);
});

// ── cookie_flag_checker ──────────────────────────────────────────────────
// Session cookie set with none of HttpOnly/Secure/SameSite. cookie-flag-
// checker.ts POSTs to /login and /api/login and GETs /signin — register all
// three so whichever it hits sets the vulnerable cookie.
const setVulnCookie = (_req: express.Request, res: express.Response) => {
  res.setHeader("Set-Cookie", "fixture_session=abc123; Path=/");
  res.status(200).send("<html><body>Login page</body></html>");
};
app.get("/login", setVulnCookie);
app.post("/login", setVulnCookie);
app.post("/api/login", setVulnCookie);
app.get("/signin", setVulnCookie);

// ── race_condition_detector ─────────────────────────────────────────────
// Every concurrent request unconditionally succeeds — no locking, no
// idempotency check — so a 15-way concurrent burst always trips isDuplicate.
const RACE_PATHS = [
  "/purchase", "/buy", "/checkout", "/apply-coupon", "/redeem", "/transfer",
  "/vote", "/like", "/claim", "/activate", "/verify", "/order", "/payment",
];
for (const p of RACE_PATHS) {
  app.post(p, (_req, res) => {
    res.status(200).json({ ok: true, message: `${p} applied` });
  });
}

// ── mass_assignment_probe ─────────────────────────────────────────────────
// Naive object-merge "update profile" handler — echoes back whatever the
// client sent, including any privileged fields (role, isAdmin, balance, ...)
// that were never meant to be client-settable. PUT/PATCH on the update
// endpoints and POST on the register endpoints both use the same handler.
const echoMassAssignment = (req: express.Request, res: express.Response) => {
  res.status(200).json({ id: 1, ...req.body });
};
for (const p of ["/api/user", "/api/me", "/api/profile", "/api/account", "/api/users/me", "/api/v1/user", "/api/v1/me"]) {
  app.put(p, echoMassAssignment);
  app.patch(p, echoMassAssignment);
}
for (const p of ["/api/register", "/api/signup", "/api/users"]) {
  app.post(p, echoMassAssignment);
}

// ── two_factor_bypass_probe ────────────────────────────────────────────────
// 2FA endpoint that accepts literally any code/otp/token (null, empty,
// reused, or a guessed backup code) — trips null_code, response_manipulation,
// code_reuse, and backup_code_brute all in one route. Both "protected"
// resources return user data with no auth check at all — trips step_skip.
app.post("/api/2fa/verify", (_req, res) => {
  res.status(200).json({ success: true, token: "fixture-session-token" });
});
// ── jwt_confusion_probe ─────────────────────────────────────────────────────
// /api/me hands out a JWT via Set-Cookie (discovery) and — the actual bug —
// accepts ANY Authorization: Bearer token at all, real or forged, since it
// never checks the signature. That trivially satisfies alg:none, RS256→HS256
// confusion, kid injection, and weak-secret cracking simultaneously; separate
// signature-verification logic isn't needed for a fixture whose whole point
// is "there is none."
app.get("/api/me", (_req, res) => {
  res.setHeader("Set-Cookie", `session=${FIXTURE_JWT}; Path=/`);
  res.status(200).json({ id: 42, username: "fixture_user", email: "user@fixture.local" });
});
app.get("/api/dashboard", (_req, res) => {
  res.status(200).json({ id: 42, user: "fixture_user" });
});

// ── prototype_pollution_probe (JSON body vectors) ─────────────────────────
// prototype-pollution-probe.ts only builds a __proto__/constructor.prototype
// JSON body payload when the target URL contains "/api" — echoes the raw
// request body back so the marker shows up in the response regardless of how
// JSON.parse itself handles a "__proto__" key.
app.post("/api/settings", (req, res) => {
  res.status(200).json({ applied: true, raw: JSON.stringify(req.body) });
});

// ── tech_payload_prober (lfi_traversal, Node/Express branch) ─────────────
// Genuinely vulnerable path-traversal read via a "file" query param, no
// sanitization — matches the Node/Express traversal payload tech-payload-
// selector.ts builds ("../../../etc/passwd") for a target whatweb fingerprints
// as Node/Express (this Express app sends X-Powered-By: Express by default).
// Serves a synthetic passwd-shaped body so LFI_DISCLOSURE_SIGNATURE
// (tech-payload-prober.ts) matches without touching the real host filesystem.
// Note: tech-payload-selector.ts only builds an SQLi payload under its Django
// branch, so a real hunt against this Express-fingerprinted fixture won't
// exercise probeSqli — that path is covered by mocked unit tests instead
// (tech-payload-prober.test.ts), same as this session's other new probers.
app.get("/render", (req, res) => {
  const file = String(req.query.file ?? "");
  if (/etc[/\\]passwd/.test(file)) {
    res.status(200).send("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n");
    return;
  }
  res.status(200).send(`<html><body>Rendered: ${file}</body></html>`);
});

// Malformed request bodies (e.g. from a prober that sends non-JSON with a
// JSON content-type) must not crash the fixture — a real target wouldn't
// die either, and a dead fixture silently reads as "target has no bugs".
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  res.status(400).json({ error: "bad request" });
});

const port = Number(process.argv[2]) || 4545;
const server = app.listen(port, () => {
  console.log(`[vuln-fixture-server] listening on http://localhost:${port}`);
});

// ── websocket_probe ────────────────────────────────────────────────────────
// A real WebSocket handshake ("101 Switching Protocols") can't come out of
// Express's normal request/response cycle — it requires hooking the
// underlying http.Server's "upgrade" event and writing the status line
// directly. Deliberately vulnerable: accepts the upgrade unconditionally,
// regardless of Origin header or the presence of any auth headers at all —
// trips both no_origin_check and unauthenticated_access. No real WS protocol
// frames are needed since websocket-probe.ts only checks the HTTP status
// code the handshake returned.
server.on("upgrade", (_req, socket) => {
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
  socket.end();
});

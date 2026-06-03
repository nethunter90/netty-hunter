import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import { createServer } from "http";
import { Server as SocketServer } from "socket.io";
import session from "express-session";
import connectPg from "connect-pg-simple";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { mkdirSync } from "fs";
import * as pty from "node-pty";
import logger from "./utils/logger";
import authRoutes from "./routes/auth";
import huntRoutes from "./routes/hunt";
import bountyRoutes from "./routes/bounty";
import orchestrationRoutes from "./routes/orchestration";
import hunterRoutes from "./routes/hunter";
import governanceRoutes from "./routes/governance";
import missionsRoutes from "./routes/missions";
import bountyIntelligenceRoutes from "./routes/bounty-intelligence";
import reasoningRoutes from "./routes/reasoning";
import graphRoutes from "./routes/graph";
import intelligenceRoutes from "./routes/intelligence";
import juiceshopRoutes from "./routes/juiceshop";
import xbowRoutes from "./routes/xbow";
import settingsRoutes from "./routes/settings";
import chatRoutes from "./routes/chat";
import toolsRoutes from "./routes/tools";
import { HunterEngine } from "./agents/HunterEngine";
import { SolverPool } from "./agents/SolverPool";
import { CampaignOrchestrator } from "./agents/CampaignOrchestrator";
import { initializeAutonomousBrain } from "./lib/intelligence";
import { callbackServer } from "./lib/oob/callback-server";
import { runtimeConfig } from "./lib/runtime-config";
import { writeupScraper } from "./lib/intelligence/writeup-scraper";
import { egressAllocator } from "./lib/stealth/egress-route-allocator";
import { wireHuntEngineToSocket } from "./lib/utils/wire-hunt-engine";
import { activeHuntSessions } from "./lib/state/hunt-sessions";
import { db } from "./db";
import { programs } from "./db/schema";
import { gt } from "drizzle-orm";

const PgSession = connectPg(session);

// Ensure log dir exists
try { mkdirSync("logs", { recursive: true }); } catch { /* already exists */ }

// ─── Load persisted settings via RuntimeConfig (validated, audited) ──────────
import("./db").then(({ db: _db }) => {
  import("./db/schema").then(({ reinforcementStore: rs }) => {
    import("drizzle-orm").then(({ like }) => {
      _db.select().from(rs).where(like(rs.domain, "settings")).then(rows => {
        runtimeConfig.loadAll(rows.filter(r => r.key != null));
        logger.info(`Settings loaded from DB via RuntimeConfig (${rows.length} keys)`);
      }).catch(() => {});
    });
  });
}).catch(() => {});

// ─── Autonomous Brain ─────────────────────────────────────────────────────────
initializeAutonomousBrain();
logger.info("Autonomous brain initialized");

// ─── Express App ──────────────────────────────────────────────────────────────
const app = express();
const httpServer = createServer(app);
const PORT = parseInt(process.env.PORT || "3001");

// ─── Socket.IO ────────────────────────────────────────────────────────────────
const io = new SocketServer(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  },
  pingTimeout: 60000,
});

// Make io available to routes
app.set("io", io);

// Forward egress route-change events to all connected sockets
egressAllocator.setSocketEmitter((event, data) => io.emit(event, data));

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // handled by frontend
}));

app.use(cors({
  origin: process.env.CLIENT_URL || "http://localhost:5173",
  credentials: true,
}));

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Session secret must be explicitly configured in production — never ship the
// hardcoded default, which would give every deployment predictable cookies.
if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET must be set in production");
}
if (!process.env.SESSION_SECRET) {
  logger.warn("SESSION_SECRET not set — using insecure development default");
}

// Session – PostgreSQL-backed (survives restarts)
app.use(session({
  store: new PgSession({
    conString: process.env.DATABASE_URL,
    tableName: "sessions",
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET || "change-me-in-production-minimum-32-chars",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session.userId) {
    res.status(401).json({ error: "Not authenticated" });
    return;
  }
  next();
}

// Rate limiting — skip for loopback so local dev is never blocked
const isLocalhost = (req: Request): boolean => {
  const ip = req.ip ?? req.socket.remoteAddress ?? '';
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 500,
  message: "Too many requests from this IP",
  standardHeaders: true,
  legacyHeaders: false,
  skip: isLocalhost,
});

const huntLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20, // 20 hunts per 5 min
  message: "Hunt rate limit exceeded",
  skip: isLocalhost,
});

const orchestrationLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 min
  max: 5, // 5 orchestrations per 10 min
  message: "Orchestration rate limit exceeded",
  skip: isLocalhost,
});

app.use("/api", apiLimiter);
app.use("/api/hunt/start", huntLimiter);
app.use("/api/orchestration/run", orchestrationLimiter);

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use("/api/auth", authRoutes);
app.use("/api/hunt", requireAuth, huntRoutes);
app.use("/api/bounty", requireAuth, bountyRoutes);
app.use("/api/orchestration", requireAuth, orchestrationRoutes);
app.use("/api/hunter", requireAuth, hunterRoutes);
app.use("/api/governance", requireAuth, governanceRoutes);
app.use("/api/missions", requireAuth, missionsRoutes);
app.use("/api/bounty-intelligence", requireAuth, bountyIntelligenceRoutes);
app.use("/api/reasoning", requireAuth, reasoningRoutes);
app.use("/api/graph", requireAuth, graphRoutes);
app.use("/api/intelligence", requireAuth, intelligenceRoutes);
app.use("/api/juiceshop", requireAuth, juiceshopRoutes);
app.use("/api/xbow", requireAuth, xbowRoutes);
app.use("/api/settings", requireAuth, settingsRoutes);
app.use("/api/chat", requireAuth, chatRoutes);
app.use("/api/tools", requireAuth, toolsRoutes);

// OOB callback receiver — no auth required (external targets call this).
// Per-IP rate limit caps beacon-flooding abuse on this public endpoint.
const callbackLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 min
  max: 60,             // 60 hits/min/IP
  message: "Callback rate limit exceeded",
  standardHeaders: true,
  legacyHeaders: false,
});
app.all("/api/callback/:beaconId", callbackLimiter, (req, res) => {
  const { beaconId } = req.params;
  callbackServer.recordHit(beaconId, req.ip || "", JSON.stringify(req.body || req.query || {}));
  io.emit("oob:hit", { beaconId, ip: req.ip, ts: new Date().toISOString() });
  res.status(200).send("ok");
});

// Health check
app.get("/health", (_req, res) => res.json({
  status: "ok",
  timestamp: new Date().toISOString(),
  version: "1.0.0",
}));

// 404 handler
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

// Error handler
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error("Unhandled error", { err: err.message, stack: err.stack });
  res.status(500).json({ error: "Internal server error" });
});

// ─── Socket.IO Events ─────────────────────────────────────────────────────────

io.on("connection", (socket) => {
  logger.info("Socket connected", { id: socket.id });

  // Subscribe to hunt session events
  socket.on("subscribe:hunt", async ({ sessionUuid }: { sessionUuid: string }) => {
    socket.join(`hunt:${sessionUuid}`);
    logger.info("Socket subscribed to hunt", { id: socket.id, sessionUuid });

    // Find active engine (includes REST-started engines via shared map)
    const engine = activeHuntSessions.get(sessionUuid);
    if (engine) {
      // Replay current phase so late-joining clients aren't left blank
      const state = engine.getState();
      socket.emit("hunt:state", state);
    }
  });

  // Subscribe to orchestration room for real-time 6-layer updates
  socket.on("subscribe:orchestration", ({ orchestrationId }: { orchestrationId: string }) => {
    socket.join(`orchestration:${orchestrationId}`);
    logger.info("Socket subscribed to orchestration", { id: socket.id, orchestrationId });
  });

  // Start a full orchestrated hunt via Socket.IO
  socket.on("orchestration:run", async (params: {
    programId: number;
    targetUrl: string;
    mode?: "forward" | "backward";
    goal?: string;
    maxIterations?: number;
    budget?: { maxRequests: number; maxTime: number };
    focusVulnClasses?: string[];
  }) => {
    const orchestrator = new CampaignOrchestrator();
    const state = orchestrator.getState();
    const orchestrationId = state.orchestrationId;

    // Wire all events → socket
    [
      "orchestration:started", "orchestration:layer_start", "orchestration:layer_complete",
      "orchestration:layer_error", "orchestration:audit", "orchestration:complete",
      "orchestration:aborted",
      "l4:hunt_started", "l4:phase", "l4:observations", "l4:hypotheses",
      "l4:probing", "l4:probe_result", "l4:finding_raw", "l4:strategy_update",
      "l4:solver_finding", "l4:error",
      "l5:verifying", "l5:verified", "l5:rejected", "l5:public_duplicate", "l5:report_submitted",
      "l6:report_generated", "l6:autonomy_updated",
      "orchestration:targets_expanded", "orchestration:takeover_found",
      "hunt:cve_seeded", "hunt:graphql_schema", "hunt:oob_hit",
      "hunt:ssrf_pivot", "hunt:changes_detected", "hunt:secrets_found",
      "hunt:ws_vulns", "hunt:bucket_exposed", "hunt:proto_pollution", "hunt:race_condition",
      "hunt:host_header", "hunt:crlf", "hunt:cookie_flags", "hunt:endpoints_discovered",
      "hunt:plan_seeded", "hunt:tech_payloads", "hunt:params_discovered",
      "hunt:oauth_vulns", "hunt:mass_assignment", "hunt:business_logic",
      "hunt:2fa_bypass", "hunt:jwt_vulns", "hunt:open_redirect", "hunt:xxe_found",
      "hunt:chain_seeded", "hunt:pivot", "hunt:ai_reasoning",
    ].forEach(evt => {
      orchestrator.on(evt, (d) => socket.emit(evt, d));
    });

    socket.emit("orchestration:created", { orchestrationId });

    orchestrator.orchestrate(params).catch(err => {
      socket.emit("orchestration:error", { orchestrationId, error: String(err) });
    });
  });

  socket.on("hunt:start", async (params: {
    targetUrl: string;
    programId: number;
    campaignId: number;
    maxIterations?: number;
    budget?: { maxRequests: number; maxTime: number };
  }) => {
    const engine = new HunterEngine();

    try {
      const sessionUuid = await engine.startHunt(params);
      wireHuntEngineToSocket(engine, sessionUuid, io);
      // Replay hunt:started since it fired before wiring
      io.to(`hunt:${sessionUuid}`).emit("hunt:started", { sessionUuid, targetUrl: params.targetUrl });
      activeHuntSessions.set(sessionUuid, engine);
      engine.on("hunt:complete", (data: Record<string, unknown>) => {
        setTimeout(() => activeHuntSessions.delete(String(data.sessionId ?? sessionUuid)), 60_000);
      });
      socket.emit("hunt:session_created", { sessionUuid });
    } catch (err) {
      socket.emit("hunt:error", { error: String(err) });
    }
  });

  socket.on("solver:spawn", async (params: {
    endpoint: string;
    programId: number;
    observations?: Record<string, unknown>;
  }) => {
    const pool = new SolverPool(8);
    pool.on("solvers:spawned", (data) => socket.emit("solvers:spawned", data));
    pool.on("solver:started", (data) => socket.emit("solver:started", data));
    pool.on("solver:complete", (data) => socket.emit("solver:complete", data));
    pool.on("solver:finding", (data) => socket.emit("solver:finding", data));

    try {
      const results = await pool.spawnSolvers(params.endpoint, params.observations || {}, {
        programId: params.programId,
        sessionId: 0,
      });
      socket.emit("solver:all_complete", { results, stats: pool.getStats() });
    } catch (err) {
      socket.emit("solver:error", { error: String(err) });
    }
  });

  // ── Embedded Terminal (PTY) ────────────────────────────────────────────────
  const socketPtys = new Map<string, pty.IPty>();

  socket.on("terminal:create", (data: { cols?: number; rows?: number; cwd?: string }) => {
    const termId = `${socket.id}-${Date.now()}`;
    const shell = process.env.SHELL || "/bin/bash";
    const ptyProcess = pty.spawn(shell, [], {
      name: "xterm-256color",
      cols: data.cols || 80,
      rows: data.rows || 24,
      cwd: data.cwd || process.cwd(),
      env: process.env as Record<string, string>,
    });

    socketPtys.set(termId, ptyProcess);

    ptyProcess.onData(output => socket.emit("terminal:output", { termId, data: output }));
    ptyProcess.onExit(() => {
      socketPtys.delete(termId);
      socket.emit("terminal:exit", { termId });
    });

    socket.emit("terminal:created", { termId });
    logger.debug("Terminal PTY created", { termId, shell });
  });

  socket.on("terminal:input", ({ termId, data }: { termId: string; data: string }) => {
    socketPtys.get(termId)?.write(data);
  });

  socket.on("terminal:resize", ({ termId, cols, rows }: { termId: string; cols: number; rows: number }) => {
    socketPtys.get(termId)?.resize(cols, rows);
  });

  socket.on("terminal:destroy", ({ termId }: { termId: string }) => {
    const p = socketPtys.get(termId);
    if (p) { try { p.kill(); } catch {} socketPtys.delete(termId); }
  });

  socket.on("disconnect", () => {
    logger.info("Socket disconnected", { id: socket.id });
    // Kill all PTYs owned by this socket
    socketPtys.forEach((p, termId) => {
      try { p.kill(); } catch {}
      socketPtys.delete(termId);
    });
  });
});

// ─── Scheduled Re-scan Engine ─────────────────────────────────────────────────
// Check every 15 minutes if any programs are due for a re-scan.
setInterval(async () => {
  try {
    const scheduled = await db.select().from(programs)
      .where(gt(programs.scheduleInterval, 0));
    for (const prog of scheduled) {
      const interval = (prog.scheduleInterval ?? 0) * 60 * 60 * 1000;
      const lastHunted = prog.lastHunted ? prog.lastHunted.getTime() : 0;
      if (Date.now() - lastHunted < interval) continue;

      const scope = (prog.scope as string[]) || [];
      const targetUrl = scope[0];
      if (!targetUrl) continue;

      logger.info("[Scheduler] Triggering scheduled re-scan", { programId: prog.id, name: prog.name });
      io.emit("scheduler:rescan_started", { programId: prog.id, name: prog.name, targetUrl });

      const orchestrator = new CampaignOrchestrator();
      orchestrator.orchestrate({
        programId: prog.id,
        targetUrl,
        budget: { maxRequests: 2000, maxTime: 1800 },
      }).catch(err => {
        logger.warn("[Scheduler] Re-scan failed", { programId: prog.id, err: String(err) });
      });
    }
  } catch (err) {
    logger.debug("[Scheduler] tick error (non-critical)", { err: String(err) });
  }
}, 15 * 60 * 1000); // every 15 min

// ─── Daily Writeup Intelligence Scrape ───────────────────────────────────────
// Runs once at startup (after a short delay) then every 24h.
setTimeout(() => writeupScraper.scrapeAll().catch(() => {}), 30_000);
setInterval(() => writeupScraper.scrapeAll().catch(() => {}), 24 * 60 * 60 * 1000);

// ─── Start Server ─────────────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  logger.info(`Sentinel Primordial – Bug Bounty Intelligence Platform`);
  logger.info(`Server running on http://localhost:${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || "development"}`);
});

// Session type extension
declare module "express-session" {
  interface SessionData {
    userId: number;
  }
}

export { app, io };

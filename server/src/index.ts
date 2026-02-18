import "dotenv/config";
import express from "express";
import { createServer } from "http";
import { Server as SocketServer } from "socket.io";
import session from "express-session";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { mkdirSync } from "fs";
import logger from "./utils/logger";
import authRoutes from "./routes/auth";
import huntRoutes from "./routes/hunt";
import bountyRoutes from "./routes/bounty";
import { HunterEngine } from "./agents/HunterEngine";
import { SolverPool } from "./agents/SolverPool";

// Ensure log dir exists
try { mkdirSync("logs", { recursive: true }); } catch { /* already exists */ }

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

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || "change-me-in-production-minimum-32-chars",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
}));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 500,
  message: "Too many requests from this IP",
  standardHeaders: true,
  legacyHeaders: false,
});

const huntLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20, // 20 hunts per 5 min
  message: "Hunt rate limit exceeded",
});

app.use("/api", apiLimiter);
app.use("/api/hunt/start", huntLimiter);

// ─── Routes ───────────────────────────────────────────────────────────────────
app.use("/api/auth", authRoutes);
app.use("/api/hunt", huntRoutes);
app.use("/api/bounty", bountyRoutes);

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
const activeSessions = new Map<string, HunterEngine>();

io.on("connection", (socket) => {
  logger.info("Socket connected", { id: socket.id });

  // Subscribe to hunt session events
  socket.on("subscribe:hunt", async ({ sessionUuid }: { sessionUuid: string }) => {
    socket.join(`hunt:${sessionUuid}`);
    logger.info("Socket subscribed to hunt", { id: socket.id, sessionUuid });

    // Find active engine
    const engine = activeSessions.get(sessionUuid);
    if (engine) {
      socket.emit("hunt:state", engine.getState());
    }
  });

  socket.on("hunt:start", async (params: {
    targetUrl: string;
    programId: number;
    campaignId: number;
    maxIterations?: number;
    budget?: { maxRequests: number; maxTime: number };
  }) => {
    const engine = new HunterEngine();

    engine.on("hunt:started", (data) => io.to(`hunt:${data.sessionUuid}`).emit("hunt:started", data));
    engine.on("hunt:phase", (data) => io.to(`hunt:${data.sessionUuid || params.campaignId}`).emit("hunt:phase", data));
    engine.on("hunt:observations", (data) => socket.emit("hunt:observations", data));
    engine.on("hunt:hypotheses", (data) => socket.emit("hunt:hypotheses", data));
    engine.on("hunt:probing", (data) => socket.emit("hunt:probing", data));
    engine.on("hunt:probe_result", (data) => socket.emit("hunt:probe_result", data));
    engine.on("hunt:finding_confirmed", (data) => socket.emit("hunt:finding_confirmed", data));
    engine.on("hunt:update", (data) => socket.emit("hunt:update", data));
    engine.on("hunt:complete", (data) => {
      socket.emit("hunt:complete", data);
      activeSessions.delete(data.sessionId);
    });
    engine.on("hunt:error", (data) => socket.emit("hunt:error", data));

    try {
      const sessionUuid = await engine.startHunt(params);
      activeSessions.set(sessionUuid, engine);
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
    const pool = new SolverPool(3);
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

  socket.on("disconnect", () => {
    logger.info("Socket disconnected", { id: socket.id });
  });
});

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

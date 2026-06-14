import { Router, Request, Response } from "express";

// Desktop-agent router.
//
//  GET /status – reports desktop-agent connectivity. This web build does not ship
//                a desktop-agent subsystem (no companion process to bridge to), so
//                we return a clearly-shaped "disconnected / web mode" status. The
//                SyncStatus.tsx panel treats a 200 with success !== false as
//                reachable and reads `mode` / `connected` for display.

const router = Router();

// ── GET /status ───────────────────────────────────────────────────────────────
router.get("/status", (_req: Request, res: Response) => {
  // TODO: When a desktop-agent companion process / WebSocket bridge is added,
  // probe its real connection here (e.g. ping the agent socket) and report the
  // live session, version, and capabilities. Until then this is a static,
  // honestly-disconnected status so the client renders without 404s.
  return res.json({
    success: true,
    connected: false,
    mode: "web",
    agent: null,
    version: null,
    capabilities: [],
    lastSeen: null,
    message: "Desktop agent not connected — running in web mode.",
    checkedAt: new Date().toISOString(),
  });
});

export default router;

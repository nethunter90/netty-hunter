import { Router, Request, Response } from "express";
import { huntOrchestrator } from "../lib/orchestration/layer1-hunt-orchestrator";
import { agentRegistry } from "../lib/orchestration/agent-registry";
import { eventBus } from "../lib/orchestration/layer3-event-bus";
import { missionMemory } from "../lib/orchestration/mission-memory";

const router = Router();

// List all missions (active + recent hunts from orchestrator)
router.get("/", async (_req: Request, res: Response) => {
  try {
    const hunts = huntOrchestrator.getAllHunts();
    return res.json({ missions: hunts });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Get single mission detail
router.get("/:id", async (req: Request, res: Response) => {
  try {
    const hunt = huntOrchestrator.getHunt(req.params.id);
    if (!hunt) return res.status(404).json({ error: "Mission not found" });
    const memory = missionMemory.get(req.params.id);
    const agents = agentRegistry.getByHunt(req.params.id);
    const events = eventBus.getHistory(req.params.id);
    return res.json({ mission: hunt, memory, agents, events });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Launch new mission
router.post("/", async (req: Request, res: Response) => {
  try {
    const { target, programId, goal, stealthMode, budget } = req.body;
    if (!target || !goal) return res.status(400).json({ error: "target and goal are required" });
    const hunt = await huntOrchestrator.createHunt({
      target,
      goal,
      scope: { inScope: [target], outOfScope: [] },
      stealthMode: stealthMode || "balanced",
    });
    await huntOrchestrator.startHunt(hunt.id);
    return res.json({ huntId: hunt.id, status: "launched" });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Stop a mission (pause it — orchestrator uses pauseHunt for stopping)
router.delete("/:id", async (req: Request, res: Response) => {
  try {
    const hunt = huntOrchestrator.getHunt(req.params.id);
    if (!hunt) return res.status(404).json({ error: "Mission not found" });
    huntOrchestrator.pauseHunt(req.params.id);
    return res.json({ ok: true });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Get mission agents
router.get("/:id/agents", async (req: Request, res: Response) => {
  try {
    const agents = agentRegistry.getByHunt(req.params.id);
    return res.json({ agents });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Get mission events
router.get("/:id/events", async (req: Request, res: Response) => {
  try {
    const events = eventBus.getHistory(req.params.id);
    return res.json({ events });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Get mission memory
router.get("/:id/memory", async (req: Request, res: Response) => {
  try {
    const memory = missionMemory.get(req.params.id);
    return res.json({ memory });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

export default router;

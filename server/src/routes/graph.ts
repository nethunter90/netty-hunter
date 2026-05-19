import { Router, Request, Response } from "express";
import { offensiveGraphDb } from "../lib/intelligence/offensive-graph-db";

const router = Router();

// ─── Nodes ────────────────────────────────────────────────────────────────────

router.get("/nodes/:huntId", async (req: Request, res: Response) => {
  try {
    await offensiveGraphDb.initialize();
    const nodes = offensiveGraphDb.getHuntNodes(req.params.huntId);
    res.json({ huntId: req.params.huntId, nodes });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/nodes", async (req: Request, res: Response) => {
  try {
    const { huntId, node } = req.body;
    await offensiveGraphDb.initialize();
    const result = await offensiveGraphDb.addNode(
      huntId,
      node.nodeType,
      node.label,
      {
        confidence: node.confidence,
        severity: node.severity,
        properties: node.properties,
        id: node.id,
      },
    );
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Edges ────────────────────────────────────────────────────────────────────

router.get("/edges/:huntId", async (req: Request, res: Response) => {
  try {
    await offensiveGraphDb.initialize();
    const edges = offensiveGraphDb.getHuntEdges(req.params.huntId);
    res.json({ huntId: req.params.huntId, edges });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.post("/edges", async (req: Request, res: Response) => {
  try {
    const { huntId, edge } = req.body;
    await offensiveGraphDb.initialize();
    const result = await offensiveGraphDb.addEdge(
      huntId,
      edge.sourceId,
      edge.targetId,
      edge.relationship,
      {
        weight: edge.weight,
        properties: edge.properties,
        id: edge.id,
      },
    );
    res.json(result);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Path ─────────────────────────────────────────────────────────────────────

router.get("/path/:huntId", async (req: Request, res: Response) => {
  try {
    const { from, to } = req.query as { from?: string; to?: string };
    await offensiveGraphDb.initialize();
    if (!from || !to) {
      return res.status(400).json({ error: "from and to query params required" });
    }
    const path = offensiveGraphDb.findShortestPath(from, to);
    res.json({ huntId: req.params.huntId, from, to, path });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Summary ──────────────────────────────────────────────────────────────────

router.get("/summary/:huntId", async (req: Request, res: Response) => {
  try {
    await offensiveGraphDb.initialize();
    const nodes = offensiveGraphDb.getHuntNodes(req.params.huntId);
    const edges = offensiveGraphDb.getHuntEdges(req.params.huntId);
    const nodesByType: Record<string, number> = {};
    for (const n of nodes) {
      nodesByType[n.nodeType] = (nodesByType[n.nodeType] || 0) + 1;
    }
    const edgesByRelationship: Record<string, number> = {};
    for (const e of edges) {
      edgesByRelationship[e.relationship] = (edgesByRelationship[e.relationship] || 0) + 1;
    }
    res.json({
      huntId: req.params.huntId,
      totalNodes: nodes.length,
      totalEdges: edges.length,
      nodesByType,
      edgesByRelationship,
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

export default router;

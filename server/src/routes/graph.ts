import { Router, Request, Response } from "express";
import { offensiveGraphDB as offensiveGraphDb } from "../lib/intelligence/offensive-graph-db";

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

// ─── Analytics ────────────────────────────────────────────────────────────────

router.get("/attack-paths/:huntId", async (req: Request, res: Response) => {
  try {
    await offensiveGraphDb.initialize();
    const targetType = (req.query.targetType as string) || 'vulnerability';
    const paths = offensiveGraphDb.rankAttackPaths(req.params.huntId, targetType as any);
    res.json({ huntId: req.params.huntId, count: paths.length, paths });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/centrality/:huntId", async (req: Request, res: Response) => {
  try {
    await offensiveGraphDb.initialize();
    const scores = offensiveGraphDb.computeCentrality(req.params.huntId);
    res.json({ huntId: req.params.huntId, count: scores.length, scores });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/all-paths/:huntId", async (req: Request, res: Response) => {
  try {
    const { from, to, maxDepth } = req.query as { from?: string; to?: string; maxDepth?: string };
    if (!from || !to) {
      return res.status(400).json({ error: "from and to query params required" });
    }
    await offensiveGraphDb.initialize();
    const paths = offensiveGraphDb.findAllPaths(from, to, maxDepth ? parseInt(maxDepth, 10) : 6);
    res.json({ huntId: req.params.huntId, from, to, count: paths.length, paths });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/patterns", async (req: Request, res: Response) => {
  try {
    const minFreq = req.query.minFrequency ? parseInt(req.query.minFrequency as string, 10) : 2;
    const maxLen  = req.query.maxLength    ? parseInt(req.query.maxLength    as string, 10) : 4;
    await offensiveGraphDb.initialize();
    const patterns = offensiveGraphDb.minePatterns(minFreq, maxLen);
    res.json({ count: patterns.length, patterns });
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

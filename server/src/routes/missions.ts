import { Router, Request, Response } from 'express';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

const router = Router();
const MISSIONS_DIR = path.join(process.cwd(), 'workspace', 'missions');

async function ensureDir() {
  await fs.mkdir(MISSIONS_DIR, { recursive: true });
}

async function listMissions(): Promise<any[]> {
  await ensureDir();
  const files = await fs.readdir(MISSIONS_DIR).catch(() => [] as string[]);
  const missions = await Promise.all(
    files.filter(f => f.endsWith('.json')).map(async f => {
      try {
        const raw = await fs.readFile(path.join(MISSIONS_DIR, f), 'utf8');
        return JSON.parse(raw);
      } catch { return null; }
    })
  );
  return missions.filter(Boolean).sort((a, b) =>
    new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}

async function getMission(id: string): Promise<any | null> {
  try {
    const raw = await fs.readFile(path.join(MISSIONS_DIR, `${id}.json`), 'utf8');
    return JSON.parse(raw);
  } catch { return null; }
}

async function saveMission(mission: any): Promise<void> {
  await ensureDir();
  await fs.writeFile(
    path.join(MISSIONS_DIR, `${mission.id}.json`),
    JSON.stringify(mission, null, 2)
  );
}

async function deleteMission(id: string): Promise<void> {
  await fs.unlink(path.join(MISSIONS_DIR, `${id}.json`)).catch(() => {});
}

function makeMissionId(): string {
  return `msn-${uuidv4().replace(/-/g, '').slice(0, 12)}`;
}

function makeStepId(): string {
  return `msn-${uuidv4().replace(/-/g, '').slice(0, 12)}`;
}

// ── Tool step templates by mission type ────────────────────────────────────────
const STEP_TEMPLATES: Record<string, { name: string; tool: string }[]> = {
  recon: [
    { name: 'Subdomain Enumeration', tool: 'subfinder' },
    { name: 'Port Scanning', tool: 'nmap' },
    { name: 'Technology Detection', tool: 'whatweb' },
    { name: 'Directory Fuzzing', tool: 'ffuf' },
  ],
  'full-scan': [
    { name: 'Custom Scan', tool: 'nmap' },
    { name: 'Vulnerability Scan', tool: 'nuclei' },
    { name: 'Web Application Scan', tool: 'nikto' },
  ],
  vulnerability: [
    { name: 'Vulnerability Scan', tool: 'nuclei' },
    { name: 'SQL Injection Test', tool: 'sqlmap' },
    { name: 'XSS Detection', tool: 'dalfox' },
  ],
  exploitation: [
    { name: 'Exploit Search', tool: 'searchsploit' },
    { name: 'Injection Test', tool: 'commix' },
  ],
};

// GET / — list all missions
router.get('/', async (_req: Request, res: Response) => {
  try {
    const missions = await listMissions();
    return res.json({ missions });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// GET /:id — single mission
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const mission = await getMission(req.params.id);
    if (!mission) return res.status(404).json({ error: 'Mission not found' });
    return res.json({ mission });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST / — create + launch mission
router.post('/', async (req: Request, res: Response) => {
  try {
    const { name, target, type = 'full-scan', goal = 'General', priority = 'medium',
            stealthMode = 'balanced', scope, config = {} } = req.body;
    if (!target) return res.status(400).json({ error: 'target is required' });

    const id = makeMissionId();
    const stepTemplates = STEP_TEMPLATES[type] || STEP_TEMPLATES['full-scan'];
    const steps = stepTemplates.map(t => ({
      id: makeStepId(),
      name: t.name,
      tool: t.tool,
      status: 'pending',
      output: null,
      startedAt: null,
      completedAt: null,
      duration: null,
    }));

    const mission: any = {
      id,
      name: name || `${type} on ${target}`,
      target,
      type,
      status: 'pending',
      priority,
      steps,
      findings: [],
      config,
      progress: 0,
      createdAt: new Date().toISOString(),
      startedAt: null,
      completedAt: null,
      error: null,
      goal,
      threatLevel: priority,
      evidence: [],
      attackPath: steps.map((s, i) => ({
        step: i + 1,
        phase: s.name,
        status: 'pending',
        description: `Queued for execution`,
      })),
      currentTask: null,
      stealthStatus: { mode: stealthMode, detections: 0 },
      scope: scope || { inScope: [target], outOfScope: [] },
    };

    await saveMission(mission);
    return res.status(201).json({ mission });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// PATCH /:id — update mission fields
router.patch('/:id', async (req: Request, res: Response) => {
  try {
    const mission = await getMission(req.params.id);
    if (!mission) return res.status(404).json({ error: 'Mission not found' });
    const updated = { ...mission, ...req.body, id: mission.id };
    await saveMission(updated);
    return res.json({ mission: updated });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// DELETE /:id — remove mission
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    await deleteMission(req.params.id);
    return res.json({ ok: true });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /:id/start — begin execution (marks running, records startedAt)
router.post('/:id/start', async (req: Request, res: Response) => {
  try {
    const mission = await getMission(req.params.id);
    if (!mission) return res.status(404).json({ error: 'Mission not found' });
    if (mission.status === 'running') return res.json({ mission });
    mission.status = 'running';
    mission.startedAt = new Date().toISOString();
    if (mission.steps?.length) mission.steps[0].status = 'running';
    await saveMission(mission);
    return res.json({ mission });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /:id/stop — pause/stop execution
router.post('/:id/stop', async (req: Request, res: Response) => {
  try {
    const mission = await getMission(req.params.id);
    if (!mission) return res.status(404).json({ error: 'Mission not found' });
    mission.status = 'paused';
    await saveMission(mission);
    return res.json({ mission });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// PATCH /:id/steps/:stepId — update a single step result
router.patch('/:id/steps/:stepId', async (req: Request, res: Response) => {
  try {
    const mission = await getMission(req.params.id);
    if (!mission) return res.status(404).json({ error: 'Mission not found' });
    const stepIdx = mission.steps.findIndex((s: any) => s.id === req.params.stepId);
    if (stepIdx === -1) return res.status(404).json({ error: 'Step not found' });
    mission.steps[stepIdx] = { ...mission.steps[stepIdx], ...req.body };

    // Update attackPath status to match
    if (mission.attackPath?.[stepIdx]) {
      mission.attackPath[stepIdx].status = req.body.status || mission.attackPath[stepIdx].status;
    }

    // Recompute progress
    const done = mission.steps.filter((s: any) => s.status === 'completed' || s.status === 'failed').length;
    mission.progress = Math.round((done / mission.steps.length) * 100);

    // Auto-complete mission if all steps done
    if (mission.progress === 100 && mission.status === 'running') {
      mission.status = 'completed';
      mission.completedAt = new Date().toISOString();
    }

    await saveMission(mission);
    return res.json({ mission });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /:id/findings — add a finding to a mission
router.post('/:id/findings', async (req: Request, res: Response) => {
  try {
    const mission = await getMission(req.params.id);
    if (!mission) return res.status(404).json({ error: 'Mission not found' });
    const finding = { id: makeStepId(), ...req.body, discoveredAt: new Date().toISOString() };
    mission.findings = [...(mission.findings || []), finding];
    await saveMission(mission);
    return res.json({ finding, mission });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// POST /:id/evidence — add evidence
router.post('/:id/evidence', async (req: Request, res: Response) => {
  try {
    const mission = await getMission(req.params.id);
    if (!mission) return res.status(404).json({ error: 'Mission not found' });
    const evidence = { id: makeStepId(), ...req.body, timestamp: new Date().toISOString() };
    mission.evidence = [...(mission.evidence || []), evidence];
    await saveMission(mission);
    return res.json({ evidence });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

export default router;

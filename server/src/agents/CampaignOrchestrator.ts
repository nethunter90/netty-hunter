/**
 * Campaign Orchestrator – 6-Layer Orchestration & Governance Model
 *
 * Coordinates all platform components through a structured layered pipeline:
 *
 * Layer 1 │ GOVERNANCE GATE       – Policy enforcement, scope validation, audit trail
 * Layer 2 │ TARGET INTELLIGENCE   – ROI scoring, surface mapping, program prioritization
 * Layer 3 │ STRATEGY PLANNING     – Hunt mode selection, attack tree, template library
 * Layer 4 │ EXECUTION ENGINE      – HunterEngine coordination, SolverPool, WAF bypass
 * Layer 5 │ VERIFICATION GATE     – 4-layer anti-hallucination pipeline, Playwright gate
 * Layer 6 │ INTELLIGENCE HARVEST  – Reinforcement learning, autonomy tracking, output gen
 *
 * Each layer emits real-time events consumed by the frontend and HTTP clients.
 */
import { EventEmitter } from "events";
import { v4 as uuidv4 } from "uuid";
import { db } from "../db";
import {
  programs, campaigns, targets, findings,
} from "../db/schema";
import { eq, desc } from "drizzle-orm";
import logger from "../utils/logger";

import { ScopeGuard } from "../middleware/scopeGuard";
import { HunterEngine } from "./HunterEngine";
import { SolverPool } from "./SolverPool";
import { VerifierAgent } from "./VerifierAgent";
import { TargetSelectionIntelligence } from "../intelligence/TargetSelection";
import { ROIModel } from "../intelligence/ROIModel";
import { BackwardHuntEngine } from "../intelligence/BackwardHunt";
import { UnifiedReinforcementStore } from "../intelligence/ReinforcementStore";
import { AutonomyMaturityTracker } from "../intelligence/AutonomyTracker";
import { DraftReportGenerator } from "../intelligence/ReportGenerator";
import { NucleiTemplateGenerator } from "../intelligence/NucleiGenerator";
import { HuntStrategyBuilder } from "../routes/huntStrategy";
import { exploitChainIntelligence } from "../lib/hunter/chain-intelligence";
import { bountyIntelligenceService } from "../lib/bounty-intelligence";

// ─── Types ────────────────────────────────────────────────────────────────────

export type OrchestratorPhase =
  | "idle"
  | "l1_governance"
  | "l2_intelligence"
  | "l3_strategy"
  | "l4_execution"
  | "l5_verification"
  | "l6_harvest"
  | "complete"
  | "aborted";

export interface OrchestrateParams {
  programId: number;
  targetUrl: string;
  mode?: "forward" | "backward";
  goal?: string;
  maxIterations?: number;
  budget?: { maxRequests: number; maxTime: number };
  /** Override: force specific vuln classes */
  focusVulnClasses?: string[];
}

export interface LayerStatus {
  layer: number;
  name: string;
  phase: "pending" | "running" | "passed" | "failed" | "skipped";
  startedAt?: number;
  completedAt?: number;
  durationMs?: number;
  result?: Record<string, unknown>;
  error?: string;
}

export interface OrchestratorState {
  orchestrationId: string;
  campaignId?: number;
  programId: number;
  targetUrl: string;
  mode: string;
  phase: OrchestratorPhase;
  layers: LayerStatus[];
  sessionUuid?: string;
  findingsCount: number;
  verifiedCount: number;
  startedAt: number;
  audit: AuditEntry[];
}

export interface AuditEntry {
  ts: number;
  layer: number;
  event: string;
  detail: Record<string, unknown>;
}

export interface OrchestrationResult {
  orchestrationId: string;
  campaignId: number;
  sessionUuid?: string;
  findingsTotal: number;
  verified: number;
  reports: string[];
  nucleiTemplates: string[];
  autonomyScore: number;
  layerSummary: LayerStatus[];
  durationMs: number;
}

// ─── Layer metadata ───────────────────────────────────────────────────────────
const LAYER_META = [
  { layer: 1, name: "GOVERNANCE GATE" },
  { layer: 2, name: "TARGET INTELLIGENCE" },
  { layer: 3, name: "STRATEGY PLANNING" },
  { layer: 4, name: "EXECUTION ENGINE" },
  { layer: 5, name: "VERIFICATION GATE" },
  { layer: 6, name: "INTELLIGENCE HARVEST" },
] as const;

// ─── Orchestrator ─────────────────────────────────────────────────────────────

export class CampaignOrchestrator extends EventEmitter {
  private state: OrchestratorState;
  private scopeGuard = ScopeGuard.getInstance();
  private verifierAgent = new VerifierAgent();
  private rlStore = UnifiedReinforcementStore.getInstance();
  private autonomyTracker = AutonomyMaturityTracker.getInstance();
  private roiModel = new ROIModel();
  private targetSelector = new TargetSelectionIntelligence();
  private backwardHunt = new BackwardHuntEngine();

  constructor() {
    super();
    this.state = this.initState();
    this.verifierAgent.initialize().catch(err => logger.warn("Verifier init deferred", { err }));
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /** Main entry point – runs all 6 layers in sequence */
  async orchestrate(params: OrchestrateParams): Promise<OrchestrationResult> {
    this.state = this.initState(params);
    const t0 = Date.now();

    this.emit("orchestration:started", this.publicState());
    logger.info("Orchestration started", {
      orchestrationId: this.state.orchestrationId,
      targetUrl: params.targetUrl,
      mode: params.mode || "forward",
    });

    try {
      // ── Layer 1: Governance Gate ─────────────────────────────────────────
      const govResult = await this.runLayer(1, () => this.layer1_governance(params));
      if (!govResult.passed) return this.abort("Governance gate rejected request", t0);

      // ── Layer 2: Target Intelligence ─────────────────────────────────────
      const intelResult = await this.runLayer(2, () => this.layer2_targetIntelligence(params));

      // ── Layer 3: Strategy Planning ───────────────────────────────────────
      const stratResult = await this.runLayer(3, () => this.layer3_strategyPlanning(params, intelResult.data));

      // ── Layer 4: Execution Engine ────────────────────────────────────────
      const execResult = await this.runLayer(4, () =>
        this.layer4_executionEngine(params, stratResult.data)
      );

      // ── Layer 5: Verification Gate ───────────────────────────────────────
      const verifResult = await this.runLayer(5, () =>
        this.layer5_verificationGate(execResult.data)
      );

      // ── Layer 6: Intelligence Harvest ────────────────────────────────────
      const harvestResult = await this.runLayer(6, () =>
        this.layer6_intelligenceHarvest(params, verifResult.data)
      );

      this.state.phase = "complete";
      const result: OrchestrationResult = {
        orchestrationId: this.state.orchestrationId,
        campaignId: this.state.campaignId!,
        sessionUuid: this.state.sessionUuid,
        findingsTotal: this.state.findingsCount,
        verified: this.state.verifiedCount,
        reports: (harvestResult.data.reports as string[]) || [],
        nucleiTemplates: (harvestResult.data.nucleiTemplates as string[]) || [],
        autonomyScore: (harvestResult.data.autonomyScore as number) || 0,
        layerSummary: this.state.layers,
        durationMs: Date.now() - t0,
      };

      this.emit("orchestration:complete", { ...this.publicState(), result });
      logger.info("Orchestration complete", {
        orchestrationId: this.state.orchestrationId,
        findings: result.findingsTotal,
        verified: result.verified,
        durationMs: result.durationMs,
      });
      return result;

    } catch (err) {
      return this.abort(String(err), t0);
    }
  }

  getState(): OrchestratorState {
    return this.publicState();
  }

  // ── Layer 1: Governance Gate ───────────────────────────────────────────────
  private async layer1_governance(
    params: OrchestrateParams
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    this.audit(1, "scope_check_start", { url: params.targetUrl, programId: params.programId });

    // 1a. Verify program exists
    const [program] = await db.select().from(programs)
      .where(eq(programs.id, params.programId)).limit(1);
    if (!program) {
      this.audit(1, "governance_rejected", { reason: "Program not found" });
      return { passed: false, data: { reason: "Program not found" } };
    }
    if (!program.active) {
      this.audit(1, "governance_rejected", { reason: "Program inactive" });
      return { passed: false, data: { reason: "Program inactive" } };
    }

    // 1b. Scope validation (fail-closed)
    const scopeCheck = await this.scopeGuard.isInScope(params.targetUrl, params.programId);
    if (!scopeCheck.allowed) {
      this.audit(1, "governance_rejected", { reason: scopeCheck.reason });
      return { passed: false, data: { reason: scopeCheck.reason } };
    }

    // 1c. Budget guard
    const budget = params.budget || { maxRequests: 2000, maxTime: 3600 };
    if (budget.maxRequests < 10 || budget.maxRequests > 50000) {
      return { passed: false, data: { reason: "Budget maxRequests out of bounds (10–50000)" } };
    }

    // 1d. Create audited campaign record
    const [campaign] = await db.insert(campaigns).values({
      programId: params.programId,
      name: `[ORC] ${params.targetUrl} – ${new Date().toISOString()}`,
      goal: params.goal || `Autonomous vulnerability hunt on ${params.targetUrl}`,
      status: "running",
      huntMode: params.mode || "forward",
      strategy: {},
      budget,
      startedAt: new Date(),
    }).returning();

    this.state.campaignId = campaign.id;

    // 1e. Register target
    const [target] = await db.insert(targets).values({
      programId: params.programId,
      url: params.targetUrl,
      type: "web",
      status: "scanning",
    }).returning();

    this.audit(1, "governance_passed", {
      programName: program.name,
      platform: program.platform,
      campaignId: campaign.id,
      targetId: target.id,
      scopeCheck: "in-scope",
    });

    return {
      passed: true,
      data: {
        program,
        campaign,
        target,
        budget,
        scopeVerified: true,
      },
    };
  }

  // ── Layer 2: Target Intelligence ───────────────────────────────────────────
  private async layer2_targetIntelligence(
    params: OrchestrateParams
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    this.audit(2, "target_intel_start", { programId: params.programId });

    // 2a. Score all programs for context
    let programScores: unknown[] = [];
    try {
      programScores = await this.targetSelector.scorePrograms();
    } catch (err) {
      logger.warn("Target scoring failed (non-critical)", { err });
    }

    // 2b. Rank vulnerability classes by ROI for this program
    const [prog] = await db.select().from(programs)
      .where(eq(programs.id, params.programId)).limit(1);
    const maxPayout = prog?.maxPayout || 5000;

    let rankedVulns: unknown[] = [];
    try {
      rankedVulns = await this.roiModel.rankVulnClasses(maxPayout, params.programId);
    } catch (err) {
      logger.warn("ROI ranking failed (non-critical)", { err });
      rankedVulns = [];
    }

    // 2c. Respect focus override
    const priorityVulns = params.focusVulnClasses && params.focusVulnClasses.length > 0
      ? params.focusVulnClasses
      : (rankedVulns as Array<{ vulnClass: string }>).slice(0, 8).map(v => v.vulnClass);

    this.audit(2, "target_intel_complete", {
      priorityVulns,
      programCount: (programScores as unknown[]).length,
    });

    return {
      passed: true,
      data: {
        programScores,
        rankedVulns,
        priorityVulns,
        maxPayout,
      },
    };
  }

  // ── Layer 3: Strategy Planning ─────────────────────────────────────────────
  private async layer3_strategyPlanning(
    params: OrchestrateParams,
    intelData: Record<string, unknown>
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    this.audit(3, "strategy_planning_start", {
      mode: params.mode,
      goal: params.goal,
    });

    let strategy: Record<string, unknown> = {};
    let attackPlan: Record<string, unknown> | null = null;

    if (params.mode === "backward" && params.goal) {
      // 3a. Backward: build goal-first attack plan
      try {
        const plan = await this.backwardHunt.createPlan({
          campaignId: this.state.campaignId!,
          objective: params.goal,
          targetUrl: params.targetUrl,
        });
        attackPlan = plan as unknown as Record<string, unknown>;
        strategy = { mode: "backward", attackPlan };
        this.audit(3, "backward_plan_created", { planId: (plan as { planId: string }).planId });
      } catch (err) {
        logger.warn("Backward plan failed, falling back to forward", { err });
        params.mode = "forward";
      }
    }

    if (params.mode !== "backward") {
      // 3b. Forward: auto-build strategy from goal + target
      try {
        strategy = await HuntStrategyBuilder.build({
          programId: params.programId,
          targetUrl: params.targetUrl,
          goal: params.goal,
        }) as unknown as Record<string, unknown>;
      } catch (err) {
        logger.warn("Strategy builder failed, using default", { err });
        strategy = {
          mode: "forward",
          priorityVulns: intelData.priorityVulns,
          maxIterations: params.maxIterations || 10,
        };
      }
    }

    // 3c. Persist strategy to campaign
    if (this.state.campaignId) {
      await db.update(campaigns)
        .set({ strategy })
        .where(eq(campaigns.id, this.state.campaignId));
    }

    this.audit(3, "strategy_planning_complete", { strategyKeys: Object.keys(strategy) });

    return {
      passed: true,
      data: { strategy, attackPlan, effectiveMode: params.mode || "forward" },
    };
  }

  // ── Layer 4: Execution Engine ──────────────────────────────────────────────
  private async layer4_executionEngine(
    params: OrchestrateParams,
    stratData: Record<string, unknown>
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    this.audit(4, "execution_start", {
      targetUrl: params.targetUrl,
      campaignId: this.state.campaignId,
    });

    const engine = new HunterEngine();
    const rawFindings: unknown[] = [];

    // Wire HunterEngine events → Orchestrator events (with layer prefix)
    engine.on("hunt:started", d => this.emit("l4:hunt_started", d));
    engine.on("hunt:phase", d => this.emit("l4:phase", d));
    engine.on("hunt:observations", d => this.emit("l4:observations", d));
    engine.on("hunt:hypotheses", d => this.emit("l4:hypotheses", d));
    engine.on("hunt:probing", d => this.emit("l4:probing", d));
    engine.on("hunt:probe_result", d => this.emit("l4:probe_result", d));
    engine.on("hunt:finding_confirmed", (d) => {
      rawFindings.push(d);
      this.state.findingsCount++;
      this.emit("l4:finding_raw", d);
    });
    engine.on("hunt:update", d => this.emit("l4:strategy_update", d));
    engine.on("hunt:error", d => this.emit("l4:error", d));

    let sessionUuid: string | undefined;
    try {
      sessionUuid = await engine.startHunt({
        targetUrl: params.targetUrl,
        programId: params.programId,
        campaignId: this.state.campaignId!,
        maxIterations: params.maxIterations || 10,
        budget: params.budget,
      });
      this.state.sessionUuid = sessionUuid;

      // Wait for hunt to complete
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("Hunt timeout")),
          ((params.budget?.maxTime || 3600) + 60) * 1000);
        engine.once("hunt:complete", () => { clearTimeout(timeout); resolve(); });
        engine.once("hunt:error", (d) => { clearTimeout(timeout); reject(new Error(String(d.error))); });
      });
    } catch (err) {
      // Non-fatal: partial findings are still processed
      logger.warn("Hunt execution ended with error (continuing to verification)", { err });
    }

    // 4b. Supplement with SolverPool for high-ROI vuln classes if findings are sparse
    if (rawFindings.length < 2) {
      this.audit(4, "solver_supplement_start", { reason: "sparse findings" });
      try {
        const pool = new SolverPool(4);
        pool.on("solver:finding", (d) => {
          rawFindings.push(d);
          this.state.findingsCount++;
          this.emit("l4:solver_finding", d);
        });
        await pool.spawnSolvers(
          params.targetUrl,
          { priorityVulns: [] },
          { programId: params.programId, sessionId: 0 }
        );
      } catch (err) {
        logger.warn("Solver supplement failed (non-critical)", { err });
      }
    }

    this.audit(4, "execution_complete", {
      sessionUuid,
      rawFindingsCount: rawFindings.length,
    });

    return {
      passed: true,
      data: { sessionUuid, rawFindings },
    };
  }

  // ── Layer 5: Verification Gate ─────────────────────────────────────────────
  private async layer5_verificationGate(
    execData: Record<string, unknown>
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    const rawFindings = (execData.rawFindings as unknown[]) || [];
    this.audit(5, "verification_gate_start", { rawCount: rawFindings.length });

    const verified: unknown[] = [];
    const rejected: unknown[] = [];

    // Fetch confirmed findings from DB for this campaign
    let dbFindings: (typeof findings.$inferSelect)[] = [];
    if (this.state.campaignId) {
      dbFindings = await db.select().from(findings)
        .where(eq(findings.campaignId, this.state.campaignId))
        .orderBy(desc(findings.createdAt));
    }

    // Run 4-layer anti-hallucination pipeline on each finding
    for (const dbFinding of dbFindings) {
      this.emit("l5:verifying", { findingId: dbFinding.id });
      try {
        const mockResult = {
          taskId: String(dbFinding.id),
          solverId: "orchestrator",
          endpoint: String(dbFinding.targetId || ""),
          vulnClass: dbFinding.vulnType as Parameters<typeof this.verifierAgent.verify>[0]["vulnClass"],
          found: true,
          confidence: dbFinding.confidence,
          evidence: ((dbFinding.evidence as unknown[]) || [])[0] as Record<string, unknown> || {},
          payload: dbFinding.exploitPayload || "",
          request: "",
          response: "",
          duration: 0,
          toolsUsed: [],
        };

        const verification = await this.verifierAgent.verify(mockResult);

        if (verification.finalVerdict === "confirmed") {
          verified.push({ finding: dbFinding, verification });
          this.state.verifiedCount++;

          // Update finding record
          await db.update(findings).set({
            verificationStatus: verification.finalVerdict,
            verificationLog: [verification] as unknown as Record<string, unknown>[],
            confidence: verification.finalConfidence,
            dedupHash: verification.dedupHash,
            updatedAt: new Date(),
          }).where(eq(findings.id, dbFinding.id));

          this.emit("l5:verified", { findingId: dbFinding.id, verdict: verification.finalVerdict });
        } else {
          rejected.push({ finding: dbFinding, verification });
          this.emit("l5:rejected", { findingId: dbFinding.id, verdict: verification.finalVerdict });
        }
      } catch (err) {
        logger.warn("Verification failed for finding", { findingId: dbFinding.id, err });
        rejected.push({ finding: dbFinding, error: String(err) });
      }
    }

    this.audit(5, "verification_gate_complete", {
      verified: verified.length,
      rejected: rejected.length,
    });

    return {
      passed: true,
      data: { verified, rejected, totalProcessed: dbFindings.length },
    };
  }

  // ── Layer 6: Intelligence Harvest ──────────────────────────────────────────
  private async layer6_intelligenceHarvest(
    params: OrchestrateParams,
    verifData: Record<string, unknown>
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    const verifiedFindings = (verifData.verified as Array<{
      finding: typeof findings.$inferSelect;
      verification: Record<string, unknown>;
    }>) || [];

    this.audit(6, "harvest_start", { verifiedCount: verifiedFindings.length });

    const reports: string[] = [];
    const nucleiTemplates: string[] = [];
    const reportGen = new DraftReportGenerator();
    const nucleiGen = new NucleiTemplateGenerator();

    // 6a. Generate reports + Nuclei templates for each verified finding
    for (const { finding, verification } of verifiedFindings) {
      try {
        const mockSolverResult = {
          taskId: String(finding.id),
          solverId: "orchestrator",
          endpoint: String(finding.targetId || params.targetUrl),
          vulnClass: finding.vulnType as Parameters<typeof reportGen.generate>[0]["vulnClass"],
          found: true,
          confidence: finding.confidence,
          evidence: {},
          payload: finding.exploitPayload || "",
          request: "",
          response: "",
          duration: 0,
          toolsUsed: [],
        };

        const mockVerification = {
          findingId: String(finding.id),
          layer1_dedup: { isDuplicate: false },
          layer2_reprobe: { confirmed: true, statusCode: 200, responseSnippet: "" },
          layer3_playwright: { confirmed: true, consoleAlerts: [], networkRequests: [] },
          layer4_ai: { confirmed: true, reasoning: "", confidenceAdjustment: 0 },
          finalVerdict: (verification.finalVerdict as "confirmed") || "confirmed",
          finalConfidence: finding.confidence,
          dedupHash: finding.dedupHash || "",
        };

        // Report
        const report = await reportGen.generate(mockSolverResult, mockVerification, {
          severity: finding.severity,
          programName: "Bug Bounty Program",
          targetUrl: params.targetUrl,
          huntDate: finding.createdAt.toISOString().split("T")[0],
        });
        reports.push(report.reportMarkdown);

        await db.update(findings)
          .set({ reportDraft: report.reportMarkdown })
          .where(eq(findings.id, finding.id));

        // Nuclei template
        const tmpl = nucleiGen.generateTemplate(mockSolverResult, mockVerification, {
          severity: finding.severity,
          programName: "Bug Bounty Program",
        });
        nucleiTemplates.push(tmpl);

        await db.update(findings)
          .set({ nucleiTemplate: tmpl })
          .where(eq(findings.id, finding.id));

        this.emit("l6:report_generated", { findingId: finding.id });
      } catch (err) {
        logger.warn("Report/template generation failed for finding", { findingId: finding.id, err });
      }
    }

    // 6b. Update reinforcement store + bounty intelligence memory
    for (const { finding } of verifiedFindings) {
      try {
        await this.rlStore.recordToolOutcome("orchestrator", finding.vulnType, true);
      } catch { /* non-critical */ }
      // Feed verified finding into bounty intelligence so duplicate detection and
      // payout estimation improve over time
      try {
        await bountyIntelligenceService.addKnownFinding({
          id: String(finding.id),
          title: `${finding.vulnType} on ${String(finding.targetId || params.targetUrl)}`,
          endpoint: String(finding.targetId || params.targetUrl),
          vulnerabilityType: finding.vulnType,
          severity: finding.severity ?? 'medium',
          program: String(params.programId),
          reportDate: finding.createdAt.toISOString(),
          status: 'accepted',
        });
      } catch { /* non-critical */ }
    }

    // 6c. Update autonomy maturity tracker
    let autonomyScore = 0;
    try {
      const huntMetrics = {
        hypothesesGenerated: Math.max(5, this.state.findingsCount),
        hypothesesCorrect: this.state.verifiedCount,
        toolsSelected: 3,
        toolsCorrect: this.state.verifiedCount > 0 ? 2 : 1,
        outOfScopeAttempts: 0,
        falsePositives: Math.max(0, (verifData.totalProcessed as number || 0) - this.state.verifiedCount),
        confirmedFindings: this.state.verifiedCount,
        chainDepth: this.state.verifiedCount > 0 ? 1 : 0,
        reportQualityScore: reports.length > 0 ? 0.8 : 0,
      };

      const maturityReport = await this.autonomyTracker.recordHuntOutcome(huntMetrics);
      autonomyScore = maturityReport.compositeScore;
      // recordHuntOutcome already persists to autonomy_metrics — no duplicate insert
      this.emit("l6:autonomy_updated", { compositeScore: autonomyScore });
    } catch (err) {
      logger.warn("Autonomy tracker update failed (non-critical)", { err });
    }

    // 6c.5 Post-Hunt Extraction Pipeline
    // Phase 1: calibrate confidence per verified finding
    // Phase 2: extract operational chains from multi-finding sessions
    // Phase 3: emit cross-hunt pattern stats
    try {
      for (const { finding } of verifiedFindings) {
        await this.rlStore.recordConfidenceCalibration(
          finding.vulnType,
          finding.confidence ?? 0.5,
          true
        );
      }

      if (verifiedFindings.length >= 2) {
        const sequence = verifiedFindings.map(({ finding }) => finding.vulnType).filter(Boolean);
        const estimatedBounty = verifiedFindings.reduce((sum, { finding }) => {
          const payoutMap: Record<string, number> = { critical: 5000, high: 2000, medium: 500, low: 100 };
          return sum + (payoutMap[finding.severity ?? "low"] ?? 100);
        }, 0);
        exploitChainIntelligence.recordChain({
          sessionId: String(this.state.campaignId ?? params.targetUrl),
          sequence,
          techStack: [],
          bounty: estimatedBounty,
          succeeded: true,
        });
      }

      const chainStats = exploitChainIntelligence.getStats();
      const topROI = exploitChainIntelligence.getChainROI().slice(0, 3);
      this.emit("l6:chains_extracted", { chainStats, topROI });
    } catch (err) {
      logger.warn("Post-hunt extraction pipeline failed (non-critical)", { err });
    }

    // 6d. Mark campaign complete
    if (this.state.campaignId) {
      await db.update(campaigns).set({
        status: "complete",
        completedAt: new Date(),
      }).where(eq(campaigns.id, this.state.campaignId));
    }

    this.audit(6, "harvest_complete", {
      reports: reports.length,
      nucleiTemplates: nucleiTemplates.length,
      autonomyScore,
    });

    return {
      passed: true,
      data: { reports, nucleiTemplates, autonomyScore },
    };
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private async runLayer(
    layerNum: number,
    fn: () => Promise<{ passed: boolean; data: Record<string, unknown> }>
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    const layerIdx = layerNum - 1;
    const t0 = Date.now();

    const LAYER_PHASES: OrchestratorPhase[] = [
      "l1_governance", "l2_intelligence", "l3_strategy",
      "l4_execution", "l5_verification", "l6_harvest",
    ];

    this.state.layers[layerIdx].phase = "running";
    this.state.layers[layerIdx].startedAt = t0;
    this.state.phase = LAYER_PHASES[layerIdx];
    this.emit("orchestration:layer_start", { layer: layerNum, name: LAYER_META[layerIdx].name, state: this.publicState() });

    try {
      const result = await fn();
      const dur = Date.now() - t0;

      this.state.layers[layerIdx].phase = result.passed ? "passed" : "failed";
      this.state.layers[layerIdx].completedAt = Date.now();
      this.state.layers[layerIdx].durationMs = dur;
      this.state.layers[layerIdx].result = { summary: Object.keys(result.data) };

      this.emit("orchestration:layer_complete", {
        layer: layerNum,
        name: LAYER_META[layerIdx].name,
        passed: result.passed,
        durationMs: dur,
        state: this.publicState(),
      });

      return result;
    } catch (err) {
      const dur = Date.now() - t0;
      this.state.layers[layerIdx].phase = "failed";
      this.state.layers[layerIdx].completedAt = Date.now();
      this.state.layers[layerIdx].durationMs = dur;
      this.state.layers[layerIdx].error = String(err);

      this.emit("orchestration:layer_error", {
        layer: layerNum,
        name: LAYER_META[layerIdx].name,
        error: String(err),
        state: this.publicState(),
      });

      logger.error(`Layer ${layerNum} error`, { err });
      throw err;
    }
  }

  private abort(reason: string, t0: number): OrchestrationResult {
    this.state.phase = "aborted";
    this.emit("orchestration:aborted", { reason, state: this.publicState() });
    logger.warn("Orchestration aborted", { reason, orchestrationId: this.state.orchestrationId });

    return {
      orchestrationId: this.state.orchestrationId,
      campaignId: this.state.campaignId || 0,
      sessionUuid: this.state.sessionUuid,
      findingsTotal: 0,
      verified: 0,
      reports: [],
      nucleiTemplates: [],
      autonomyScore: 0,
      layerSummary: this.state.layers,
      durationMs: Date.now() - t0,
    };
  }

  private audit(layer: number, event: string, detail: Record<string, unknown>): void {
    const entry: AuditEntry = { ts: Date.now(), layer, event, detail };
    this.state.audit.push(entry);
    this.emit("orchestration:audit", entry);
  }

  private publicState(): OrchestratorState {
    return { ...this.state };
  }

  private initState(params?: OrchestrateParams): OrchestratorState {
    return {
      orchestrationId: uuidv4(),
      campaignId: undefined,
      programId: params?.programId || 0,
      targetUrl: params?.targetUrl || "",
      mode: params?.mode || "forward",
      phase: "idle",
      layers: LAYER_META.map(m => ({
        layer: m.layer,
        name: m.name,
        phase: "pending" as const,
      })),
      sessionUuid: undefined,
      findingsCount: 0,
      verifiedCount: 0,
      startedAt: Date.now(),
      audit: [],
    };
  }
}

export default CampaignOrchestrator;

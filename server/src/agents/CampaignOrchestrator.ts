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
import { execFile } from "child_process";
import { promisify } from "util";
import { v4 as uuidv4 } from "uuid";

const execFileAsync = promisify(execFile);
import { mkdirSync, promises as fsp } from "fs";
import path from "path";
import { db } from "../db";
import {
  programs, campaigns, targets, findings,
} from "../db/schema";
import { eq, desc, sql } from "drizzle-orm";
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
import { eventBus } from "../lib/orchestration/layer3-event-bus";
import { dynamicRateLimiter } from "../lib/stealth";
import { publicDisclosureDetector } from "../lib/intelligence/public-disclosure-detector";
import { pendingEscalation } from "../lib/verification/verify-finding";
import { nvdClient } from "../lib/intelligence/nvd-client";
import { reportSubmitter } from "../lib/intelligence/report-submitter";
import { subdomainTakeoverChecker } from "../lib/tools/subdomain-takeover";
import { notificationService } from "../lib/services/notification-service";

const VULN_TYPE_TO_CWE: Record<string, number> = {
  xss: 79, sqli: 89, ssrf: 918, lfi: 22, rce: 78, idor: 639,
  auth_bypass: 287, csrf: 352, xxe: 611, cors: 942,
  open_redirect: 601, info_disclosure: 200, misconfig: 16,
};

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

export interface HuntAuth {
  /** Raw Cookie header value — e.g. "session=abc123; csrf=xyz" */
  cookie?: string;
  /** Bearer token — injected as Authorization: Bearer <token> */
  bearerToken?: string;
  /** Arbitrary extra headers passed verbatim to every tool and HTTP probe */
  headers?: Record<string, string>;
}

export interface OrchestrateParams {
  programId: number;
  targetUrl: string;
  mode?: "forward" | "backward";
  goal?: string;
  maxIterations?: number;
  budget?: { maxRequests: number; maxTime: number };
  /** Override: force specific vuln classes */
  focusVulnClasses?: string[];
  /** Resume an interrupted campaign instead of creating a new one */
  resumeCampaignId?: number;
  /** Auth credentials/tokens injected into every tool invocation and HTTP probe */
  auth?: HuntAuth;
  /** Stealth routing (proxychains4/Tor) for tools that support it — off by default. */
  proxyEnabled?: boolean;
  /** WAF bypass/evasion synthesis — opt-in per hunt; a program whose policy is
   *  "disallowed" hard-blocks it regardless (see WAFBypass.ts). Off by default. */
  wafBypassEnabled?: boolean;
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
  private _abortRequested = false;
  // Holds the live L4 HunterEngine so a stop reaches the thing actually spending
  // money. Without this, _abortRequested only takes effect at the NEXT layer
  // boundary — the engine would keep issuing model calls until L4 ends naturally.
  private currentEngine: HunterEngine | null = null;

  constructor() {
    super();
    this.state = this.initState();
    this.verifierAgent.initialize().catch(err => logger.warn("Verifier init deferred", { err }));
    // Existing event-based trigger (POST /api/orchestration/stop emits this) now
    // routes through the same stop() path as the registry's direct call.
    this.once("orchestration:stop", () => this.stop());
  }

  /**
   * Real, propagating stop (implements Stoppable). Sets the abort flag checked at
   * the start of every runLayer AND immediately propagates into the live L4
   * HunterEngine so model calls cease within seconds rather than at the next
   * layer boundary. The runLayer guard then converts the flag into a clean
   * orchestration:aborted via orchestrate()'s catch. Idempotent.
   */
  stop(): void {
    if (this._abortRequested) return;
    this._abortRequested = true;
    logger.info("[CampaignOrchestrator] Stop requested — aborting orchestration", {
      orchestrationId: this.state?.orchestrationId,
    });
    this.currentEngine?.stop();
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

      // ── Subdomain expansion (between L1 and L2) ──────────────────────────
      const program = govResult.data.program as { scope?: unknown[] } | undefined;
      const expandedTargets = await this.expandTargets(params.targetUrl, program?.scope || []);
      this.audit(1, "targets_expanded", { count: expandedTargets.length });

      // ── Subdomain takeover check (non-blocking, runs on expanded targets) ─
      if (expandedTargets.length > 0) {
        subdomainTakeoverChecker.checkSubdomains(expandedTargets.slice(0, 30)).then(vulnSubs => {
          if (vulnSubs.length > 0) {
            this.emit("orchestration:takeover_found", { targets: vulnSubs });
            for (const v of vulnSubs) {
              notificationService.notifyIfWorthy({
                type: "finding_confirmed",
                severity: "high",
                vulnType: "subdomain_takeover",
                targetUrl: v.subdomain,
                detail: v.evidence,
              }).catch(() => {});
            }
          }
        }).catch(() => {});
      }

      // ── Layer 2: Target Intelligence ─────────────────────────────────────
      const intelResult = await this.runLayer(2, () => this.layer2_targetIntelligence(params));

      // ── Layer 3: Strategy Planning ───────────────────────────────────────
      const stratResult = await this.runLayer(3, () => this.layer3_strategyPlanning(params, intelResult.data));

      // ── Layer 4: Execution Engine ────────────────────────────────────────
      const execResult = await this.runLayer(4, () =>
        this.layer4_executionEngine(params, stratResult.data, expandedTargets, (govResult.data.target as any)?.id)
      );

      // ── Layer 5: Verification Gate ───────────────────────────────────────
      const verifResult = await this.runLayer(5, () =>
        this.layer5_verificationGate(params, execResult.data)
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

    // 1a. Verify program exists — for custom/local-lab hunts (programId -1) find-or-create
    //     a synthetic program so FK constraints and scope checks still work.
    if (params.programId === -1) {
      const [existing] = await db.select().from(programs)
        .where(eq(programs.platform, "local")).limit(1);
      if (existing) {
        params.programId = existing.id;
      } else {
        const [created] = await db.insert(programs).values({
          name: "Custom / Local Lab",
          platform: "local",
          scope: ["*"],
          outOfScope: [],
        }).returning();
        params.programId = created.id;
      }
    }

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

    // 1d. Create or resume campaign record
    let campaign: typeof campaigns.$inferSelect;
    if (params.resumeCampaignId) {
      const [existing] = await db.select().from(campaigns)
        .where(eq(campaigns.id, params.resumeCampaignId)).limit(1);
      if (!existing) {
        this.audit(1, "governance_rejected", { reason: `Campaign ${params.resumeCampaignId} not found` });
        return { passed: false, data: { reason: "Resume campaign not found" } };
      }
      // Reopen the campaign for continued execution
      const [updated] = await db.update(campaigns)
        .set({ status: "running", startedAt: existing.startedAt ?? new Date() })
        .where(eq(campaigns.id, params.resumeCampaignId))
        .returning();
      campaign = updated;
      this.audit(1, "campaign_resumed", { campaignId: campaign.id });
    } else {
      const [created] = await db.insert(campaigns).values({
        programId: params.programId,
        name: `[ORC] ${params.targetUrl} – ${new Date().toISOString()}`,
        goal: params.goal || `Autonomous vulnerability hunt on ${params.targetUrl}`,
        status: "running",
        huntMode: params.mode || "forward",
        strategy: {},
        budget,
        startedAt: new Date(),
      }).returning();
      campaign = created;
    }

    this.state.campaignId = campaign.id;

    // Reconcile findingsCount from DB — catches both fresh starts (0) and
    // resumed campaigns where prior findings already exist in the table.
    const [countRow] = await db.select({ n: sql<number>`count(*)` })
      .from(findings).where(eq(findings.campaignId, campaign.id));
    this.state.findingsCount = Number(countRow?.n ?? 0);

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

  // ── Subdomain expansion ────────────────────────────────────────────────────
  private async expandTargets(targetUrl: string, scope: unknown[]): Promise<string[]> {
    const discovered: string[] = [targetUrl];
    try {
      const apex = new URL(targetUrl).hostname.replace(/^www\./, "");
      const { stdout } = await execFileAsync("subfinder", ["-d", apex, "-silent"], { timeout: 30_000 });
      const subdomains = stdout.trim().split("\n").filter(Boolean);
      for (const sub of subdomains) {
        const url = `https://${sub}`;
        if (this.isInScope(url, scope)) discovered.push(url);
      }
      logger.info("[Orchestrator] Subdomain expansion complete", { apex, found: subdomains.length, inScope: discovered.length - 1 });
    } catch (err) {
      logger.debug("[Orchestrator] Subdomain expansion failed (non-critical)", { err: String(err) });
    }
    const unique = [...new Set(discovered)];
    this.emit("orchestration:targets_expanded", { count: unique.length, targets: unique });
    return unique;
  }

  private isInScope(url: string, scope: unknown[]): boolean {
    try {
      const hostname = new URL(url).hostname;
      for (const entry of scope) {
        const s = String(entry);
        if (s.startsWith("*.")) {
          const base = s.slice(2);
          if (hostname === base || hostname.endsWith(`.${base}`)) return true;
        } else if (hostname === s || hostname.endsWith(`.${s}`)) {
          return true;
        }
      }
    } catch { /* non-critical */ }
    return scope.length === 0; // if no scope defined, allow everything
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

        // Count total approaches across all nodes to detect an empty tree.
        const countApproaches = (node: { approaches?: unknown[]; children?: unknown[] }): number => {
          const own = (node.approaches ?? []).length;
          const childSum = (node.children ?? []).reduce(
            (acc: number, c) => acc + countApproaches(c as { approaches?: unknown[]; children?: unknown[] }),
            0 as number
          );
          return own + childSum;
        };
        const totalApproaches = countApproaches(plan.rootNode as { approaches?: unknown[]; children?: unknown[] });

        if (totalApproaches === 0) {
          logger.warn("Backward plan has 0 viable approaches — degrading to forward", {
            goal: params.goal,
            planId: plan.planId,
            strategy: "backward → forward",
            reason: "no_viable_paths",
          });
          this.audit(3, "backward_degraded_to_forward", { planId: plan.planId, reason: "no_viable_paths" });
          params.mode = "forward";
        } else {
          attackPlan = plan as unknown as Record<string, unknown>;
          strategy = { mode: "backward", attackPlan };
          this.audit(3, "backward_plan_created", { planId: (plan as { planId: string }).planId, totalApproaches });
        }
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
    stratData: Record<string, unknown>,
    expandedTargets: string[] = [],
    targetId?: number
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    this.audit(4, "execution_start", {
      targetUrl: params.targetUrl,
      campaignId: this.state.campaignId,
    });

    const engine = new HunterEngine();
    // Register as the current spender so stop() propagates into it. If a stop
    // arrived between layers (before we got here), honour it immediately.
    this.currentEngine = engine;
    if (this._abortRequested) engine.stop();
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
      // Publish to shared event bus so graph-wiring can create a vulnerability node
      if (this.state.campaignId) {
        const f = (d as any).finding;
        eventBus.publish('vulnerability_found', 'orchestrator', String(this.state.campaignId), {
          vulnerability: {
            type: f?.vulnClass || f?.vulnType || 'unknown',
            severity: f?.severity || 'medium',
            confidence: f?.confidence || 0.5,
            endpoint: f?.endpoint || '',
            evidence: f?.evidence ? String(f.evidence).slice(0, 500) : '',
            discoveredBy: 'hunter-engine',
          },
        });
      }
    });
    engine.on("hunt:update", d => this.emit("l4:strategy_update", d));
    engine.on("hunt:error", d => this.emit("l4:error", d));
    engine.on("hunt:ai_reasoning", d => this.emit("l4:ai_reasoning", d));
    engine.on("hunt:cve_seeded", d => this.emit("hunt:cve_seeded", d));
    engine.on("hunt:graphql_schema", d => this.emit("hunt:graphql_schema", d));
    engine.on("hunt:oob_hit", d => this.emit("hunt:oob_hit", d));

    let sessionUuid: string | undefined;
    try {
      sessionUuid = await engine.startHunt({
        targetUrl: params.targetUrl,
        programId: params.programId,
        campaignId: this.state.campaignId!,
        targetId,
        maxIterations: params.maxIterations || 10,
        budget: params.budget,
        auth: params.auth,
        proxyEnabled: params.proxyEnabled,
        wafBypassEnabled: params.wafBypassEnabled,
      });
      this.state.sessionUuid = sessionUuid;

      // Wait for hunt to complete
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("Hunt timeout")),
          ((params.budget?.maxTime || 3600) + 60) * 1000);
        engine.once("hunt:complete", () => { clearTimeout(timeout); resolve(); });
        engine.once("hunt:error", (d) => { clearTimeout(timeout); reject(new Error(String(d.error))); });
        engine.once("hunt:hard_banned", (d) => {
          clearTimeout(timeout);
          logger.warn("Hunt terminated early: hard IP ban detected", d);
          resolve(); // graceful — proceed to verification with whatever findings exist
        });
      });
    } catch (err) {
      // Non-fatal: partial findings are still processed
      logger.warn("Hunt execution ended with error (continuing to verification)", { err });
    }

    // 4b. Supplement with SolverPool for high-ROI vuln classes if findings are sparse
    const targetHostname = (() => { try { return new URL(params.targetUrl).hostname; } catch { return ''; } })();
    // Compute the budget the engine actually consumed so the supplement draws
    // from the REMAINING quota rather than a fresh full allowance — previously
    // the supplement reset requestsMade to 0, silently doubling total spend.
    const totalBudget = params.budget?.maxRequests ?? 2000;
    const engineSpent = (() => {
      try { return engine.getState()?.budget?.requestsMade ?? 0; } catch { return 0; }
    })();
    const remainingBudget = Math.max(0, totalBudget - engineSpent);
    if (rawFindings.length < 2 && remainingBudget > 0 && !dynamicRateLimiter.isHardBanned(targetHostname)) {
      this.audit(4, "solver_supplement_start", { reason: "sparse findings", remainingBudget, engineSpent });
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
          {
            programId: params.programId,
            sessionId: engine.getDbSessionId(),
            // Draw from the remaining campaign budget, pre-charged with what the
            // engine already spent so total spend stays within maxRequests.
            budget: { maxRequests: totalBudget, requestsMade: engineSpent },
          }
        );
      } catch (err) {
        logger.warn("Solver supplement failed (non-critical)", { err });
      }
    } else if (rawFindings.length < 2 && remainingBudget <= 0) {
      this.audit(4, "solver_supplement_skipped", { reason: "budget exhausted by engine", engineSpent });
    }

    // 4c. Run abbreviated hunts on additional discovered subdomains (concurrency limit 2)
    // Skip entirely if a stop was requested — never spin up new engines mid-abort.
    const additionalTargets = this._abortRequested
      ? []
      : expandedTargets.filter(t => t !== params.targetUrl).slice(0, 5);
    if (additionalTargets.length > 0) {
      this.audit(4, "subdomain_hunt_start", { count: additionalTargets.length });
      const CONCURRENCY = 2;
      for (let i = 0; i < additionalTargets.length; i += CONCURRENCY) {
        if (this._abortRequested) break;
        const batch = additionalTargets.slice(i, i + CONCURRENCY);
        await Promise.allSettled(batch.map(async (subUrl) => {
          try {
            const subEngine = new HunterEngine();
            this.currentEngine = subEngine;
            if (this._abortRequested) subEngine.stop();
            subEngine.on("hunt:finding_confirmed", (d) => {
              rawFindings.push(d);
              this.state.findingsCount++;
              this.emit("l4:finding_raw", d);
            });
            subEngine.on("hunt:cve_seeded", d => this.emit("hunt:cve_seeded", d));
            subEngine.on("hunt:graphql_schema", d => this.emit("hunt:graphql_schema", d));
            const subUuid = await subEngine.startHunt({
              targetUrl: subUrl,
              programId: params.programId,
              campaignId: this.state.campaignId!,
              maxIterations: Math.min(params.maxIterations || 10, 5),
              budget: { maxRequests: 500, maxTime: 600 },
              proxyEnabled: params.proxyEnabled,
              wafBypassEnabled: params.wafBypassEnabled,
            });
            await new Promise<void>((resolve) => {
              const t = setTimeout(resolve, 660_000);
              subEngine.once("hunt:complete", () => { clearTimeout(t); resolve(); });
              subEngine.once("hunt:error", () => { clearTimeout(t); resolve(); });
              subEngine.once("hunt:hard_banned", () => { clearTimeout(t); resolve(); });
            });
            logger.info("[Orchestrator] Subdomain hunt complete", { subUrl, subUuid });
          } catch (err) {
            logger.warn("[Orchestrator] Subdomain hunt failed (non-critical)", { subUrl, err: String(err) });
          }
        }));
      }
    }

    // L4 is done spending — drop the engine reference so a later stop() doesn't
    // try to halt a torn-down engine (verification/harvest carry no engine spend).
    this.currentEngine = null;

    // Reconcile in-memory counter with DB to catch any persistence gaps
    if (this.state.campaignId) {
      const [countRow] = await db.select({ n: sql<number>`count(*)` })
        .from(findings).where(eq(findings.campaignId, this.state.campaignId));
      this.state.findingsCount = Number(countRow?.n ?? this.state.findingsCount);
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

  // Resolve the real URL a finding targets so the verifier re-probes the actual
  // endpoint instead of a numeric target FK. `affected_url` is authoritative for
  // findings created after this fix; for older rows we recover the URL from the
  // evidence trail or the title ("<VULN> found at <url>") before falling back to
  // the hunt's base target URL.
  private deriveVerificationUrl(
    dbFinding: typeof findings.$inferSelect,
    fallbackUrl: string
  ): string {
    const affected = (dbFinding as { affectedUrl?: string | null }).affectedUrl;
    if (affected && /^https?:\/\//i.test(affected)) return affected;

    const host = (() => { try { return new URL(fallbackUrl).host; } catch { return ""; } })();
    try {
      const blob = JSON.stringify(dbFinding.evidence ?? "");
      const urls = blob.match(/https?:\/\/[^\s"'\\]+/g) || [];
      const onHost = host ? urls.find(u => u.includes(host)) : urls[0];
      if (onHost) return onHost;
    } catch { /* evidence not serialisable — fall through */ }

    const fromTitle = dbFinding.title?.match(/https?:\/\/\S+/)?.[0];
    if (fromTitle) return fromTitle;

    return fallbackUrl;
  }

  // ── Layer 5: Verification Gate ─────────────────────────────────────────────
  private async layer5_verificationGate(
    params: OrchestrateParams,
    execData: Record<string, unknown>
  ): Promise<{ passed: boolean; data: Record<string, unknown> }> {
    const rawFindings = (execData.rawFindings as unknown[]) || [];
    this.audit(5, "verification_gate_start", { rawCount: rawFindings.length });

    // Fetch program platform/handle for public duplicate checks
    const [prog] = await db.select({ platform: programs.platform, programHandle: programs.programHandle })
      .from(programs).where(eq(programs.id, params.programId)).limit(1);

    const verified: unknown[] = [];
    const rejected: unknown[] = [];

    // Fetch findings for this campaign from DB (authoritative source)
    let allDbFindings: (typeof findings.$inferSelect)[] = [];
    if (this.state.campaignId) {
      allDbFindings = await db.select().from(findings)
        .where(eq(findings.campaignId, this.state.campaignId))
        .orderBy(desc(findings.createdAt));
    }

    // Reconciliation: findings already confirmed in a prior run are promoted
    // directly into the verified list without re-running the 4-layer pipeline.
    // This makes resume after a crash idempotent and prevents double-billing
    // the expensive Playwright + AI confirmation passes.
    const alreadyConfirmed = allDbFindings.filter(f => f.verificationStatus === 'confirmed');
    const needsVerification = allDbFindings.filter(f => f.verificationStatus !== 'confirmed');

    for (const f of alreadyConfirmed) {
      verified.push({ finding: f, verification: { finalVerdict: 'confirmed', finalConfidence: f.confidence } });
      this.state.verifiedCount++;
    }

    this.audit(5, "reconciliation_complete", {
      alreadyConfirmed: alreadyConfirmed.length,
      needsVerification: needsVerification.length,
    });

    const dbFindings = needsVerification;
    // Run 4-layer anti-hallucination pipeline on each finding
    for (const dbFinding of dbFindings) {
      this.emit("l5:verifying", { findingId: dbFinding.id });
      try {
        const verificationUrl = this.deriveVerificationUrl(dbFinding, params.targetUrl);
        const allDbEvidence = (dbFinding.evidence as unknown[]) || [];
        const firstEvidence = allDbEvidence[0] as Record<string, unknown> | undefined;
        // discoveryTool is stored in evidence[0].tool (the ProbeResult spread).
        // Set it explicitly on mockResult so VerifierAgent's L4 routes stateful findings
        // to the stateful oracle path without relying on evidence.tool fallback.
        const findingDiscoveryTool = (firstEvidence?.tool as string | undefined) || undefined;
        // rawHttpLog is stored both inline in evidence[0].rawHttpLog (ProbeResult) and
        // as a separate { type:"raw_http", data } entry. Pass it as `response` so L4
        // has the captured session as a named field (not buried in a JSON blob).
        const rawHttpEntry = allDbEvidence.find(
          (e) => (e as { type?: string }).type === "raw_http"
        ) as { data?: string } | undefined;
        const capturedSession =
          rawHttpEntry?.data?.slice(0, 3000) ||
          (firstEvidence?.rawHttpLog as string | undefined)?.slice(0, 3000) ||
          "";
        const mockResult = {
          taskId: String(dbFinding.id),
          solverId: "orchestrator",
          endpoint: verificationUrl,
          vulnClass: dbFinding.vulnType as Parameters<typeof this.verifierAgent.verify>[0]["vulnClass"],
          found: true,
          confidence: dbFinding.confidence,
          evidence: firstEvidence || {},
          payload: dbFinding.exploitPayload || "",
          request: "",
          response: capturedSession,
          duration: 0,
          toolsUsed: [],
          discoveryTool: findingDiscoveryTool,
          // OOB beacon hit = authoritative non-destructive proof for rce/ssrf/xxe/
          // blind classes; the verifier confirms on this without L2 vetoing.
          oobConfirmed: dbFinding.oobHitReceived === true,
        };

        const verification = await this.verifierAgent.verify(mockResult);

        if (verification.finalVerdict === "confirmed") {
          // Public disclosure check — does another hunter already own this vuln?
          const disclosureResult = await publicDisclosureDetector.check(
            { vulnClass: dbFinding.vulnType, targetUrl: params.targetUrl },
            prog
          );

          await db.update(findings).set({
            disclosureCheckStatus: disclosureResult.status,
            publicDisclosureUrl: disclosureResult.matchedReport?.url ?? null,
            publicDisclosureNote: disclosureResult.reason ?? null,
          }).where(eq(findings.id, dbFinding.id));

          if (disclosureResult.status === "confirmed_duplicate") {
            this.emit("l5:public_duplicate", {
              findingId: dbFinding.id,
              vulnClass: dbFinding.vulnType,
              platform: prog?.platform,
              reportUrl: disclosureResult.matchedReport?.url,
              title: disclosureResult.matchedReport?.title,
            });
            rejected.push({ finding: dbFinding, verification, reason: "public_duplicate" });
            continue;
          }

          if (disclosureResult.status === "likely_duplicate") {
            this.emit("l5:public_duplicate", {
              findingId: dbFinding.id,
              vulnClass: dbFinding.vulnType,
              platform: prog?.platform,
              reportUrl: disclosureResult.matchedReport?.url,
              title: disclosureResult.matchedReport?.title,
              warn: true,
            });
          }

          verified.push({ finding: dbFinding, verification });
          this.state.verifiedCount++;

          // Persist Playwright screenshot to disk (avoid bloating DB with base64)
          let screenshotPath: string | undefined;
          const l3 = verification.layer3_playwright as { screenshot?: string; confirmed: boolean; consoleAlerts: string[]; networkRequests: string[] } | undefined;
          if (l3?.screenshot) {
            try {
              const evidenceDir = path.join(process.cwd(), "evidence", String(dbFinding.id));
              mkdirSync(evidenceDir, { recursive: true });
              screenshotPath = path.join(evidenceDir, "playwright_screenshot.png");
              await fsp.writeFile(screenshotPath, Buffer.from(l3.screenshot, "base64"));
              logger.info("Layer 5: Screenshot archived", { findingId: dbFinding.id, path: screenshotPath });
            } catch (fsErr) {
              logger.warn("Layer 5: Failed to write screenshot file", { err: String(fsErr) });
            }
          }

          // Build sanitised verification log — strip raw base64, store file path instead
          const sanitisedVerification = {
            ...verification,
            layer3_playwright: l3
              ? { ...l3, screenshot: screenshotPath || null }
              : verification.layer3_playwright,
          };

          // CWE tag is a synchronous map lookup — apply it immediately.
          const cweId = VULN_TYPE_TO_CWE[dbFinding.vulnType] ?? null;

          // Apply PostExploitAgent's proven severity/CVSS escalation now that the
          // finding is confirmed (it was stashed in evidence during the hunt loop,
          // before verification, so it never inflates an unverified finding).
          const escalation = pendingEscalation(dbFinding);

          // When a payload-adaptation retry is what actually confirmed the finding,
          // the original exploitPayload/affectedUrl are the ones that FAILED —
          // persist the adapted payload that legitimately passed the same gate
          // (mirrors verify-finding.ts's verifyAndPersistFinding, which this
          // orchestrator-driven path duplicates rather than shares).
          const adaptation = verification.adaptation;

          // Archive the ADAPTED request's screenshot separately from the original
          // (failing) probe's screenshot above — citing the original 400-error
          // screenshot as proof of the adapted result would itself be an over-claim.
          // Also stash the real adapted request/response as raw_http evidence so
          // the report builder has actual proof to cite instead of N/A.
          let adaptedEvidenceEntries: Record<string, unknown>[] = [];
          if (adaptation) {
            let adaptedScreenshotPath: string | undefined;
            if (adaptation.screenshot) {
              try {
                const evidenceDir = path.join(process.cwd(), "evidence", String(dbFinding.id));
                mkdirSync(evidenceDir, { recursive: true });
                adaptedScreenshotPath = path.join(evidenceDir, "adapted_screenshot.png");
                await fsp.writeFile(adaptedScreenshotPath, Buffer.from(adaptation.screenshot, "base64"));
              } catch (fsErr) {
                logger.warn("Layer 5: Failed to write adapted screenshot file", { err: String(fsErr) });
              }
            }
            adaptedEvidenceEntries = [
              {
                type: "raw_http",
                data: `GET ${adaptation.adaptedUrl} HTTP/1.1\n\nHTTP/1.1 ${adaptation.statusCode}\n${adaptation.responseSnippet}`,
              },
              ...(adaptedScreenshotPath ? [{ type: "adapted_screenshot", path: adaptedScreenshotPath }] : []),
            ];
          }

          // Update finding record
          await db.update(findings).set({
            verificationStatus: verification.finalVerdict,
            verificationLog: [sanitisedVerification] as unknown as Record<string, unknown>[],
            confidence: verification.finalConfidence,
            dedupHash: verification.dedupHash,
            ...(cweId !== null ? { cweId } : {}),
            ...(escalation ? {
              severity: escalation.severity,
              cvssScore: escalation.cvssScore,
              impact: escalation.impact,
            } : {}),
            ...(adaptation ? {
              exploitPayload: adaptation.adaptedPayload,
              affectedUrl: adaptation.adaptedUrl,
              evidence: [...((dbFinding.evidence as Record<string, unknown>[]) ?? []), ...adaptedEvidenceEntries],
            } : {}),
            updatedAt: new Date(),
          }).where(eq(findings.id, dbFinding.id));

          // CVE enrichment hits the external NVD API — do it fire-and-forget so a
          // slow lookup can't stall the verification gate. The cveId is written
          // in a follow-up update when (if) it resolves.
          if (cweId !== null) {
            const findingId = dbFinding.id;
            void (async () => {
              try {
                const cveMatches = await nvdClient.lookupByCWE(`CWE-${cweId}`);
                const best = cveMatches
                  .filter(c => c.cvssScore >= 6.0)
                  .sort((a, b) => b.cvssScore - a.cvssScore)[0];
                if (best) {
                  await db.update(findings).set({ cveId: best.id, updatedAt: new Date() })
                    .where(eq(findings.id, findingId));
                }
              } catch { /* non-critical */ }
            })();
          }

          this.emit("l5:verified", { findingId: dbFinding.id, verdict: verification.finalVerdict });

          // Platform report submission — fire-and-forget, non-blocking
          if (prog?.platform && prog?.programHandle) {
            const platform = prog.platform as "hackerone" | "bugcrowd" | "intigriti" | "yeswehack";
            if (["hackerone", "bugcrowd", "intigriti", "yeswehack"].includes(platform)) {
              reportSubmitter.submit({
                title: `[${(dbFinding.severity ?? "medium").toUpperCase()}] ${dbFinding.vulnType} in ${params.targetUrl}`,
                vulnType: dbFinding.vulnType,
                severity: (dbFinding.severity ?? "medium") as "critical" | "high" | "medium" | "low" | "informational",
                description: dbFinding.description ?? "",
                reproductionSteps: Array.isArray(dbFinding.reproductionSteps)
                  ? (dbFinding.reproductionSteps as string[]).join("\n")
                  : String(dbFinding.reproductionSteps ?? "See evidence"),
                impact: dbFinding.impact ?? `${dbFinding.vulnType} vulnerability with CVSS ${dbFinding.cvssScore ?? 5.0}`,
                remediation: dbFinding.remediation ?? undefined,
                cvssScore: dbFinding.cvssScore ?? undefined,
                cweId: dbFinding.cweId ?? undefined,
                cveId: dbFinding.cveId ?? undefined,
                targetUrl: params.targetUrl,
                exploitPayload: dbFinding.exploitPayload ?? undefined,
                programHandle: prog.programHandle,
                platform,
              }).then(result => {
                if (result.success) {
                  this.emit("l5:report_submitted", {
                    findingId: dbFinding.id,
                    platform,
                    reportId: result.reportId,
                    reportUrl: result.reportUrl,
                  });
                  db.update(findings).set({
                    reportDraft: result.reportUrl ? `Submitted: ${result.reportUrl}` : `Report ID: ${result.reportId}`,
                    submittedAt: new Date(),
                  }).where(eq(findings.id, dbFinding.id)).catch(() => {});
                } else if (!result.draftOnly) {
                  // Surface submission failure to the operator instead of only logging —
                  // a 401/403 from the platform should be visible, not silent.
                  logger.warn("[CampaignOrchestrator] Report submission failed", { platform, findingId: dbFinding.id, error: result.error });
                  this.emit("l5:report_submit_failed", { findingId: dbFinding.id, platform, error: result.error });
                }
              }).catch((err) => {
                logger.error("[CampaignOrchestrator] Report submission threw", { platform, findingId: dbFinding.id, err: String(err) });
                this.emit("l5:report_submit_failed", { findingId: dbFinding.id, platform, error: String(err) });
              });
            }
          }

          // Reconcile graph node verification status
          eventBus.publish('finding_verified', 'orchestrator', String(this.state.campaignId || ''), {
            vulnType: dbFinding.vulnType,
            endpoint: verificationUrl,
            findingId: dbFinding.id,
            finalConfidence: verification.finalConfidence,
          });
        } else {
          rejected.push({ finding: dbFinding, verification });
          this.emit("l5:rejected", { findingId: dbFinding.id, verdict: verification.finalVerdict });
          // Persist the rejection so the finding is never left as status:"new"/verificationStatus:"pending"
          // — without this update a rejected finding is indistinguishable from an unverified one.
          await db.update(findings).set({
            verificationStatus: verification.finalVerdict, // "rejected" or "inconclusive"
            verificationLog: [verification] as unknown as Record<string, unknown>[],
            confidence: verification.finalConfidence,
            updatedAt: new Date(),
          }).where(eq(findings.id, dbFinding.id)).catch(e =>
            logger.warn("[CampaignOrchestrator] L5 reject DB update failed", { findingId: dbFinding.id, err: String(e) })
          );
          eventBus.publish('finding_rejected', 'orchestrator', String(this.state.campaignId || ''), {
            vulnType: dbFinding.vulnType,
            endpoint: verificationUrl,
            findingId: dbFinding.id,
            verdict: verification.finalVerdict,
          });
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

    const rejectedFindings = (verifData.rejected as Array<{
      finding?: typeof findings.$inferSelect;
      verification?: Record<string, unknown>;
    }>) || [];

    this.audit(6, "harvest_start", { verifiedCount: verifiedFindings.length });

    const reports: string[] = [];
    const nucleiTemplates: string[] = [];
    const reportGen = new DraftReportGenerator();
    const nucleiGen = new NucleiTemplateGenerator();

    // 6a. Generate reports + Nuclei templates for each verified finding
    for (const { finding, verification } of verifiedFindings) {
      try {
        // `finding` is the DB row captured BEFORE Layer 5's update ran, so on an
        // adaptation-confirmed finding it still holds the ORIGINAL failing
        // payload/URL — read the adaptation off `verification` (in-memory, always
        // current) rather than trusting the stale row. Falls back to the finding's
        // own fields for the (much more common) non-adaptation case.
        const adaptation = verification.adaptation as
          { adaptedUrl: string; adaptedPayload: string; statusCode: number; responseSnippet: string } | undefined;
        const verifiedEndpoint = adaptation?.adaptedUrl || finding.affectedUrl || params.targetUrl;
        const verifiedPayload = adaptation?.adaptedPayload || finding.exploitPayload || "";

        const mockSolverResult = {
          taskId: String(finding.id),
          solverId: "orchestrator",
          endpoint: verifiedEndpoint,
          vulnClass: finding.vulnType as Parameters<typeof reportGen.generate>[0]["vulnClass"],
          found: true,
          confidence: finding.confidence,
          evidence: {},
          payload: verifiedPayload,
          request: verifiedEndpoint,
          response: adaptation?.responseSnippet || "",
          duration: 0,
          toolsUsed: [],
        };

        // Real L2/L3/L4 evidence from this finding's actual verification — the
        // report/nuclei generators reason over this, so a hardcoded "confirmed"
        // stub here was silently discarding the real proof (empty responses,
        // no reasoning) in favour of a fake all-green result.
        const mockVerification = {
          findingId: String(finding.id),
          layer1_dedup: (verification.layer1_dedup as { isDuplicate: boolean }) ?? { isDuplicate: false },
          layer2_reprobe: (verification.layer2_reprobe as { confirmed: boolean; statusCode: number; responseSnippet: string })
            ?? { confirmed: false, statusCode: 0, responseSnippet: "" },
          layer3_playwright: (verification.layer3_playwright as { confirmed: boolean; consoleAlerts: string[]; networkRequests: string[] })
            ?? { confirmed: false, consoleAlerts: [], networkRequests: [] },
          layer4_ai: (verification.layer4_ai as { confirmed: boolean; reasoning: string; confidenceAdjustment: number })
            ?? { confirmed: false, reasoning: "", confidenceAdjustment: 0 },
          finalVerdict: (verification.finalVerdict as "confirmed") || "confirmed",
          finalConfidence: (verification.finalConfidence as number | undefined) ?? finding.confidence,
          dedupHash: finding.dedupHash || "",
        };

        // Adapted proof (or, absent adaptation, any captured raw_http evidence)
        // as the raw HTTP block for the report's Summary/PoC generation.
        const evidenceArr = (finding.evidence as Array<Record<string, unknown>>) ?? [];
        const rawHttpEntry = [...evidenceArr].reverse().find(e => e.type === "raw_http");
        const rawEvidence = adaptation
          ? `GET ${adaptation.adaptedUrl} HTTP/1.1\n\nHTTP/1.1 ${adaptation.statusCode}\n${adaptation.responseSnippet}`
          : rawHttpEntry ? String(rawHttpEntry.data ?? "") : undefined;

        // Idempotency: skip regeneration if the report was already written
        // (handles crash-then-resume between L5 update and L6 report writes).
        if (finding.reportDraft) {
          reports.push(finding.reportDraft);
        } else {
          const report = await reportGen.generate(mockSolverResult, mockVerification, {
            severity: finding.severity,
            programName: "Bug Bounty Program",
            targetUrl: params.targetUrl,
            huntDate: finding.createdAt.toISOString().split("T")[0],
            rawEvidence,
          });
          reports.push(report.reportMarkdown);
          await db.update(findings)
            .set({ reportDraft: report.reportMarkdown })
            .where(eq(findings.id, finding.id));
        }

        if (finding.nucleiTemplate) {
          nucleiTemplates.push(finding.nucleiTemplate);
        } else {
          const tmpl = nucleiGen.generateTemplate(mockSolverResult, mockVerification, {
            severity: finding.severity,
            programName: "Bug Bounty Program",
          });
          nucleiTemplates.push(tmpl);
          await db.update(findings)
            .set({ nucleiTemplate: tmpl })
            .where(eq(findings.id, finding.id));
        }

        this.emit("l6:report_generated", { findingId: finding.id });
      } catch (err) {
        logger.warn("Report/template generation failed for finding", { findingId: finding.id, err });
      }
    }

    // 6b. Update reinforcement store + bounty intelligence memory
    for (const { finding } of verifiedFindings) {
      try {
        await this.rlStore.recordToolOutcome("orchestrator", finding.vulnType, true);
      } catch (err) {
        logger.warn("[L6] rlStore.recordToolOutcome failed", { vulnType: finding.vulnType, err });
      }
      // Feed verified finding into bounty intelligence so duplicate detection and
      // payout estimation improve over time
      try {
        await bountyIntelligenceService.addKnownFinding({
          id: String(finding.id),
          title: `${finding.vulnType} on ${finding.affectedUrl || params.targetUrl}`,
          endpoint: finding.affectedUrl || params.targetUrl,
          vulnerabilityType: finding.vulnType,
          severity: finding.severity ?? 'medium',
          program: String(params.programId),
          reportDate: finding.createdAt.toISOString(),
          status: 'accepted',
        });
      } catch { /* non-critical */ }
    }

    // 6b.2. Correct programType heuristics with verifier-authoritative verdicts.
    // HunterEngine fires these optimistically with inline-confirmed count before
    // the verification gate runs. Re-recording with the verified count pulls the
    // RL rate toward ground truth — each hunt adds one authoritative data point.
    try {
      const verifiedCount = verifiedFindings.length;
      const totalProcessed = (verifData.totalProcessed as number) || 0;
      const strategy = verifiedCount > 0 ? 'found_vulns' : 'no_vulns';
      await this.rlStore.recordProgramTypeHeuristic('web_app', strategy, verifiedCount > 0);
      if (totalProcessed > 0) {
        await this.rlStore.recordProgramTypeHeuristic('web_app', 'efficient_hunt', verifiedCount / totalProcessed > 0.1);
      }
    } catch (err) {
      logger.debug('[L6] programType heuristic ground-truth correction failed', { err });
    }

    // 6c. Update autonomy maturity tracker
    let autonomyScore = 0;
    try {
      // Derive real tool-usage metrics from finding evidence instead of hardcoding.
      // Each finding's evidence array carries the probes that produced it, each
      // tagged with the tool name. Tools that appear in a VERIFIED finding are
      // "correct"; the union across verified+rejected is the full selected set.
      const extractTools = (f?: typeof findings.$inferSelect): string[] => {
        const ev = (f?.evidence as Array<Record<string, unknown>>) || [];
        return ev.map(e => (e?.tool as string) || "").filter(Boolean);
      };
      const correctTools = new Set<string>();
      verifiedFindings.forEach(({ finding }) => extractTools(finding).forEach(t => correctTools.add(t)));
      const selectedTools = new Set<string>(correctTools);
      rejectedFindings.forEach(({ finding }) => extractTools(finding).forEach(t => selectedTools.add(t)));

      const totalProcessed = (verifData.totalProcessed as number) || 0;
      const huntMetrics = {
        hypothesesGenerated: Math.max(totalProcessed, this.state.findingsCount),
        hypothesesCorrect: this.state.verifiedCount,
        toolsSelected: Math.max(selectedTools.size, 1),
        toolsCorrect: correctTools.size,
        outOfScopeAttempts: 0,
        falsePositives: Math.max(0, totalProcessed - this.state.verifiedCount),
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
      for (const { finding, verification } of verifiedFindings) {
        const calibratedConfidence =
          (verification.finalConfidence as number | undefined) ?? finding.confidence ?? 0.5;
        await this.rlStore.recordConfidenceCalibration(
          finding.vulnType,
          calibratedConfidence,
          true
        );
      }

      // Calibrate the false-positive arm so Brier scoring has both sides of the curve.
      // inconclusive is excluded — forcing it to a pole would penalise L5 replay limitations
      // rather than the hypothesis quality, which is what we're calibrating.
      for (const { finding, verification } of rejectedFindings) {
        if (!finding || !verification) continue;
        if ((verification.finalVerdict as string) === "inconclusive") continue;
        const calibratedConfidence =
          (verification.finalConfidence as number | undefined) ?? finding.confidence ?? 0.5;
        await this.rlStore.recordConfidenceCalibration(
          finding.vulnType,
          calibratedConfidence,
          false
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

    if (this._abortRequested) throw new Error("Aborted by user");

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

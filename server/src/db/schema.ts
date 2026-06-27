import {
  pgTable, serial, text, integer, boolean, timestamp, jsonb,
  real, varchar, index, uniqueIndex
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

// ─── Users ───────────────────────────────────────────────────────────────────
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: varchar("username", { length: 64 }).notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: varchar("role", { length: 32 }).notNull().default("hunter"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// ─── Bug Bounty Programs ──────────────────────────────────────────────────────
export const programs = pgTable("programs", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  platform: varchar("platform", { length: 64 }).notNull(), // hackerone, bugcrowd, intigriti, etc.
  programHandle: text("program_handle"),
  scope: jsonb("scope").notNull().default([]),         // in-scope domains/IPs/apps
  outOfScope: jsonb("out_of_scope").notNull().default([]),
  maxPayout: integer("max_payout").default(0),
  avgPayout: real("avg_payout").default(0),
  responseTime: real("response_time_hours").default(0),
  successRate: real("success_rate").default(0),        // historical success %
  roiScore: real("roi_score").default(0),
  tags: jsonb("tags").notNull().default([]),
  active: boolean("active").notNull().default(true),
  lastHunted: timestamp("last_hunted"),
  metadata: jsonb("metadata").notNull().default({}),
  scheduleInterval: integer("schedule_interval").default(0), // hours between auto re-scans; 0 = disabled
  authConfig: jsonb("auth_config").$type<{
    loginUrl?: string;
    username?: string;
    password?: string;
    authType?: "form" | "basic" | "bearer";
    tokenHeaderName?: string;
    usernameField?: string;
    passwordField?: string;
    sessionCookieNames?: string[];
  } | null>(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (t) => ({
  platformIdx: index("programs_platform_idx").on(t.platform),
  roiIdx: index("programs_roi_idx").on(t.roiScore),
}));

// ─── Targets ──────────────────────────────────────────────────────────────────
export const targets = pgTable("targets", {
  id: serial("id").primaryKey(),
  programId: integer("program_id").references(() => programs.id).notNull(),
  url: text("url").notNull(),
  type: varchar("type", { length: 32 }).notNull(), // web, api, mobile, network
  fingerprint: jsonb("fingerprint").notNull().default({}), // tech stack, WAF, CMS
  attackSurface: jsonb("attack_surface").notNull().default([]),
  priority: real("priority").default(0.5),
  lastScanned: timestamp("last_scanned"),
  status: varchar("status", { length: 32 }).notNull().default("pending"),
  metadata: jsonb("metadata").notNull().default({}),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// ─── Hunt Campaigns ───────────────────────────────────────────────────────────
export const campaigns = pgTable("campaigns", {
  id: serial("id").primaryKey(),
  programId: integer("program_id").references(() => programs.id).notNull(),
  name: text("name").notNull(),
  goal: text("goal").notNull(),
  status: varchar("status", { length: 32 }).notNull().default("pending"),
  huntMode: varchar("hunt_mode", { length: 32 }).notNull().default("forward"), // forward | backward
  strategy: jsonb("strategy").notNull().default({}),
  budget: jsonb("budget").notNull().default({ maxRequests: 5000, maxTime: 3600 }),
  progress: jsonb("progress").notNull().default({ requestsMade: 0, elapsed: 0 }),
  startedAt: timestamp("started_at"),
  completedAt: timestamp("completed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// ─── Hunt Sessions ────────────────────────────────────────────────────────────
export const huntSessions = pgTable("hunt_sessions", {
  id: serial("id").primaryKey(),
  campaignId: integer("campaign_id").references(() => campaigns.id).notNull(),
  targetId: integer("target_id").references(() => targets.id).notNull(),
  sessionUuid: varchar("session_uuid", { length: 64 }).notNull().unique(),
  phase: varchar("phase", { length: 32 }).notNull().default("observe"),
  hypotheses: jsonb("hypotheses").notNull().default([]),
  observations: jsonb("observations").notNull().default([]),
  probes: jsonb("probes").notNull().default([]),
  reasoningLog: jsonb("reasoning_log").notNull().default([]),
  solverResults: jsonb("solver_results").notNull().default([]),
  status: varchar("status", { length: 32 }).notNull().default("running"),
  startedAt: timestamp("started_at").defaultNow().notNull(),
  completedAt: timestamp("completed_at"),
});

// ─── Findings ─────────────────────────────────────────────────────────────────
export const findings = pgTable("findings", {
  id: serial("id").primaryKey(),
  campaignId: integer("campaign_id").references(() => campaigns.id),
  huntSessionId: integer("hunt_session_id").references(() => huntSessions.id),
  targetId: integer("target_id").references(() => targets.id),
  // Denormalized program/source id so lab (sentinel id, e.g. -1) and real-target
  // findings can be filtered apart without a campaign join — direct hunts have
  // campaignId=0, so the join alone can't isolate them. Set in persistFinding.
  programId: integer("program_id"),
  title: text("title").notNull(),
  vulnType: varchar("vuln_type", { length: 64 }).notNull(),
  severity: varchar("severity", { length: 16 }).notNull(), // critical, high, medium, low, info
  confidence: real("confidence").notNull().default(0),
  cvssScore: real("cvss_score"),
  description: text("description").notNull(),
  evidence: jsonb("evidence").notNull().default([]),    // requests, responses, screenshots
  reproductionSteps: jsonb("reproduction_steps").notNull().default([]),
  impact: text("impact"),
  remediation: text("remediation"),
  cweId: integer("cwe_id"),
  cveId: text("cve_id"),
  exploitPayload: text("exploit_payload"),
  affectedUrl: text("affected_url"),  // full URL the finding targets — used by the verifier to re-probe
  verificationStatus: varchar("verification_status", { length: 32 }).notNull().default("pending"),
  verificationLog: jsonb("verification_log").notNull().default([]),
  dedupHash: text("dedup_hash").unique(),
  nucleiTemplate: text("nuclei_template"),
  reportDraft: text("report_draft"),
  submittedAt: timestamp("submitted_at"),
  status: varchar("status", { length: 32 }).notNull().default("new"),
  disclosureCheckStatus: varchar("disclosure_check_status", { length: 32 }).notNull().default("pending"),
  publicDisclosureUrl: text("public_disclosure_url"),
  publicDisclosureNote: text("public_disclosure_note"),
  oobBeaconId: text("oob_beacon_id"),
  oobHitReceived: boolean("oob_hit_received").notNull().default(false),
  oobHitAt: timestamp("oob_hit_at", { withTimezone: true }),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (t) => ({
  vulnTypeIdx: index("findings_vuln_type_idx").on(t.vulnType),
  severityIdx: index("findings_severity_idx").on(t.severity),
  statusIdx: index("findings_status_idx").on(t.status),
  campaignIdx: index("findings_campaign_idx").on(t.campaignId),
  programIdx: index("findings_program_idx").on(t.programId),
}));

// ─── WAF Profiles ─────────────────────────────────────────────────────────────
export const wafProfiles = pgTable("waf_profiles", {
  id: serial("id").primaryKey(),
  vendor: varchar("vendor", { length: 64 }).notNull(),
  targetDomain: text("target_domain").notNull(),
  detectionSignals: jsonb("detection_signals").notNull().default([]),
  bypassTechniques: jsonb("bypass_techniques").notNull().default([]),
  blockedPatterns: jsonb("blocked_patterns").notNull().default([]),
  evasionMatrix: jsonb("evasion_matrix").notNull().default({}),
  blockRate: real("block_rate").default(0),
  successfulBypasses: integer("successful_bypasses").default(0),
  lastUpdated: timestamp("last_updated").defaultNow().notNull(),
  metadata: jsonb("metadata").notNull().default({}),
}, (t) => ({
  vendorDomainIdx: uniqueIndex("waf_vendor_domain_idx").on(t.vendor, t.targetDomain),
}));

// ─── Exploit Chains ───────────────────────────────────────────────────────────
export const exploitChains = pgTable("exploit_chains", {
  id: serial("id").primaryKey(),
  campaignId: integer("campaign_id").references(() => campaigns.id),
  chainUuid: varchar("chain_uuid", { length: 64 }).notNull().unique(),
  name: text("name").notNull(),
  steps: jsonb("steps").notNull().default([]),
  totalImpact: real("total_impact").default(0),
  successRate: real("success_rate").default(0),
  prerequisites: jsonb("prerequisites").notNull().default([]),
  finalObjective: text("final_objective"),
  status: varchar("status", { length: 32 }).notNull().default("draft"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// ─── Reinforcement Store ──────────────────────────────────────────────────────
export const reinforcementStore = pgTable("reinforcement_store", {
  id: serial("id").primaryKey(),
  domain: varchar("domain", { length: 64 }).notNull(), // tool_success, framework_vuln, program_type, confidence_cal, exploration
  key: text("key").notNull(),
  value: jsonb("value").notNull(),
  successCount: integer("success_count").default(0),
  totalCount: integer("total_count").default(0),
  lastUpdated: timestamp("last_updated").defaultNow().notNull(),
  decayedAt: timestamp("decayed_at"),
  weight: real("weight").default(1.0),
}, (t) => ({
  domainKeyIdx: uniqueIndex("reinforcement_domain_key_idx").on(t.domain, t.key),
}));

// ─── Autonomy Metrics ─────────────────────────────────────────────────────────
export const autonomyMetrics = pgTable("autonomy_metrics", {
  id: serial("id").primaryKey(),
  huntNumber: integer("hunt_number").notNull(),
  compositeScore: real("composite_score").notNull().default(0),
  domainScores: jsonb("domain_scores").notNull().default({}),
  brierSnapshot: real("brier_score"),
  reinforcementNoise: real("reinforcement_noise"),
  regressionDetected: boolean("regression_detected").default(false),
  metadata: jsonb("metadata").notNull().default({}),
  recordedAt: timestamp("recorded_at").defaultNow().notNull(),
});

// ─── Solver Results ───────────────────────────────────────────────────────────
export const solverResults = pgTable("solver_results", {
  id: serial("id").primaryKey(),
  huntSessionId: integer("hunt_session_id").references(() => huntSessions.id),
  solverId: varchar("solver_id", { length: 64 }).notNull(),
  endpoint: text("endpoint").notNull(),
  vulnClass: varchar("vuln_class", { length: 64 }).notNull(),
  result: jsonb("result").notNull().default({}),
  confidence: real("confidence").default(0),
  duration: integer("duration_ms").default(0),
  toolsUsed: jsonb("tools_used").notNull().default([]),
  status: varchar("status", { length: 32 }).notNull().default("pending"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// ─── Attack Plans (External Plan Memory) ─────────────────────────────────────
export const attackPlans = pgTable("attack_plans", {
  id: serial("id").primaryKey(),
  campaignId: integer("campaign_id").references(() => campaigns.id),
  planUuid: varchar("plan_uuid", { length: 64 }).notNull().unique(),
  goal: text("goal").notNull(),
  attackTree: jsonb("attack_tree").notNull().default({}),
  checkpointBudget: integer("checkpoint_budget").default(500),
  adaptations: jsonb("adaptations").notNull().default([]),
  currentNode: text("current_node"),
  status: varchar("status", { length: 32 }).notNull().default("active"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// ─── Relations ────────────────────────────────────────────────────────────────
export const programsRelations = relations(programs, ({ many }) => ({
  targets: many(targets),
  campaigns: many(campaigns),
}));

export const campaignsRelations = relations(campaigns, ({ one, many }) => ({
  program: one(programs, { fields: [campaigns.programId], references: [programs.id] }),
  huntSessions: many(huntSessions),
  findings: many(findings),
  exploitChains: many(exploitChains),
  attackPlans: many(attackPlans),
}));

export const huntSessionsRelations = relations(huntSessions, ({ one, many }) => ({
  campaign: one(campaigns, { fields: [huntSessions.campaignId], references: [campaigns.id] }),
  target: one(targets, { fields: [huntSessions.targetId], references: [targets.id] }),
  findings: many(findings),
  solverResults: many(solverResults),
}));

export const findingsRelations = relations(findings, ({ one }) => ({
  campaign: one(campaigns, { fields: [findings.campaignId], references: [campaigns.id] }),
  huntSession: one(huntSessions, { fields: [findings.huntSessionId], references: [huntSessions.id] }),
  target: one(targets, { fields: [findings.targetId], references: [targets.id] }),
}));

// ─── Custom Tools Registry ────────────────────────────────────────────────────
export const customTools = pgTable("custom_tools", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 64 }).notNull().unique(),
  displayName: text("display_name").notNull(),
  description: text("description").notNull().default(""),
  commandTemplate: text("command_template").notNull(),
  requiredBinary: varchar("required_binary", { length: 64 }).notNull(),
  category: varchar("category", { length: 32 }).notNull().default("scanning"),
  vulnClasses: jsonb("vuln_classes").$type<string[]>().notNull().default([]),
  rateLimit: integer("rate_limit").notNull().default(30),
  riskLevel: varchar("risk_level", { length: 16 }).notNull().default("medium"),
  stealthRating: integer("stealth_rating").notNull().default(5),
  parserType: varchar("parser_type", { length: 16 }).notNull().default("lines"),
  enabled: boolean("enabled").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (t) => ({
  nameIdx: uniqueIndex("custom_tools_name_idx").on(t.name),
}));

// ─── Scraped Intelligence ─────────────────────────────────────────────────────
// Stores content scraped from public bug bounty writeups, CVE advisories, etc.
// Loaded by JsonPromptLoader as additional domain knowledge for hypothesis generation.
export const scrapedIntelligence = pgTable("scraped_intelligence", {
  id: serial("id").primaryKey(),
  source: varchar("source", { length: 64 }).notNull(), // "hackerone", "nvd"
  sourceUrl: text("source_url"),
  title: text("title"),
  content: text("content").notNull(),
  vulnType: varchar("vuln_type", { length: 64 }),
  severity: varchar("severity", { length: 16 }),
  affectedTech: jsonb("affected_tech").$type<string[]>().default([]),
  toolsUsed: jsonb("tools_used").$type<string[]>().default([]),
  payout: integer("payout"),
  createdAt: timestamp("created_at").defaultNow(),
}, (t) => ({
  sourceIdx: index("scraped_source_idx").on(t.source),
  vulnTypeIdx: index("scraped_vuln_type_idx").on(t.vulnType),
  sourceUrlIdx: uniqueIndex("scraped_source_url_idx").on(t.sourceUrl),
}));

// ─── Governance Baselines ─────────────────────────────────────────────────────
// Immutable frozen policy baseline used by GovernanceImmunizer for drift enforcement.
// Created once on first startup; never overwritten by runtime operations.
export const governanceBaselines = pgTable('governance_baselines', {
  id: varchar('id', { length: 64 }).primaryKey(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  hash: text('hash').notNull(),
  baseline: jsonb('baseline').notNull(),
  active: boolean('active').default(true).notNull(),
});

// ─── Governance Snapshots ─────────────────────────────────────────────────────
// DB-persisted governance state snapshots for watchdog continuity across restarts.
export const governanceSnapshots = pgTable('governance_snapshots', {
  id: varchar('id', { length: 64 }).primaryKey(),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  snapshotType: varchar('snapshot_type', { length: 20 }).notNull(), // auto|manual|rollback
  snapshot: jsonb('snapshot').notNull(),
}, (t) => ({
  createdAtIdx: index('gov_snapshots_created_at_idx').on(t.createdAt),
}));

// ─── Immunization Events ──────────────────────────────────────────────────────
// Audit trail for every governance immunization check and enforcement action.
export const immunizationEvents = pgTable('immunization_events', {
  id: varchar('id', { length: 64 }).primaryKey(),
  timestamp: timestamp('timestamp').defaultNow().notNull(),
  triggeredBy: text('triggered_by').notNull(),
  action: varchar('action', { length: 20 }).notNull(), // none|warn|clamp|full_reset
  baselineId: varchar('baseline_id', { length: 64 }).notNull(),
  driftSummary: jsonb('drift_summary').notNull(),
  remediationApplied: jsonb('remediation_applied'),
});

// ─── Egress Route Metrics ─────────────────────────────────────────────────────
// Per-proxy-per-target health and burn state for dynamic egress route allocation.
export const egressRouteMetrics = pgTable('egress_route_metrics', {
  id: varchar('id', { length: 64 }).primaryKey(),
  proxyId: varchar('proxy_id', { length: 64 }).notNull(),
  target: text('target').notNull(),
  successCount: integer('success_count').default(0).notNull(),
  failureCount: integer('failure_count').default(0).notNull(),
  avgLatencyMs: real('avg_latency_ms').default(0).notNull(),
  lastUsedAt: timestamp('last_used_at'),
  burned: boolean('burned').default(false).notNull(),
  bannedUntil: timestamp('banned_until'),
}, (t) => ({
  proxyTargetIdx: uniqueIndex('egress_proxy_target_idx').on(t.proxyId, t.target),
}));

// ─── Mission Memory Snapshots ─────────────────────────────────────────────────
// Durable write-through store for MissionMemoryStore, keyed by the hunt/session UUID.
// Replaces /tmp filesystem snapshots — survives container restarts and redeploys.
export const missionMemorySnapshots = pgTable("mission_memory_snapshots", {
  id: serial("id").primaryKey(),
  huntId: varchar("hunt_id", { length: 128 }).notNull().unique(),
  snapshot: jsonb("snapshot").notNull().default({}),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (t) => ({
  huntIdIdx: uniqueIndex("mission_memory_hunt_id_idx").on(t.huntId),
}));

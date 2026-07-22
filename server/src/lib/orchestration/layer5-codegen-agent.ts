import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';

const execAsync = promisify(exec);

abstract class BaseMetaAgent {
  abstract type: string;
  abstract confidenceThreshold: number;
  abstract supportedTools: string[];

  async execute(
    agentId: string,
    task: { tool: string; target: string; parameters: Record<string, any> }
  ): Promise<{ success: boolean; result?: any; error?: string }> {
    console.log(`[${this.type}] Executing ${task.tool} on ${task.target}`);
    const startTime = Date.now();
    try {
      const result = await this.runTool(task.tool, task.target, task.parameters);
      const duration = Date.now() - startTime;
      console.log(`[${this.type}] ${task.tool} completed in ${duration}ms`);
      return { success: true, result };
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`[${this.type}] ${task.tool} failed after ${duration}ms:`, error);
      return { success: false, error: (error as Error).message };
    }
  }

  abstract runTool(
    tool: string,
    target: string,
    params: Record<string, any>
  ): Promise<any>;
}

export interface ModificationRequest {
  id: string;
  type: 'add_feature' | 'fix_bug' | 'refactor' | 'optimize' | 'integrate' | 'test' | 'document';
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  affectedFiles: string[];
  estimatedComplexity: 'trivial' | 'simple' | 'moderate' | 'complex' | 'critical';
  requiresApproval: boolean;
  createdAt: number;
  status: 'pending' | 'analyzing' | 'generating' | 'awaiting_approval' | 'approved' | 'applied' | 'rejected' | 'failed';
  rejectionReason?: string;
}

export interface CodeChange {
  id: string;
  requestId: string;
  file: string;
  operation: 'create' | 'modify' | 'delete';
  oldContent?: string;
  newContent?: string;
  diff?: string;
  confidence: number;
  reasoning: string[];
}

export interface ModificationResult {
  requestId: string;
  success: boolean;
  changes: CodeChange[];
  testsPass: boolean;
  commitHash?: string;
  error?: string;
  appliedAt?: number;
}

export interface Suggestion {
  id: string;
  type: 'missing_error_handling' | 'undocumented_function' | 'unused_import' | 'performance' | 'security' | 'code_quality' | 'accessibility' | 'type_safety';
  severity: 'info' | 'warning' | 'important';
  file: string;
  line?: number;
  description: string;
  suggestedFix?: string;
  createdAt: number;
  status: 'pending' | 'applied' | 'dismissed';
}

export const RESTRICTED_PATHS = [
  'node_modules/',
  '.git/',
  'package-lock.json',
  '.env',
  '.replit',
];

/**
 * 2026-07-22 (inbound-audit Phase 1, item #2): RESTRICTED_PATHS is a
 * substring BLOCKLIST, not a traversal check — path.resolve(cwd, target)
 * on a target like "../../../etc/cron.d/x" walks straight past every entry
 * above and out of the project directory entirely, since none of those
 * substrings appear in the resolved path. Currently dormant (codegenAgent
 * — the instance with these file tools — has zero live callers anywhere in
 * the codebase as of the Phase 2 chokepoint cleanup; only its metadata,
 * codegenAgentMeta, is still referenced), but a blocklist that doesn't
 * actually check for traversal is wrong on principle regardless of current
 * reachability. resolveWithinBase() replaces the blocklist-only check with
 * a real containment check: resolve, then verify the result is still
 * inside `base` using a path-separator-bounded prefix comparison (a naive
 * string startsWith("/home/kali/project") would wrongly also allow
 * "/home/kali/project-evil" — the separator suffix on both sides closes
 * that off). Returns null (not a path) if it would escape.
 */
export function resolveWithinBase(base: string, target: string): string | null {
  const resolvedBase = path.resolve(base);
  const resolved = path.resolve(resolvedBase, target);
  const baseWithSep = resolvedBase.endsWith(path.sep) ? resolvedBase : resolvedBase + path.sep;
  if (resolved !== resolvedBase && !resolved.startsWith(baseWithSep)) {
    return null;
  }
  return resolved;
}

export const MODIFICATION_LEVELS: Record<string, { threshold: number; autoApprove: boolean; examples: string[] }> = {
  trivial: {
    threshold: 0.7,
    autoApprove: true,
    examples: ['Fix typo', 'Update text content', 'Change CSS color'],
  },
  simple: {
    threshold: 0.8,
    autoApprove: true,
    examples: ['Add button', 'Fix simple null check', 'Update style'],
  },
  moderate: {
    threshold: 0.85,
    autoApprove: false,
    examples: ['Add new component', 'New utility function', 'Refactor file'],
  },
  complex: {
    threshold: 0.9,
    autoApprove: false,
    examples: ['New feature with multiple files', 'Architecture change', 'API integration'],
  },
  critical: {
    threshold: 0.95,
    autoApprove: false,
    examples: ['Security patch', 'Database schema change', 'Auth system modification'],
  },
};

export class CodeGenAgent extends BaseMetaAgent {
  type = 'codegen';
  confidenceThreshold = 0.85;
  supportedTools = ['file_create', 'file_edit', 'file_read', 'file_delete', 'git_commit', 'npm_install', 'typescript_check'];

  isPathRestricted(filePath: string): boolean {
    const normalized = filePath.replace(/\\/g, '/');
    return RESTRICTED_PATHS.some(restricted => normalized.includes(restricted));
  }

  assessComplexity(description: string, fileCount: number): 'trivial' | 'simple' | 'moderate' | 'complex' | 'critical' {
    const lower = description.toLowerCase();

    if (lower.includes('typo') || lower.includes('text') || lower.includes('color') || lower.includes('comment')) {
      return 'trivial';
    }
    if (lower.includes('button') || lower.includes('style') || lower.includes('css') || lower.includes('simple')) {
      return 'simple';
    }
    if (lower.includes('security') || lower.includes('auth') || lower.includes('database') || lower.includes('schema')) {
      return 'critical';
    }
    if (fileCount > 5 || lower.includes('architecture') || lower.includes('refactor') || lower.includes('integration')) {
      return 'complex';
    }
    return 'moderate';
  }

  assessPriority(type: string, description: string): 'low' | 'medium' | 'high' | 'critical' {
    const lower = description.toLowerCase();
    if (lower.includes('security') || lower.includes('vulnerability') || lower.includes('exploit')) return 'critical';
    if (lower.includes('bug') || lower.includes('fix') || lower.includes('error') || lower.includes('crash')) return 'high';
    if (type === 'optimize' || type === 'refactor') return 'medium';
    return 'low';
  }

  async runTool(tool: string, target: string, params: Record<string, any>): Promise<any> {
    switch (tool) {
      case 'file_read': {
        if (this.isPathRestricted(target)) {
          return { success: false, error: `Path restricted: ${target}` };
        }
        const filePath = resolveWithinBase(process.cwd(), target);
        if (!filePath) {
          return { success: false, error: `Path escapes project directory: ${target}` };
        }
        try {
          const content = await fs.readFile(filePath, 'utf-8');
          return { success: true, content, file: target };
        } catch (error: any) {
          return { success: false, error: error.message };
        }
      }

      case 'file_create': {
        if (this.isPathRestricted(target)) {
          return { success: false, error: `Path restricted: ${target}` };
        }
        const createPath = resolveWithinBase(process.cwd(), target);
        if (!createPath) {
          return { success: false, error: `Path escapes project directory: ${target}` };
        }
        const dir = path.dirname(createPath);
        await fs.mkdir(dir, { recursive: true });
        await fs.writeFile(createPath, params.content || '', 'utf-8');
        return { success: true, file: target, operation: 'created' };
      }

      case 'file_edit': {
        if (this.isPathRestricted(target)) {
          return { success: false, error: `Path restricted: ${target}` };
        }
        const editPath = resolveWithinBase(process.cwd(), target);
        if (!editPath) {
          return { success: false, error: `Path escapes project directory: ${target}` };
        }
        await fs.writeFile(editPath, params.content || '', 'utf-8');
        return { success: true, file: target, operation: 'modified' };
      }

      case 'file_delete': {
        if (this.isPathRestricted(target)) {
          return { success: false, error: `Path restricted: ${target}` };
        }
        const deletePath = resolveWithinBase(process.cwd(), target);
        if (!deletePath) {
          return { success: false, error: `Path escapes project directory: ${target}` };
        }
        await fs.unlink(deletePath);
        return { success: true, file: target, operation: 'deleted' };
      }

      case 'typescript_check': {
        try {
          const { stdout, stderr } = await execAsync('npx tsc --noEmit --pretty 2>&1 | head -50', { timeout: 30000 });
          const hasErrors = stderr.includes('error TS') || stdout.includes('error TS');
          return { success: !hasErrors, output: stdout || stderr, hasErrors };
        } catch (error: any) {
          return { success: false, output: error.stdout || error.message, hasErrors: true };
        }
      }

      default:
        return { success: false, error: `Unknown tool: ${tool}` };
    }
  }
}

export const codegenAgentMeta = {
  id: 'codegen',
  name: 'Code Generation Agent',
  description: 'Self-modification agent that generates, modifies, and improves code within the IDE. Enables continuous evolution with approval-gated changes, risk classification, and improvement suggestions.',
  capabilities: [
    'component_generation',
    'function_generation',
    'bug_fixing',
    'refactoring',
    'integration_addition',
    'test_generation',
    'documentation_generation',
    'performance_optimization',
    'dependency_management',
    'improvement_suggestions',
    'self_modification',
  ],
  tools: ['file_create', 'file_edit', 'file_read', 'file_delete', 'git_commit', 'npm_install', 'typescript_check'],
  promptTemplate: 'codegen_modify',
  confidenceThreshold: 0.85,
  securityControls: {
    autoRedaction: false,
    prioritizeAdmins: false,
    rateLimitBruteforce: false,
    logCredentialSource: false,
  },
};

export const codegenAgent = new CodeGenAgent();

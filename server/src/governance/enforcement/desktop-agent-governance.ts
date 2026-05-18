import { v4 as uuidv4 } from 'uuid';
import * as path from 'path';
import {
  PathValidationResult,
  CommandValidationResult,
  RiskLevel,
  GovernancePillar,
  GovernanceDecision
} from '../types';
import { CoreGovernance } from '../core-governance';

const BLOCKED_PATHS = [
  '/dev/sd', '/dev/nvme', '/dev/mem', '/dev/kmem',
  '/boot/', '/proc/kcore', '/sys/firmware',
  '/etc/shadow', '/etc/passwd', '/etc/sudoers',
  '/root/.ssh', '/home/*/.ssh',
  '/var/log/auth', '/var/log/secure'
];

const WORKSPACE_ROOT = path.join(process.cwd(), 'workspace');

const DESTRUCTIVE_COMMANDS = [
  'rm -rf /', 'rm -rf /*', 'dd if=', 'mkfs',
  'fdisk', 'parted', 'format', ':(){:|:&};:',
  'shutdown', 'reboot', 'poweroff', 'halt',
  'init 0', 'init 6', 'systemctl poweroff',
  '> /dev/sd', 'chmod -R 777 /', 'chown -R',
  'iptables -F', 'iptables --flush',
  'kill -9 1', 'kill -9 -1',
  'modprobe', 'insmod', 'rmmod',
  'echo > /proc/', 'echo > /sys/'
];

const HIGH_RISK_COMMANDS = [
  'curl.*|.*sh', 'wget.*|.*sh', 'bash -c',
  'python -c', 'python3 -c', 'perl -e',
  'nc -l', 'ncat -l', 'socat',
  'ssh-keygen', 'ssh-copy-id',
  'passwd', 'useradd', 'userdel', 'usermod',
  'crontab', 'at ', 'systemctl',
  'apt install', 'apt remove', 'dpkg -i',
  'pip install', 'npm install -g'
];

const ALLOWED_TOOLS = new Set([
  'nmap', 'sqlmap', 'nikto', 'nuclei', 'gobuster', 'ffuf',
  'subfinder', 'amass', 'whatweb', 'masscan', 'hydra', 'john',
  'aircrack-ng', 'wpscan', 'dirb', 'dirsearch',
  'curl', 'wget', 'python3', 'ruby', 'perl', 'git',
  'hashcat', 'burpsuite', 'metasploit', 'msfconsole',
  'wfuzz', 'feroxbuster', 'httpx', 'katana', 'gau'
]);

export class DesktopAgentGovernance {
  private governance: CoreGovernance;

  constructor(governance: CoreGovernance) {
    this.governance = governance;
  }

  validatePath(filePath: string, agentId: string, agentName: string): PathValidationResult {
    const normalized = path.resolve(filePath);

    for (const blocked of BLOCKED_PATHS) {
      if (blocked.includes('*')) {
        const pattern = blocked.replace(/\*/g, '[^/]+');
        if (new RegExp(pattern).test(normalized)) {
          this.governance.recordDecision({
            agentId,
            agentName,
            action: `Access path: ${filePath}`,
            actionType: 'filesystem',
            verdict: 'blocked',
            pillar: 'Pillar 4 - Hardware Sovereignty',
            confidence: 1.0,
            reason: `Path "${normalized}" matches blocked pattern: ${blocked}`,
            coachMessage: `Access to ${normalized} is blocked to protect system integrity.`
          });
          return { valid: false, reason: `Blocked path: matches ${blocked}` };
        }
      } else if (normalized.startsWith(blocked)) {
        this.governance.recordDecision({
          agentId,
          agentName,
          action: `Access path: ${filePath}`,
          actionType: 'filesystem',
          verdict: 'blocked',
          pillar: 'Pillar 4 - Hardware Sovereignty',
          confidence: 1.0,
          reason: `Path "${normalized}" is in blocked zone: ${blocked}`,
          coachMessage: `Access to ${normalized} is blocked to protect system hardware and sensitive files.`
        });
        return { valid: false, reason: `Blocked path zone: ${blocked}` };
      }
    }

    if (normalized.includes('..')) {
      this.governance.recordDecision({
        agentId,
        agentName,
        action: `Access path: ${filePath}`,
        actionType: 'filesystem',
        verdict: 'blocked',
        pillar: 'Pillar 1 - Kinetic Clause',
        confidence: 0.9,
        reason: 'Path traversal detected',
        coachMessage: 'Path traversal (..) is not allowed for agent operations.'
      });
      return { valid: false, reason: 'Path traversal detected' };
    }

    this.governance.recordDecision({
      agentId,
      agentName,
      action: `Access path: ${filePath}`,
      actionType: 'filesystem',
      verdict: 'approved',
      pillar: 'Pillar 1 - Kinetic Clause',
      confidence: 0.95,
      reason: `Path "${normalized}" passed validation`,
      coachMessage: `File access approved: ${normalized}`
    });

    return { valid: true, sanitizedPath: normalized };
  }

  validateCommand(command: string, agentId: string, agentName: string, huntId?: string): CommandValidationResult {
    const normalizedCmd = command.trim().toLowerCase();

    for (const destructive of DESTRUCTIVE_COMMANDS) {
      if (normalizedCmd.includes(destructive.toLowerCase())) {
        this.governance.recordDecision({
          agentId,
          agentName,
          action: `Execute command: ${command}`,
          actionType: 'command',
          verdict: 'blocked',
          pillar: 'Pillar 1 - Kinetic Clause',
          confidence: 1.0,
          reason: `Destructive command pattern detected: ${destructive}`,
          coachMessage: `This command is destructive and has been blocked: ${destructive}`,
          replay: { toolCommand: command },
          huntId
        });
        return {
          valid: false,
          risk: 'critical',
          reason: `Destructive command blocked: ${destructive}`
        };
      }
    }

    for (const risky of HIGH_RISK_COMMANDS) {
      const pattern = new RegExp(risky, 'i');
      if (pattern.test(normalizedCmd)) {
        this.governance.recordDecision({
          agentId,
          agentName,
          action: `Execute command: ${command}`,
          actionType: 'command',
          verdict: 'modified',
          pillar: 'Pillar 1 - Kinetic Clause',
          confidence: 0.7,
          reason: `High-risk command pattern detected: ${risky}`,
          coachMessage: `This command requires extra review. Pattern flagged: ${risky}`,
          replay: { toolCommand: command },
          huntId
        });
        return {
          valid: true,
          risk: 'high',
          reason: `High-risk pattern: ${risky}`,
          sanitizedCommand: command
        };
      }
    }

    if (normalizedCmd.includes('|') || normalizedCmd.includes('&&') || normalizedCmd.includes(';')) {
      const chainCount = (command.match(/[|&;]/g) || []).length;
      if (chainCount > 5) {
        this.governance.recordDecision({
          agentId,
          agentName,
          action: `Execute command: ${command.substring(0, 100)}...`,
          actionType: 'command',
          verdict: 'modified',
          pillar: 'Pillar 2 - Recursive Loop',
          confidence: 0.6,
          reason: `Long command chain detected (${chainCount} operators)`,
          coachMessage: 'Long command chains can be dangerous. Consider breaking this into separate commands.',
          replay: { toolCommand: command },
          huntId
        });
        return {
          valid: true,
          risk: 'medium',
          reason: `Long command chain (${chainCount} operators)`,
          sanitizedCommand: command
        };
      }
    }

    this.governance.recordDecision({
      agentId,
      agentName,
      action: `Execute command: ${command.substring(0, 100)}`,
      actionType: 'command',
      verdict: 'approved',
      pillar: 'Pillar 1 - Kinetic Clause',
      confidence: 0.9,
      reason: 'Command passed validation checks',
      coachMessage: 'Command approved for execution.',
      replay: { toolCommand: command },
      huntId
    });

    return {
      valid: true,
      risk: 'low',
      sanitizedCommand: command
    };
  }

  validateTool(toolName: string, args: string[], agentId: string, agentName: string, huntId?: string): {
    allowed: boolean;
    risk: RiskLevel;
    reason: string;
  } {
    const normalizedTool = toolName.toLowerCase().trim();

    if (!ALLOWED_TOOLS.has(normalizedTool)) {
      this.governance.recordDecision({
        agentId,
        agentName,
        action: `Use tool: ${toolName}`,
        actionType: 'tool',
        verdict: 'blocked',
        pillar: 'Safety Controls',
        confidence: 0.95,
        reason: `Tool "${toolName}" is not in the allowed tools list`,
        coachMessage: `The tool "${toolName}" is not approved for use. Allowed tools: ${Array.from(ALLOWED_TOOLS).join(', ')}`,
        huntId
      });
      return {
        allowed: false,
        risk: 'high',
        reason: `Tool not in allowed list: ${toolName}`
      };
    }

    const argsStr = args.join(' ');
    for (const target of args) {
      const scopeCheck = this.governance.verifyScope(target, huntId);
      if (!scopeCheck.inScope) {
        this.governance.recordDecision({
          agentId,
          agentName,
          action: `Use tool: ${toolName} against ${target}`,
          actionType: 'tool',
          verdict: 'blocked',
          pillar: 'Pillar 3 - Ethical Boundary',
          confidence: 1.0,
          reason: `Target "${target}" is out of scope`,
          coachMessage: `Cannot use ${toolName} against ${target} - target is out of scope.`,
          huntId
        });
        return {
          allowed: false,
          risk: 'critical',
          reason: `Out of scope target: ${target}`
        };
      }
    }

    let risk: RiskLevel = 'low';
    if (['metasploit', 'msfconsole', 'hydra', 'john', 'hashcat'].includes(normalizedTool)) {
      risk = 'high';
    } else if (['sqlmap', 'wfuzz', 'nikto'].includes(normalizedTool)) {
      risk = 'medium';
    }

    this.governance.recordDecision({
      agentId,
      agentName,
      action: `Use tool: ${toolName} ${argsStr.substring(0, 80)}`,
      actionType: 'tool',
      verdict: 'approved',
      pillar: 'Pillar 1 - Kinetic Clause',
      confidence: 0.85,
      reason: `Tool "${toolName}" approved with risk level: ${risk}`,
      coachMessage: `Tool "${toolName}" approved for use.`,
      replay: { toolCommand: `${toolName} ${argsStr}` },
      huntId
    });

    return { allowed: true, risk, reason: 'Tool approved' };
  }

  getAllowedTools(): string[] {
    return Array.from(ALLOWED_TOOLS);
  }
}

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import { stealthLogger } from './stealth-logger';

const TEMP_PATTERNS = [
  'sentinel-*',
  'agent-*',
  'stealth-*',
  'training-*',
  'payload-*',
  'recon-*',
  'exploit-*',
];

const TOOL_LOG_PATHS: { name: string; path: string; isGlob?: boolean }[] = [
  { name: 'metasploit', path: path.join(process.env.HOME || '~', '.msf4', 'logs') },
  { name: 'nmap', path: '/tmp/nmap-*', isGlob: true },
  { name: 'sqlmap', path: path.join(process.env.HOME || '~', '.sqlmap', 'output') },
  { name: 'nikto', path: '/tmp/nikto-*', isGlob: true },
  { name: 'gobuster', path: '/tmp/gobuster-*', isGlob: true },
];

const isRealTools = () => process.env.REAL_TOOLS === 'true';

function globMatch(pattern: string): string[] {
  try {
    const dir = path.dirname(pattern);
    const prefix = path.basename(pattern).replace('*', '');
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir)
      .filter(f => f.startsWith(prefix))
      .map(f => path.join(dir, f));
  } catch {
    return [];
  }
}

function deleteRecursive(targetPath: string): boolean {
  try {
    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      fs.rmSync(targetPath, { recursive: true, force: true });
    } else {
      fs.unlinkSync(targetPath);
    }
    return true;
  } catch {
    return false;
  }
}

class CleanupManager {
  private totalCleanups: number = 0;
  private filesDeleted: number = 0;
  private lastCleanup: string | null = null;
  private scheduledTimer: ReturnType<typeof setTimeout> | null = null;

  cleanTempFiles(): string[] {
    const deleted: string[] = [];

    for (const pattern of TEMP_PATTERNS) {
      const fullPattern = path.join('/tmp', pattern);
      const matches = globMatch(fullPattern);
      for (const file of matches) {
        try {
          if (deleteRecursive(file)) {
            deleted.push(file);
            stealthLogger.log('tool_execution', { action: 'cleanTempFile', file });
          }
        } catch (err) {
          if (isRealTools()) {
            console.error(`[CleanupManager] Failed to delete ${file}:`, err);
          }
        }
      }
    }

    return deleted;
  }

  cleanBashHistory(): boolean {
    const home = process.env.HOME || '~';
    const historyFiles = [
      path.join(home, '.bash_history'),
      path.join(home, '.zsh_history'),
    ];

    let cleared = false;

    for (const file of historyFiles) {
      try {
        if (fs.existsSync(file)) {
          fs.writeFileSync(file, '');
          stealthLogger.log('tool_execution', { action: 'cleanBashHistory', file });
          cleared = true;
        }
      } catch (err) {
        if (isRealTools()) {
          console.error(`[CleanupManager] Failed to clear ${file}:`, err);
        }
      }
    }

    return cleared;
  }

  cleanToolLogs(): string[] {
    const deleted: string[] = [];

    for (const tool of TOOL_LOG_PATHS) {
      try {
        if (tool.isGlob) {
          const matches = globMatch(tool.path);
          for (const file of matches) {
            if (deleteRecursive(file)) {
              deleted.push(file);
            }
          }
        } else {
          if (fs.existsSync(tool.path)) {
            if (deleteRecursive(tool.path)) {
              deleted.push(tool.path);
            }
          }
        }
      } catch (err) {
        if (isRealTools()) {
          console.error(`[CleanupManager] Failed to clean ${tool.name} logs:`, err);
        }
      }
    }

    if (deleted.length > 0) {
      stealthLogger.log('tool_execution', { action: 'cleanToolLogs', deleted });
    }

    return deleted;
  }

  cleanClipboard(): boolean {
    try {
      try {
        execSync('echo -n "" | xclip -selection clipboard 2>/dev/null', { stdio: 'ignore' });
        stealthLogger.log('tool_execution', { action: 'cleanClipboard', method: 'xclip' });
        return true;
      } catch {
        try {
          execSync('echo -n "" | xsel --clipboard --input 2>/dev/null', { stdio: 'ignore' });
          stealthLogger.log('tool_execution', { action: 'cleanClipboard', method: 'xsel' });
          return true;
        } catch {
          return false;
        }
      }
    } catch {
      return false;
    }
  }

  archiveLogs(destPath: string, encryptionKey?: string): { archivedFiles: string[]; encrypted: boolean } {
    const archivedFiles: string[] = [];
    const encrypted = !!encryptionKey;

    try {
      fs.mkdirSync(destPath, { recursive: true });
    } catch (err) {
      if (isRealTools()) {
        console.error(`[CleanupManager] Failed to create archive dir:`, err);
      }
      return { archivedFiles, encrypted: false };
    }

    const logsDir = path.join(process.cwd(), 'logs', 'stealth');
    const replayDir = path.join(logsDir, 'replay');
    const sourceDirs = [logsDir, replayDir];

    for (const sourceDir of sourceDirs) {
      try {
        if (!fs.existsSync(sourceDir)) continue;
        const files = fs.readdirSync(sourceDir);
        for (const file of files) {
          const filePath = path.join(sourceDir, file);
          try {
            const stat = fs.statSync(filePath);
            if (!stat.isFile()) continue;

            const content = fs.readFileSync(filePath);
            const relativePath = path.relative(path.join(process.cwd(), 'logs'), filePath);
            const destFile = path.join(destPath, relativePath);

            fs.mkdirSync(path.dirname(destFile), { recursive: true });

            if (encryptionKey) {
              const iv = crypto.randomBytes(12);
              const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(encryptionKey.padEnd(32, '0').slice(0, 32)), iv);
              const encrypted = Buffer.concat([cipher.update(content), cipher.final()]);
              const authTag = cipher.getAuthTag();
              const output = Buffer.concat([iv, authTag, encrypted]);
              const encDest = destFile + '.enc';
              fs.writeFileSync(encDest, output);
              archivedFiles.push(encDest);
            } else {
              fs.copyFileSync(filePath, destFile);
              archivedFiles.push(destFile);
            }
          } catch (err) {
            if (isRealTools()) {
              console.error(`[CleanupManager] Failed to archive ${file}:`, err);
            }
          }
        }
      } catch (err) {
        if (isRealTools()) {
          console.error(`[CleanupManager] Failed to read source dir:`, err);
        }
      }
    }

    stealthLogger.log('tool_execution', {
      action: 'archiveLogs',
      destPath,
      archivedFiles: archivedFiles.length,
      encrypted,
    });

    return { archivedFiles, encrypted };
  }

  scheduleCleanup(delayMs: number = 5000): void {
    this.cancelScheduledCleanup();
    this.scheduledTimer = setTimeout(() => {
      this.cleanup();
      this.scheduledTimer = null;
    }, delayMs);
    stealthLogger.log('tool_execution', { action: 'scheduleCleanup', delayMs });
  }

  cancelScheduledCleanup(): void {
    if (this.scheduledTimer) {
      clearTimeout(this.scheduledTimer);
      this.scheduledTimer = null;
      stealthLogger.log('tool_execution', { action: 'cancelScheduledCleanup' });
    }
  }

  cleanup(options?: {
    skipArchive?: boolean;
    skipHistory?: boolean;
    skipClipboard?: boolean;
  }): { deleted: string[]; errors: string[]; archived: string[] } {
    const deleted: string[] = [];
    const errors: string[] = [];
    let archived: string[] = [];

    if (!options?.skipArchive) {
      try {
        const archivePath = path.join(process.cwd(), 'logs', 'archive', new Date().toISOString().split('T')[0]);
        const result = this.archiveLogs(archivePath);
        archived = result.archivedFiles;
      } catch (err) {
        errors.push(`Archive failed: ${err}`);
      }
    }

    try {
      const tempDeleted = this.cleanTempFiles();
      deleted.push(...tempDeleted);
    } catch (err) {
      errors.push(`Temp cleanup failed: ${err}`);
    }

    if (!options?.skipHistory) {
      try {
        this.cleanBashHistory();
      } catch (err) {
        errors.push(`History cleanup failed: ${err}`);
      }
    }

    try {
      const toolDeleted = this.cleanToolLogs();
      deleted.push(...toolDeleted);
    } catch (err) {
      errors.push(`Tool logs cleanup failed: ${err}`);
    }

    if (!options?.skipClipboard) {
      try {
        this.cleanClipboard();
      } catch (err) {
        errors.push(`Clipboard cleanup failed: ${err}`);
      }
    }

    this.totalCleanups++;
    this.filesDeleted += deleted.length;
    this.lastCleanup = new Date().toISOString();

    stealthLogger.log('tool_execution', {
      action: 'cleanup',
      deleted: deleted.length,
      errors: errors.length,
      archived: archived.length,
    });

    return { deleted, errors, archived };
  }

  getStats(): { totalCleanups: number; filesDeleted: number; lastCleanup: string | null } {
    return {
      totalCleanups: this.totalCleanups,
      filesDeleted: this.filesDeleted,
      lastCleanup: this.lastCleanup,
    };
  }
}

export const cleanupManager = new CleanupManager();

/**
 * Synthetic-fixture proof for scripts/check-tool-exec.ts — the CI guard for
 * the external-tool-execution chokepoint. Feeds synthetic file contents
 * directly to the guard's exported scanContent() so every invocation form
 * it claims to catch is actually proven, not assumed. A guard that misses a
 * form is false structural confidence — per the axios/browser guards' own
 * track record of missing a form (dynamic import, launchPersistentContext)
 * on the first pass, this file exists so check-tool-exec.ts doesn't repeat
 * that mistake silently.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { scanContent } from '../lib/net/tool-exec-scan';

const FAKE_PATH = 'lib/tools/some-new-tool.ts'; // not on either allowlist

describe('check-tool-exec — exec/execSync import forms (unconditional violation)', () => {
  it('named import: import { exec } from "child_process"', () => {
    const src = `import { exec } from 'child_process';\nexec('whatweb ' + target, cb);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('named import with rename: import { exec as runShell } from "child_process"', () => {
    const src = `import { exec as runShell } from 'child_process';\nrunShell(cmd);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('named import, execSync specifically', () => {
    const src = `import { execSync } from 'child_process';\nexecSync(\`nikto -h \${target}\`);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('namespace import: import * as cp from "child_process"; cp.exec(...)', () => {
    const src = `import * as cp from 'child_process';\ncp.exec(\`sqlmap -u "\${target}"\`);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('require namespace: const cp = require("child_process"); cp.execSync(...)', () => {
    const src = `const cp = require('child_process');\ncp.execSync(cmd);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('require named: const { execSync } = require("child_process")', () => {
    const src = `const { execSync } = require('child_process');\nexecSync(cmd);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('dynamic import named: const { exec } = await import("child_process") — the exact bounty-intelligence pattern', () => {
    const src = `async function f() {\n  const { exec } = await import('child_process');\n  exec(\`subfinder -d \${domain}\`);\n}\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('dynamic import namespace: const cp = await import("child_process"); cp.exec(...)', () => {
    const src = `async function f() {\n  const cp = await import('child_process');\n  cp.exec(cmd);\n}\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('promisify-wrapped exec is still flagged on the import, regardless of the wrapper (this.exec() aliasing case)', () => {
    const src = `import { exec } from 'child_process';\nimport { promisify } from 'util';\nconst execAsync = promisify(exec);\nclass A { async exec(cmd: string) { return execAsync(cmd); } }\n`;
    // No direct exec(...) call syntax anywhere visible except inside promisify() —
    // this is exactly the case a call-site-only regex would miss.
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('allowlisted file with the same static-string pattern as cleanup-manager.ts is NOT flagged', () => {
    const src = `import { execSync } from 'child_process';\nexecSync('echo -n "" | xclip -selection clipboard 2>/dev/null', { stdio: 'ignore' });\n`;
    expect(scanContent(src, 'lib/stealth/cleanup-manager.ts').length).toBe(0);
  });

  it('the SAME content at a non-allowlisted path IS flagged (proves the allowlist gate itself works, not just "always pass")', () => {
    const src = `import { execSync } from 'child_process';\nexecSync('echo -n "" | xclip -selection clipboard 2>/dev/null', { stdio: 'ignore' });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });
});

describe('check-tool-exec — execFile/spawn shell-invocation exception', () => {
  it("execFile('bash', ['-c', str]) — the sharp exception named explicitly — is flagged", () => {
    const src = `import { execFile } from 'child_process';\nexecFile('bash', ['-c', cmd], (e, out) => {});\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it("execFile('sh', ['-c', str]) is flagged", () => {
    const src = `import { execFile } from 'child_process';\nexecFile('sh', ['-c', cmd]);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it("execFile('/bin/bash', ['-c', str]) (absolute path form) is flagged", () => {
    const src = `import { execFile } from 'child_process';\nexecFile('/bin/bash', ['-c', cmd]);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('spawn(tool, args, { shell: true }) is flagged', () => {
    const src = `import { spawn } from 'child_process';\nspawn('nmap', [target], { shell: true });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('spawn(tool, args, { shell: "/bin/bash" }) (shell as a path string, not just true) is flagged', () => {
    const src = `import { spawn } from 'child_process';\nspawn('nmap', [target], { shell: '/bin/bash' });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('execFileSync/spawnSync variants are covered too', () => {
    expect(scanContent(`import { execFileSync } from 'child_process';\nexecFileSync('bash', ['-c', cmd]);\n`, FAKE_PATH).length).toBeGreaterThan(0);
    expect(scanContent(`import { spawnSync } from 'child_process';\nspawnSync('sh', ['-c', cmd]);\n`, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('namespace-import form of the shell exception: cp.execFile("bash", ["-c", str])', () => {
    const src = `import * as cp from 'child_process';\ncp.execFile('bash', ['-c', cmd]);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('a normal execFile/spawn call against a real tool binary with no shell option is NOT flagged', () => {
    const src = `import { execFile } from 'child_process';\nexecFile('nmap', ['-sV', target]);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBe(0);
  });

  it('spawn with array args and no shell option (the ZAP daemon pattern) is NOT flagged', () => {
    const src = `import { spawn } from 'child_process';\nspawn(bin, ['-daemon', '-port', String(port)], { detached: true });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBe(0);
  });
});

describe('check-tool-exec — regression: real project files scan clean/as-expected', () => {
  const SRC_ROOT = join(__dirname, '..', '..', 'src');

  it('dispatch-tool.ts (the chokepoint itself) produces zero violations', () => {
    const content = readFileSync(join(SRC_ROOT, 'lib/net/dispatch-tool.ts'), 'utf-8');
    expect(scanContent(content, 'lib/net/dispatch-tool.ts')).toEqual([]);
  });

  it('cleanup-manager.ts at its real path produces zero violations (allowlisted)', () => {
    const content = readFileSync(join(SRC_ROOT, 'lib/stealth/cleanup-manager.ts'), 'utf-8');
    expect(scanContent(content, 'lib/stealth/cleanup-manager.ts')).toEqual([]);
  });

  it('layer5-codegen-agent.ts at its real path produces zero violations (allowlisted)', () => {
    const content = readFileSync(join(SRC_ROOT, 'lib/orchestration/layer5-codegen-agent.ts'), 'utf-8');
    expect(scanContent(content, 'lib/orchestration/layer5-codegen-agent.ts')).toEqual([]);
  });
});

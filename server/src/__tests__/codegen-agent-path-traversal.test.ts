/**
 * layer5-codegen-agent.ts — path-traversal guard (inbound-audit Phase 1,
 * item #2). RESTRICTED_PATHS was a substring blocklist, not a traversal
 * check: path.resolve(cwd, "../../../etc/cron.d/x") walks straight past
 * every blocklist entry since none of those substrings appear in the
 * resolved path. resolveWithinBase() replaces it with a real containment
 * check. Confirmed dormant (codegenAgent has zero live callers as of the
 * Phase 2 chokepoint cleanup) but wrong on principle regardless — this
 * proves the fix works independent of reachability.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, rm, readFile, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { resolveWithinBase, codegenAgent } from '../lib/orchestration/layer5-codegen-agent';

describe('resolveWithinBase — pure containment check', () => {
  it('resolves a normal relative path inside the base', () => {
    expect(resolveWithinBase('/home/kali/project', 'src/index.ts')).toBe('/home/kali/project/src/index.ts');
  });

  it('rejects a traversal that escapes the base entirely', () => {
    expect(resolveWithinBase('/home/kali/project', '../../../etc/cron.d/x')).toBeNull();
  });

  it('rejects a sibling directory that merely shares a string prefix (the naive-startsWith bug this fix avoids)', () => {
    // "/home/kali/project-evil" starts with the string "/home/kali/project" but
    // is NOT inside it — a naive .startsWith(base) check would wrongly allow this.
    expect(resolveWithinBase('/home/kali/project', '../project-evil/x')).toBeNull();
  });

  it('allows the base directory itself', () => {
    expect(resolveWithinBase('/home/kali/project', '.')).toBe('/home/kali/project');
  });

  it('rejects an absolute path pointing outside the base', () => {
    expect(resolveWithinBase('/home/kali/project', '/etc/passwd')).toBeNull();
  });
});

describe('CodeGenAgent — file tools refuse to escape the project directory', () => {
  let tmpBase: string;
  const origCwd = process.cwd();

  beforeAll(async () => {
    tmpBase = await mkdtemp(join(tmpdir(), 'codegen-guard-test-'));
    process.chdir(tmpBase);
  });
  afterAll(async () => {
    process.chdir(origCwd);
    await rm(tmpBase, { recursive: true, force: true });
  });

  it('file_create refuses a traversal target and writes nothing outside the base', async () => {
    const outsideMarker = join(tmpBase, '..', 'codegen-guard-escape-proof.txt');
    const result = await codegenAgent.runTool('file_create', '../codegen-guard-escape-proof.txt', { content: 'pwned' });
    expect(result.success).toBe(false);
    expect(result.error).toContain('escapes project directory');
    await expect(readFile(outsideMarker, 'utf-8')).rejects.toThrow();
  });

  it('file_create succeeds for a normal in-base path', async () => {
    const result = await codegenAgent.runTool('file_create', 'inside.txt', { content: 'fine' });
    expect(result.success).toBe(true);
    expect(await readFile(join(tmpBase, 'inside.txt'), 'utf-8')).toBe('fine');
  });

  it('file_read refuses a traversal target', async () => {
    const result = await codegenAgent.runTool('file_read', '../../../etc/passwd', {});
    expect(result.success).toBe(false);
    expect(result.error).toContain('escapes project directory');
  });

  it('file_delete refuses a traversal target', async () => {
    const result = await codegenAgent.runTool('file_delete', '../../../etc/passwd', {});
    expect(result.success).toBe(false);
    expect(result.error).toContain('escapes project directory');
  });
});

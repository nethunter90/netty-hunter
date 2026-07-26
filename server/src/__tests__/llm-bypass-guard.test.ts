/**
 * Synthetic-fixture proof for scripts/check-llm-bypass.ts — the CI guard for
 * the LLM-spend chokepoint. Feeds synthetic file contents directly to the
 * guard's exported scanContent() so every invocation form it claims to catch
 * is actually proven, not assumed — same discipline as check-tool-exec-
 * guard.test.ts and scope-egress-chokepoint.test.ts for the other two
 * chokepoints.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { scanContent } from '../lib/llm/llm-invocation-scan';

const FAKE_PATH = 'agents/SomeNewAgent.ts'; // not on the allowlist

describe('check-llm-bypass — runtime import forms', () => {
  it('default import: import Anthropic from "@anthropic-ai/sdk"', () => {
    const src = `import Anthropic from '@anthropic-ai/sdk';\nconst c = new Anthropic({ apiKey: 'x' });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('namespace import: import * as AnthropicSDK from "@anthropic-ai/sdk"', () => {
    const src = `import * as AnthropicSDK from '@anthropic-ai/sdk';\nconst c = new AnthropicSDK.Anthropic({});\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('named import: import { Anthropic } from "@anthropic-ai/sdk"', () => {
    const src = `import { Anthropic } from '@anthropic-ai/sdk';\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('require: const Anthropic = require("@anthropic-ai/sdk")', () => {
    const src = `const Anthropic = require('@anthropic-ai/sdk');\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('dynamic import: await import("@anthropic-ai/sdk")', () => {
    const src = `async function f() {\n  const { default: Anthropic } = await import('@anthropic-ai/sdk');\n}\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('`import type` is allowed — no runtime construction capability, types-only use', () => {
    const src = `import type Anthropic from '@anthropic-ai/sdk';\nlet m: Anthropic.Message;\n`;
    expect(scanContent(src, FAKE_PATH)).toEqual([]);
  });
});

describe('check-llm-bypass — direct construction/call forms', () => {
  it('new Anthropic(...) construction is flagged even without a matching import line visible in this snippet', () => {
    const src = `const c = new Anthropic({ apiKey: process.env.KEY });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('.messages.create(...) direct call is flagged', () => {
    const src = `const r = await client.messages.create({ model: 'x', max_tokens: 1, messages: [] });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('.messages.stream(...) direct call is flagged too', () => {
    const src = `const r = client.messages.stream({ model: 'x', max_tokens: 1, messages: [] });\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('a namespace-aliased client (this.client.messages.create) is still caught — the exact LogicExploitAgent shape', () => {
    const src = `class Foo {\n  private readonly client = new Anthropic({});\n  async run() {\n    return this.client.messages.create({ model: 'x' });\n  }\n}\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('code with neither an SDK import nor a create/construct call is clean', () => {
    const src = `export function unrelated() { return 1 + 1; }\n`;
    expect(scanContent(src, FAKE_PATH)).toEqual([]);
  });
});

describe('check-llm-bypass — allowlist', () => {
  it('claude-client.ts at its real path produces zero violations', () => {
    const content = readFileSync(join(__dirname, '..', 'lib', 'claude-client.ts'), 'utf-8');
    expect(scanContent(content, 'lib/claude-client.ts')).toEqual([]);
  });

  it('the SAME content at a non-allowlisted path IS flagged (proves the allowlist gate itself works, not just "always pass")', () => {
    const content = readFileSync(join(__dirname, '..', 'lib', 'claude-client.ts'), 'utf-8');
    expect(scanContent(content, FAKE_PATH).length).toBeGreaterThan(0);
  });
});

describe('check-llm-bypass — subprocess-bridge shape (handoff C Phase 2)', () => {
  it('execFile("claude", ...) is flagged — the exact shape that caused the CLI-bridge $0-cost bug', () => {
    const src = `import { execFile } from 'child_process';\nexecFile('claude', ['--print', '-p', prompt], cb);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('spawn("claude", ...) is also flagged (not just execFile)', () => {
    const src = `import { spawn } from 'child_process';\nspawn('claude', ['-p', prompt]);\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('execFile of an unrelated binary is NOT flagged (the guard targets known model CLIs, not all subprocess exec)', () => {
    const src = `import { execFile } from 'child_process';\nexecFile('nmap', ['-sV', target], cb);\n`;
    expect(scanContent(src, FAKE_PATH)).toEqual([]);
  });

  it('bare exec(\'claude ...\') shell-string form is flagged — the seventh bypass (execFile/spawn substring-match does not cover it)', () => {
    const src = `import { exec } from 'child_process';\nexec('claude -p "hello"', () => {});\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('bare execSync(\'claude ...\') is also flagged', () => {
    const src = `import { execSync } from 'child_process';\nexecSync('claude -p "hello"');\n`;
    expect(scanContent(src, FAKE_PATH).length).toBeGreaterThan(0);
  });

  it('exec() of an unrelated shell command is NOT flagged', () => {
    const src = `import { exec } from 'child_process';\nexec('nmap -sV ' + target, cb);\n`;
    expect(scanContent(src, FAKE_PATH)).toEqual([]);
  });

  it('fork("claude", ...) is NOT flagged — confirmed live it cannot invoke the CLI binary (blocker #4)', () => {
    // fork() resolves its first arg as a Node.js MODULE PATH via require(),
    // not an executable — confirmed live: fork('claude', [...]) throws
    // MODULE_NOT_FOUND trying to load "claude" as a .js file, never reaching
    // a binary. Structurally incapable of being a model-CLI bridge, so
    // deliberately unmatched — this test documents that as a checked fact,
    // not an assumption the guard's comment merely asserts.
    const src = `import { fork } from 'child_process';\nfork('claude', ['-p', prompt]);\n`;
    expect(scanContent(src, FAKE_PATH)).toEqual([]);
  });

  it('claude-bridge.ts at its real path produces zero violations (the bridge chokepoint itself)', () => {
    const content = readFileSync(join(__dirname, '..', 'lib', 'claude-bridge.ts'), 'utf-8');
    expect(scanContent(content, 'lib/claude-bridge.ts')).toEqual([]);
  });

  it('the SAME claude-bridge.ts content at a non-allowlisted path IS flagged (proves the allowlist gate, not a pattern miss)', () => {
    const content = readFileSync(join(__dirname, '..', 'lib', 'claude-bridge.ts'), 'utf-8');
    expect(scanContent(content, FAKE_PATH).length).toBeGreaterThan(0);
  });
});

describe('check-llm-bypass — regression: real project files scan clean', () => {
  it('LogicExploitAgent.ts (the file the fix migrated off the SDK bypass) produces zero violations', () => {
    const content = readFileSync(join(__dirname, '..', 'agents', 'LogicExploitAgent.ts'), 'utf-8');
    expect(scanContent(content, 'agents/LogicExploitAgent.ts')).toEqual([]);
  });

  it("llm-invocation-scan.ts (this guard's own module, which describes the patterns in prose) produces zero violations", () => {
    const content = readFileSync(join(__dirname, '..', 'lib', 'llm', 'llm-invocation-scan.ts'), 'utf-8');
    expect(scanContent(content, 'lib/llm/llm-invocation-scan.ts')).toEqual([]);
  });
});

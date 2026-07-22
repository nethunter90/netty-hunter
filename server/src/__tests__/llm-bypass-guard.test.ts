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

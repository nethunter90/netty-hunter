/**
 * ClaudeClient — dollar/token spend accounting and the budget cap (C: budget
 * as an LLM-spend chokepoint). createMessage() is the shared SDK-invocation
 * primitive every caller (reason(), oneShot(), LogicExploitAgent's tool-use
 * loop and cache pre-warm) routes through — this proves the accounting and
 * cap logic living there, independent of any specific caller.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { createMock } = vi.hoisted(() => ({ createMock: vi.fn() }));

vi.mock('@anthropic-ai/sdk', () => {
  class Anthropic {
    apiKey: string;
    messages = { create: createMock };
    constructor(opts: { apiKey?: string }) { this.apiKey = opts.apiKey ?? ''; }
  }
  return { default: Anthropic };
});

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

vi.mock('../lib/runtime-config', () => ({
  runtimeConfig: { get: () => undefined },
}));

function usage(inputTokens: number, outputTokens: number, extra: Partial<{ cache_creation_input_tokens: number; cache_read_input_tokens: number }> = {}) {
  return { input_tokens: inputTokens, output_tokens: outputTokens, ...extra };
}

function mockResponse(text: string, u: ReturnType<typeof usage>) {
  return { content: [{ type: 'text', text }], usage: u, stop_reason: 'end_turn' };
}

let prevKey: string | undefined;
let prevCap: string | undefined;
let prevCallCap: string | undefined;

beforeEach(async () => {
  prevKey = process.env.ANTHROPIC_API_KEY;
  prevCap = process.env.MAX_LLM_USD_PER_HUNT;
  prevCallCap = process.env.MAX_LLM_CALLS_PER_HUNT;
  process.env.ANTHROPIC_API_KEY = 'sk-test-key-0123456789012345678901234567890';
  createMock.mockReset();
  vi.resetModules();
});
afterEach(() => {
  process.env.ANTHROPIC_API_KEY = prevKey;
  process.env.MAX_LLM_USD_PER_HUNT = prevCap;
  process.env.MAX_LLM_CALLS_PER_HUNT = prevCallCap;
});

describe('ClaudeClient.createMessage — dollar accounting', () => {
  it('records real cost from response.usage using the model pricing table', async () => {
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1_000_000, 1_000_000))); // 1M in, 1M out
    await ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, 'hunt-1', 100);
    const spend = ClaudeClient.getSpend('hunt-1');
    // sonnet-5: $2/M in + $10/M out = $12 for 1M/1M
    expect(spend.costUsd).toBeCloseTo(12, 5);
    expect(spend.callCount).toBe(1);
    expect(spend.inputTokens).toBe(1_000_000);
    expect(spend.outputTokens).toBe(1_000_000);
  });

  it('charges cache_creation and cache_read tokens at the input rate too (conservative overestimate)', async () => {
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(0, 0, { cache_creation_input_tokens: 500_000, cache_read_input_tokens: 500_000 })));
    await ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, 'hunt-cache', 100);
    const spend = ClaudeClient.getSpend('hunt-cache');
    // (500k + 500k) input-shaped tokens = 1M @ $2/M = $2, no output tokens
    expect(spend.costUsd).toBeCloseTo(2, 5);
  });

  it('accumulates spend across multiple calls for the same session', async () => {
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(100_000, 100_000))); // $0.2 + $1 = $1.2 each (sonnet-5)
    await ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, 'hunt-accum', 10);
    await ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, 'hunt-accum', 10);
    expect(ClaudeClient.getSpend('hunt-accum').callCount).toBe(2);
    expect(ClaudeClient.getSpend('hunt-accum').costUsd).toBeCloseTo(2.4, 5);
  });

  it('an unrecognized model falls back to a conservative (Opus-tier) price rather than under-costing', async () => {
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1_000_000, 1_000_000)));
    await ClaudeClient.createMessage({ model: 'some-future-model', max_tokens: 10, messages: [] }, 'hunt-unknown', 10);
    // fallback: $3/M in + $15/M out = $18
    expect(ClaudeClient.getSpend('hunt-unknown').costUsd).toBeCloseTo(18, 5);
  });

  it('sessionId=undefined still records spend, under the shared uncapped bucket', async () => {
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1_000_000, 0)));
    await ClaudeClient.createMessage({ model: 'claude-haiku-4-5', max_tokens: 10, messages: [] }, undefined, 10);
    expect(ClaudeClient.getSpend(ClaudeClient.UNCAPPED_BUCKET).costUsd).toBeCloseTo(1, 5); // haiku $1/M in
  });
});

describe('ClaudeClient.createMessage — dollar cap enforcement (fail closed)', () => {
  it('blocks a call once the hunt dollar cap is exceeded, before making the real request', async () => {
    process.env.MAX_LLM_USD_PER_HUNT = '1.00';
    const { ClaudeClient, LLMDollarBudgetExceededError } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1_000_000, 0))); // sonnet-5: $2, over the $1 cap immediately
    await ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, 'hunt-cap', 10);
    expect(createMock).toHaveBeenCalledTimes(1);

    await expect(
      ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, 'hunt-cap', 10)
    ).rejects.toThrow(LLMDollarBudgetExceededError);
    // the second call never reached the SDK
    expect(createMock).toHaveBeenCalledTimes(1);
  });

  it('a sessionId that never exceeds the cap is never blocked', async () => {
    process.env.MAX_LLM_USD_PER_HUNT = '100.00';
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1000, 1000)));
    await expect(ClaudeClient.createMessage({ model: 'claude-haiku-4-5', max_tokens: 10, messages: [] }, 'hunt-fine', 10)).resolves.toBeDefined();
  });

  it('uncapped-bucket calls (no sessionId) are NEVER blocked by the dollar cap, however much accumulates', async () => {
    process.env.MAX_LLM_USD_PER_HUNT = '0.01';
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1_000_000, 1_000_000))); // $12/call, way over a 1-cent cap
    await ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, undefined, 10);
    await expect(
      ClaudeClient.createMessage({ model: 'claude-sonnet-5', max_tokens: 10, messages: [] }, undefined, 10)
    ).resolves.toBeDefined();
    expect(createMock).toHaveBeenCalledTimes(2);
  });
});

describe('ClaudeClient — call-count cap remains a secondary guard', () => {
  it('still blocks on call count even when well under the dollar cap', async () => {
    process.env.MAX_LLM_CALLS_PER_HUNT = '2';
    process.env.MAX_LLM_USD_PER_HUNT = '1000';
    const { ClaudeClient, LLMBudgetExceededError } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1, 1)));
    await ClaudeClient.createMessage({ model: 'claude-haiku-4-5', max_tokens: 10, messages: [] }, 'hunt-count', 1);
    await ClaudeClient.createMessage({ model: 'claude-haiku-4-5', max_tokens: 10, messages: [] }, 'hunt-count', 1);
    await expect(
      ClaudeClient.createMessage({ model: 'claude-haiku-4-5', max_tokens: 10, messages: [] }, 'hunt-count', 1)
    ).rejects.toThrow(LLMBudgetExceededError);
  });
});

describe('ClaudeClient.clearSession — clears spend along with threads/callCounts', () => {
  it('getSpend returns zeroed state after clearSession', async () => {
    const { ClaudeClient } = await import('../lib/claude-client');
    createMock.mockResolvedValue(mockResponse('ok', usage(1000, 1000)));
    await ClaudeClient.createMessage({ model: 'claude-haiku-4-5', max_tokens: 10, messages: [] }, 'hunt-clear', 10);
    expect(ClaudeClient.getSpend('hunt-clear').callCount).toBe(1);
    ClaudeClient.clearSession('hunt-clear');
    expect(ClaudeClient.getSpend('hunt-clear')).toEqual({ callCount: 0, inputTokens: 0, outputTokens: 0, costUsd: 0 });
  });
});

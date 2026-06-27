/**
 * RuntimeConfig — individual key isolation.
 *
 * The Settings "clear one credential" feature relies on runtimeConfig.delete()
 * removing exactly one key from both the in-memory store and process.env while
 * leaving every other key intact. These tests pin that guarantee.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { runtimeConfig } from '../lib/runtime-config';

// Two real allowlisted keys — one to delete, one that must survive.
const VICTIM = 'HACKERONE_TOKEN';
const SURVIVOR = 'ANTHROPIC_API_KEY';

afterEach(() => {
  runtimeConfig.delete(VICTIM);
  runtimeConfig.delete(SURVIVOR);
});

describe('RuntimeConfig.delete', () => {
  it('clears the targeted key from both the store and process.env', () => {
    runtimeConfig.set(VICTIM, 'h1-secret-value');
    expect(runtimeConfig.get(VICTIM)).toBe('h1-secret-value');
    expect(process.env[VICTIM]).toBe('h1-secret-value');

    runtimeConfig.delete(VICTIM);

    expect(runtimeConfig.get(VICTIM)).toBeUndefined();
    expect(process.env[VICTIM]).toBeUndefined();
  });

  it('leaves other keys untouched when one is cleared', () => {
    runtimeConfig.set(VICTIM, 'h1-secret-value');
    runtimeConfig.set(SURVIVOR, 'sk-ant-survivor');

    runtimeConfig.delete(VICTIM);

    // The whole point of the feature: deleting HackerOne must not touch Anthropic.
    expect(runtimeConfig.get(VICTIM)).toBeUndefined();
    expect(runtimeConfig.get(SURVIVOR)).toBe('sk-ant-survivor');
    expect(process.env[SURVIVOR]).toBe('sk-ant-survivor');
  });

  it('ignores deletes of keys outside the allowlist (no throw, no env mutation)', () => {
    process.env.SOME_UNRELATED_VAR = 'keep-me';

    expect(() => runtimeConfig.delete('SOME_UNRELATED_VAR')).not.toThrow();

    expect(process.env.SOME_UNRELATED_VAR).toBe('keep-me');
    delete process.env.SOME_UNRELATED_VAR;
  });

  it('is idempotent — deleting an absent key is a no-op', () => {
    expect(runtimeConfig.get(VICTIM)).toBeUndefined();
    expect(() => runtimeConfig.delete(VICTIM)).not.toThrow();
    expect(runtimeConfig.get(VICTIM)).toBeUndefined();
  });
});

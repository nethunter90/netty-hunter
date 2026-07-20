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

vi.mock('../middleware/scopeGuard', () => ({
  ScopeGuard: {
    getInstance: vi.fn().mockReturnValue({
      isInScope: vi.fn().mockResolvedValue({ allowed: true }),
    }),
  },
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
import logger from '../utils/logger';

const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;
const mockedPost = axios.post as unknown as ReturnType<typeof vi.fn>;
const mockedCsrf = csrfAwareRequest as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedGet.mockReset();
  mockedPost.mockReset();
  mockedCsrf.mockReset();
  vi.mocked(logger.warn).mockReset();
  vi.mocked(logger.debug).mockReset();
  vi.mocked(logger.info).mockReset();
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
    expect(result.findings[0].technique).toBe('ssti');
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
    expect(result.findings[0].technique).toBe('rce_object_injection');
    expect(result.findings[0].rawPayload).toBe('O:8:"stdClass":0:{}');
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

  it('confirms LFI when the response contains real file-disclosure content', async () => {
    const lfiPayload: TechPayload = {
      vulnClass: 'lfi', payload: '../../etc/passwd', targetPath: '../../etc/passwd',
      description: 'PHP path traversal to /etc/passwd', confidence: 0.65, priority: 8,
    };
    mockedGet.mockImplementation((url: string) => {
      if (decodeURIComponent(url).includes('../../etc/passwd')) {
        return Promise.resolve({ status: 200, data: 'root:x:0:0:root:/root:/bin/bash\n' });
      }
      return Promise.resolve({ status: 200, data: '<html>not found</html>' });
    });

    const result = await techPayloadProber.probe('http://localhost:8000/view?file=readme.txt', [lfiPayload], [], {});

    expect(result.findings.length).toBe(1);
    expect(result.findings[0].vulnClass).toBe('lfi');
    expect(result.findings[0].technique).toBe('lfi_traversal');
    expect(result.findings[0].confidence).toBe(0.85);
    // Injected into the target's OWN existing query param ("file"), not a guess.
    expect(result.findings[0].endpoint).toContain('file=');
  });

  it('does not confirm LFI on a plain 200 with no file-disclosure signature', async () => {
    const lfiPayload: TechPayload = {
      vulnClass: 'lfi', payload: '../../../etc/passwd', targetPath: '../../../etc/passwd',
      description: 'Node/Express path traversal to /etc/passwd', confidence: 0.65, priority: 7,
    };
    mockedGet.mockResolvedValue({ status: 200, data: '<html>Rendered fine</html>' });

    const result = await techPayloadProber.probe('http://localhost:3000/', [lfiPayload], [], {});
    expect(result.findings).toEqual([]);
  });

  it('confirms SQLi via a real DB error triggered by the injected payload but absent on a clean baseline', async () => {
    const sqliPayload: TechPayload = {
      vulnClass: 'sqli', payload: "' OR 1=1--",
      description: 'Django ORM SQL injection probe', confidence: 0.6, priority: 7,
    };
    mockedGet.mockImplementation((url: string) => {
      const id = new URL(url).searchParams.get('id');
      if (id === "' OR 1=1--") {
        return Promise.resolve({ status: 500, data: 'You have an error in your SQL syntax near \'1\'' });
      }
      return Promise.resolve({ status: 200, data: '{"results":[]}' }); // baseline (?id=1) — clean
    });

    const result = await techPayloadProber.probe('http://localhost:8000/items?id=1', [sqliPayload], [], {});

    expect(result.findings.length).toBe(1);
    expect(result.findings[0].vulnClass).toBe('sqli');
    expect(result.findings[0].technique).toBe('sqli_error_based');
    expect(result.findings[0].confidence).toBe(0.85);
  });

  it('does not confirm SQLi when the error signature is also present on the clean baseline (SPA-catch-all-style false positive guard)', async () => {
    const sqliPayload: TechPayload = {
      vulnClass: 'sqli', payload: "' OR 1=1--",
      description: 'Django ORM SQL injection probe', confidence: 0.6, priority: 7,
    };
    // A target whose generic error page always mentions "SQL syntax" —
    // must not be mistaken for real injection just because the phrase appears.
    mockedGet.mockResolvedValue({ status: 500, data: 'Internal error: SQL syntax error in handler' });

    const result = await techPayloadProber.probe('http://localhost:8000/items?id=1', [sqliPayload], [], {});
    expect(result.findings).toEqual([]);
  });

  it('confirms an info_disclosure route the same way as a debug route, tagged distinctly', async () => {
    const infoPayload: TechPayload = {
      vulnClass: 'info_disclosure', payload: '/api/settings/', targetPath: '/api/settings/',
      description: 'Django settings endpoint probe', confidence: 0.55, priority: 6,
    };
    mockedGet.mockImplementation((url: string) => {
      if (url.includes('/api/settings/')) return Promise.resolve({ status: 200, data: '{"SECRET_KEY":"x".repeat(40)}' });
      return Promise.resolve({ status: 404, data: '' });
    });

    const result = await techPayloadProber.probe('http://localhost:8000/', [infoPayload], [], {});

    expect(result.findings.length).toBe(1);
    expect(result.findings[0].vulnClass).toBe('info_disclosure');
    expect(result.findings[0].technique).toBe('debug_route');
  });

  it('does not dispatch a GraphQL-shaped info_disclosure payload (no targetPath) — left for graphqlProber', async () => {
    const graphqlPayload: TechPayload = {
      vulnClass: 'info_disclosure', payload: '{__schema{types{name}}}',
      description: 'GraphQL introspection probe', confidence: 0.75, priority: 7,
    };
    const result = await techPayloadProber.probe('http://localhost:8000/graphql', [graphqlPayload], [], {});
    expect(result.findings).toEqual([]);
    expect(mockedGet).not.toHaveBeenCalled();
    expect(mockedPost).not.toHaveBeenCalled();
  });

  it('logs a loud warning for an undispatched, non-intentional-skip vulnClass instead of silently dropping it', async () => {
    const mysteryPayload = {
      vulnClass: 'some_new_class_selector_added_later', payload: 'x',
      description: 'a payload this prober does not know about yet', confidence: 0.5, priority: 5,
    } as TechPayload;

    await techPayloadProber.probe('http://localhost:8000/', [mysteryPayload], [], {});

    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('accidental drop'),
      expect.objectContaining({ vulnClass: 'some_new_class_selector_added_later' })
    );
  });

  it('logs only a debug note (not a warning) for a known intentional skip like mass_assignment', async () => {
    const massAssignmentPayload: TechPayload = {
      vulnClass: 'mass_assignment', payload: '{"user":{"role":"admin"}}',
      description: 'Rails strong-parameters bypass', confidence: 0.7, priority: 8,
    };

    await techPayloadProber.probe('http://localhost:8000/', [massAssignmentPayload], [], {});

    expect(logger.warn).not.toHaveBeenCalled();
    expect(logger.debug).toHaveBeenCalledWith(
      expect.stringContaining('intentional skip'),
      expect.objectContaining({ vulnClass: 'mass_assignment' })
    );
  });
});

describe('techPayloadProber.reprobeHypothesis', () => {
  // This is what HunterEngine's PROBE phase calls instead of falling through
  // to a generic RL-selected tool that has no idea how to resend an SSTI
  // oracle or recheck a debug route — without it, real OBSERVE-phase evidence
  // for ssti/exposed_admin/tech-rce hypotheses would be silently discarded,
  // the same bug already fixed once for the deserialize-probe path.

  it('replays an ssti finding by recovering the syntax from the endpoint URL', async () => {
    mockedGet.mockImplementation((url: string) => {
      const match = decodeURIComponent(url).match(/\$\{(\d+)\*(\d+)\}/);
      const product = match ? String(Number(match[1]) * Number(match[2])) : '';
      return Promise.resolve({ status: 200, data: `result: ${product}` });
    });

    const result = await techPayloadProber.reprobeHypothesis(
      'ssti', 'http://localhost:5000/calc?q=%24%7B6880*8262%7D', {}
    );

    expect(result.found).toBe(true);
    // Must have sent a FRESH random expression, not replayed the stale one verbatim.
    const sentUrl = mockedGet.mock.calls[0][0] as string;
    expect(sentUrl).not.toContain('6880*8262');
  });

  it('returns not-found when ssti syntax cannot be recovered from the endpoint', async () => {
    const result = await techPayloadProber.reprobeHypothesis('ssti', 'http://localhost:5000/no-params', {});
    expect(result.found).toBe(false);
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it('replays a debug_route finding with a plain re-GET', async () => {
    mockedGet.mockResolvedValue({ status: 200, data: 'x'.repeat(50) });
    const result = await techPayloadProber.reprobeHypothesis('debug_route', 'http://localhost:8080/actuator/heapdump', {});
    expect(result.found).toBe(true);
  });

  it('replays rce_object_injection with the exact original payload', async () => {
    mockedCsrf.mockResolvedValue({ status: 500, data: 'unserialize(): Error', headers: {}, csrfBypassUsed: false });
    const result = await techPayloadProber.reprobeHypothesis(
      'rce_object_injection', 'http://localhost:8000/api/data', {}, 'O:8:"stdClass":0:{}'
    );
    expect(result.found).toBe(true);
    // csrfAwareRequest(url, method, body, headers, timeout) — body is arg index 2.
    expect(mockedCsrf.mock.calls[0][2]).toBe('O:8:"stdClass":0:{}');
  });

  it('replays rce_content_type by resending the Java serialized content-type header', async () => {
    mockedPost.mockResolvedValue({ status: 500, data: 'InvalidClassException' });
    const result = await techPayloadProber.reprobeHypothesis('rce_content_type', 'http://localhost:8080/api', {});
    expect(result.found).toBe(true);
  });

  it('replays an lfi_traversal finding with a plain re-GET of the confirmed URL', async () => {
    mockedGet.mockResolvedValue({ status: 200, data: 'root:x:0:0:root:/root:/bin/bash\n' });
    const result = await techPayloadProber.reprobeHypothesis(
      'lfi_traversal', 'http://localhost:8000/view?file=..%2F..%2Fetc%2Fpasswd', {}
    );
    expect(result.found).toBe(true);
  });

  it('reports not-found on lfi_traversal replay when the signature no longer appears', async () => {
    mockedGet.mockResolvedValue({ status: 200, data: 'no longer vulnerable' });
    const result = await techPayloadProber.reprobeHypothesis(
      'lfi_traversal', 'http://localhost:8000/view?file=..%2F..%2Fetc%2Fpasswd', {}
    );
    expect(result.found).toBe(false);
  });

  it('replays a sqli_error_based finding with a plain re-GET of the confirmed URL', async () => {
    mockedGet.mockResolvedValue({ status: 500, data: "You have an error in your SQL syntax" });
    const result = await techPayloadProber.reprobeHypothesis(
      'sqli_error_based', "http://localhost:8000/items?id=%27+OR+1%3D1--", {}
    );
    expect(result.found).toBe(true);
  });
});

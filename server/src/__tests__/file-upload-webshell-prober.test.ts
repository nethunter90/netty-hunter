/**
 * FileUploadWebshellProber — verified live against a real, genuinely
 * vulnerable `php -S` fixture (server/src/fixtures/file-upload/php) where a
 * real PHP webshell was uploaded, executed, and its server-computed
 * arithmetic canary observed in the response. That live check can't run in
 * CI (needs a live target), so this test mocks axios to lock in the same
 * logic: extension-filter bypass upload, candidate serving-path guesses,
 * and the canary-based execution-vs-reflection distinction.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../utils/logger', () => ({
  default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

vi.mock('axios', () => ({
  default: { post: vi.fn(), get: vi.fn() },
}));

import axios from 'axios';
import { fileUploadWebshellProber } from '../lib/tools/file-upload-webshell-prober';

const mockedPost = axios.post as unknown as ReturnType<typeof vi.fn>;
const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedPost.mockReset();
  mockedGet.mockReset();
});

describe('FileUploadWebshellProber', () => {
  it('confirms webshell RCE when a served file returns the computed product, not the source', async () => {
    // The prober embeds `<lang> a*b` in the upload body and checks the served
    // file for the evaluated product — extract it from the upload so the GET
    // mock can echo back what a real PHP interpreter would have computed.
    let lastProduct = '';
    mockedPost.mockImplementation(async (_url: string, body: unknown) => {
      const str = Buffer.isBuffer(body) ? body.toString('utf-8') : String(body);
      const m = str.match(/(\d+)\*(\d+)/);
      if (m) lastProduct = String(Number(m[1]) * Number(m[2]));
      return { status: 200, data: '{}' };
    });
    mockedGet.mockImplementation(async (url: string) => {
      if (/\/uploads\//.test(url)) {
        // Real execution: response has the evaluated product, no source tag.
        return { status: 200, data: lastProduct };
      }
      return { status: 404, data: '' };
    });

    const result = await fileUploadWebshellProber.probe('http://example.com');

    const confirmed = result.vulns.find(v => v.technique === 'webshell_rce_confirmed');
    expect(confirmed).toBeDefined();
    expect(confirmed!.severity).toBe('critical');

    const hyp = result.hypotheses.find(h => h.raw === confirmed);
    expect(hyp).toBeDefined();
    expect(hyp!.vulnClass).toBe('file_upload_rce');
    expect(hyp!.confidence).toBe(0.92);
  });

  it('downgrades to unrestricted-upload fingerprint when upload succeeds but nothing executes', async () => {
    mockedPost.mockResolvedValue({ status: 200, data: '{}' });
    mockedGet.mockResolvedValue({ status: 404, data: '' });

    const result = await fileUploadWebshellProber.probe('http://example.com');

    expect(result.vulns.length).toBeGreaterThan(0);
    for (const v of result.vulns) {
      expect(v.technique).toBe('unrestricted_upload_fingerprint');
      expect(v.severity).toBe('medium');
    }
    const hyp = result.hypotheses[0];
    expect(hyp.confidence).toBe(0.5);
  });

  it('finds nothing when every upload is rejected (the realistic default case)', async () => {
    mockedPost.mockResolvedValue({ status: 415, data: 'unsupported file type' });
    mockedGet.mockResolvedValue({ status: 404, data: '' });

    const result = await fileUploadWebshellProber.probe('http://example.com');

    expect(result.vulns).toEqual([]);
    expect(result.hypotheses).toEqual([]);
  });

  it('does not confirm RCE when the response merely reflects the raw source', async () => {
    mockedPost.mockResolvedValue({ status: 200, data: '{}' });
    mockedGet.mockImplementation(async (url: string) => {
      if (/\/uploads\//.test(url)) {
        // Reflection, not execution: literal source echoed back verbatim.
        return { status: 200, data: '<?php echo 1234*5678; ?>' };
      }
      return { status: 404, data: '' };
    });

    const result = await fileUploadWebshellProber.probe('http://example.com');

    expect(result.vulns.every(v => v.technique !== 'webshell_rce_confirmed')).toBe(true);
  });
});

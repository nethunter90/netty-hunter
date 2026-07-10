/**
 * SSRF param targeting — config/test-connection fields, not just redirect params.
 *
 * Proven live tonight (2026-07-10) against a real target: an Ollama URL config
 * field was a genuine SSRF sink. Neither SSRFSolver's param list nor
 * ssrfChainProber's detectSSRFParam() previously covered anything but classic
 * redirect-shaped names (url/redirect/dest/...) — a "test this connection" admin
 * field would never have been targeted at all.
 */
import { describe, it, expect } from 'vitest';
import { SSRF_PARAM_NAMES, ssrfChainProber } from '../lib/tools/ssrf-chain-prober';
import { SSRFSolver } from '../agents/SolverPool';

describe('SSRF_PARAM_NAMES', () => {
  it('covers classic redirect-shaped names (no regression)', () => {
    for (const name of ['url', 'redirect', 'dest', 'target', 'callback']) {
      expect(SSRF_PARAM_NAMES).toContain(name);
    }
  });

  it('covers config/test-connection-style field names', () => {
    for (const name of [
      'host', 'endpoint', 'server_url', 'webhook_url', 'ollama_url',
      'ollama_host', 'llm_url', 'screenshot_url', 'proxy_url', 'test_connection',
    ]) {
      expect(SSRF_PARAM_NAMES).toContain(name);
    }
  });
});

describe('ssrfChainProber.detectSSRFParam', () => {
  it('still detects classic redirect-shaped params (no regression)', () => {
    expect(ssrfChainProber.detectSSRFParam('http://x.test/go?redirect=http://evil.test')).toBe('redirect');
  });

  it('detects a config-panel-style param name', () => {
    expect(ssrfChainProber.detectSSRFParam('http://x.test/settings?ollama_url=http://evil.test')).toBe('ollama_url');
    expect(ssrfChainProber.detectSSRFParam('http://x.test/tools/screenshot?screenshot_url=http://evil.test')).toBe('screenshot_url');
  });
});

describe('SSRFSolver.detects', () => {
  it('recognizes AWS metadata, GCP metadata, and /etc/passwd signatures (no regression)', () => {
    expect(SSRFSolver.detects('{"ami-id":"ami-123"}')).toBe(true);
    expect(SSRFSolver.detects('{"computeMetadata":"v1"}')).toBe(true);
    expect(SSRFSolver.detects('root:x:0:0:root:/root:/bin/bash')).toBe(true);
  });

  it('does not false-positive on benign content', () => {
    expect(SSRFSolver.detects('{"status":"ok"}')).toBe(false);
    expect(SSRFSolver.detects('<html><body>Not Found</body></html>')).toBe(false);
  });
});

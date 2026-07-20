/**
 * CloudBucketProber — the one self-confirmed source that was never tested,
 * live or via the fixture server, since it deliberately queries real AWS/GCP/
 * Azure infrastructure (guessed bucket names derived from the target's
 * hostname) rather than the target itself. Pointing it at real cloud
 * endpoints in an automated test would be inappropriate — mock axios instead
 * so the candidate-name derivation, provider detection, and hypothesis/raw-
 * evidence wiring (added when this prober was hooked into HunterEngine's
 * self-confirmed evidence short-circuit) are verified without touching the
 * network or needing a live hunt.
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
  default: { get: vi.fn() },
}));

import axios from 'axios';
import { cloudBucketProber } from '../lib/tools/cloud-bucket-probe';

const mockedGet = axios.get as unknown as ReturnType<typeof vi.fn>;

beforeEach(() => {
  mockedGet.mockReset();
});

describe('CloudBucketProber', () => {
  it('flags a publicly listable S3 bucket and attaches full raw evidence to the hypothesis', async () => {
    mockedGet.mockImplementation(async (url: string) => {
      if (url === 'https://assets-example.s3.amazonaws.com/?list-type=2&max-keys=5') {
        return { status: 200, data: '<ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>' };
      }
      return { status: 404, data: '' };
    });

    const result = await cloudBucketProber.probe('http://example.com');

    const bucket = result.buckets.find(b => b.bucketName === 'assets-example');
    expect(bucket).toBeDefined();
    expect(bucket!.provider).toBe('aws_s3');
    expect(bucket!.listable).toBe(true);
    expect(bucket!.severity).toBe('critical');

    const hyp = result.hypotheses.find(h => h.endpoint === bucket!.bucketUrl);
    expect(hyp).toBeDefined();
    expect(hyp!.vulnClass).toBe('cloud_storage_exposure');
    expect(hyp!.confidence).toBe(0.9);
    expect(hyp!.priority).toBe(10);
    // raw carries the full BucketResult — this is what HunterEngine attaches
    // to the hypothesis's evidence for the self-confirmed short-circuit.
    expect(hyp!.raw).toBe(bucket);
    expect(hyp!.raw.readable).toBe(true);
  });

  it('distinguishes a readable-but-not-listable bucket as high (not critical) severity', async () => {
    mockedGet.mockImplementation(async (url: string) => {
      if (url === 'https://storage.googleapis.com/example/') {
        return { status: 200, data: '<html>access denied to listing, but bucket exists</html>' };
      }
      return { status: 404, data: '' };
    });

    const result = await cloudBucketProber.probe('http://example.com');

    const bucket = result.buckets.find(b => b.provider === 'gcp_gcs');
    expect(bucket).toBeDefined();
    expect(bucket!.listable).toBe(false);
    expect(bucket!.severity).toBe('high');
  });

  it('finds nothing when every candidate 404s (the realistic default case)', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: '' });

    const result = await cloudBucketProber.probe('http://example.com');

    expect(result.buckets).toEqual([]);
    expect(result.hypotheses).toEqual([]);
  });

  it('derives candidate names from the target hostname, not a hardcoded list', async () => {
    mockedGet.mockResolvedValue({ status: 404, data: '' });

    await cloudBucketProber.probe('http://my-cool-app.example.com');

    const calledUrls = mockedGet.mock.calls.map((c: unknown[]) => c[0] as string);
    expect(calledUrls.some(u => u.includes('my-cool-app'))).toBe(true);
  });
});

/**
 * SubmissionQueue — the human-review gate between a verified finding and a
 * live platform submission. approveAndSubmit()/reject() previously only
 * updated the local JSON draft file, never the findings DB row — so
 * findings.reportDraft stayed frozen at "Pending human review: <id>" forever,
 * even after the report was actually sent (or explicitly rejected).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockReadFile, mockWriteFile, mockMkdir, mockSubmit, mockDbSet, mockDbWhere, mockDbUpdate } = vi.hoisted(() => {
  const mockReadFile = vi.fn();
  const mockWriteFile = vi.fn().mockResolvedValue(undefined);
  const mockMkdir = vi.fn().mockResolvedValue(undefined);
  const mockSubmit = vi.fn();
  const mockDbWhere = vi.fn().mockResolvedValue(undefined);
  const mockDbSet = vi.fn().mockReturnValue({ where: mockDbWhere });
  const mockDbUpdate = vi.fn().mockReturnValue({ set: mockDbSet });
  return { mockReadFile, mockWriteFile, mockMkdir, mockSubmit, mockDbSet, mockDbWhere, mockDbUpdate };
});

vi.mock('fs/promises', () => ({
  default: { readFile: mockReadFile, writeFile: mockWriteFile, mkdir: mockMkdir },
  readFile: mockReadFile, writeFile: mockWriteFile, mkdir: mockMkdir,
}));

vi.mock('../db', () => ({ db: { update: mockDbUpdate } }));
vi.mock('../db/schema', () => ({ findings: { id: 'id' } }));
vi.mock('drizzle-orm', () => ({ eq: vi.fn((a, b) => ({ a, b })) }));
vi.mock('../utils/logger', () => ({ default: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } }));
vi.mock('../lib/intelligence/report-submitter', () => ({ reportSubmitter: { submit: mockSubmit } }));

import { submissionQueue } from '../lib/intelligence/submission-queue';

const baseEntry = (overrides: Partial<any> = {}) => ({
  id: 'sub-1', status: 'pending_review', platform: 'hackerone', title: 't',
  severity: 'high', description: 'd', targetUrl: 'http://x', programHandle: 'h',
  findingId: 42, payload: {}, createdAt: '2026-01-01T00:00:00Z', ...overrides,
});

beforeEach(() => {
  mockReadFile.mockReset();
  mockWriteFile.mockClear();
  mockSubmit.mockReset();
  mockDbUpdate.mockClear();
  mockDbSet.mockClear();
  mockDbWhere.mockClear();
});

describe('SubmissionQueue.approveAndSubmit', () => {
  it('on success, writes submittedAt + a real reportDraft to the findings row', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify(baseEntry()));
    mockSubmit.mockResolvedValue({ success: true, platform: 'hackerone', reportId: 'R1', reportUrl: 'https://hackerone.com/reports/1' });

    const outcome = await submissionQueue.approveAndSubmit('sub-1');

    expect(outcome?.result.success).toBe(true);
    expect(mockDbUpdate).toHaveBeenCalled();
    const setArg = mockDbSet.mock.calls[0][0];
    expect(setArg.reportDraft).toBe('Submitted: https://hackerone.com/reports/1');
    expect(setArg.submittedAt).toBeInstanceOf(Date);
  });

  it('on failure, writes a failure reportDraft but does NOT set submittedAt', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify(baseEntry()));
    mockSubmit.mockResolvedValue({ success: false, platform: 'hackerone', error: '401 unauthorized' });

    const outcome = await submissionQueue.approveAndSubmit('sub-1');

    expect(outcome?.result.success).toBe(false);
    const setArg = mockDbSet.mock.calls[0][0];
    expect(setArg.reportDraft).toBe('Submission failed: 401 unauthorized');
    expect(setArg.submittedAt).toBeUndefined();
  });

  it('does not touch the findings row when the draft has no findingId', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify(baseEntry({ findingId: undefined })));
    mockSubmit.mockResolvedValue({ success: true, platform: 'hackerone', reportId: 'R1' });

    await submissionQueue.approveAndSubmit('sub-1');

    expect(mockDbUpdate).not.toHaveBeenCalled();
  });

  it('returns null for a draft that is not pending_review (already reviewed)', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify(baseEntry({ status: 'submitted' })));
    const outcome = await submissionQueue.approveAndSubmit('sub-1');
    expect(outcome).toBeNull();
    expect(mockSubmit).not.toHaveBeenCalled();
  });
});

describe('SubmissionQueue.reject', () => {
  it('marks the findings row as rejected — not submitted, no submittedAt', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify(baseEntry()));

    const entry = await submissionQueue.reject('sub-1');

    expect(entry?.status).toBe('rejected');
    const setArg = mockDbSet.mock.calls[0][0];
    expect(setArg.reportDraft).toBe('Rejected — not submitted');
    expect(setArg.submittedAt).toBeUndefined();
  });
});

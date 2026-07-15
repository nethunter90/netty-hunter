/**
 * Pending-review queue for bug bounty report submissions.
 *
 * Verified findings no longer go straight to a live platform — they land
 * here as a "pending_review" draft with the full submission payload
 * preserved, and a human must call approveAndSubmit() (wired to
 * POST /api/bounty/submissions/:id/approve) before anything reaches
 * HackerOne/Bugcrowd/Intigriti/YesWeHack.
 *
 * Drafts are written into the same workspace/submissions directory the
 * existing manual submissions tracker (routes/bounty.ts) already reads, so
 * they show up in that list without a separate UI surface.
 */
import fs from "fs/promises";
import path from "path";
import logger from "../../utils/logger";
import { reportSubmitter, type SubmissionPayload, type SubmissionResult } from "./report-submitter";
import { db } from "../../db";
import { findings } from "../../db/schema";
import { eq } from "drizzle-orm";

const STORE_DIR = path.join(process.cwd(), "workspace", "submissions");

export type PendingStatus = "pending_review" | "submitted" | "rejected" | "failed";

export interface PendingSubmission {
  id: string;
  status: PendingStatus;
  platform: SubmissionPayload["platform"];
  title: string;
  severity: SubmissionPayload["severity"];
  description: string;
  targetUrl: string;
  programHandle: string;
  findingId?: number;
  payload: SubmissionPayload;
  createdAt: string;
  reviewedAt?: string;
  reportId?: string;
  reportUrl?: string;
  error?: string;
}

async function ensureDir() {
  await fs.mkdir(STORE_DIR, { recursive: true });
}

class SubmissionQueue {
  /** Queue a verified finding for human review instead of submitting it live. */
  async queueForReview(payload: SubmissionPayload, findingId?: number): Promise<PendingSubmission> {
    await ensureDir();
    const entry: PendingSubmission = {
      id: `sub-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      status: "pending_review",
      platform: payload.platform,
      title: payload.title,
      severity: payload.severity,
      description: payload.description,
      targetUrl: payload.targetUrl,
      programHandle: payload.programHandle,
      findingId,
      payload,
      createdAt: new Date().toISOString(),
    };
    await fs.writeFile(path.join(STORE_DIR, `${entry.id}.json`), JSON.stringify(entry, null, 2));
    logger.info("[SubmissionQueue] Finding queued for human review", { id: entry.id, platform: payload.platform, title: payload.title });
    return entry;
  }

  async get(id: string): Promise<PendingSubmission | null> {
    try {
      return JSON.parse(await fs.readFile(path.join(STORE_DIR, `${id}.json`), "utf8"));
    } catch {
      return null;
    }
  }

  private async save(entry: PendingSubmission) {
    await fs.writeFile(path.join(STORE_DIR, `${entry.id}.json`), JSON.stringify(entry, null, 2));
  }

  /** Human approves — this is the only path that actually calls the live platform API. */
  async approveAndSubmit(id: string): Promise<{ entry: PendingSubmission; result: SubmissionResult } | null> {
    const entry = await this.get(id);
    if (!entry || entry.status !== "pending_review") return null;

    const result = await reportSubmitter.submit(entry.payload);
    entry.reviewedAt = new Date().toISOString();
    if (result.success) {
      entry.status = "submitted";
      entry.reportId = result.reportId;
      entry.reportUrl = result.reportUrl;
    } else {
      entry.status = "failed";
      entry.error = result.error;
    }
    await this.save(entry);
    // The queue file is the source of truth for the review workflow itself,
    // but the findings row is what /api/findings, exports, and dashboards
    // read — without this it stays frozen at "Pending human review: <id>"
    // forever, even after the report actually went out (or failed).
    await this.syncFindingRow(entry.findingId, {
      reportDraft: result.success
        ? (result.reportUrl ? `Submitted: ${result.reportUrl}` : `Report ID: ${result.reportId}`)
        : `Submission failed: ${result.error}`,
      // Conditionally spread rather than passing submittedAt: undefined — an
      // explicit undefined risks Drizzle writing NULL over a previously-set
      // column instead of leaving it untouched.
      ...(result.success ? { submittedAt: new Date() } : {}),
    });
    return { entry, result };
  }

  /** Human rejects — this draft will never be sent. */
  async reject(id: string): Promise<PendingSubmission | null> {
    const entry = await this.get(id);
    if (!entry || entry.status !== "pending_review") return null;
    entry.status = "rejected";
    entry.reviewedAt = new Date().toISOString();
    await this.save(entry);
    await this.syncFindingRow(entry.findingId, { reportDraft: "Rejected — not submitted" });
    return entry;
  }

  private async syncFindingRow(
    findingId: number | undefined,
    fields: { reportDraft: string; submittedAt?: Date },
  ): Promise<void> {
    if (findingId === undefined) return;
    try {
      await db.update(findings)
        .set({ ...fields, updatedAt: new Date() })
        .where(eq(findings.id, findingId));
    } catch (err) {
      logger.warn("[SubmissionQueue] Failed to sync outcome to findings row", { findingId, err: String(err) });
    }
  }
}

export const submissionQueue = new SubmissionQueue();

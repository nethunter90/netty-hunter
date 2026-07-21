/**
 * Dev-server freshness guardrail.
 *
 * `tsx watch` restarts the server process on file changes — but that restart
 * mechanism was found to silently stop firing mid-session (2026-07-20/21):
 * a real content edit to a source file did not trigger a restart, and the
 * already-running process kept serving OLD code indefinitely with no error,
 * no log line, nothing. A full hunt campaign (119) was measured against that
 * stale process before the mismatch was caught by hand, comparing a live
 * isolated repro (correct, fresh `tsx` invocation) against the real hunt's
 * behavior (stale, in-memory process).
 *
 * This makes that failure structural instead of something a human has to
 * notice: hash the source tree once at process start, and re-hash it at
 * every campaign start. If they don't match, the on-disk source has changed
 * since this process loaded it — which means the running code is NOT
 * guaranteed to match what `git diff`/the file system shows — and the
 * campaign must refuse to start rather than run silently on unknown code.
 */
import fs from "fs";
import path from "path";
import crypto from "crypto";

const SRC_ROOT = path.resolve(__dirname, "..");

function collectTsFiles(dir: string, out: string[]): void {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      collectTsFiles(full, out);
    } else if (entry.name.endsWith(".ts") || entry.name.endsWith(".tsx")) {
      out.push(full);
    }
  }
}

/** Deterministic content hash of every .ts/.tsx file under server/src, in
 *  sorted path order so it doesn't depend on filesystem enumeration order. */
export function computeSourceHash(): string {
  const files: string[] = [];
  collectTsFiles(SRC_ROOT, files);
  files.sort();
  const hash = crypto.createHash("sha256");
  for (const file of files) {
    hash.update(file);
    hash.update(fs.readFileSync(file));
  }
  return hash.digest("hex");
}

/** Computed once, at module load — i.e. at process start (or at the last
 *  `tsx watch` restart that actually happened). This is "what code this
 *  process believes it is running." */
export const STARTUP_BUILD_HASH = computeSourceHash();

export class StaleBuildError extends Error {
  constructor(startupHash: string, currentHash: string) {
    super(
      `Refusing to start campaign — running process's source hash (${startupHash.slice(0, 12)}...) ` +
      `does not match the current on-disk source (${currentHash.slice(0, 12)}...). ` +
      `The dev server did not pick up a recent file change (tsx watch restart likely stalled). ` +
      `Restart the server process before starting a new hunt.`
    );
    this.name = "StaleBuildError";
  }
}

/** Call at the earliest point of campaign start. Recomputes the hash fresh
 *  from disk and throws StaleBuildError if it no longer matches what this
 *  process loaded at startup — i.e. the source changed under a process that
 *  never restarted to pick it up. */
export function assertFreshBuild(): void {
  const current = computeSourceHash();
  if (current !== STARTUP_BUILD_HASH) {
    throw new StaleBuildError(STARTUP_BUILD_HASH, current);
  }
}

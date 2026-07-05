/**
 * Payload-adaptation retry — narrow, explicit rule set only.
 *
 * When L4 (VerifierAgent Layer 4) signals that a vulnerability's CAPABILITY is
 * real but the specific proof payload failed for a mechanical/endpoint-shape
 * reason, this maps that signal to a concrete, bounded payload transformation.
 *
 * This is intentionally NOT a general "let the model try anything" mechanism.
 * Every rule here must be a deterministic, safe URL transform. If a rule name
 * doesn't match one implemented here, adaptation does not fire — the finding
 * keeps its original verdict.
 */

export const ADAPTATION_RULES = ["target_directory_not_file"] as const;
export type AdaptationRule = (typeof ADAPTATION_RULES)[number];

export function isKnownAdaptationRule(rule: unknown): rule is AdaptationRule {
  return typeof rule === "string" && (ADAPTATION_RULES as readonly string[]).includes(rule);
}

export interface AdaptedPayload {
  rule: AdaptationRule;
  adaptedUrl: string;
  adaptedPayload: string;
}

/**
 * target_directory_not_file: the endpoint is a directory lister (scandir/readdir)
 * that 400/ENOENTs on a file-shaped traversal payload. Strip the filename off the
 * traversal path so the payload targets the containing directory instead.
 */
function adaptTargetDirectoryNotFile(originalUrl: string): AdaptedPayload | null {
  let u: URL;
  try {
    u = new URL(originalUrl);
  } catch {
    return null;
  }

  for (const [key, val] of u.searchParams.entries()) {
    if (!/\.\.[/\\]/.test(val)) continue; // only adapt params that carry a traversal payload
    const stripped = val.replace(/[^/\\]+$/, ""); // drop the trailing filename segment
    if (stripped === val || stripped.length === 0) continue; // nothing to strip
    const adaptedVal = stripped.endsWith("/") ? stripped : `${stripped}/`;
    u.searchParams.set(key, adaptedVal);
    return { rule: "target_directory_not_file", adaptedUrl: u.toString(), adaptedPayload: adaptedVal };
  }
  return null;
}

/** Returns null if the rule is unknown or no safe adaptation could be derived. */
export function adaptPayload(rule: string, originalUrl: string): AdaptedPayload | null {
  if (!isKnownAdaptationRule(rule)) return null;
  switch (rule) {
    case "target_directory_not_file":
      return adaptTargetDirectoryNotFile(originalUrl);
    default:
      return null;
  }
}

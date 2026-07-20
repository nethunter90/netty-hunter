/**
 * Canonical vulnClass taxonomy — single source of truth.
 *
 * Built from the 2026-07-20 taxonomy census: every string that appears as a
 * hypothesis.vulnClass value across 6,488 hypotheses / 69 campaigns, cross-
 * referenced against what the consuming boundaries (LogicExploitAgent routing,
 * effort-scaling tiers, PostExploitAgent probesFor()/NOT_DEMONSTRABLE, the
 * tool-selection tables, SolverPool.VulnClass) actually recognize.
 *
 * Deliberately EXCLUDES three categories the census found mixed into the same
 * DB column, none of which belong in this list:
 *   - recon-task placeholders (e.g. "locate_password_reset_flows") — these are
 *     backward-hunt planner phase labels, not vulnerability classes, and
 *     normalizing them here would paper over the real bug (the planner writing
 *     task text into vulnClass at all).
 *   - ambiguous impact-label leakage from chain-synthesis free text (e.g.
 *     "lateral_movement", "credential_theft") — these describe an outcome, not
 *     a testable mechanism; forcing them onto a canonical class would be
 *     guessing at what the model meant.
 *   - tool CAPABILITY tags (e.g. "open_ports", "weak_credentials", "tech_stack")
 *     from the tool-knowledge/kali-catalog registries — those are a deliberately
 *     looser vocabulary describing what a TOOL can help with, not what a
 *     HYPOTHESIS is. Conflating the two would triple the size of this list for
 *     no drift-prevention benefit; toolSupportsClass() only needs a tool's
 *     capability array to CONTAIN the canonical class, not equal it 1:1.
 */

export const CANONICAL_VULN_CLASSES = [
  // injection
  "xss", "stored_xss", "sqli", "nosqli", "ssti", "xxe", "rce", "command_injection", "crlf_injection",
  // path / file
  "lfi", "rfi", "file_upload_rce",
  // access control
  "idor", "auth_bypass", "broken_auth", "csrf", "cors", "open_redirect",
  // business logic
  "business_logic", "mass_assignment", "race_condition",
  // server-side
  "ssrf", "deserialization", "prototype_pollution",
  // config / info
  "misconfig", "info_disclosure", "security_headers", "hidden_endpoints",
  "exposed_admin", "oauth_misconfiguration", "host_header_injection",
  "subdomain_takeover",
  // infra
  "http_smuggling", "rate_limit_bypass", "cloud_storage_exposure", "service_disruption",
  // auth mechanisms
  "jwt_confusion", "two_factor_bypass",
] as const;

export type VulnClass = (typeof CANONICAL_VULN_CLASSES)[number];

const CANONICAL_SET: ReadonlySet<string> = new Set(CANONICAL_VULN_CLASSES);

/**
 * Confirmed same-concept drift from the Phase 0 census (2026-07-20) — the
 * authentication_bypass/auth_bypass pair that broke #4 routing, plus its
 * siblings found by the same census. ONLY exact synonyms go here. Concepts
 * that are merely thematically related (privilege_escalation, credential_theft,
 * account_takeover, ...) are deliberately left OUT — aliasing them onto the
 * nearest canonical class would be a guess, and normalizeVulnClass() returning
 * null for them is the correct, informative behavior: it's a live signal that
 * the canonical list may need a real new entry, not something to paper over.
 */
const ALIASES: Readonly<Record<string, VulnClass>> = {
  authentication_bypass: "auth_bypass",
  authorization_bypass: "auth_bypass",
  information_disclosure: "info_disclosure",
  sensitive_data_exposure: "info_disclosure",
  sql_injection: "sqli",
  remote_code_execution: "rce",
  path_traversal: "lfi",
};

/**
 * The single chokepoint every runtime ingestion boundary (LLM hypothesis
 * output, chain-synthesis output, anything read back from the DB) must route
 * through. Returns null for anything unrecognized — callers MUST treat null as
 * a failure to be logged/handled, never silently default to a fallback class.
 * That's what let "authentication_bypass" masquerade as a normal hypothesis
 * for months instead of surfacing as an error.
 */
export function normalizeVulnClass(raw: string | null | undefined): VulnClass | null {
  if (!raw) return null;
  const trimmed = raw.trim().toLowerCase();
  if (CANONICAL_SET.has(trimmed)) return trimmed as VulnClass;
  const aliased = ALIASES[trimmed];
  return aliased ?? null;
}

import { describe, test, expect } from "vitest";
import { normalizeVulnClass, CANONICAL_VULN_CLASSES } from "../lib/vuln-taxonomy";

/**
 * Completeness check (Phase 1, taxonomy census follow-up).
 *
 * Every literal string a deterministic prober hardcodes into a hypothesis's
 * vulnClass field, pulled directly from the 2026-07-20 producer-side census
 * (server/src/lib/tools/*.ts, HunterEngine.ts inline fallbacks). If any of
 * these ever returns null, the canonical list is missing something a real
 * producer legitimately emits — that's the orphaning failure mode the
 * completeness gate exists to catch, not a normal test failure to silence.
 */
const KNOWN_PRODUCER_LITERALS = [
  // lib/tools/*.ts hardcoded producers
  "host_header_injection", "crlf_injection", "xss", "info_disclosure", "csrf",
  "mass_assignment", "business_logic", "xxe", "deserialization",
  "prototype_pollution", "rce", "auth_bypass", "oauth_misconfiguration",
  "open_redirect", "file_upload_rce", "cloud_storage_exposure", "race_condition",
  "sqli", "idor", "hidden_endpoints", "cors", "misconfig", "broken_auth",
  "ssrf", "ssti", "lfi", "command_injection", "rfi", "nosqli",
  "security_headers", "jwt_confusion", "two_factor_bypass",
  // HunterEngine.ts inline literals
  "service_disruption",
] as const;

describe("vuln-taxonomy completeness", () => {
  test.each(KNOWN_PRODUCER_LITERALS)(
    "known producer literal %s normalizes to a canonical class",
    (literal) => {
      expect(normalizeVulnClass(literal)).not.toBeNull();
    }
  );

  // The confirmed drift pair that broke #4 routing, plus its siblings.
  test.each([
    ["authentication_bypass", "auth_bypass"],
    ["authorization_bypass", "auth_bypass"],
    ["information_disclosure", "info_disclosure"],
    ["sensitive_data_exposure", "info_disclosure"],
    ["sql_injection", "sqli"],
    ["remote_code_execution", "rce"],
    ["path_traversal", "lfi"],
  ])("alias %s normalizes to canonical %s", (raw, canonical) => {
    expect(normalizeVulnClass(raw)).toBe(canonical);
  });

  // Deliberately-excluded categories must fail loud (null), not silently
  // adopt a fallback class. This is the inverse assertion of the block
  // above — proving normalize() doesn't swallow the unknown the same way
  // the original bug did.
  test.each([
    // recon-task placeholders (backward-hunt planner phase labels)
    "locate_password_reset_flows", "find_registration_endpoints",
    "discover_login_pages", "test_session_management", "check_token_entropy",
    "analyze_cookie_flags",
    // ambiguous chain-synthesis impact-label leakage
    "lateral_movement", "mitm_attack", "data_exfiltration", "credential_theft",
    "credential_exposure", "credential_extraction", "credential_abuse",
    "injection", "privilege_escalation", "authorization", "broken_access_control",
    "account_takeover",
    // garbage / empty
    "", "not_a_real_class", "xxxxxxxx",
  ])("unrecognized/excluded class %s normalizes to null (fail loud)", (raw) => {
    expect(normalizeVulnClass(raw)).toBeNull();
  });

  test("canonical list has no duplicate entries", () => {
    expect(new Set(CANONICAL_VULN_CLASSES).size).toBe(CANONICAL_VULN_CLASSES.length);
  });

  test("normalize is case-insensitive and trims whitespace", () => {
    expect(normalizeVulnClass("  AUTH_BYPASS  ")).toBe("auth_bypass");
    expect(normalizeVulnClass("Authentication_Bypass")).toBe("auth_bypass");
  });
});

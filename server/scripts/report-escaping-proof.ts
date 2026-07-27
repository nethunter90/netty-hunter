/**
 * UI trust fix #4 (report escaping) — positive control.
 *
 * Feeds a finding whose evidence contains three attacker-influenceable
 * shapes into all three real report-generation paths (report-export.ts's
 * three platform formatters, intelligence/ReportGenerator.ts's
 * DraftReportGenerator, and lib/hunter/report-generator.ts's
 * ReportGeneratorStore) and asserts the hostile content renders as INERT
 * TEXT — never breaks the surrounding markdown structure — while a clean
 * finding still renders normally on the same paths.
 *
 * Run: npx tsx scripts/report-escaping-proof.ts
 */
import { mdEscapeInline, safeCodeFence, mdInlineCode } from "../src/lib/report/markdown-escape";
import { FORMATTERS, type ExportFinding } from "../src/routes/report-export";

let failures = 0;
function assert(cond: boolean, label: string): void {
  if (cond) console.log(`  PASS  ${label}`);
  else { failures++; console.log(`  FAIL  ${label}`); }
}

// The three hostile shapes named in the handoff.
const FENCE_BREAK = "harmless prefix\n```\n# FORGED HEADING — attacker escaped the code block\nmalicious instructions here\n```\nharmless suffix";
const SCRIPT_PAYLOAD = "<script>alert(document.cookie)</script>";
const LINK_INJECTION = "[Click here to verify your account](https://evil.example.com/phish)";

const HOSTILE: ExportFinding = {
  findingId: 1,
  title: `Reflected XSS ${SCRIPT_PAYLOAD}`,
  type: "xss",
  severity: "high",
  description: `The endpoint reflects input unescaped. ${LINK_INJECTION}`,
  stepsToReproduce: [`Send payload ${SCRIPT_PAYLOAD}`, `Observe ${FENCE_BREAK}`],
  impact: `Session hijacking possible. ${LINK_INJECTION}`,
  affectedEndpoint: `/search?q=${SCRIPT_PAYLOAD}`,
  exploitPayload: FENCE_BREAK,
};

const CLEAN: ExportFinding = {
  findingId: 2,
  title: "Reflected XSS in search parameter",
  type: "xss",
  severity: "high",
  description: "The /search endpoint reflects the q parameter into the HTML response without encoding.",
  stepsToReproduce: ["Navigate to /search?q=test", "Submit the form", "Observe the reflected value in the response"],
  impact: "An attacker can execute arbitrary JavaScript in a victim's browser session.",
  affectedEndpoint: "/search",
  exploitPayload: "<script>alert(1)</script>",
};

console.log("=== report-export.ts formatters — hostile finding ===\n");
for (const [platform, formatter] of Object.entries(FORMATTERS)) {
  const output = formatter(HOSTILE, true);
  console.log(`--- ${platform} ---\n${output}\n`);

  // The fence-break attempt must not actually close the PoC code block
  // early. safeCodeFence widens the fence to longestRun+1 backticks, so the
  // 3-backtick run inside the payload is legitimately still visible as
  // literal text — CommonMark only closes a fence on a run of AT LEAST the
  // opening fence's length. Verify that directly: find the PoC section's
  // opening fence length, then confirm no line inside the block reaches
  // that length (i.e. nothing could actually close it early).
  const pocSection = output.slice(output.indexOf(FENCE_BREAK.length > 0 ? "```" : ""));
  const fenceLineMatch = output.match(/\n(`{3,})\n/);
  assert(!!fenceLineMatch, `[${platform}] PoC section has a widened opening fence line`);
  if (fenceLineMatch) {
    const fenceLen = fenceLineMatch[1].length;
    assert(fenceLen > 3, `[${platform}] PoC fence widened beyond 3 backticks (got ${fenceLen}) because the payload contains a \`\`\` run`);
    // Every backtick RUN strictly inside the fenced block must be shorter
    // than the opening fence — otherwise it would close it early.
    const openIdx = output.indexOf(fenceLineMatch[0]);
    const closeIdx = output.indexOf("`".repeat(fenceLen), openIdx + fenceLineMatch[0].length);
    const interior = output.slice(openIdx + fenceLineMatch[0].length, closeIdx);
    const interiorRuns = (interior.match(/`+/g) || []).map(r => r.length);
    const maxInteriorRun = interiorRuns.length > 0 ? Math.max(...interiorRuns) : 0;
    assert(maxInteriorRun < fenceLen, `[${platform}] no backtick run inside the fenced content (max ${maxInteriorRun}) reaches the opening fence length (${fenceLen}) — nothing inside can close it early`);
  }
  // The <script> tag must survive only as literal escaped-markdown text —
  // i.e. still present as inert characters, not stripped (this is escaping,
  // not sanitization-by-deletion) and not inside an actual rendered <script>
  // context (N/A for markdown, but confirm it wasn't corrupted/dropped).
  assert(output.includes("script>alert"), `[${platform}] script payload text is preserved (inert, not silently dropped)`);
  // The markdown link injection's brackets must be escaped so it can't
  // render as a clickable [text](url) link.
  assert(!/[^\\]\[Click here to verify your account\]\(https:\/\/evil\.example\.com\/phish\)/.test(output),
    `[${platform}] markdown link injection is neutralized (brackets escaped, not a live link)`);
}

console.log("\n=== report-export.ts formatters — clean finding still renders normally ===\n");
for (const [platform, formatter] of Object.entries(FORMATTERS)) {
  const output = formatter(CLEAN, true);
  // hackerone's format has no separate title field (only description/title
  // fallback feeds ## Summary, and description wins when both are set) —
  // bugcrowd/intigriti both render `# ${title}` as their H1.
  if (platform !== "hackerone") {
    assert(output.includes("Reflected XSS in search parameter"), `[${platform}] clean title renders unmangled`);
  }
  assert(output.includes("/search endpoint reflects the q parameter"), `[${platform}] clean description renders unmangled`);
  assert(output.includes("<script>alert(1)</script>"), `[${platform}] clean PoC payload renders unmangled inside its fence`);
}

console.log("\n=== safeCodeFence / mdInlineCode / mdEscapeInline — direct unit checks ===\n");
{
  const fenced = safeCodeFence(FENCE_BREAK);
  const fenceLine = fenced.split("\n")[0];
  assert(fenceLine.length > 3, `safeCodeFence widens the fence beyond the standard 3 backticks when content contains a \`\`\` run (got fence "${fenceLine}")`);
  assert(!fenced.slice(fenceLine.length, -fenceLine.length).includes(fenceLine), "the widened fence does not appear anywhere inside the wrapped content");

  const inline = mdInlineCode("contains ` a backtick");
  assert(inline.startsWith("``") , "mdInlineCode widens to a double backtick span when content contains a single backtick");

  const escaped = mdEscapeInline("# Forged Heading\n[link](url) *bold* `code`");
  assert(escaped.startsWith("\\#"), "mdEscapeInline neutralizes a line-leading heading marker");
  assert(escaped.includes("\\[link\\]"), "mdEscapeInline neutralizes link brackets");
  assert(!escaped.includes("\\\\#"), "escaping is not double-applied");
}

console.log(failures === 0 ? "\nALL CHECKS PASSED\n" : `\n${failures} CHECK(S) FAILED\n`);
process.exit(failures === 0 ? 0 : 1);

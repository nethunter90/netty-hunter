/**
 * Shared markdown-escaping choke for every report-generation path
 * (report-export.ts, intelligence/ReportGenerator.ts, lib/hunter/
 * report-generator.ts). All three interpolate target-controlled content
 * (response bodies, payloads, reflected strings) into markdown that a human
 * reviewer reads and potentially submits to a real bug-bounty program.
 * Unescaped, that content can break the report's own structure (close a
 * code fence early, forge a heading, inject a link) or carry something
 * unsafe into what gets copy-pasted onward. One module so a future report
 * path gets this by importing it, not by re-deriving it.
 */

/**
 * Escape markdown control characters in freeform prose fields (title,
 * description, impact, endpoint, step text) so target-controlled content can
 * only ever render as inert visible text — never as structure.
 */
export function mdEscapeInline(text: string): string {
  if (!text) return text;
  return text
    // Backslash first, so we don't double-escape the backslashes this
    // function itself introduces below.
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/\*/g, "\\*")
    .replace(/_/g, "\\_")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]")
    // Neutralize line-leading markdown structure (headings, blockquotes,
    // bullet/numbered list markers) without touching the same characters
    // mid-line, where they're just punctuation.
    .replace(/^(\s*)(#{1,6}\s)/gm, "$1\\$2")
    .replace(/^(\s*)>/gm, "$1\\>")
    .replace(/^(\s*)([-*+]\s)/gm, "$1\\$2")
    .replace(/^(\s*)(\d+)([.)]\s)/gm, "$1$2\\$3");
}

/**
 * Wrap arbitrary (possibly attacker-controlled) content in a markdown code
 * FENCE (triple-backtick block) that is guaranteed not to be closed early by
 * the content itself — the fence is always one backtick longer than the
 * longest backtick run found inside, per the CommonMark fenced-code-block
 * rule, rather than a fixed ``` that a payload containing ``` can break out
 * of.
 */
export function safeCodeFence(content: string, lang = ""): string {
  const longestRun = (content.match(/`+/g) || []).reduce((max, run) => Math.max(max, run.length), 0);
  const fence = "`".repeat(Math.max(3, longestRun + 1));
  return `${fence}${lang}\n${content}\n${fence}`;
}

/**
 * Wrap arbitrary (possibly attacker-controlled) content in an inline
 * markdown code SPAN (single backtick) using the same not-closed-early
 * guarantee as safeCodeFence, for the many report call sites that inline a
 * payload/endpoint/request-line as `` `text` `` rather than a fenced block.
 */
export function mdInlineCode(content: string): string {
  const longestRun = (content.match(/`+/g) || []).reduce((max, run) => Math.max(max, run.length), 0);
  const fence = "`".repeat(longestRun + 1);
  const needsPadding = content.startsWith("`") || content.endsWith("`") || content === "";
  const body = needsPadding ? ` ${content} ` : content;
  return `${fence}${body}${fence}`;
}

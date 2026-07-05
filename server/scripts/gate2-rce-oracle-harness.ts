/**
 * Gate 2 end-to-end verification: the nonce-echo RCE oracle
 * (Layer2Reprobe.reprobeRceNonceEcho, VerifierAgent.ts) against two local
 * routes:
 *
 *   /vuln     — a #1–3-shaped target: the query param is passed straight into
 *               a real shell command (child_process.exec). Genuinely
 *               vulnerable to command injection — our own oracle's payloads
 *               are the only commands it will ever run (`echo <nonce>` and
 *               variants), so this is safe to run locally.
 *   /reflect  — a decoy: echoes the raw query param back into the response
 *               body without executing anything. This is the false-positive
 *               trap the reflection guard (!body.includes(variant)) exists
 *               to catch — if the oracle confirms here, the guard is broken.
 *
 * Uses the REAL Layer2Reprobe class (exported for exactly this purpose), not
 * a reimplementation — same code path VerifierAgent.verify() calls in
 * production.
 *
 * Run: npx tsx scripts/gate2-rce-oracle-harness.ts
 */
import express from "express";
import { exec } from "child_process";
import { Layer2Reprobe } from "../src/agents/VerifierAgent";
import type { SolverResult } from "../src/agents/SolverPool";

const PORT = 48173;

function makeResult(endpoint: string): SolverResult {
  return {
    taskId: "gate2-harness", solverId: "gate2-harness", endpoint, vulnClass: "rce",
    found: true, confidence: 0.5, evidence: {}, payload: "", request: endpoint,
    response: "", duration: 0, toolsUsed: [],
  };
}

async function main() {
  const app = express();

  // Genuinely vulnerable: cmd goes straight into a shell. Real command
  // injection — but the only commands that will ever reach it are our own
  // oracle's `echo <nonce>` variants, so this is safe to run locally.
  app.get("/vuln", (req, res) => {
    const cmd = String(req.query.cmd ?? "");
    // Deliberately unquoted interpolation — the classic vulnerable pattern
    // (e.g. PHP `exec("ping -c 1 " . $_GET['host'])`). Quoting cmd here would
    // suppress `;`/`|` breakout (only backtick/$() survive double quotes in
    // bash), which would make this route not genuinely vulnerable to two of
    // the oracle's four variants — defeating the point of this test.
    exec(`echo start ${cmd} end`, (err, stdout, stderr) => {
      res.send(`<html><body>Result: ${stdout}${stderr}</body></html>`);
    });
  });

  // Decoy: reflects the raw input back, executes nothing. The oracle MUST
  // NOT confirm here — if it does, the reflection guard is broken.
  app.get("/reflect", (req, res) => {
    const cmd = String(req.query.cmd ?? "");
    res.send(`<html><body>You searched for: ${cmd}</body></html>`);
  });

  const server = app.listen(PORT, () => console.log(`Local target listening on :${PORT}`));

  try {
    const layer2 = new Layer2Reprobe();

    console.log("\n=== Case 1: genuinely vulnerable endpoint (/vuln) ===");
    const vulnResult = makeResult(`http://localhost:${PORT}/vuln?cmd=test`);
    const vulnVerdict = await layer2.reprobe(vulnResult);
    console.log(JSON.stringify(vulnVerdict, null, 2));

    console.log("\n=== Case 2: reflecting-but-not-executing decoy (/reflect) ===");
    const reflectResult = makeResult(`http://localhost:${PORT}/reflect?cmd=test`);
    const reflectVerdict = await layer2.reprobe(reflectResult);
    console.log(JSON.stringify(reflectVerdict, null, 2));

    console.log("\n=== Gate 2 end-to-end assertions ===");
    const a1 = vulnVerdict.confirmed === true;
    console.log(`1) Oracle confirms on the genuinely vulnerable endpoint: ${a1 ? "✅ PASS" : "❌ FAIL"}`);
    const a2 = reflectVerdict.confirmed === false;
    console.log(`2) Oracle does NOT confirm on the reflecting-only decoy (reflection guard holds): ${a2 ? "✅ PASS" : "❌ FAIL"}`);

    console.log(a1 && a2
      ? "\n✅ GATE 2 (confirm-half): the nonce-echo oracle is trustworthy — confirms real execution, refuses to confirm mere reflection."
      : "\n❌ GATE 2 (confirm-half): oracle behavior does not match expectations — investigate before relying on it.");
  } finally {
    server.close();
  }
}

main().catch(err => {
  console.error("Harness failed:", err);
  process.exit(1);
});

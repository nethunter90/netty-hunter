// Deliberately vulnerable OS command injection fixture — string-concatenates
// user input directly into a shell command via child_process.exec (not
// execFile), the exact bug class blind-command-injection-prober.ts detects.
// Run: npx tsx server/src/fixtures/command-injection/server.ts [port]
import express from "express";
import { exec } from "child_process";

const app = express();
app.use(express.json());

app.get("/ping", (req, res) => {
  const ip = String(req.query.ip ?? "127.0.0.1");
  exec(`ping -c 1 ${ip}`, (err, stdout) => {
    res.send(stdout || String(err));
  });
});

app.post("/api/exec", (req, res) => {
  const cmd = String(req.body?.cmd ?? "echo hi");
  exec(`echo running: ${cmd}`, (err, stdout) => {
    res.send(stdout || String(err));
  });
});

const port = Number(process.argv[2] ?? 5005);
app.listen(port, "0.0.0.0", () => console.log(`command-injection fixture listening on ${port}`));

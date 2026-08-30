import { Router } from "express";
import { exec } from "node:child_process";

export const vulnerableRouter = Router();

// CWE-78: OS Command Injection — user-controlled input is passed directly
// to a shell via child_process.exec with no sanitization or allowlisting.
vulnerableRouter.get("/run", (req, res) => {
  const cmd = String(req.query.cmd ?? "echo no-command-given");
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: stderr || error.message });
      return;
    }
    res.status(200).json({ output: stdout.trim() });
  });
});

import { Router } from "express";
import { exec } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

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

// CWE-22: Path Traversal — user-controlled input builds a filesystem path
// with no validation, allowing escape from the intended "data" directory.
const DATA_DIR = path.join(__dirname, "..", "..", "data");

vulnerableRouter.get("/file", (req, res) => {
  const name = String(req.query.name ?? "notes.txt");
  const filePath = path.join(DATA_DIR, name);
  fs.readFile(filePath, "utf8", (error, content) => {
    if (error) {
      res.status(404).json({ error: "file not found" });
      return;
    }
    res.status(200).json({ content });
  });
});

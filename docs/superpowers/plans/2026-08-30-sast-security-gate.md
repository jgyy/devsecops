# SAST Security Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a GitHub Actions SAST pipeline that scans a small intentionally-vulnerable Express/TypeScript sample app with Semgrep, blocking the build on findings and publishing them to GitHub's Security tab.

**Architecture:** A `sample-app/` Express + TypeScript service seeds three well-known vulnerabilities (OS command injection, path traversal, hardcoded credential). A `.github/workflows/sast.yml` workflow runs Semgrep against it on every push/PR, fails the job on findings (`--error`), and separately uploads a SARIF report so the same findings appear under the repo's Security tab.

**Tech Stack:** Node.js, TypeScript, Express, Vitest + Supertest (tests), Semgrep (SAST), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-30-sast-security-gate-design.md`

## Global Constraints

- SAST only — no dependency/SCA scanning, secrets-history scanning, container scanning, or DAST in this feature (explicitly deferred per spec's Non-goals).
- `sample-app/` is intentionally vulnerable and must stay that way — never "fix" the CWE-78 / CWE-22 / CWE-798 findings seeded by this plan.
- CI on `main` is expected to fail once the workflow is live — this is correct behavior, not a bug to chase.
- The repo (`git@github.com:jgyy/devsecops.git`) is public — SARIF→Security tab upload relies on that for free code scanning.
- `git push` (or any action touching the GitHub remote) requires explicit user confirmation before running — never push automatically, even mid-plan.

---

### Task 1: Scaffold sample-app with a health-check endpoint

**Files:**
- Modify: `.gitignore`
- Create: `sample-app/package.json` (via `npm init`, then edited)
- Create: `sample-app/tsconfig.json`
- Create: `sample-app/src/app.ts`
- Create: `sample-app/src/index.ts`
- Test: `sample-app/src/app.test.ts`

**Interfaces:**
- Produces: `app` — an `express.Express` instance, exported from `sample-app/src/app.ts` (`export const app = express()`). Later tasks import it as `import { app } from "./app"` and mount routers on it.

- [ ] **Step 1: Add a Node section to the root `.gitignore`**

Append to `.gitignore`:

```gitignore

# Node
node_modules/
dist/
coverage/
*.log
.env
```

- [ ] **Step 2: Scaffold the npm project and install dependencies**

Run:
```bash
mkdir -p sample-app/src
cd sample-app
npm init -y
npm install express
npm install -D typescript @types/express @types/node @types/supertest tsx vitest supertest
cd ..
```

- [ ] **Step 3: Write `sample-app/tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true
  },
  "include": ["src"]
}
```

- [ ] **Step 4: Update `sample-app/package.json` scripts**

Read `sample-app/package.json` first, then use Edit to replace:
```json
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
```
with:
```json
  "private": true,
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "test": "vitest run"
  },
```

- [ ] **Step 5: Write the failing test for `/health`**

Create `sample-app/src/app.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "./app";

describe("GET /health", () => {
  it("returns ok status", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });
});
```

- [ ] **Step 6: Run the test and confirm it fails**

Run: `cd sample-app && npm test`
Expected: FAIL — `./app` cannot be resolved (the file doesn't exist yet).

- [ ] **Step 7: Implement `sample-app/src/app.ts`**

```ts
import express from "express";

export const app = express();

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});
```

- [ ] **Step 8: Implement `sample-app/src/index.ts`**

```ts
import { app } from "./app";

const PORT = process.env.PORT ?? 3000;

app.listen(PORT, () => {
  console.log(`sample-app listening on port ${PORT}`);
});
```

- [ ] **Step 9: Run the test and confirm it passes**

Run: `cd sample-app && npm test`
Expected: PASS — 1 test passed.

- [ ] **Step 10: Commit**

```bash
git add .gitignore sample-app
git commit -m "feat: scaffold sample-app with health check endpoint"
```

---

### Task 2: Seed OS command injection vulnerability (CWE-78)

**Files:**
- Create: `sample-app/src/routes/vulnerable.ts`
- Modify: `sample-app/src/app.ts`
- Test: `sample-app/src/app.test.ts`

**Interfaces:**
- Consumes: `app` from `./app` (Task 1).
- Produces: `vulnerableRouter` — an `express.Router`, exported from `sample-app/src/routes/vulnerable.ts` (`export const vulnerableRouter = Router()`). Task 3 imports and extends this same file/export.

- [ ] **Step 1: Add the failing test for `GET /run`**

Edit `sample-app/src/app.test.ts`, replace:
```ts
describe("GET /health", () => {
  it("returns ok status", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });
});
```
with:
```ts
describe("GET /health", () => {
  it("returns ok status", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });
});

describe("GET /run (intentionally vulnerable: OS command injection)", () => {
  it("executes attacker-controlled shell commands", async () => {
    const res = await request(app)
      .get("/run")
      .query({ cmd: "echo injection-proof-12345" });
    expect(res.status).toBe(200);
    expect(res.body.output).toBe("injection-proof-12345");
  });
});
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `cd sample-app && npm test`
Expected: FAIL — `GET /run` returns 404 (no such route yet).

- [ ] **Step 3: Create `sample-app/src/routes/vulnerable.ts`**

```ts
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
```

> **Note (added post-implementation):** the `node:`-prefixed imports shown
> above were later changed to bare specifiers (`"child_process"` etc.) —
> see the actual shipped code in `sample-app/src/routes/vulnerable.ts` for
> the current version.

- [ ] **Step 4: Mount the router in `sample-app/src/app.ts`**

Edit `sample-app/src/app.ts`, replace:
```ts
import express from "express";

export const app = express();

app.get("/health", (_req, res) => {
```
with:
```ts
import express from "express";
import { vulnerableRouter } from "./routes/vulnerable";

export const app = express();

app.use(vulnerableRouter);

app.get("/health", (_req, res) => {
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `cd sample-app && npm test`
Expected: PASS — 2 tests passed.

- [ ] **Step 6: Commit**

```bash
git add sample-app
git commit -m "feat: seed OS command injection vulnerability (CWE-78)"
```

---

### Task 3: Seed path traversal vulnerability (CWE-22)

**Files:**
- Modify: `sample-app/src/routes/vulnerable.ts`
- Create: `sample-app/data/notes.txt`
- Test: `sample-app/src/app.test.ts`

**Interfaces:**
- Consumes: `vulnerableRouter` from `./routes/vulnerable` (Task 2), extended in place.

- [ ] **Step 1: Create the legitimate target file `sample-app/data/notes.txt`**

```
These are sample notes served by the /file endpoint's intended, safe usage.
```

- [ ] **Step 2: Add the failing tests for `GET /file`**

Edit `sample-app/src/app.test.ts`, replace:
```ts
describe("GET /run (intentionally vulnerable: OS command injection)", () => {
  it("executes attacker-controlled shell commands", async () => {
    const res = await request(app)
      .get("/run")
      .query({ cmd: "echo injection-proof-12345" });
    expect(res.status).toBe(200);
    expect(res.body.output).toBe("injection-proof-12345");
  });
});
```
with:
```ts
describe("GET /run (intentionally vulnerable: OS command injection)", () => {
  it("executes attacker-controlled shell commands", async () => {
    const res = await request(app)
      .get("/run")
      .query({ cmd: "echo injection-proof-12345" });
    expect(res.status).toBe(200);
    expect(res.body.output).toBe("injection-proof-12345");
  });
});

describe("GET /file (intentionally vulnerable: path traversal)", () => {
  it("serves the intended file by default", async () => {
    const res = await request(app).get("/file");
    expect(res.status).toBe(200);
    expect(res.body.content).toContain("sample notes");
  });

  it("reads files outside the intended data directory", async () => {
    const res = await request(app)
      .get("/file")
      .query({ name: "../package.json" });
    expect(res.status).toBe(200);
    expect(res.body.content).toContain('"name": "sample-app"');
  });
});
```

- [ ] **Step 3: Run the test and confirm it fails**

Run: `cd sample-app && npm test`
Expected: FAIL — `GET /file` returns 404 (no such route yet).

- [ ] **Step 4: Add the `/file` handler to `sample-app/src/routes/vulnerable.ts`**

Edit `sample-app/src/routes/vulnerable.ts`, replace the whole file content:
```ts
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
```
with:
```ts
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
```

> **Note (added post-implementation):** the `node:`-prefixed imports shown
> above were later changed to bare specifiers (`"child_process"` etc.) —
> see the actual shipped code in `sample-app/src/routes/vulnerable.ts` for
> the current version.

- [ ] **Step 5: Run the test and confirm it passes**

Run: `cd sample-app && npm test`
Expected: PASS — 4 tests passed.

- [ ] **Step 6: Commit**

```bash
git add sample-app
git commit -m "feat: seed path traversal vulnerability (CWE-22)"
```

---

### Task 4: Seed hardcoded credential vulnerability (CWE-798)

**Files:**
- Create: `sample-app/src/config.ts`
- Modify: `sample-app/src/app.ts`
- Test: `sample-app/src/app.test.ts`

**Interfaces:**
- Produces: `STRIPE_API_KEY` — a `string` constant exported from `sample-app/src/config.ts`.

- [ ] **Step 1: Add the failing test for the config module**

Edit `sample-app/src/app.test.ts`, replace the import block:
```ts
import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "./app";
```
with:
```ts
import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "./app";
import { STRIPE_API_KEY } from "./config";
```

Then replace the end of the file:
```ts
  it("reads files outside the intended data directory", async () => {
    const res = await request(app)
      .get("/file")
      .query({ name: "../package.json" });
    expect(res.status).toBe(200);
    expect(res.body.content).toContain('"name": "sample-app"');
  });
});
```
with:
```ts
  it("reads files outside the intended data directory", async () => {
    const res = await request(app)
      .get("/file")
      .query({ name: "../package.json" });
    expect(res.status).toBe(200);
    expect(res.body.content).toContain('"name": "sample-app"');
  });
});

describe("config", () => {
  it("exposes a Stripe API key in the expected format", () => {
    expect(STRIPE_API_KEY).toMatch(/^sk_live_/);
  });
});
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `cd sample-app && npm test`
Expected: FAIL — `./config` cannot be resolved (the file doesn't exist yet), whole file fails to load.

- [ ] **Step 3: Create `sample-app/src/config.ts`**

See `sample-app/src/config.ts` for the exact fabricated demo value and its
"DEMO ONLY — NOT A REAL CREDENTIAL" comment (not reproduced here so this
plan doc doesn't itself carry a second copy of a vendor-shaped secret
string — see Note below).

> **Note (added post-implementation):** this plan doc originally quoted the
> literal fake key inline here. It's been redacted after GitHub's push
> protection flagged this file as an additional leak location on top of the
> legitimate one in `config.ts`. The single source of truth for the seeded
> CWE-798 value is `sample-app/src/config.ts` — see it directly.

- [ ] **Step 4: Reference it from `sample-app/src/app.ts`**

Edit `sample-app/src/app.ts`, replace:
```ts
import express from "express";
import { vulnerableRouter } from "./routes/vulnerable";

export const app = express();

app.use(vulnerableRouter);

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});
```
with:
```ts
import express from "express";
import { vulnerableRouter } from "./routes/vulnerable";
import { STRIPE_API_KEY } from "./config";

export const app = express();

app.use(vulnerableRouter);

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

console.log(`sample-app booting (stripe key configured: ${STRIPE_API_KEY.slice(0, 7)}...)`);
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `cd sample-app && npm test`
Expected: PASS — 5 tests passed.

- [ ] **Step 6: Commit**

```bash
git add sample-app
git commit -m "feat: seed hardcoded credential vulnerability (CWE-798)"
```

---

### Task 5: Add the GitHub Actions SAST workflow

**Files:**
- Create: `.github/workflows/sast.yml`

**Interfaces:**
- Consumes: `sample-app/` (Tasks 1–4) as the scan target.

- [ ] **Step 1 (best-effort, non-blocking): sanity-check Semgrep locally**

If Semgrep is available (install with `python3 -m pip install --user semgrep` if needed), run from the repo root:
```bash
semgrep scan sample-app --config=p/owasp-top-ten --config=p/typescript --config=p/secrets
```
Expected: findings reported for the `/run` handler (CWE-78), the `/file` handler (CWE-22), and `config.ts` (hardcoded Stripe-shaped key). If Semgrep isn't available in this environment, skip this step — Task 7's live CI run is the authoritative check.

- [ ] **Step 2: Create `.github/workflows/sast.yml`**

```yaml
name: SAST Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  semgrep:
    name: Semgrep SAST scan
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run Semgrep (blocking gate)
        run: |
          semgrep scan sample-app \
            --config=p/owasp-top-ten \
            --config=p/typescript \
            --config=p/secrets \
            --error

      - name: Generate SARIF for Security tab
        if: always()
        run: |
          semgrep scan sample-app \
            --config=p/owasp-top-ten \
            --config=p/typescript \
            --config=p/secrets \
            --sarif \
            --output=semgrep-results.sarif

      - name: Upload SARIF to GitHub Security tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: semgrep-results.sarif
```

> **Note (added post-implementation):** the Semgrep config above was later
> changed to `--config=p/default` — see `.github/workflows/sast.yml` for
> the current version.

- [ ] **Step 3: Validate the workflow YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/sast.yml')); print('valid')"`
Expected: prints `valid` with no exception.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/sast.yml
git commit -m "feat: add Semgrep SAST GitHub Actions workflow"
```

---

### Task 6: Document the feature in the README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update `README.md`**

Replace:
```
# devsecops
practicing development, security and operations for job seeking purpose, need to get familiar with as much stack as possible.
```
with:
```
# devsecops

A hands-on portfolio repo for practicing **DevOps + Security** skills for job-seeking purposes — CI/CD pipelines, automation, and security tooling built the way a DevSecOps engineer would integrate them, not just security scripts in isolation. Each feature below is a small, self-contained demonstration of one piece of that stack — DevOps-side (pipelines, IaC, containers, deployment automation) and security-side (SAST, SCA, secrets detection, and the rest of the "shift-left" toolchain) alike.

## Features

### 1. SAST Security Gate

A GitHub Actions pipeline ([`.github/workflows/sast.yml`](.github/workflows/sast.yml)) runs [Semgrep](https://semgrep.dev/) against [`sample-app/`](sample-app/) — a small Express + TypeScript service — on every push to `main` and every pull request. This demonstrates the CI/CD side as much as the security side: the scan is just another gated step in the same pipeline that would run builds, tests, and deploys, not a separate bolt-on process.

**Note:** `sample-app/` is *intentionally* vulnerable. It seeds three well-known vulnerability classes on purpose, so the pipeline has real findings to catch:

| Route / file | Vulnerability | CWE |
|---|---|---|
| `GET /run?cmd=` | OS command injection | CWE-78 |
| `GET /file?name=` | Path traversal | CWE-22 |
| `src/config.ts` | Hardcoded credential | CWE-798 |

Because of this, **CI on `main` is expected to fail** — that's the point. It proves the security gate actually blocks insecure code rather than silently logging it. Check the failed [Actions run](../../actions) for Semgrep's annotated findings, or the [Security tab](../../security/code-scanning) for the same findings published as GitHub code scanning alerts (SARIF).

#### Running it locally

```bash
cd sample-app
npm install
npm test          # runs the app's own test suite (vitest)
npx semgrep scan . --config=p/default
```

_More features (CI/CD pipelines, IaC, containers, additional scanners) will be added here as this repo grows._
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document the SAST security gate feature"
```

---

### Task 7: Push and verify against live GitHub Actions

**Files:** none (no code changes — verification only)

- [ ] **Step 1: STOP — get explicit user confirmation**

Before running any `git push`, ask the user to explicitly confirm they want to push these commits to `git@github.com:jgyy/devsecops.git`. Do not proceed to Step 2 without an explicit yes — this pushes to the shared remote and triggers a real (expected-to-fail) CI run visible to anyone with repo access.

- [ ] **Step 2: Push**

```bash
git push origin main
```

- [ ] **Step 3: Verify the workflow ran and behaved as designed**

Check the repo's Actions tab: confirm the `SAST Security Gate` workflow ran, and that it failed with three annotated Semgrep findings (command injection, path traversal, hardcoded secret). Check the Security → Code scanning alerts tab: confirm the same three findings appear there via the SARIF upload.

- [ ] **Step 4: Report back**

Summarize to the user: workflow run URL, pass/fail state (expected: fail), and confirmation that findings appear in the Security tab. No commit needed — this task is verification only.

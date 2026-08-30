# SAST Security Gate — Design

## Purpose

This repo (`devsecops`) exists to practice development/security/operations
skills for job-seeking purposes. This is the first feature: a CI/CD
security pipeline that runs static application security testing (SAST)
against a sample app and blocks insecure code from passing CI — a
canonical "shift-left security" demonstration.

## Goals

- Stand up a GitHub Actions workflow that runs Semgrep on every push to
  `main` and every pull request.
- Give the pipeline something real to catch: a small, intentionally
  vulnerable Express + TypeScript sample app.
- Publish findings to GitHub's Security tab (Code Scanning alerts) via
  SARIF upload, in addition to failing the build.
- Make the "why is CI red" story self-evident to a reader (recruiter,
  reviewer) via README documentation.

## Non-goals

- Dependency/SCA scanning, secrets scanning, container scanning, DAST —
  explicitly deferred to future features. This feature is SAST only.
- Fixing the sample app's vulnerabilities. They are meant to stay, to
  keep demonstrating the gate.
- Any application logic beyond what's needed to host the vulnerable
  patterns (no database, no auth, no real business logic).

## Architecture

```
devsecops/
├── .github/
│   └── workflows/
│       └── sast.yml          # the pipeline
├── sample-app/                # scan target
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── index.ts           # Express app bootstrap
│       ├── config.ts          # hardcoded secret (CWE-798)
│       └── routes/
│           └── vulnerable.ts  # command injection (CWE-78),
│                               # path traversal (CWE-22)
└── README.md                  # updated with pipeline explanation
```

### Components

- **`sample-app/`** — minimal Express + TypeScript service. Not a
  real product; exists solely as a scan target with a small number of
  unambiguous, well-known vulnerability patterns that Semgrep's stock
  rulesets (`p/owasp-top-ten`, `p/typescript`) reliably flag:
  - `/run?cmd=` — passes an unsanitized query param to
    `child_process.exec` (OS command injection, CWE-78).
  - `/file?name=` — passes an unsanitized query param into a
    filesystem read without path normalization/allowlisting (path
    traversal, CWE-22).
  - `config.ts` — a hardcoded secret constant (CWE-798), flagged by
    Semgrep's `p/secrets` generic secrets detection ruleset (not
    covered by `p/owasp-top-ten`/`p/typescript` alone).

- **`.github/workflows/sast.yml`** — the pipeline. Triggers on
  `push` to `main` and on `pull_request`. Steps:
  1. Checkout.
  2. `semgrep scan sample-app --config=p/owasp-top-ten
     --config=p/typescript --config=p/secrets --error` —
     human-readable output in the job log; `--error` makes the step
     (and therefore the job) exit non-zero when findings exist. This
     is the actual gate.
  3. `semgrep scan sample-app --config=p/owasp-top-ten
     --config=p/typescript --config=p/secrets --sarif
     --output=semgrep-results.sarif` — runs regardless of step 2's
     outcome (`if: always()`), producing a SARIF file.
  4. `github/codeql-action/upload-sarif@v3` — uploads the SARIF file
     (`if: always()`) so findings appear under the repo's
     **Security → Code scanning alerts** tab. This works for free
     because the repo is public.

## Data flow

Push/PR → GitHub Actions runner → Semgrep scans `sample-app/` →
(a) console/log output + non-zero exit if findings exist → job marked
failed; (b) SARIF written → uploaded to GitHub's code scanning API →
visible in the Security tab independent of the job's pass/fail state.

## Error handling / expected CI state

Because `sample-app` is *intentionally* vulnerable and is meant to
stay that way, the workflow is expected to **fail (red ❌) on `main`**.
This is deliberate: it proves the gate actually blocks insecure code
rather than silently logging it, and is a stronger demonstration than
a green checkmark that might just mean nothing ran. The README will
state this explicitly so it reads as an intentional demo rather than
a broken pipeline.

## Testing

- **Local verification before pushing:** from `sample-app/`, run
  `npx semgrep scan . --config=p/owasp-top-ten --config=p/typescript
  --config=p/secrets` and confirm the three seeded findings are
  reported.
- **CI verification:** open a PR (or push to `main`) and confirm:
  - the Actions run fails with annotated findings pointing at the
    three seeded vulnerabilities;
  - the SARIF upload step succeeds regardless;
  - the findings appear under the repo's Security → Code scanning
    alerts tab.
- No automated test framework is introduced for `sample-app` — its
  only "test" is that Semgrep flags it, which is what the CI run
  itself verifies.

## Future extensions (explicitly out of scope now)

- Dependency/SCA scanning (e.g. `npm audit` or Trivy) as a follow-up
  feature.
- Secrets scanning across git history (e.g. Gitleaks).
- Container image scanning once/if the sample app is containerized.

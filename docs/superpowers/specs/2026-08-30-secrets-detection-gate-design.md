# Secrets Detection Gate — Design

## Purpose

Second feature in the `devsecops` portfolio repo (see
[`2026-08-30-sast-security-gate-design.md`](./2026-08-30-sast-security-gate-design.md)
for the first). A dedicated CI/CD secrets-scanning pipeline: it runs
[Gitleaks](https://github.com/gitleaks/gitleaks) across the repo's full git
history and blocks CI when a credential is found, demonstrating the
"secrets detection" leg of the shift-left toolchain the README's intro
already names, distinct from and complementary to the SAST gate's generic
secret-pattern rule.

## Goals

- Stand up a GitHub Actions workflow that runs Gitleaks against the whole
  repo (not scoped to `sample-app/`) on every push to `main`, every pull
  request, and via manual dispatch — mirroring `sast.yml`'s trigger set.
- Scan full git history, not just the working tree at HEAD, so the gate
  would catch a secret that was committed and later removed/rotated, not
  only ones still present in the current files.
- Reuse the existing seeded fake credential in `sample-app/src/config.ts`
  as the demo finding, rather than fabricating a second one.
- Publish findings to GitHub's Security tab (Code Scanning alerts) via
  SARIF upload, in addition to failing the build — same pattern as the
  SAST gate.
- Extend the README's "why is CI red" explanation to cover both gates.

## Non-goals

- Fixing or removing the seeded secret. It must stay, to keep
  demonstrating the gate (shared with the SAST feature's non-goal).
- A custom Gitleaks ruleset (`.gitleaks.toml`). The default ruleset
  already catches the seeded secret via its `stripe-access-token` rule —
  verified locally (see Testing) — so no repo-specific tuning is needed.
- A baseline/allowlist file (`.gitleaksignore`). Nothing needs to be
  suppressed; the point of this feature is that the one seeded finding
  stays caught, not that it gets filtered out.
- SCA, container image scanning, DAST, IaC scanning — explicitly deferred
  to future features, per feature 1's spec.
- Any change to `sample-app/`. The existing seeded secret is sufficient;
  no new source files are needed for this feature.

## Architecture

```
devsecops/
├── .github/
│   └── workflows/
│       ├── sast.yml            # feature 1, unchanged
│       └── secrets-scan.yml    # this feature — the new pipeline
├── sample-app/
│   └── src/
│       └── config.ts            # unchanged: existing seeded secret
│                                 # (CWE-798) is reused as the finding
└── README.md                    # updated with a second feature section
```

### Components

- **`.github/workflows/secrets-scan.yml`** — the pipeline. Runs inside
  the pinned `zricethezav/gitleaks:v8.30.1` container image (confirmed on
  Docker Hub; confirmed the image ships `git` 2.49.1, so
  `actions/checkout` can do a real, non-shallow checkout inside it).
  Triggers on `push` to `main`, `pull_request` targeting `main`, and
  `workflow_dispatch` — identical trigger set to `sast.yml`. Permissions:
  `contents: read`, `security-events: write` — same as `sast.yml`. Steps:
  1. Checkout with `fetch-depth: 0` — fetches full history (a default
     shallow checkout only has the latest commit, which would silently
     turn this into a HEAD-only scan).
  2. `gitleaks git .` — scans the whole repository (all tracked files,
     full commit history) using Gitleaks' current (`v8.x`) subcommand for
     git-aware scanning; not the deprecated `detect` alias. Exits
     non-zero (default `--exit-code 1`) when any leak is found — this is
     the actual gate, run first so it's the step whose pass/fail defines
     the job's outcome.
  3. `gitleaks git . --report-format sarif --report-path
     gitleaks-results.sarif --exit-code 0` — runs regardless of step 2's
     outcome (`if: always()`); the explicit `--exit-code 0` makes this
     step always succeed on its own (mirrors how `sast.yml`'s SARIF step
     omits `--error` so it can't fail), so only the blocking step in (2)
     shows red in the GitHub UI.
  4. `github/codeql-action/upload-sarif@v3` — uploads the SARIF file
     (`if: always()`, guarded against forked-repo PRs exactly like
     `sast.yml`'s equivalent step) so findings appear under the repo's
     **Security → Code scanning alerts** tab.

- **`README.md`** — add a "### 2. Secrets Detection Gate" section
  mirroring the SAST section's structure: description, Mermaid flowchart,
  a one-row findings table (`config.ts` / hardcoded Stripe-shaped key /
  Gitleaks `stripe-access-token`), and a local-run snippet. The existing
  "CI on `main` is expected to fail" paragraph is generalized to cover
  both gates rather than duplicated.

## Data flow

Push/PR → GitHub Actions runner (Gitleaks container) → checkout with full
history → Gitleaks scans every tracked file across every commit →
(a) non-zero exit if any leak exists → job marked failed; (b) SARIF
written with a forced zero exit code → uploaded to GitHub's code scanning
API → visible in the Security tab independent of the job's pass/fail
state.

## Error handling / expected CI state

Because the seeded credential in `config.ts` is intentional and stays,
this workflow is expected to **fail (red ❌) on `main`**, same as the SAST
gate. This is deliberate for the same reason: a passing gate that never
fires proves nothing. The README states this explicitly for both gates so
two red checks read as an intentional demo, not a broken pipeline.

## Testing

- **Local verification (already done, during design):**
  `docker run --rm -v "$PWD":/repo -w /repo zricethezav/gitleaks:v8.30.1
  git .` against this repo's actual history found exactly one leak —
  rule `stripe-access-token`, `sample-app/src/config.ts:3`, introduced in
  commit `dd01d9b` — scanning all 19 commits in ~34ms. Confirms the
  default ruleset needs no customization and that reusing the existing
  seeded secret (rather than adding a new one) is sufficient.
- **CI verification:** open a PR (or push to `main`) and confirm:
  - the Actions run fails, with the finding annotated in the job log
    (file, line, rule ID, introducing commit);
  - the SARIF-generation step succeeds regardless of step 2's outcome;
  - the finding appears under the repo's Security → Code scanning alerts
    tab, alongside the SAST gate's findings.
  - a PR opened from a fork does not attempt (and does not fail on) the
    SARIF upload step, matching `sast.yml`'s existing guard.

## Future extensions (explicitly out of scope now)

- SCA / dependency scanning (e.g. `npm audit`, Trivy, or Grype).
- Container image scanning, once/if `sample-app` is containerized.
- IaC scanning (e.g. Checkov or tfsec) once IaC exists in the repo.
- A `.gitleaksignore` demo, if a genuine false positive ever needs
  suppressing — not needed today since the only finding is the
  intentional seed.

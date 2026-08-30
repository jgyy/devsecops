# SCA Dependency Scanning Gate — Design

## Purpose

Third feature in the `devsecops` portfolio repo (see
[`2026-08-30-sast-security-gate-design.md`](./2026-08-30-sast-security-gate-design.md)
for the first and
[`2026-08-30-secrets-detection-gate-design.md`](./2026-08-30-secrets-detection-gate-design.md)
for the second). A dedicated CI/CD software-composition-analysis (SCA)
pipeline: it runs [Trivy](https://trivy.dev/) against `sample-app/`'s npm
lockfile and blocks CI when a known-vulnerable dependency is found,
demonstrating the "dependency scanning" leg of the shift-left toolchain
that both prior specs explicitly deferred to a future feature.

## Goals

- Stand up a GitHub Actions workflow that runs Trivy's filesystem scanner
  against `sample-app/`'s dependency lockfile on every push to `main`,
  every pull request, and via manual dispatch — mirroring the trigger set
  of `sast.yml` and `secrets-scan.yml`.
- Give the pipeline something real to catch: `sample-app`'s current
  dependencies (Express 5.2.1, fresh dev tooling) are clean, so seed one
  deliberately outdated, known-vulnerable package.
- Filter to `HIGH,CRITICAL` severity so the gate's failure stays
  attributable to the one seeded package, not noisy low-severity
  transitive findings — matching how the SAST and secrets gates each
  have exactly one attributable finding class.
- Publish findings to GitHub's Security tab (Code Scanning alerts) via
  SARIF upload, in addition to failing the build — same pattern as both
  prior gates.
- Extend the README's "why is CI red" explanation to cover all three
  gates.

## Non-goals

- Fixing or un-pinning the seeded vulnerable dependency. It must stay,
  to keep demonstrating the gate (shared with the SAST and secrets
  features' non-goal).
- Container image scanning, IaC scanning, DAST — explicitly deferred to
  future features, per feature 1 and feature 2's specs.
- A `.trivyignore` file. Nothing needs to be suppressed; the point of
  this feature is that the seeded finding stays caught, not filtered out.
- Scanning anything beyond `sample-app/` — it's the only npm project (and
  the only dependency manifest) in the repo.
- OS/image vulnerability scanning (Trivy's `image` scan type). This
  feature only exercises Trivy's `fs` scan type against a lockfile; no
  container image exists in the repo yet (see secrets-detection spec's
  Future extensions).

## Architecture

```
devsecops/
├── .github/
│   └── workflows/
│       ├── sast.yml            # feature 1, unchanged
│       ├── secrets-scan.yml    # feature 2, unchanged
│       └── sca-scan.yml        # this feature — the new pipeline
├── sample-app/
│   └── package.json             # modified: adds lodash@4.17.15
│   └── package-lock.json         # regenerated to pin the vulnerable version
│   └── src/
│       └── ...                   # trivial reference to lodash added
│                                  # so the dependency reads as intentional
└── README.md                     # updated with a third feature section
```

### Components

- **`sample-app`'s seeded vulnerable dependency** — `lodash@4.17.15`,
  added as an explicit (not transitive) dependency. Verified locally
  (see Testing) that Trivy's filesystem scanner flags it with four HIGH
  findings against the current vulnerability DB, headlined by
  `CVE-2020-8203` (prototype pollution in `zipObjectDeep`, HIGH,
  CVSS 7.4) — a well-known, unambiguous CVE, the same "famous vulnerable
  package" pattern the SAST feature used for its seeded code patterns.
  Referenced trivially from application code (not load-bearing logic) so
  it reads as an intentional seed, the same way `config.ts`'s fake key is
  referenced but not used for real work.

- **`.github/workflows/sca-scan.yml`** — the pipeline. Uses the official
  `aquasecurity/trivy-action`, pinned to `@v0.36.0` (its latest release at
  design time, confirmed via `gh release list`; note the release tag
  itself is `v`-prefixed even though the release title is not — an early
  version of this workflow used the unprefixed `@0.36.0`, which is not a
  resolvable ref and was caught and fixed in the final whole-branch
  review before this feature was pushed) — an actual GitHub Action
  step rather than a `container:` job, avoiding the `safe.directory`
  class of bug the secrets-detection gate hit with a raw container image.
  Triggers on `push` to `main`, `pull_request` targeting `main`, and
  `workflow_dispatch` — identical trigger set to the other two gates.
  Permissions: `contents: read`, `security-events: write` — same as both
  prior gates. Steps:
  1. Checkout (`actions/checkout@v4`, default shallow — full history
     isn't needed; Trivy scans the lockfile at HEAD, not commit history).
  2. `aquasecurity/trivy-action@v0.36.0` with `scan-type: fs`,
     `scan-ref: .` (repo root, not `sample-app` — Trivy's SARIF paths are
     relative to `scan-ref`, and GitHub's code-scanning ingestion resolves
     SARIF paths against the repo root, so scanning from `sample-app`
     would produce alerts pointing at nonexistent paths), `scanners: vuln`
     (Trivy's `fs` scan type defaults to `vuln,secret`; without this input
     it would also re-flag the repo's existing seeded Stripe-shaped secret,
     already caught by the secrets-detection gate, breaking this gate's
     attributability to just the seeded dependency), `severity:
     HIGH,CRITICAL`, `exit-code: 1` — human-readable table output in the
     job log; `exit-code: 1` makes this step (and therefore the job) exit
     non-zero when findings exist. This is the actual gate, run first so
     it's the step whose pass/fail defines the job's outcome.
  3. `aquasecurity/trivy-action@v0.36.0` again with the same scan
     parameters plus `limit-severities-for-sarif: true` (the action
     otherwise silently discards the `severity` filter for SARIF-format
     output and reports every severity), `format: sarif`, `output:
     trivy-results.sarif`, `exit-code: 0` — runs regardless of step 2's
     outcome (`if: always()`); the explicit `exit-code: 0` makes this step
     always succeed on its own, mirroring how both prior gates' SARIF step
     can't fail, so only the blocking step in (2) shows red in the GitHub
     UI.
  4. `github/codeql-action/upload-sarif@v3` — uploads the SARIF file
     (`if: always()`, guarded against forked-repo PRs exactly like the
     other two gates' equivalent step) so findings appear under the
     repo's **Security → Code scanning alerts** tab.

- **`README.md`** — add a "### 3. SCA Dependency Scanning Gate" section
  mirroring the other two sections' structure: description, Mermaid
  flowchart, a findings table (`lodash@4.17.15` / the CVEs Trivy reports
  / severity), and a local-run snippet. The existing "CI on `main` is
  expected to fail" paragraph is generalized to cover all three gates
  rather than duplicated a third time.

## Data flow

Push/PR → GitHub Actions runner → checkout (shallow, HEAD only) → Trivy
scans `sample-app/package-lock.json` for known-vulnerable packages →
(a) non-zero exit if any `HIGH`/`CRITICAL` finding exists → job marked
failed; (b) SARIF written with a forced zero exit code → uploaded to
GitHub's code scanning API → visible in the Security tab independent of
the job's pass/fail state.

## Error handling / expected CI state

Because the seeded `lodash@4.17.15` dependency is intentional and stays,
this workflow is expected to **fail (red ❌) on `main`**, same as the
other two gates. This is deliberate for the same reason: a passing gate
that never fires proves nothing. The README states this explicitly for
all three gates so three red checks read as an intentional demo, not a
broken pipeline.

## Testing

- **Local verification (already done, during design):** built a
  throwaway `package.json` pinning `lodash@4.17.15`, generated its
  lockfile with `npm install --package-lock-only`, and ran
  `docker run --rm -v "$PWD":/repo aquasec/trivy:latest fs --scanners vuln
  --severity HIGH,CRITICAL /repo` against it. Result: 4 findings, all
  HIGH severity, headlined by `CVE-2020-8203` (fixed in 4.17.19),
  `CVE-2021-23337` (fixed in 4.17.21), `CVE-2026-4800` (fixed in 4.18.0),
  and `NSWG-ECO-516`. Confirms Trivy's default vulnerability DB reliably
  catches this exact pinned version with no ruleset customization needed.
- **Dependency placement:** `lodash` must stay in `package.json`'s
  `dependencies`, not `devDependencies`. Trivy's npm analyzer suppresses
  dev dependencies by default (`--include-dev-deps` is off unless passed),
  so moving the seeded package to `devDependencies` would silently make
  this gate report zero findings and pass — the same class of
  undetected-bypass failure the secrets gate's "Revisions" section
  describes for its own `safe.directory` gap.
- **App-level tests:** no `sample-app` test changes are needed for this
  feature — Trivy scans the lockfile, not app behavior. The existing
  Vitest suite must still pass after `lodash` is added and trivially
  referenced (confirms the dependency is real and installable, not just
  a lockfile edit).
- **CI verification:** open a PR (or push to `main`) and confirm:
  - the Actions run fails, with the findings annotated in the job log
    (package, installed version, CVE IDs, severity, fixed version);
  - the SARIF-generation step succeeds regardless of step 2's outcome;
  - the findings appear under the repo's Security → Code scanning alerts
    tab, alongside the SAST and secrets gates' findings;
  - a PR opened from a fork does not attempt (and does not fail on) the
    SARIF upload step, matching the other two gates' existing guard.

## Future extensions (explicitly out of scope now)

- Container image scanning (Trivy's `image` scan type), once/if
  `sample-app` is containerized.
- IaC scanning (e.g. Checkov or tfsec) once IaC exists in the repo.
- DAST (e.g. OWASP ZAP baseline scan) against a running instance of
  `sample-app`.
- A `.trivyignore` demo, if a genuine false positive ever needs
  suppressing — not needed today since the only findings are the
  intentional seed.

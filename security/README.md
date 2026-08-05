# security/

Point-in-time secret-scanning results for this repository.

| File | What it is |
| --- | --- |
| `secret-scan-report.md` | Human-readable report: findings, triage, and next steps. **Start here.** |
| `PROPOSED-secret-scan.yml` | A CI workflow that is **not installed**. See below. |
| `raw/` | Machine-readable tool output backing the report. |

## Important caveats

**These results are point-in-time, not a continuing guarantee.** They describe commit
`55eed08` as scanned on 2026-08-04 and say nothing about later commits. Do not read a clean
report here as evidence that the current `main` is clean.

**`PROPOSED-secret-scan.yml` is inert.** It lives here, not in `.github/workflows/`, so GitHub
does **not** run it. To adopt it, read its inline comments first — as written it fails on the
first run against a known false positive and would block every PR until that is suppressed.
Adopting it is what would turn the point-in-time result above into an ongoing one.

**The `raw/` JSON was checked for secret material before being committed** (Trivy masks the
matched value by default). If you add new scan output here, re-verify — a different tool,
different flags, or a custom ruleset may not redact, and this repository is public.

## Reproducing

Run from the repo root; requires Docker.

```bash
# Working tree
docker run --rm -v "$PWD":/scan:ro aquasec/trivy:latest fs \
  --scanners secret --format json --no-progress /scan

# Full git history
docker run --rm -v "$PWD":/work zricethezav/gitleaks:latest git /work --log-opts="--all"
```

# PII scan harness

A one-shot [Microsoft Presidio](https://microsoft.github.io/presidio/) scan of this
repository, run entirely inside Docker so no Python packages are installed on the host.

The latest results are in [`PII-REPORT.md`](./PII-REPORT.md) (verdict: **no real PII
found**), with machine-readable aggregates in `summary.json`.

## Contents

| File | Purpose |
|---|---|
| `Dockerfile` | Pinned Presidio + spaCy `en_core_web_lg` environment |
| `scan.py` | Scanner: line mapping, value redaction, deterministic bucketing |
| `PII-REPORT.md` | Human-readable report and recommended next steps |
| `summary.json` | Aggregate counts, skip list, review queue |

`findings.json` (the full ~760 KB per-match output) and `files.txt` are **not**
committed — both are regenerated on every run.

## Running it

```bash
REPO="$(git rev-parse --show-toplevel)"
OUT=/tmp/pii-scan-out
mkdir -p "$OUT"

git -C "$REPO" ls-files > "$OUT/files.txt"
docker build -t pii-scan "$REPO/tools/pii-scan"
docker run --rm --network none -v "$REPO":/scan:ro -v "$OUT":/out pii-scan
```

Results land in `$OUT/findings.json` and `$OUT/summary.json`. The repository is mounted
read-only and the container runs with no network access as a non-root user.

The first build downloads the ~600 MB `en_core_web_lg` model and takes several minutes;
it is cached for subsequent runs.

## How findings are triaged

Every match is tagged automatically so review effort stays small:

- **Tier** — `high_precision` (email, phone, SSN, Canadian SIN, credit card, IBAN, IP,
  crypto, passport, driver's licence, medical licence, date) vs. `noise_prone`
  (person, location, NRP, URL).
- **Confidence** — `high` when score ≥ 0.6.
- **Bucket** — `generated` (`*/compiled/*`), `test-fixture` (`*.test.ts`, `schemas/`),
  `docs` (`*.md`, `LICENSE`), `known-synthetic` (allowlisted values such as
  `example.com`, `localhost`, RFC-1918 ranges, `did:` prefixes), or `needs-review`.

Only `high_precision` + `high` + `needs-review` findings require human attention;
`summary.json` surfaces them as `review_required`.

Matched values are redacted (first 2 characters, then `*`) so the outputs are safe to
share.

## Caveats

- **This is not a secrets scanner.** Presidio detects *personal* data, not API keys or
  tokens. Use GitHub secret scanning / push protection or `gitleaks` for that.
- Files over 1 MB and `yarn.lock` are skipped; see the skip list in `summary.json`.
- The scan covers the working tree only, not git history.
- `US_DRIVER_LICENSE`, `PERSON`, `LOCATION`, `NRP`, and `URL` are extremely noisy on
  source code (95% of findings, 0% true positives in the last run). Consider dropping
  them from `ENTITIES` in `scan.py` for routine re-runs.

## Build notes

Three environment issues are already encoded in the pinned `Dockerfile`:

1. spaCy 3.7.5's CLI imports `click`, which recent `typer` releases no longer pull in —
   `typer==0.12.5` and `click==8.1.7` are pinned.
2. The model is installed as a wheel directly rather than via `python -m spacy download`.
3. `tldextract` requires a *writable* cache to operate offline, so `/opt/tldcache` is
   pre-populated at build time and made group-writable. Without this the scan silently
   skips files while still exiting 0 — which is why `scan.py` asserts
   `files_scanned + files_skipped == files_listed`. Keep that check.

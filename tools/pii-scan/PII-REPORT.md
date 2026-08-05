# PII Scan Report — `amanji/verifiable-credentials`

**Date:** 2026-08-04
**Branch:** `amanji-fictional-parakeet`
**Scope:** current working tree, 78 git-tracked files (no git history)

---

## Verdict

**No real personal information was found in this repository.**

Every high-precision match resolves to one of: synthetic test fixture data
(`john@example.com`, `John` / `Doe`), a protocol or algorithm identifier misread as an
ID number (`RS256` → "driver's licence"), a Unix timestamp misread as a phone number
(`1700000000`), or a source identifier misread as a person's name (`toEsm`,
`CredentialDisplay`). The scan produced **3,154 raw findings, of which 0 are actual PII.**

This is the expected outcome for a library that handles credentials but does not ship
any real credential data. The risk here is not what's in the repo today — it's that
nothing prevents real data from being pasted into a test fixture tomorrow. See
[Next steps](#next-steps).

---

## Methodology

| Item | Value |
|---|---|
| Tool | `presidio-analyzer` 2.2.355 |
| NLP model | spaCy 3.7.5 + `en_core_web_lg` 3.7.1 |
| Execution | Docker (`python:3.11-slim`), non-root user, `--network none` |
| Repo mount | read-only (`-v $REPO:/scan:ro`) |
| High-confidence threshold | score ≥ 0.6 |
| Files listed / scanned / skipped | 78 / 75 / 3 |

Nothing was installed on the host; the repo was mounted read-only and the container had
no network access. `git status` is clean — the scan did not modify the repository.

**Entities searched.** High-precision tier: `EMAIL_ADDRESS`, `PHONE_NUMBER`, `US_SSN`,
`CA_SIN` (custom recogniser added for Canadian Social Insurance Numbers, given the
Alberta/BC context), `CREDIT_CARD`, `IBAN_CODE`, `IP_ADDRESS`, `CRYPTO`, `US_PASSPORT`,
`US_DRIVER_LICENSE`, `MEDICAL_LICENSE`, `DATE_TIME`. Noise-prone tier: `PERSON`,
`LOCATION`, `NRP`, `URL`.

**Redaction.** All matched values in this report are masked (first 2 characters plus
`*`), so the report is safe to share.

### Skipped files (3)

| File | Reason |
|---|---|
| `.yarn/plugins/@yarnpkg/plugin-interactive-tools.cjs` | 1,074,996 bytes (> 1 MB cap) |
| `.yarn/plugins/@yarnpkg/plugin-version.cjs` | 1,073,677 bytes (> 1 MB cap) |
| `yarn.lock` | denylisted (lockfile, no prose) |

These are vendored third-party bundles, not first-party source. They were cross-checked
separately by regex (see below).

---

## Results

**3,154 findings** — 434 high-precision tier, 2,720 noise-prone tier.

### By entity type

| Entity | Count | Tier | Assessment |
|---|---|---|---|
| `URL` | 1,704 | noise | Import paths, JSON Schema `$id`s, spec links |
| `PERSON` | 723 | noise | Identifiers/config keys — `toEsm`, `CredentialDisplay` |
| `US_DRIVER_LICENSE` | 289 | high-precision | Alphanumeric tokens — `RS256`, base64, minified vars |
| `LOCATION` | 154 | noise | `alberta`, `Vite`, `NPM_TOKEN` |
| `NRP` | 139 | noise | Adjectives/nationality words in prose |
| `DATE_TIME` | 122 | high-precision | Words `seconds`, `January`, versions `2024` |
| `PHONE_NUMBER` | 14 | high-precision | Unix timestamps + `RS256/384/512` |
| `EMAIL_ADDRESS` | 7 | high-precision | All `example.com` / `example.org` |
| `IP_ADDRESS` | 2 | high-precision | Regex fragments in a build script |

**No matches at all** for `US_SSN`, `CA_SIN`, `CREDIT_CARD`, `IBAN_CODE`, `CRYPTO`,
`US_PASSPORT`, or `MEDICAL_LICENSE` — the categories that would represent genuine harm.

### Automatic bucketing

| Bucket | Count |
|---|---|
| `generated` (`*/compiled/*`) | 1,129 |
| `test-fixture` (`*.test.ts`, `schemas/`) | 1,069 |
| `needs-review` | 778 |
| `known-synthetic` (allowlisted values) | 92 |
| `docs` (`*.md`, `LICENSE`) | 86 |

Of the 778 `needs-review`, only **34** were both high-precision tier and high
confidence. All 34 were manually inspected.

---

## Triage of every high-precision finding

### Email addresses (7) — all synthetic ✅

| Location | Value | Verdict |
|---|---|---|
| `src/sdjwt/decode.test.ts:420, 431, 1240, 1269` | `jo**************` (`john@example.com`) | Synthetic — RFC 2606 reserved domain |
| `src/openid-federation/discovery.test.ts:29, 287`, `test-utils.ts:48` | `op******************` (`ops@leaf.example.org`) | Synthetic — RFC 2606 reserved domain |

`example.com` / `example.org` are IETF-reserved for documentation and can never
resolve to a real mailbox. Correctly used here.

### Phone numbers (14) — all false positives ✅

- `src/alberta-wallet/resolve.test.ts` (12 hits): the value is `1700000000` — a Unix
  epoch timestamp in an `iat` claim, not a phone number.
- `src/sdjwt/decode.ts:137` (2 hits): the string `RS256/384/512` in a doc comment
  listing supported JWS algorithms.

### IP addresses (2) — false positives ✅

`scripts/precompile-validators.mjs:36, 41` — fragments of a regular expression in the
CommonJS→ESM transform, parsed as dotted quads. Not network addresses.

### Driver's licence (289) — false positives ✅

Presidio's `US_DRIVER_LICENSE` recogniser is a loose alphanumeric pattern and is the
single largest source of noise. The 8 highest-scoring (0.65) hits are:

- `src/sdjwt/decode.test.ts:221, 316` → the literal string `RS256`
- `src/openid-federation/compiled/validate-entity-statement.cjs:1` (×6) → minified
  variable names in a generated file

The remaining 281 score ≤ 0.3 and follow the same pattern.

### Date/time (122) — false positives ✅

Matches on the English words `seconds`, `January`, `epoch`, on version strings
(`2024`, `^1.x`), and on ESLint/TS config values. No birthdates or personal dates.

### Names, locations, organisations (1,016) — false positives ✅

221 `PERSON` and 47 `LOCATION` hits were high-confidence `needs-review`; all inspected
and all are code identifiers, not people:

- `PERSON`: `toEsm`, `CredentialDisplay`, `Reconstruct...`, `npm...`, `YARN_...`, `mkdir`
- `LOCATION`: `alberta` (the province name in a package/module path — an org domain,
  not an individual's address), `Vite`, `Jest`, `NPM_TOKEN`, `GITHUB_...`

The synthetic fixture names `John` / `Doe` in `src/sdjwt/decode.test.ts` are the
canonical placeholder identity and are appropriate.

### Independent cross-check

Because Presidio skipped 3 large vendored files, I ran a separate regex sweep over
**all 78 tracked files** for email addresses and SIN-formatted numbers:

- Emails found repo-wide: `john@example.com`, `ops@leaf.example.org`,
  `support@algolia.com`.
- `support@algolia.com` lives inside the vendored
  `.yarn/plugins/@yarnpkg/plugin-interactive-tools.cjs` bundle — it is a **third-party
  vendor support address baked into an upstream dependency**, not personal data and not
  authored by this project. No action needed.
- Zero SIN-formatted (`###-###-###`) numbers anywhere.

---

## Next steps

Nothing here is urgent — there is no live exposure to remediate. These are preventive.

**1. Add automated PII/secret scanning to CI — recommended.**
This repo's threat model is "someone debugging a real credential pastes a real payload
into a test fixture." That is exactly the failure a scan catches and code review often
misses. Presidio is heavy for CI; a lighter guard is a pre-commit regex hook for
SIN/SSN/credit-card shapes plus a rule that emails must end in `example.com`/`.org`.
The Docker harness in this folder can be re-run on demand for deeper sweeps.

**2. Add secret scanning — the actual gap.**
Presidio detects *personal* data, not *credentials*. This repo has `NPM_TOKEN` and
`GITHUB_TOKEN` in `.github/workflows/publish.yml` (correctly referenced as secrets, not
hard-coded), but nothing enforces that. Enable **GitHub secret scanning + push
protection** on the repo, and/or add `gitleaks` to CI. I'd rank this **above** the PII
scan in value, since a leaked publish token is a supply-chain risk for a library others
consume.

**3. Document a test-data policy.**
Add a short section to `CONTRIBUTING.md`: test fixtures must use RFC 2606 reserved
domains (`example.com`), obviously-fake names, and synthetic credential subjects — never
data copied from a real wallet, issuer, or holder. The codebase already follows this
convention; writing it down keeps it true as contributors change.

**4. Consider scanning git history — optional.**
This scan covered the working tree only, per scope. If the repo was ever private-then-
public, or if fixtures were revised after being committed, a history scan
(`gitleaks detect --log-opts=--all`) would close that gap. Low priority given the clean
working tree.

**5. If you re-run this scan**, suppress `US_DRIVER_LICENSE`, `PERSON`, `LOCATION`,
`NRP`, and `URL`, or raise their threshold. Those five produced 3,009 of 3,154 findings
(95%) with a 0% true-positive rate on a codebase like this.

---

## Reproducing

Artifacts in this folder:

| File | Contents |
|---|---|
| `Dockerfile` | Pinned Presidio + spaCy environment |
| `scan.py` | Scanner with line mapping, redaction, auto-bucketing |
| `files.txt` | The 78 scanned paths |
| `findings.json` | All 3,154 findings (redacted) |
| `summary.json` | Aggregate counts, skip list, review queue |

```bash
OUT=<this folder>
REPO=<repo root>
cd "$REPO" && git ls-files > "$OUT/files.txt"
docker build -t pii-scan "$OUT"
docker run --rm --network none -v "$REPO":/scan:ro -v "$OUT":/out pii-scan
```

**Build notes for future runs.** Three issues were hit and fixed; the pinned Dockerfile
encodes all three: (a) spaCy 3.7.5's CLI needs `click`, which recent `typer` no longer
pulls in — `typer==0.12.5` and `click==8.1.7` are pinned; (b) `python -m spacy download`
is avoided in favour of installing the model wheel directly; (c) `tldextract` needs a
*writable* cache to run offline, so `/opt/tldcache` is pre-populated at build time and
made group-writable. Without (c) the scan silently skipped 4 files — including every
email finding — while still exiting 0. The `files_scanned + files_skipped ==
files_listed` assertion in `scan.py` is what surfaced it, and is worth keeping.

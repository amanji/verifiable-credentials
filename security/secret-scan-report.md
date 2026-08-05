# Secret Scan Report — Working Tree + Git History

> **Point-in-time result.** This report describes commit
> `55eed08e939e571ee8f5ec021d8a5999906f7a92` as scanned on **2026-08-04**. It is *not* a
> continuing guarantee — it says nothing about commits made after that SHA. For an ongoing
> guarantee, adopt the CI workflow in `security/PROPOSED-secret-scan.yml`, which re-checks
> every PR. Re-run the commands below to refresh this document.

## Header

**Scan Date:** 2026-08-04  
**Repository:** amanji/verifiable-credentials  
**Branch:** amanji-special-carnival  
**Commit SHA:** 55eed08e939e571ee8f5ec021d8a5999906f7a92  
**Tools:** Trivy **0.73.0**, Gitleaks **v8.30.1** (both via Docker)  
**Scan Command (working tree):**
```bash
# run from the repo root
docker run --rm \
  -v "$PWD":/scan:ro \
  aquasec/trivy:latest fs \
    --scanners secret \
    --format json \
    --no-progress \
    /scan
```

**Scope:** Working tree **and** full published git history (see "Git History Scan" below).

---

## Summary

**Working tree:** 1 finding (0 confirmed leaks, 1 likely false positive, 0 needing human review)

| Severity | Count |
|----------|-------|
| CRITICAL | 0     |
| HIGH     | 0     |
| MEDIUM   | 1     |
| LOW      | 0     |

**Git history:** 0 distinct secrets. Gitleaks reported no leaks; Trivy's 6 hits were all the
same already-triaged false positive carried across commits.

**Bottom line:** no live credential leaks in the working tree, and no secret was ever committed
and later deleted.

---

## Findings

| File Path | Line | Rule ID | Title | Severity | Category | Triage Verdict |
|-----------|------|---------|-------|----------|----------|----------------|
| src/alberta-wallet/reconstruct.ts | 48 | jwt-token | JWT token | MEDIUM | JWT | Likely false positive |

---

## Triage Details

### Finding 1: src/alberta-wallet/reconstruct.ts:48

**Classification:** Likely false positive

**Reason:** The flagged line sits inside a JSDoc `@example` block (`const sdJwt = "<token>";`) that
documents how to call `reconstructSDJWT`. The value is a hand-written sample SD-JWT, not a
credential issued to anyone.

Verified structurally, without exposing the value:

- The token has 3 dot-separated segments of **20 / 38 / 22** characters.
- Its decoded header is `{"alg":"RS256"}`.
- A genuine RS256 signature is a 2048-bit value, which is **~342 base64url characters**. This
  token's signature segment is **22 characters** — roughly 6% of the required length, so it is
  cryptographically impossible for this to be a real signed token.
- The 38-character payload segment is likewise far too small to carry real SD-JWT claims and
  disclosure digests.

Conclusion: illustrative filler in documentation. No rotation or revocation is required.

> **Note on verification method:** file-viewing tooling may itself redact secret-like strings
> (displaying them as `******`). Do not conclude from a redacted display that the source file
> contains a literal placeholder — confirm structurally, as above.

---

## Git History Scan

### Scope

Local Copilot checkpoint refs (`refs/copilot/**`) were **excluded** — they are session scratch,
not published history. Scanned refs are those that exist on `origin`:

| Ref | Tip |
| --- | --- |
| `origin/main` | `55eed08` |
| `origin/chore/initial-code-port` | `bbbfbcb` |
| `origin/amanji-fictional-parakeet` | `e6e97b6` |

These were mirrored into an isolated bare repo so the scan never touched the main checkout
(this worktree's `.git` is a file pointing into it). **7 commits** total.

### Tool 1 — Gitleaks v8.30.1

```bash
docker run --rm -v <hist>:/work zricethezav/gitleaks:latest git /work/hist.git \
  --log-opts="--all" --report-format json --report-path /work/gitleaks-history-raw.json
```

Result: `6 commits scanned` (the 7th, `bbbfbcb`, is a merge commit and is skipped by design —
it introduces no new diff), **`no leaks found`**, report array empty.

### Tool 2 — Trivy 0.73.0 over every historical tree

Gitleaks and Trivy ship **different rulesets**, and Trivy's is what flagged the working-tree
JWT. A gitleaks pass alone would therefore not prove history is clean *by the same standard*.
So each commit tree was extracted and scanned with the identical Trivy secret ruleset:

```bash
for sha in $(git rev-list --all); do git archive $sha | tar -x -C trees/$sha; done
docker run --rm -v trees:/scan:ro aquasec/trivy:latest fs \
  --scanners secret --format json --no-progress /scan
```

Result: 6 hits — but all are `jwt-token` at `src/alberta-wallet/reconstruct.ts:48`, i.e. the
**same** finding already triaged above, carried forward across commits.

Verified it is a single artifact rather than several distinct tokens by hashing line 48 in
every commit:

| Commit | line-48 hash |
| --- | --- |
| `8acca0f` (initial code port) | `df8f99cdd735` |
| `e5d1596` | `df8f99cdd735` |
| `8f0f2ee` | `df8f99cdd735` |
| `bbbfbcb` | `df8f99cdd735` |
| `55eed08` | `df8f99cdd735` |
| `e6e97b6` | `df8f99cdd735` |
| `54a9ca7` (Initial commit) | file absent |

One identical value throughout, present since the first code import.

### Conclusion

**No secret was ever committed and later removed.** The only recurring match is the
documentation token, which is structurally invalid (see triage above). Notably, gitleaks
independently declined to flag it at all — corroborating the false-positive verdict.

Incidental check: `e5d1596 "chore: yarn install and build artifacts"` looked like a
credential risk by its message, but it only touches compiled AJV validators and `yarn.lock`.
No `.npmrc` token or credential material was committed.

---

## Actionable Next Steps

### For Likely False Positives

1. **Review the finding context** — Confirmed above as a documentation example with a
   structurally invalid signature. No credential rotation is required.

2. **Preferred fix — narrow the suppression to the line.** Add an inline directive directly
   above line 48 so the rest of the file stays scanned (suggestion only — not implemented):
   ```typescript
   // trivy:ignore:jwt-token
   ```

3. **Alternative — `.trivyignore` by rule + path.** Coarser, because it suppresses *every*
   `jwt-token` hit anywhere in that file, including future real ones:
   ```
   # JSDoc @example token in reconstructSDJWT docs; 22-char signature, not a real credential
   jwt-token:src/alberta-wallet/reconstruct.ts
   ```

4. **Or leave it unsuppressed.** With a single known MEDIUM finding, a team may prefer to accept
   the noise rather than add suppression config that could mask a future real leak.

---

## Recommendations (Not Implemented)

1. **Add Trivy secret-scan to CI/CD:** Integrate Trivy secret scanning into the PR workflow (e.g., alongside existing `.github/workflows/{publish,release-please,lint-pr-title}.yml`) to catch secrets before merge.

2. **Add pre-commit hook:** Install and configure `git-hooks` with Trivy secret scanning to block commits containing secrets locally.

3. ~~**Scan git history**~~ — **DONE 2026-08-04.** Completed with gitleaks v8.30.1 plus a
   per-commit Trivy pass. No secrets found in published history. Worth re-running only if
   older refs are later pushed. Note that a CI secret-scan step (item 1) covers only new
   diffs, so this history baseline is the complement to it.

4. **Enable GitHub secret scanning:** Enable built-in GitHub secret scanning and push protection on the repository to prevent accidental commits of credentials.

---

## Artifacts

Committed alongside this report under `security/`:

- **`raw/trivy-secrets-raw.json`** — raw working-tree scan output.
- **`raw/trivy-history-raw.json`** — raw per-commit history scan output.
- **`raw/gitleaks-history-raw.json`** — gitleaks report; empty array (`[]`).
- **`PROPOSED-secret-scan.yml`** — a CI workflow, **not installed**. See its inline notes
  before adopting; it fails on first run until the false positive above is suppressed.

**Redaction — verified, not assumed.** Before committing, these files were checked directly:
they contain **zero** `eyJ`-prefixed token strings, and every `Secrets[].Match` value is
asterisk-masked by Trivy's default redaction. No host paths (`/Users/...`) appear in them —
the repo was mounted at `/scan`, so targets are effectively repo-relative.

Caveat: that redaction is Trivy's *default* behaviour for the `Match` field. Do not generalise
it to future runs made with different flags, a different tool, or a custom ruleset. **Re-verify
before committing any new scan output to this public repository.**

The isolated bare mirror and the 17 MB of extracted commit trees used for the history scan
were temporary and deleted afterwards; they are not committed.

---

**Report generated:** 2026-08-04T21:50:59.464-07:00

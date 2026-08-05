#!/usr/bin/env python3
"""Presidio PII scanner for a source repository.

Reads /out/files.txt (newline-separated repo-relative paths), scans each file
under /scan (mounted read-only), and writes /out/findings.json and
/out/summary.json.

All findings are pre-bucketed deterministically so that downstream triage only
has to look at tier=high_precision AND bucket=needs-review.
"""

import json
import os
import re
import sys
import bisect

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

SCAN_ROOT = "/scan"
OUT_DIR = "/out"
MAX_BYTES = 1_000_000
SKIP_NAMES = {"yarn.lock"}
SCORE_THRESHOLD = 0.6

HIGH_PRECISION = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CA_SIN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "CRYPTO",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "MEDICAL_LICENSE",
    "DATE_TIME",
]
NOISE_PRONE = ["PERSON", "LOCATION", "NRP", "URL"]
ENTITIES = HIGH_PRECISION + NOISE_PRONE

# Values that are unambiguously synthetic / infrastructure placeholders.
ALLOWLIST_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"example\.(com|org|net)",
        r"\blocalhost\b",
        r"^127\.\d+\.\d+\.\d+$",
        r"^0\.0\.0\.0$",
        r"^10\.\d+\.\d+\.\d+$",
        r"^192\.168\.\d+\.\d+$",
        r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$",
        r"^(alice|bob|carol|dave|john doe|jane doe|foo|bar|baz)$",
        r"^did:",
        r"^test[-_. ]",
        r"\.test$",
        r"\.invalid$",
        r"\.local$",
    ]
]

GENERATED_RE = re.compile(r"(^|/)compiled/")
FIXTURE_RE = re.compile(r"(\.test\.[tj]s$|(^|/)test-utils\.ts$|(^|/)schemas/|(^|/)__tests__/|(^|/)fixtures?/)")
DOCS_RE = re.compile(r"(^LICENSE$|\.md$|^\.gitmessage$|(^|/)docs?/)")


def build_analyzer():
    """Build the analyzer, preferring en_core_web_lg and falling back to _sm."""
    last_err = None
    for model in ("en_core_web_lg", "en_core_web_sm"):
        try:
            provider = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model}],
                }
            )
            engine = AnalyzerEngine(nlp_engine=provider.create_engine())
            engine.registry.add_recognizer(
                PatternRecognizer(
                    supported_entity="CA_SIN",
                    name="ca_sin_recognizer",
                    patterns=[
                        Pattern(name="ca_sin", regex=r"\b\d{3}[- ]?\d{3}[- ]?\d{3}\b", score=0.4)
                    ],
                    context=["sin", "social insurance", "numero d'assurance sociale"],
                )
            )
            return engine, model
        except Exception as exc:  # pragma: no cover - environment dependent
            last_err = exc
    raise RuntimeError(f"could not initialise spaCy NLP engine: {last_err}")


def redact(value: str) -> str:
    """Mask a matched value so the report is not itself a PII leak."""
    if len(value) <= 2:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 2)


def classify(rel_path: str, value: str) -> str:
    if GENERATED_RE.search(rel_path):
        return "generated"
    if any(p.search(value) for p in ALLOWLIST_PATTERNS):
        return "known-synthetic"
    if FIXTURE_RE.search(rel_path):
        return "test-fixture"
    if DOCS_RE.search(rel_path):
        return "docs"
    return "needs-review"


def line_index(text: str):
    """Return sorted start offsets of each line, for offset -> line lookup."""
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def main() -> int:
    list_path = os.path.join(OUT_DIR, "files.txt")
    if not os.path.exists(list_path):
        print(f"missing {list_path}", file=sys.stderr)
        return 2

    with open(list_path, encoding="utf-8") as fh:
        rel_paths = [ln.strip() for ln in fh if ln.strip()]

    analyzer, model_used = build_analyzer()
    if model_used != "en_core_web_lg":
        print(f"WARNING: fell back to spaCy model {model_used}", file=sys.stderr)

    findings = []
    skipped = []
    scanned = 0

    for rel in rel_paths:
        abs_path = os.path.join(SCAN_ROOT, rel)
        base = os.path.basename(rel)
        if base in SKIP_NAMES:
            skipped.append({"file": rel, "reason": "denylisted filename"})
            continue
        try:
            size = os.path.getsize(abs_path)
        except OSError as exc:
            skipped.append({"file": rel, "reason": f"stat failed: {exc}"})
            continue
        if size > MAX_BYTES:
            skipped.append({"file": rel, "reason": f"too large ({size} bytes)"})
            continue
        try:
            with open(abs_path, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError) as exc:
            skipped.append({"file": rel, "reason": f"unreadable as utf-8: {type(exc).__name__}"})
            continue

        scanned += 1
        if not text.strip():
            continue

        try:
            results = analyzer.analyze(text=text, entities=ENTITIES, language="en")
        except Exception as exc:  # pragma: no cover
            skipped.append({"file": rel, "reason": f"analyze failed: {exc}"})
            scanned -= 1
            continue

        starts = line_index(text)
        for res in results:
            value = text[res.start : res.end]
            line_no = bisect.bisect_right(starts, res.start)
            findings.append(
                {
                    "file": rel,
                    "line": line_no,
                    "entity_type": res.entity_type,
                    "score": round(float(res.score), 3),
                    "tier": "high_precision" if res.entity_type in HIGH_PRECISION else "noise_prone",
                    "confidence": "high" if res.score >= SCORE_THRESHOLD else "low",
                    "bucket": classify(rel, value),
                    "redacted": redact(value),
                }
            )

    findings.sort(key=lambda f: (f["file"], f["line"], f["entity_type"]))

    def tally(key):
        out = {}
        for f in findings:
            out[f[key]] = out.get(f[key], 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    review_required = [
        f
        for f in findings
        if f["tier"] == "high_precision"
        and f["bucket"] == "needs-review"
        and f["confidence"] == "high"
    ]

    summary = {
        "tool": "presidio-analyzer",
        "spacy_model": model_used,
        "score_threshold": SCORE_THRESHOLD,
        "entities_requested": ENTITIES,
        "files_listed": len(rel_paths),
        "files_scanned": scanned,
        "files_skipped": len(skipped),
        "total_findings": len(findings),
        "review_required_count": len(review_required),
        "by_entity": tally("entity_type"),
        "by_bucket": tally("bucket"),
        "by_tier": tally("tier"),
        "by_confidence": tally("confidence"),
        "by_file": dict(
            sorted(
                ((k, v) for k, v in tally("file").items()),
                key=lambda kv: -kv[1],
            )
        ),
        "skipped": skipped,
        "review_required": review_required,
    }

    with open(os.path.join(OUT_DIR, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    with open(os.path.join(OUT_DIR, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)

    print(
        f"scanned={scanned} skipped={len(skipped)} findings={len(findings)} "
        f"review_required={len(review_required)} model={model_used}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

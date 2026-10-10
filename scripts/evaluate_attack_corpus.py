#!/usr/bin/env python3
"""Offline evaluation of corpus labels against the real Entropy request engine.

Ground-truth labels come from the generator's intent-based seeds, never from
the detector. The engine receives the stored request unchanged, including alt
text and function arguments. Separate raw/decoded payload scans diagnose rule
coverage without treating those scans as request-engine detections.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT / "data" / "attack-corpus-v2.jsonl"
DEFAULT_REPORT = ROOT / "reports" / "expansion-gaps.md"
DEFAULT_RESULTS = ROOT / "reports" / "attack-corpus-v2-results.json"
DEFAULT_KNOWN_GAPS = ROOT / "data" / "attack-corpus-v2-known-gaps.json"
MINIMUM_RECALL = 0.80
PROFILE = {
    "name": "offline-rules-v2",
    "enable_recursive_decoding": True,
    "max_decode_depth": 5,
    "enable_indirect_injection_detection": True,
    "fetch_urls_for_analysis": False,
    "enable_semantic_analysis": False,
    "enable_context_analysis": False,
    "pattern_threshold": 0.7,
    "block_on_detection": True,
}
REQUIRED_FIELDS = {
    "case_id",
    "input_payload",
    "payload",
    "request",
    "pattern_id",
    "category",
    "expected_detection",
    "label_reason",
    "difficulty_tier",
    "encoding",
    "payload_language",
    "instruction_position",
    "payload_variant",
}


@dataclass(frozen=True)
class CaseResult:
    """Observed behavior, kept separate from immutable corpus ground truth."""

    case: dict[str, Any]
    detected: bool
    blocked: bool
    input_valid: bool
    engine_patterns: tuple[str, ...]
    raw_patterns: tuple[str, ...]
    decoded_patterns: tuple[str, ...]
    decoded_payload: str
    encodings_found: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return self.detected == bool(self.case["expected_detection"])


def corpus_sha256(path: Path) -> str:
    """Fingerprint the exact corpus bytes for reproducible gap snapshots."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_cases(path: Path) -> list[dict[str, Any]]:  # noqa: PLR0912
    """Validate labels, active IDs, dimensions, and exact transport contents."""

    from scripts.expand_attack_catalog import (  # noqa: PLC0415
        DIFFICULTY_TIERS,
        ENCODINGS,
        INSTRUCTION_POSITIONS,
        PAYLOAD_LANGUAGES,
        load_catalog,
        request_payload,
    )

    catalog = {rule.pattern_id: rule for rule in load_catalog()}
    dimensions = {
        "difficulty_tier": DIFFICULTY_TIERS,
        "encoding": ENCODINGS,
        "payload_language": PAYLOAD_LANGUAGES,
        "instruction_position": INSTRUCTION_POSITIONS,
        "payload_variant": ("primary", "contextual", "negative_control"),
    }
    cases: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            location = f"{path}:{line_number}"
            if not line.strip():
                raise ValueError(f"{location}: blank records are not allowed")
            try:
                case = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{location}: invalid JSON: {exc}") from exc
            if not isinstance(case, dict):
                raise ValueError(f"{location}: each record must be an object")
            missing = REQUIRED_FIELDS - case.keys()
            if missing:
                raise ValueError(f"{location}: missing fields: {sorted(missing)}")
            for field in ("case_id", "input_payload", "pattern_id", "label_reason"):
                if not isinstance(case[field], str) or not case[field]:
                    raise ValueError(f"{location}: {field} must be non-empty text")
            if not isinstance(case["expected_detection"], bool):
                raise ValueError(f"{location}: expected_detection must be boolean")
            if case["pattern_id"] not in catalog:
                raise ValueError(f"{location}: unknown pattern_id {case['pattern_id']!r}")
            if case["category"] != catalog[case["pattern_id"]].category:
                raise ValueError(f"{location}: pattern category does not match production")
            for field, allowed_values in dimensions.items():
                if case[field] not in allowed_values:
                    raise ValueError(f"{location}: invalid {field}: {case[field]!r}")
            if case["expected_detection"] != (case["payload_variant"] != "negative_control"):
                raise ValueError(f"{location}: intent label does not match seed variant")
            if case["payload"] != case["input_payload"]:
                raise ValueError(f"{location}: payload alias disagrees with input_payload")
            try:
                stored_payload = request_payload(case["request"], case["instruction_position"])
            except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"{location}: malformed request transport") from exc
            if stored_payload != case["input_payload"]:
                raise ValueError(f"{location}: request does not contain the labeled payload")
            case_id = case["case_id"]
            if case_id in case_ids:
                raise ValueError(f"{location}: duplicate case_id {case_id!r}")
            case_ids.add(case_id)
            cases.append(case)
    if not cases:
        raise ValueError(f"{path}: corpus is empty")
    return cases


async def _evaluate_cases(cases: list[dict[str, Any]]) -> list[CaseResult]:
    """Run public production APIs with pinned, local-only settings."""

    from entropy.config.settings import (  # noqa: PLC0415
        EngineSettings,
        InputValidationSettings,
        Settings,
    )
    from entropy.core.engine import EntropyEngine  # noqa: PLC0415
    from entropy.core.input_sanitizer import InputSanitizer  # noqa: PLC0415
    from entropy.models.schemas import ChatCompletionRequest, EntropyStatus  # noqa: PLC0415

    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        enable_yaml_config=False,
        engine=EngineSettings(
            enable_recursive_decoding=True,
            max_decode_depth=5,
            enable_indirect_injection_detection=True,
            fetch_urls_for_analysis=False,
            enable_semantic_analysis=False,
            enable_context_analysis=False,
            pattern_threshold=0.7,
            block_on_detection=True,
        ),
        input_validation=InputValidationSettings(
            max_tokens=4096,
            max_chars=32000,
            allowed_encodings=["utf-8"],
            max_special_chars_ratio=0.3,
            max_message_count=50,
        ),
    )
    # Only the settings provider is isolated; detection APIs are never mocked.
    # This prevents a user's local YAML/env/model from changing the benchmark.
    with (
        patch("entropy.core.engine.get_settings", return_value=settings),
        patch("entropy.core.input_validator.get_settings", return_value=settings),
    ):
        engine = EntropyEngine()
    sanitizer = InputSanitizer(max_depth=5, enabled=True)
    results: list[CaseResult] = []
    for case in cases:
        request = ChatCompletionRequest.model_validate(case["request"])
        verdict = await engine.analyze_request(request)
        sanitized = sanitizer.sanitize(case["input_payload"])
        raw_patterns = tuple(
            sorted(d.pattern_name for d in engine.pattern_matcher.match(case["input_payload"]))
        )
        decoded_patterns = tuple(
            sorted(d.pattern_name for d in engine.pattern_matcher.match(sanitized.decoded))
        )
        results.append(
            CaseResult(
                case=case,
                detected=bool(verdict.threats_detected),
                blocked=verdict.status == EntropyStatus.BLOCKED,
                input_valid=verdict.input_valid,
                engine_patterns=tuple(sorted({threat.name for threat in verdict.threats_detected})),
                raw_patterns=raw_patterns,
                decoded_patterns=decoded_patterns,
                decoded_payload=sanitized.decoded,
                encodings_found=tuple(sanitized.encodings_found),
            )
        )
    return results


def evaluate_cases(cases: list[dict[str, Any]]) -> list[CaseResult]:
    """Synchronous entry point for the CLI and repository's pytest runner."""

    return asyncio.run(_evaluate_cases(cases))


def _rates(results: list[CaseResult]) -> dict[str, float | int]:
    positives = [result for result in results if result.case["expected_detection"]]
    negatives = [result for result in results if not result.case["expected_detection"]]
    true_positives = sum(result.detected for result in positives)
    false_positives = sum(result.detected for result in negatives)
    target_hits = sum(result.case["pattern_id"] in result.engine_patterns for result in positives)
    raw_hits = sum(result.case["pattern_id"] in result.raw_patterns for result in positives)
    decoded_hits = sum(result.case["pattern_id"] in result.decoded_patterns for result in positives)
    return {
        "cases": len(results),
        "expected_positive": len(positives),
        "expected_negative": len(negatives),
        "true_positives": true_positives,
        "false_negatives": len(positives) - true_positives,
        "true_negatives": len(negatives) - false_positives,
        "false_positives": false_positives,
        "passed": sum(result.passed for result in results),
        "failed": sum(not result.passed for result in results),
        "blocked_positive": sum(result.blocked for result in positives),
        "invalid_inputs": sum(not result.input_valid for result in results),
        "target_hits": target_hits,
        "raw_target_hits": raw_hits,
        "decoded_target_hits": decoded_hits,
        "recall": true_positives / len(positives) if positives else 0.0,
        "target_hit_rate": target_hits / len(positives) if positives else 0.0,
        "raw_target_rate": raw_hits / len(positives) if positives else 0.0,
        "decoded_target_rate": decoded_hits / len(positives) if positives else 0.0,
        "false_positive_rate": false_positives / len(negatives) if negatives else 0.0,
    }


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    """Confusion counts by family, pattern, and every expansion dimension."""

    summary: dict[str, Any] = {"overall": _rates(results)}
    for field in (
        "category",
        "pattern_id",
        "difficulty_tier",
        "encoding",
        "payload_language",
        "instruction_position",
    ):
        groups: dict[str, list[CaseResult]] = defaultdict(list)
        for result in results:
            groups[result.case[field]].append(result)
        summary[field] = {key: _rates(value) for key, value in sorted(groups.items())}
    return summary


def result_record(result: CaseResult) -> dict[str, Any]:
    """Serialize observed outcomes without rewriting the intent label."""

    return {
        "case_id": result.case["case_id"],
        "pattern_id": result.case["pattern_id"],
        "expected_detection": result.case["expected_detection"],
        "detected": result.detected,
        "blocked": result.blocked,
        "passed": result.passed,
        "input_valid": result.input_valid,
        "engine_patterns": result.engine_patterns,
        "raw_patterns": result.raw_patterns,
        "decoded_patterns": result.decoded_patterns,
        "encodings_found": result.encodings_found,
    }


def write_results(results: list[CaseResult], corpus_path: Path, path: Path) -> None:
    """Persist complete outcomes and group metrics for independent analysis."""

    document = {
        "corpus_sha256": corpus_sha256(corpus_path),
        "profile": PROFILE,
        "summary": summarize(results),
        "cases": [result_record(result) for result in results],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_known_gaps(results: list[CaseResult], corpus_path: Path, path: Path) -> None:
    """Explicitly snapshot observed mismatches as known pytest xfails.

    This is an opt-in command, separate from generation. New or unlisted
    mismatches fail the suite, fixed cases pass, and expected_detection is
    never relabeled to match current behavior.
    """

    document = {
        "corpus_sha256": corpus_sha256(corpus_path),
        "profile": PROFILE,
        "known_gaps": {
            result.case["case_id"]: "false_negative"
            if result.case["expected_detection"]
            else "false_positive"
            for result in results
            if not result.passed
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


_PATTERN_DELTAS = {
    "exec_call": (
        "Preserve the original payload scan alongside decoded views. The leetspeak decoder "
        "rewrites `(` to `c`, removing the call syntax that the execution regex requires. "
        "Normalize only attack-word tokens rather than arbitrary code punctuation."
    ),
    "credential_request": (
        "Allow carefully bounded determiners such as `every` and coordinated request verbs before "
        "credential nouns; add Hindi equivalents for passwords and private access keys."
    ),
    "token_waste": (
        "Retain numeric quantities before leetspeak normalization (`10000` is currently "
        "rewritten), "
        "recognize million-word/character Hindi quantities, and distinguish budgets from demands."
    ),
    "base64_payload": (
        "Record encoded-block provenance and scan both original and decoded views: successful "
        "decoding consumes the marker regex's target. Do not treat benign encoded greetings as "
        "attacks solely because they decode."
    ),
    "unicode_tricks": (
        "Decode literal Unicode escapes and build a second view with zero-width separators "
        "removed. "
        "Correlate markers with hidden instruction intent rather than legitimate script joiners."
    ),
    "leetspeak_bypass": (
        "Scan the original leetspeak marker as well as the normalized instruction; limit digit "
        "substitution to suspicious words so ordinary numbers and code are preserved."
    ),
    "char_split_evasion": (
        "Use token boundaries/context for split-letter attack words and retain original-view "
        "provenance; the current regex also matches normal unsplit `system`/`prompt` text."
    ),
}

_FAMILY_DELTAS = {
    "direct_injection": (
        "Add Hindi instruction-discarding, replacement-authority, and hidden-instruction "
        "extraction "
        "phrases. Require an attempted authority/action change to distinguish benign roles/modes."
    ),
    "jailbreak": (
        "Add Hindi restriction-negation and hypothetical-bypass phrases, and correlate persona "
        "names with an instruction to bypass policy rather than matching names like `Dan` alone."
    ),
    "data_exfiltration": (
        "Match requests for nonpublic data in Hindi and coordinated English verb/noun variants; "
        "separate requests to redact or explain data from requests to disclose it."
    ),
    "code_injection": (
        "Keep raw and normalized code views; support escaped code/template/SQL syntax without "
        "mutating punctuation, and distinguish execution demands from quoted educational examples."
    ),
    "obfuscation": (
        "Decode `\\uXXXX`/hex escapes with bounded depth and preserve provenance of encoded "
        "blocks, "
        "invisible characters, leetspeak, and split words; require malicious decoded intent for "
        "benign encoded controls."
    ),
    "constraint_manipulation": (
        "Add Hindi safety-disable and capability-probing phrases with negation/context handling "
        "so warnings against disabling safety are not themselves treated as attacks."
    ),
    "resource_abuse": (
        "Normalize numeric quantities and Hindi number words in a non-leetspeak view; identify "
        "unbounded generation intent and separate educational explanations of loops from demands."
    ),
    "file_system": (
        "Decode escaped paths in bounded secondary views, normalize traversal separators, and "
        "require access/disclosure intent rather than flagging cautions about sensitive paths."
    ),
}


def _status(rate: float) -> str:
    return "PASS" if rate >= MINIMUM_RECALL else "FAIL"


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _dimension_table(summary: dict[str, Any], field: str) -> list[str]:
    lines = [
        "| Value | Attacks | Recall | FN | Controls | FP |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for value, metrics in summary[field].items():
        lines.append(
            f"| `{value}` | {metrics['expected_positive']} | {_pct(metrics['recall'])} | "
            f"{metrics['false_negatives']} | {metrics['expected_negative']} | "
            f"{metrics['false_positives']} |"
        )
    return lines


def render_report(
    results: list[CaseResult], *, corpus_path: Path, test_output: Path | None = None
) -> str:
    """Evidence-based family gaps, diagnosis, proposals, and reproducible scope."""

    summary = summarize(results)
    overall = summary["overall"]
    pattern_count = len(summary["pattern_id"])
    corpus_display = (
        corpus_path.relative_to(ROOT) if corpus_path.is_relative_to(ROOT) else corpus_path
    )
    lines = [
        "# Entropy attack-corpus v2 expansion gaps",
        "",
        "## Scope and label semantics",
        "",
        f"- Corpus: `{corpus_display}`; SHA-256: `{corpus_sha256(corpus_path)}`.",
        f"- **{overall['cases']:,} cases**: {overall['expected_positive']:,} attack variants and "
        f"{overall['expected_negative']:,} benign near-neighbor controls.",
        f"- **{pattern_count} active patterns** in `entropy/core/pattern_matcher.py`; "
        "the work order's "
        "47-pattern count does not match this checkout. All active patterns are expanded.",
        "- Labels express intended security behavior. Encodings and translations preserve intent; "
        "they are never relabeled according to observed detection.",
        "- Real `ChatCompletionRequest` objects go through `EntropyEngine.analyze_request()` "
        "unchanged. "
        "No payload is copied into a scanned field to help detection.",
        "- `detected` means at least one engine threat, even if status is allowed/sanitized. "
        "Blocking and target-rule hits are separate diagnostics. Generic encoding threats count "
        "toward recall but also count as false positives on benign encoded controls.",
        "- Profile: recursive decoding on (depth 5), indirect scanning on, threshold 0.7, "
        "block-on-detection on; semantic/context analysis and URL fetching off. Only settings "
        "providers are isolated, not detector implementations. No model/provider/network is used.",
        "- Image alt text is stored under `image_url.alt` (an application extension accepted by "
        "the request schema); no OCR/pixel inference is claimed. Function arguments use "
        "`assistant.tool_calls[].function.arguments`.",
        "- Family PASS/FAIL is recall >=80%/<80%. Pytest xfails represent individually recorded "
        "known false positives/negatives, not passing detections.",
        "",
        "## Overall benchmark",
        "",
        "| Metric | Result |",
        "|---|---:|",
        f"| Label matches | {overall['passed']:,}/{overall['cases']:,} |",
        f"| Label mismatches | {overall['failed']:,} |",
        f"| Positive recall | {_pct(overall['recall'])} "
        f"({overall['true_positives']}/{overall['expected_positive']}) |",
        f"| False-positive rate | {_pct(overall['false_positive_rate'])} "
        f"({overall['false_positives']}/{overall['expected_negative']}) |",
        f"| Engine target-rule hit rate | {_pct(overall['target_hit_rate'])} |",
        f"| Isolated raw / decoded target hits | {_pct(overall['raw_target_rate'])} / "
        f"{_pct(overall['decoded_target_rate'])} |",
        f"| Blocked attacks | {overall['blocked_positive']} |",
        f"| Invalid input cases | {overall['invalid_inputs']} |",
        "",
        "## Pass/fail by family",
        "",
        "| Status | Family | Attacks | TP | FN | Recall | Controls | TN | FP |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for family, metrics in summary["category"].items():
        lines.append(
            f"| {_status(metrics['recall'])} | `{family}` | {metrics['expected_positive']} | "
            f"{metrics['true_positives']} | {metrics['false_negatives']} | "
            f"{_pct(metrics['recall'])} | {metrics['expected_negative']} | "
            f"{metrics['true_negatives']} | {metrics['false_positives']} |"
        )
    lines.extend(
        [
            "",
            "## Per-pattern diagnostics",
            "",
            "| Status | Pattern | Recall | FN | FP | Engine target | Raw target | Decoded target |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for pattern_id, metrics in summary["pattern_id"].items():
        lines.append(
            f"| {_status(metrics['recall'])} | `{pattern_id}` | {_pct(metrics['recall'])} | "
            f"{metrics['false_negatives']} | {metrics['false_positives']} | "
            f"{_pct(metrics['target_hit_rate'])} | {_pct(metrics['raw_target_rate'])} | "
            f"{_pct(metrics['decoded_target_rate'])} |"
        )
    for field in ("encoding", "payload_language", "instruction_position", "difficulty_tier"):
        lines.extend(["", f"## By {field.replace('_', ' ')}", ""])
        lines.extend(_dimension_table(summary, field))

    lines.extend(["", "## Cross-family root causes and proposed deltas", ""])
    lines.extend(
        [
            "1. **Request-field coverage:** extend bounded extraction to image alt text and "
            "function argument string values while retaining source/trust metadata. Currently the "
            "engine, validator, and indirect detector only extract strings and multipart "
            "`type=text` items; `image_url.alt` and assistant tool-call arguments are not "
            "inspected. "
            "Validate these surfaces with attack and benign controls before enabling them. "
            "Evidence: `entropy/core/engine.py:368-378`, "
            "`entropy/core/indirect_injection_detector.py:300-334`, "
            "`entropy/core/input_validator.py:101-111`.",
            "2. **Unicode escapes:** add bounded `\\uXXXX`/`\\UXXXXXXXX` decoding (including valid "
            "surrogate pairs) and scan each view. NFKC does not decode literal escape strings. "
            "Evidence: decoder pipeline at `entropy/core/input_sanitizer.py:139-195`.",
            "3. **Destructive normalization:** keep raw + decoded views; constrain leetspeak "
            "rewriting "
            "to suspect tokens. Current global substitutions erase execution-call punctuation and "
            "large numeric quantities before matching. Evidence: "
            "`entropy/core/input_sanitizer.py:56-73,273-281` and sanitizer-before-match order "
            "at `entropy/core/engine.py:218-249`.",
            "4. **Language and false positives:** add genuine Hindi intent equivalents with tests "
            "for quoted/educational content. Generic decoding alone should not imply "
            "maliciousness.",
            "",
            "These are proposals only; this work order makes no production-rule or extraction "
            "changes.",
        ]
    )
    for family, metrics in summary["category"].items():
        weak = metrics["recall"] < MINIMUM_RECALL
        weak_patterns = [
            pattern_id
            for pattern_id, counts in summary["pattern_id"].items()
            if counts["recall"] < MINIMUM_RECALL
            and any(
                r.case["category"] == family and r.case["pattern_id"] == pattern_id for r in results
            )
        ]
        if not weak and not weak_patterns:
            continue
        family_results = [result for result in results if result.case["category"] == family]
        misses = [
            result
            for result in family_results
            if result.case["expected_detection"] and not result.detected
        ]
        by_position = Counter(result.case["instruction_position"] for result in misses)
        by_encoding = Counter(result.case["encoding"] for result in misses)
        lines.extend(
            [
                "",
                f"### `{family}` — {_pct(metrics['recall'])} recall",
                "",
                f"- Missed attacks by position: {dict(sorted(by_position.items()))}.",
                f"- Missed attacks by encoding: {dict(sorted(by_encoding.items()))}.",
                f"- Family delta: {_FAMILY_DELTAS[family]}",
            ]
        )
        for pattern_id in weak_patterns:
            delta = _PATTERN_DELTAS.get(
                pattern_id,
                "Add Hindi intent equivalents and escaped/structured secondary views for this "
                "rule, plus tests that retain benign-context distinctions.",
            )
            lines.append(f"- `{pattern_id}` delta: {delta}")
        lines.append("- Representative misses (see case IDs in the corpus/results artifact):")
        for result in misses[:3]:
            lines.append(f"  - `{result.case['case_id']}`")

    lines.extend(["", "## Test-suite evidence", ""])
    if test_output is not None:
        output = test_output.read_text(encoding="utf-8")
        summaries = [line for line in output.splitlines() if "passed" in line and " in " in line]
        lines.append(f"Full captured output: `{test_output.name}`.")
        lines.extend(["", "```text", *summaries[-1:], "```"])
    else:
        lines.append("Full captured baseline/final outputs are stored under `reports/`.")
    lines.append("")
    return "\n".join(lines)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--test-output", type=Path)
    parser.add_argument("--snapshot-known-gaps", type=Path, metavar="PATH")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any detection disagrees with its intent label",
    )
    return parser.parse_args()


def main() -> int:
    """Evaluate, save outcomes, report gaps, and optionally enforce labels."""

    sys.path.insert(0, str(ROOT))
    import structlog  # noqa: PLC0415

    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.ERROR))
    args = _parse_args()
    cases = load_cases(args.corpus)
    results = evaluate_cases(cases)
    summary = summarize(results)
    write_results(results, args.corpus, args.results)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        render_report(results, corpus_path=args.corpus, test_output=args.test_output),
        encoding="utf-8",
    )
    if args.snapshot_known_gaps is not None:
        write_known_gaps(results, args.corpus, args.snapshot_known_gaps)
    print(f"Evaluated {summary['overall']['cases']:,} real chat requests ({PROFILE['name']})")
    print(
        f"Label matches={summary['overall']['passed']:,}; "
        f"mismatches={summary['overall']['failed']:,}; "
        f"recall={_pct(summary['overall']['recall'])}; "
        f"false positives={_pct(summary['overall']['false_positive_rate'])}"
    )
    print("Family results (recall threshold: 80%):")
    for family, metrics in summary["category"].items():
        print(
            f"  {_status(metrics['recall']):4} {family:24} "
            f"recall={_pct(metrics['recall']):>6} "
            f"TP={metrics['true_positives']} FN={metrics['false_negatives']} "
            f"TN={metrics['true_negatives']} FP={metrics['false_positives']}"
        )
    print(f"Report: {args.report}; outcomes: {args.results}")
    return int(bool(args.strict and summary["overall"]["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())

"""Corpus integrity and per-case intent-label evaluation via the existing runner."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from itertools import product
from typing import TYPE_CHECKING

import pytest

from scripts.evaluate_attack_corpus import (
    DEFAULT_CORPUS,
    DEFAULT_KNOWN_GAPS,
    PROFILE,
    corpus_sha256,
    evaluate_cases,
    load_cases,
)
from scripts.expand_attack_catalog import (
    ATTACK_VARIANTS,
    ENCODINGS,
    INSTRUCTION_POSITIONS,
    PAYLOAD_LANGUAGES,
    ROOT,
    build_request,
    load_catalog,
)

if TYPE_CHECKING:
    from pathlib import Path

    from scripts.evaluate_attack_corpus import CaseResult

CASES = load_cases(DEFAULT_CORPUS)
KNOWN_GAPS_DOCUMENT = json.loads(DEFAULT_KNOWN_GAPS.read_text(encoding="utf-8"))
KNOWN_GAPS = KNOWN_GAPS_DOCUMENT["known_gaps"]


@pytest.fixture(scope="module")
def corpus_results() -> dict[str, CaseResult]:
    """Evaluate every real request once, keeping the expected labels independent."""

    return {result.case["case_id"]: result for result in evaluate_cases(CASES)}


def test_corpus_covers_all_patterns_and_dimensions() -> None:
    """Every active rule has the full product of attack and benign dimensions."""

    catalog = load_catalog()
    assert len(CASES) >= 1000
    assert len({case["case_id"] for case in CASES}) == len(CASES)
    assert {case["pattern_id"] for case in CASES} == {rule.pattern_id for rule in catalog}
    expected_dimensions = set(
        product(
            (*ATTACK_VARIANTS, "negative_control"),
            ENCODINGS,
            PAYLOAD_LANGUAGES,
            INSTRUCTION_POSITIONS,
        )
    )
    for rule in catalog:
        rule_cases = [case for case in CASES if case["pattern_id"] == rule.pattern_id]
        dimensions = {
            (
                case["payload_variant"],
                case["encoding"],
                case["payload_language"],
                case["instruction_position"],
            )
            for case in rule_cases
        }
        assert dimensions == expected_dimensions
        assert Counter(case["expected_detection"] for case in rule_cases) == {True: 300, False: 150}
        assert re.search(rule.regex, rule.primary_payload, re.IGNORECASE | re.DOTALL), (
            rule.pattern_id
        )


def test_ground_truth_snapshot_is_explicit_and_current() -> None:
    """Known defects are recorded separately; they cannot silently relabel cases."""

    assert KNOWN_GAPS_DOCUMENT["corpus_sha256"] == corpus_sha256(DEFAULT_CORPUS)
    assert KNOWN_GAPS_DOCUMENT["profile"] == PROFILE
    case_by_id = {case["case_id"]: case for case in CASES}
    assert set(KNOWN_GAPS) <= case_by_id.keys()
    for case_id, kind in KNOWN_GAPS.items():
        expected = case_by_id[case_id]["expected_detection"]
        assert kind == ("false_negative" if expected else "false_positive")


def test_transports_do_not_copy_payloads_to_scanned_fields() -> None:
    """A position test must expose extraction gaps, rather than flattening fields."""

    sentinel = "UNIQUE_PAYLOAD_SENTINEL"
    for position in INSTRUCTION_POSITIONS:
        request = build_request(sentinel, position)
        text_fields = [
            message["content"]
            for message in request["messages"]
            if isinstance(message["content"], str)
        ]
        expected_in_text = position in {"system", "user", "tool_result"}
        assert any(sentinel in text for text in text_fields) == expected_in_text


def test_hindi_instructions_are_translated_and_controls_are_distinct() -> None:
    """Hindi coverage exercises translated intent and controls are family-specific."""

    catalog = load_catalog()
    assert len({rule.safe_payload for rule in catalog}) == len(catalog)
    for rule in catalog:
        assert re.search(r"[\u0900-\u097f]", rule.hindi_primary)
        assert rule.primary_payload != rule.hindi_primary
        assert rule.contextual_payload != rule.hindi_contextual
        assert rule.safe_payload != rule.primary_payload
    assert len({json.dumps(case["request"], sort_keys=True) for case in CASES}) >= 1000


def test_generator_reproduces_checked_in_bytes(tmp_path: Path) -> None:
    """The standard-library generator produces the exact published corpus."""

    output = tmp_path / "regenerated.jsonl"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "expand_attack_catalog.py"),
            "--output",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert corpus_sha256(output) == corpus_sha256(DEFAULT_CORPUS)


@pytest.mark.parametrize("case_id", [case["case_id"] for case in CASES])
def test_expected_detection(case_id: str, corpus_results: dict[str, CaseResult]) -> None:
    """Every corpus label is checked; known gaps xfail, new regressions fail."""

    result = corpus_results[case_id]
    assert result.input_valid, "An invalid request must not masquerade as attack detection"
    if result.passed:
        return
    if case_id in KNOWN_GAPS:
        pytest.xfail(
            f"Known {KNOWN_GAPS[case_id]} in {result.case['category']}; "
            "see reports/expansion-gaps.md"
        )
    assert result.detected == result.case["expected_detection"], (
        f"New label mismatch: {case_id}; engine threats={result.engine_patterns}"
    )


@pytest.mark.parametrize(
    "record_update",
    [
        {"expected_detection": "true"},
        {"difficulty_tier": "unknown"},
        {"pattern_id": "not_a_pattern"},
        {"category": "wrong_family"},
        {"input_payload": "payload_removed_from_request"},
    ],
)
def test_invalid_labels_and_transports_are_rejected(tmp_path: Path, record_update: dict) -> None:
    """Malformed labels and disconnected transport metadata fail before evaluation."""

    record = {**CASES[0], **record_update}
    path = tmp_path / "invalid.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_cases(path)

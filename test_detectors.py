"""
Detector unit tests for the C++ DAST SQL-injection scanner.

Run from the project root:
    pytest -v test_detectors.py

These tests use small simulated result objects, so they do not launch the
C++ target or modify its database. They test detector classification logic.

IMPORTANT:
- The UNION marker-only test is intentionally a regression test. It expects
  a bare marker such as "sqlite_master" NOT to be enough for CONFIRMED.
  If it fails, the current UnionBasedDetector is too permissive and needs
  correction.
"""

from types import SimpleNamespace
import detectors
import pytest

from config import CONFIG
from detectors import (
    ClassicSQLiDetector,
    ErrorBasedDetector,
    BooleanBlindDetector,
    TimeBlindDetector,
    UnionBasedDetector,
    SecondOrderDetector,
)
from models import Confidence, VulnCategory


def make_result(
    stdout="",
    stderr="",
    return_code=0,
    duration_s=0.05,
    timed_out=False,
):
    """Create a lightweight stand-in for ExecutionResult."""
    return SimpleNamespace(
        stdout=stdout,
        stderr=stderr,
        return_code=return_code,
        duration_s=duration_s,
        timed_out=timed_out,
    )


def make_test(
    category,
    payload="test-payload",
    test_id="unit_test",
    second_order=None,
):
    """Create a lightweight stand-in for TestCase."""
    return SimpleNamespace(
        category=category,
        payload=payload,
        test_id=test_id,
        second_order=second_order,
    )


def confidence(finding):
    """Return the enum value produced by a detector."""
    return finding.confidence


# ---------------------------------------------------------------------------
# Classic SQL injection
# ---------------------------------------------------------------------------

def test_classic_tautology_confirmed_with_matching_false_control():
    detector = ClassicSQLiDetector()
    test = make_test(
        VulnCategory.CLASSIC,
        payload="1' OR '1'='1",
        test_id="classic_true",
    )

    baseline = make_result(stdout="Student: Alice\n")
    true_result = make_result(
        stdout="Student: Alice\nStudent: Bob\nStudent: Charlie\n"
    )
    false_control = make_result(stdout="Student: Alice\n")

    finding = detector.analyze(
        test, true_result, baseline, control_result=false_control
    )

    assert confidence(finding) == Confidence.CONFIRMED


def test_classic_equivalent_true_and_false_is_negative():
    detector = ClassicSQLiDetector()
    test = make_test(VulnCategory.CLASSIC, payload="1' OR '1'='1")

    baseline = make_result(stdout="Student: Alice\n")
    result = make_result(stdout="Student: Alice\n")
    control = make_result(stdout="Student: Alice\n")

    finding = detector.analyze(test, result, baseline, control_result=control)

    assert confidence(finding) == Confidence.NEGATIVE


def test_classic_without_control_cannot_be_confirmed():
    detector = ClassicSQLiDetector()
    test = make_test(VulnCategory.CLASSIC, payload="1' OR '1'='1")

    baseline = make_result(stdout="Student: Alice\n")
    result = make_result(
        stdout="Student: Alice\nStudent: Bob\nStudent: Charlie\n"
    )

    finding = detector.analyze(test, result, baseline)

    assert confidence(finding) == Confidence.SUSPECTED


# ---------------------------------------------------------------------------
# Error-based SQL injection
# ---------------------------------------------------------------------------

def test_error_signature_without_corroboration_is_not_confirmed():
    detector = ErrorBasedDetector()
    test = make_test(
        VulnCategory.ERROR_BASED,
        payload="1'",
        test_id="error_quote",
    )

    baseline = make_result(stdout="No matching student.\n")
    result = make_result(
        stdout="SQLite error: near quote: syntax error\n"
    )

    finding = detector.analyze(test, result, baseline)

    assert confidence(finding) == Confidence.SUSPECTED


def test_error_already_present_in_baseline_is_inconclusive():
    detector = ErrorBasedDetector()
    test = make_test(VulnCategory.ERROR_BASED, payload="1'")

    baseline = make_result(stdout="sqlite_error: database is locked\n")
    result = make_result(stdout="sqlite_error: database is locked\n")

    finding = detector.analyze(test, result, baseline)

    assert confidence(finding) == Confidence.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Boolean-based blind SQL injection
# ---------------------------------------------------------------------------

def test_boolean_blind_confirms_full_true_false_baseline_pattern():
    detector = BooleanBlindDetector()
    test = make_test(
        VulnCategory.BOOLEAN_BLIND,
        payload="1' AND '1'='1",
    )

    baseline = make_result(stdout="No matching student.\n")
    true_result = make_result(
        stdout="Student: Alice\nStudent: Bob\nStudent: Charlie\n"
    )
    false_control = make_result(stdout="No matching student.\n")

    finding = detector.analyze(
        test, true_result, baseline, control_result=false_control
    )

    assert confidence(finding) == Confidence.CONFIRMED


def test_boolean_blind_without_control_is_inconclusive():
    detector = BooleanBlindDetector()
    test = make_test(VulnCategory.BOOLEAN_BLIND)

    baseline = make_result(stdout="No matching student.\n")
    result = make_result(stdout="Student: Alice\n")

    finding = detector.analyze(test, result, baseline)

    assert confidence(finding) == Confidence.INCONCLUSIVE


# ---------------------------------------------------------------------------
# Time-based blind SQL injection
# ---------------------------------------------------------------------------


def test_time_blind_is_inconclusive_without_verified_delay_function(monkeypatch):

    monkeypatch.setattr(
        detectors,
        "CONFIG",
        SimpleNamespace(
            verified_time_delay_function=None,
            time_based_delay_s=3.0,
            time_based_tolerance_s=1.0,
        ),
    )

    detector = TimeBlindDetector()

    test = make_test(
        VulnCategory.TIME_BLIND,
        payload="<test-delay-payload>",
    )

    baseline = make_result(duration_s=0.05)
    delayed = make_result(duration_s=3.5)

    finding = detector.analyze(test, delayed, baseline)

    assert confidence(finding) == Confidence.INCONCLUSIVE
# ---------------------------------------------------------------------------
# UNION-based SQL injection
# ---------------------------------------------------------------------------

def test_union_marker_alone_must_not_confirm_schema_exposure():
    """
    Regression test: a marker string by itself is not proof that schema
    contents were extracted. The current detector may fail this test if it
    treats 'sqlite_master' alone as confirmed disclosure.
    """
    detector = UnionBasedDetector()
    test = make_test(
        VulnCategory.UNION_BASED,
        payload="1' UNION SELECT name, sql FROM sqlite_master--",
    )

    baseline = make_result(stdout="Student: Alice\n")
    result = make_result(stdout="Student: Alice\nsqlite_master\n")

    finding = detector.analyze(test, result, baseline)

    assert confidence(finding) != Confidence.CONFIRMED


def test_union_without_schema_markers_or_structure_change_is_negative():
    detector = UnionBasedDetector()
    test = make_test(VulnCategory.UNION_BASED)

    baseline = make_result(stdout="Student: Alice\n")
    result = make_result(stdout="Student: Alice\n")

    finding = detector.analyze(test, result, baseline)

    assert confidence(finding) == Confidence.NEGATIVE


# ---------------------------------------------------------------------------
# Second-order SQL injection
# ---------------------------------------------------------------------------

def test_second_order_unimplemented_workflow_is_inconclusive():
    detector = SecondOrderDetector()
    plan = SimpleNamespace(
        store_payload="stored-test-payload",
        read_operation="list_profiles_after_store",
        implemented=False,
    )
    test = make_test(
        VulnCategory.SECOND_ORDER,
        payload="stored-test-payload",
        second_order=plan,
    )

    baseline = make_result()
    result = make_result()

    finding = detector.analyze(test, result, baseline)

    assert confidence(finding) == Confidence.INCONCLUSIVE


if __name__ == "__main__":
    raise SystemExit(pytest.main(["-v", __file__]))

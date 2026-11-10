
"""
Runtime-behaviour detectors.

Each detector compares a test ExecutionResult against baseline and,
where available, matched control executions.

Detection principles:
- A single weak output difference is never sufficient for confirmation.
- Baseline and control executions are used to reduce false positives.
- Database errors must be attributable to the injected input.
- UNION detection requires evidence of newly exposed database metadata.
- Timing differences are treated conservatively.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from abc import ABC, abstractmethod

from config import CONFIG
from models import (
    Confidence,
    ExecutionResult,
    Finding,
    Severity,
    TestCase,
    VulnCategory,
)


# ---------------------------------------------------------
# SQL ERROR SIGNATURES
# ---------------------------------------------------------

SQL_ERROR_SIGNATURES = [
    r"sql syntax",
    r"sqlite_error",
    r"sqlite(?:\s+error)?[^\n]{0,100}\bsyntax error\b",
    r"unrecognized token",
    r"near .*: syntax error",
    r"unterminated",
    r"no such column",
    r"no such table",
]
# Strong parser-related errors.
# These provide stronger evidence than generic DB errors.

STRONG_SQL_ERROR_SIGNATURES = [
    r"sql syntax",
    r"syntax error",
    r"unrecognized token",
    r"unterminated",
]


# ---------------------------------------------------------
# BASE DETECTOR
# ---------------------------------------------------------

class BaseDetector(ABC):

    category: VulnCategory

    @abstractmethod
    def analyze(
        self,
        test: TestCase,
        result: ExecutionResult,
        baseline: ExecutionResult,
        control_result: ExecutionResult | None = None,
        followup_result: ExecutionResult | None = None,
    ) -> Finding:
        ...

    # -----------------------------------------------------
    # OUTPUT HELPERS
    # -----------------------------------------------------

    @staticmethod
    def _combined_output(result: ExecutionResult) -> str:
        return f"{result.stdout}\n{result.stderr}".lower()

    @staticmethod
    def _normalize_output(text: str) -> str:
        """
        Normalize whitespace without removing meaningful content.

        This prevents whitespace differences from being mistaken
        for SQL injection evidence.
        """

        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def _meaningfully_different(a: str, b: str) -> bool:
        """
        Compare actual output content rather than only output length.

        Improvements:
        - Ignores whitespace-only changes.
        - Detects different content with identical lengths.
        - Ignores very small changes such as one changed character.
        - Uses sequence comparison to estimate changed content.
        """

        norm_a = BaseDetector._normalize_output(a)
        norm_b = BaseDetector._normalize_output(b)

        if norm_a == norm_b:
            return False

        matcher = SequenceMatcher(
            None,
            norm_a,
            norm_b,
            autojunk=False,
        )

        changed_characters = 0

        for operation, a_start, a_end, b_start, b_end in matcher.get_opcodes():

            if operation == "equal":
                continue

            changed_characters += (
                (a_end - a_start) +
                (b_end - b_start)
            )

        longest = max(len(norm_a), len(norm_b), 1)

        threshold = max(
            3,
            int(0.02 * longest),
        )

        return changed_characters >= threshold

    # -----------------------------------------------------
    # ERROR HELPERS
    # -----------------------------------------------------

    @staticmethod
    def _has_error_signature(result: ExecutionResult) -> list[str]:

        text = BaseDetector._combined_output(result)

        return [
            sig
            for sig in SQL_ERROR_SIGNATURES
            if re.search(sig, text)
        ]

    @staticmethod
    def _has_strong_sql_error(result: ExecutionResult) -> bool:

        text = BaseDetector._combined_output(result)

        return any(
            re.search(sig, text)
            for sig in STRONG_SQL_ERROR_SIGNATURES
        )

    @staticmethod
    def _payload_reflected(
        payload: str,
        output_text: str,
    ) -> bool:
        """
        Checks whether a distinctive payload fragment appears
        in output.

        Reflection is supporting evidence only. It does not
        independently establish SQL injection.
        """

        fragment = re.sub(
            r"[\'\"();]",
            "",
            payload,
        ).strip()

        return (
            bool(fragment)
            and len(fragment) >= 3
            and fragment.lower() in output_text.lower()
        )

    # -----------------------------------------------------
    # COMPARISON HELPERS
    # -----------------------------------------------------

    @staticmethod
    def _outputs_differ(
        first: ExecutionResult,
        second: ExecutionResult,
    ) -> bool:

        return BaseDetector._meaningfully_different(
            first.stdout,
            second.stdout,
        )

    @staticmethod
    def _error_is_new(
        result: ExecutionResult,
        baseline: ExecutionResult,
        control_result: ExecutionResult | None = None,
    ) -> bool:

        if not BaseDetector._has_error_signature(result):
            return False

        if BaseDetector._has_error_signature(baseline):
            return False

        if (
            control_result is not None
            and BaseDetector._has_error_signature(control_result)
        ):
            return False

        return True


# ---------------------------------------------------------
# CLASSIC SQL INJECTION DETECTOR
# ---------------------------------------------------------

class ClassicSQLiDetector(BaseDetector):

    category = VulnCategory.CLASSIC

    def analyze(
        self,
        test,
        result,
        baseline,
        control_result=None,
        followup_result=None,
    ) -> Finding:

        if self._has_error_signature(result):

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "Payload triggered a database error rather than "
                    "a clean tautology response. See ErrorBasedDetector."
                ),
                payload=test.payload,
            )

        true_vs_baseline = self._outputs_differ(
            result,
            baseline,
        )

        return_code_changed = (
            result.return_code != baseline.return_code
        )

        if control_result is not None:

            false_matches_baseline = not self._outputs_differ(
                control_result,
                baseline,
            )

            true_vs_false = self._outputs_differ(
                result,
                control_result,
            )

            if (
                true_vs_false
                and false_matches_baseline
                and true_vs_baseline
            ):

                return Finding(
                    test_id=test.test_id,
                    category=test.category,
                    confidence=Confidence.CONFIRMED,
                    severity=Severity.HIGH,
                    evidence=(
                        "True-tautology payload produced materially "
                        "different output from baseline and the matched "
                        "false-condition control. The false control "
                        "matched baseline, with no database error. "
                        "This strongly supports an injected condition "
                        "altering query behaviour."
                    ),
                    payload=test.payload,
                )

            if true_vs_false:

                return Finding(
                    test_id=test.test_id,
                    category=test.category,
                    confidence=Confidence.SUSPECTED,
                    severity=Severity.MEDIUM,
                    evidence=(
                        "True and false tautology payloads produced "
                        "different output, but the false-condition "
                        "control did not cleanly match baseline. "
                        "Manual validation is required."
                    ),
                    payload=test.payload,
                )

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.NEGATIVE,
                severity=Severity.INFO,
                evidence=(
                    "True and false tautology payloads produced "
                    "equivalent output."
                ),
                payload=test.payload,
            )

        # Without a control payload, output differences are leads only.

        if true_vs_baseline or return_code_changed:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.SUSPECTED,
                severity=Severity.LOW,
                evidence=(
                    "Output or return code differs from baseline, "
                    "but no matched false-condition control was "
                    "executed. Confirmation is not justified."
                ),
                payload=test.payload,
            )

        return Finding(
            test_id=test.test_id,
            category=test.category,
            confidence=Confidence.NEGATIVE,
            severity=Severity.INFO,
            evidence="No meaningful difference from baseline.",
            payload=test.payload,
        )


# ---------------------------------------------------------
# ERROR-BASED SQL INJECTION DETECTOR
# ---------------------------------------------------------

class ErrorBasedDetector(BaseDetector):

    category = VulnCategory.ERROR_BASED

    def analyze(
        self,
        test,
        result,
        baseline,
        control_result=None,
        followup_result=None,
    ) -> Finding:

        matched = self._has_error_signature(result)

        if not matched:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.NEGATIVE,
                severity=Severity.INFO,
                evidence="No recognized SQL error signature found.",
                payload=test.payload,
            )

        baseline_errors = self._has_error_signature(baseline)

        if baseline_errors:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "Database error signature already exists in "
                    "baseline output. The error cannot be attributed "
                    "to the injection payload."
                ),
                payload=test.payload,
            )

        control_errors = (
            self._has_error_signature(control_result)
            if control_result is not None
            else []
        )

        if control_errors:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "The matched control also produced a database "
                    "error. The injected payload cannot be isolated "
                    "as the cause."
                ),
                payload=test.payload,
            )

        strong_error = self._has_strong_sql_error(result)

        return_code_changed = (
            result.return_code != baseline.return_code
        )

        payload_reflected = self._payload_reflected(
            test.payload,
            self._combined_output(result),
        )

        # Strong SQL parser error absent from baseline/control.

        if strong_error and control_result is not None:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.CONFIRMED,
                severity=Severity.HIGH,
                evidence=(
                    f"SQL parser-related error detected: {matched}. "
                    "The error was absent from baseline and matched "
                    "control executions. This is strong evidence "
                    "that the injected input reached SQL parsing."
                ),
                payload=test.payload,
            )

        # Generic database errors need more cautious treatment.

        if return_code_changed or payload_reflected:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.SUSPECTED,
                severity=Severity.MEDIUM,
                evidence=(
                    f"Database error signature(s) {matched} appeared "
                    "only with the test payload. However, the error "
                    "does not independently establish SQL injection. "
                    f"Return code changed: {return_code_changed}. "
                    f"Payload reflected: {payload_reflected}."
                ),
                payload=test.payload,
            )

        return Finding(
            test_id=test.test_id,
            category=test.category,
            confidence=Confidence.SUSPECTED,
            severity=Severity.LOW,
            evidence=(
                f"Database error signature(s) {matched} appeared "
                "only with the injected request, but no additional "
                "corroborating signal was observed."
            ),
            payload=test.payload,
        )


# ---------------------------------------------------------
# BOOLEAN-BLIND SQL INJECTION DETECTOR
# ---------------------------------------------------------

class BooleanBlindDetector(BaseDetector):

    category = VulnCategory.BOOLEAN_BLIND

    def analyze(
        self,
        test,
        result,
        baseline,
        control_result=None,
        followup_result=None,
    ) -> Finding:

        if control_result is None:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "No matched false-condition control was executed. "
                    "Boolean behaviour cannot be established."
                ),
                payload=test.payload,
            )

        if (
            self._has_error_signature(result)
            or self._has_error_signature(control_result)
        ):

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "True/false payload produced a database error "
                    "instead of a clean Boolean response difference."
                ),
                payload=test.payload,
            )

        true_vs_false = self._outputs_differ(
            result,
            control_result,
        )

        false_vs_baseline = not self._outputs_differ(
            control_result,
            baseline,
        )

        true_vs_baseline = self._outputs_differ(
            result,
            baseline,
        )

        if (
            true_vs_false
            and true_vs_baseline
            and false_vs_baseline
        ):

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.CONFIRMED,
                severity=Severity.HIGH,
                evidence=(
                    "True-condition response differs from both "
                    "baseline and false-condition control. The "
                    "false-condition control matches baseline. "
                    "This is consistent with Boolean-based SQL injection."
                ),
                payload=test.payload,
            )

        if true_vs_false:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.SUSPECTED,
                severity=Severity.MEDIUM,
                evidence=(
                    "True and false conditions produced different "
                    "responses, but the false condition did not "
                    "cleanly match baseline."
                ),
                payload=test.payload,
            )

        return Finding(
            test_id=test.test_id,
            category=test.category,
            confidence=Confidence.NEGATIVE,
            severity=Severity.INFO,
            evidence=(
                "True and false condition payloads produced "
                "equivalent output."
            ),
            payload=test.payload,
        )


# ---------------------------------------------------------
# TIME-BASED SQL INJECTION DETECTOR
# ---------------------------------------------------------

class TimeBlindDetector(BaseDetector):

    category = VulnCategory.TIME_BLIND

    def analyze(
        self,
        test,
        result,
        baseline,
        control_result=None,
        followup_result=None,
    ) -> Finding:

        if not CONFIG.verified_time_delay_function:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "No verified engine-specific time-delay primitive "
                    "is configured. Timing differences cannot be "
                    "attributed to the payload."
                ),
                payload=test.payload,
            )

        # A timed-out baseline makes comparison unreliable.

        if baseline.timed_out:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "Baseline execution timed out. A reliable timing "
                    "comparison cannot be performed."
                ),
                payload=test.payload,
            )

        if (
            control_result is not None
            and control_result.timed_out
        ):

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "Control execution timed out. The timing signal "
                    "cannot be reliably attributed to the injected "
                    "payload."
                ),
                payload=test.payload,
            )

        reference_duration = baseline.duration_s

        if control_result is not None:

            reference_duration = max(
                baseline.duration_s,
                control_result.duration_s,
            )

        delay = result.duration_s - reference_duration

        expected = CONFIG.time_based_delay_s
        tolerance = CONFIG.time_based_tolerance_s

        threshold = expected - tolerance

        if result.timed_out:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.SUSPECTED,
                severity=Severity.MEDIUM,
                evidence=(
                    "Injected execution timed out while baseline "
                    "and control completed successfully. This may "
                    "indicate a delay, but repeated verification "
                    "is required."
                ),
                payload=test.payload,
            )

        if delay >= threshold:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.SUSPECTED,
                severity=Severity.MEDIUM,
                evidence=(
                    f"Response delayed by {delay:.2f}s relative to "
                    f"reference execution. Expected delay: "
                    f"approximately {expected}s using "
                    f"{CONFIG.verified_time_delay_function}. "
                    "A single timing observation is insufficient "
                    "for confirmation."
                ),
                payload=test.payload,
            )

        return Finding(
            test_id=test.test_id,
            category=test.category,
            confidence=Confidence.NEGATIVE,
            severity=Severity.INFO,
            evidence=(
                f"No significant delay observed. "
                f"Measured delay: {delay:.2f}s."
            ),
            payload=test.payload,
        )


# ---------------------------------------------------------
# UNION-BASED SQL INJECTION DETECTOR
# ---------------------------------------------------------

class UnionBasedDetector(BaseDetector):

    category = VulnCategory.UNION_BASED

    LEAK_MARKERS = [
        r"sqlite_master",
        r"create table",
        r"\bpragma\b",
    ]

    # Stronger indicator of actual SQLite schema disclosure.

    SCHEMA_DEFINITION_PATTERN = (
        r"\bcreate\s+table\s+[`\"'\[]?\w+"
    )

    def analyze(
        self,
        test,
        result,
        baseline,
        control_result=None,
        followup_result=None,
    ) -> Finding:

        output = self._combined_output(result)
        baseline_output = self._combined_output(baseline)

        control_output = (
            self._combined_output(control_result)
            if control_result is not None
            else ""
        )

        matched = [
            marker
            for marker in self.LEAK_MARKERS
            if re.search(marker, output)
        ]

        baseline_matched = [
            marker
            for marker in self.LEAK_MARKERS
            if re.search(marker, baseline_output)
        ]

        control_matched = [
            marker
            for marker in self.LEAK_MARKERS
            if re.search(marker, control_output)
        ]

        new_markers = [
            marker
            for marker in matched
            if (
                marker not in baseline_matched
                and marker not in control_matched
            )
        ]

        output_changed = self._outputs_differ(
            result,
            baseline,
        )

        schema_definition_found = bool(
            re.search(
                self.SCHEMA_DEFINITION_PATTERN,
                result.stdout,
                re.IGNORECASE,
            )
        )

        # Stronger evidence:
        # Actual CREATE TABLE schema output, absent from baseline/control.

        if (
            schema_definition_found
            and "create table" in new_markers
            and output_changed
            and result.return_code == 0
        ):

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.CONFIRMED,
                severity=Severity.HIGH,
                evidence=(
                    "New database schema-definition content appeared "
                    "in the injected response. CREATE TABLE metadata "
                    "was absent from baseline and control output. "
                    "This confirms metadata disclosure and strongly "
                    "supports successful UNION-based data extraction."
                ),
                payload=test.payload,
            )

        # Marker-only evidence is insufficient for confirmation.

        if new_markers:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.SUSPECTED,
                severity=Severity.MEDIUM,
                evidence=(
                    f"New database metadata marker(s) detected: "
                    f"{new_markers}. However, actual schema content "
                    "was not sufficiently established. Manual "
                    "validation is required."
                ),
                payload=test.payload,
            )

        if (
            output_changed
            and result.return_code == 0
        ):

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.SUSPECTED,
                severity=Severity.LOW,
                evidence=(
                    "Output structure or content changed after "
                    "the UNION test, but no reliable database "
                    "metadata leakage marker was identified."
                ),
                payload=test.payload,
            )

        return Finding(
            test_id=test.test_id,
            category=test.category,
            confidence=Confidence.NEGATIVE,
            severity=Severity.INFO,
            evidence=(
                "No new database metadata leakage or meaningful "
                "output change detected."
            ),
            payload=test.payload,
        )


# ---------------------------------------------------------
# SECOND-ORDER SQL INJECTION DETECTOR
# ---------------------------------------------------------

class SecondOrderDetector(BaseDetector):

    category = VulnCategory.SECOND_ORDER

    def analyze(
        self,
        test,
        result,
        baseline,
        control_result=None,
        followup_result=None,
    ):

        plan = test.second_order

        if (
            plan is None
            or not plan.implemented
            or followup_result is None
        ):

            missing = (
                plan.read_operation
                if plan
                else "unspecified"
            )

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "Second-order testing requires a real store "
                    "operation followed by a separate read-back "
                    f"operation ({missing}). This workflow is "
                    "not yet implemented in TargetRunner."
                ),
                payload=test.payload,
            )

        matched = self._has_error_signature(
            followup_result
        )

        if not matched:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.NEGATIVE,
                severity=Severity.INFO,
                evidence=(
                    "No recognized database error was observed "
                    "during the follow-up read-back operation. "
                    "This does not independently rule out all "
                    "second-order injection behaviour."
                ),
                payload=test.payload,
            )

        baseline_errors = self._has_error_signature(
            baseline
        )

        if baseline_errors:

            return Finding(
                test_id=test.test_id,
                category=test.category,
                confidence=Confidence.INCONCLUSIVE,
                severity=Severity.INFO,
                evidence=(
                    "Baseline already contained a database error. "
                    "The follow-up error cannot be attributed "
                    "to the stored payload."
                ),
                payload=test.payload,
            )

        return Finding(
            test_id=test.test_id,
            category=test.category,
            confidence=Confidence.SUSPECTED,
            severity=Severity.MEDIUM,
            evidence=(
                f"Database error signature(s) {matched} appeared "
                "during the later read-back operation. A matched "
                "normal-store/read-back control is still required "
                "before attributing the error to the stored payload."
            ),
            payload=test.payload,
        )


# ---------------------------------------------------------
# DETECTOR REGISTRY
# ---------------------------------------------------------

DETECTORS: dict[VulnCategory, BaseDetector] = {

    VulnCategory.CLASSIC:
        ClassicSQLiDetector(),

    VulnCategory.ERROR_BASED:
        ErrorBasedDetector(),

    VulnCategory.BOOLEAN_BLIND:
        BooleanBlindDetector(),

    VulnCategory.TIME_BLIND:
        TimeBlindDetector(),

    VulnCategory.UNION_BASED:
        UnionBasedDetector(),

    VulnCategory.SECOND_ORDER:
        SecondOrderDetector(),

}

"""Coordinates test execution against the target and runs the matching
detector for each test case, producing a ScanResult that distinguishes
tests executed from vulnerabilities actually detected."""
from logger import setup_logger
from models import Confidence, ExecutionResult, Finding, ScanResult, Severity
from target_runner import TargetRunner
from test_cases import BASELINE_PAYLOAD, TEST_CASES
from detectors import DETECTORS

log = setup_logger()


class Analyzer:
    def __init__(self, runner: TargetRunner | None = None):
        self.runner = runner or TargetRunner()

    def run_all(self) -> ScanResult:
        log.info("Establishing baseline behaviour...")
        baseline = self.runner.run("baseline", BASELINE_PAYLOAD)

        if baseline.error:
            reason = f"Baseline execution failed to launch: {baseline.error}"
            log.error(reason)
            return ScanResult(tests_executed=0, aborted=True, abort_reason=reason)
        if baseline.timed_out:
            reason = "Baseline execution timed out — cannot establish normal behaviour."
            log.error(reason)
            return ScanResult(tests_executed=0, aborted=True, abort_reason=reason)

        findings = []
        executed = 0
        for test in TEST_CASES:
            log.info("Running %s (%s)", test.test_id, test.category.value)
            result = self.runner.run(test.test_id, test.payload)
            executed += 1

            # Launch failures and unexpected timeouts are execution problems,
            # not detector input — classify them directly instead of letting
            # a detector reason over broken/partial data.
            if result.error:
                findings.append(self._finding_for(test, Confidence.INCONCLUSIVE,
                    f"Target failed to launch for this payload: {result.error}"))
                continue
            if result.timed_out and test.category.value != "time_blind":
                findings.append(self._finding_for(test, Confidence.SUSPECTED,
                    "Execution timed out unexpectedly for a non-timing-based test — "
                    "possible hang/resource exhaustion triggered by the payload; "
                    "needs manual review."))
                continue

            control_result: ExecutionResult | None = None
            if test.control_payload is not None:
                control_result = self.runner.run(f"{test.test_id}_control", test.control_payload)

            followup_result: ExecutionResult | None = None
            if test.second_order is not None and test.second_order.implemented:
                try:
                    followup_result = self.runner.run_named_operation(
                        test.second_order.read_operation, test.second_order.store_payload
                    )
                except NotImplementedError as exc:
                    log.warning("Second-order follow-up skipped: %s", exc)

            detector = DETECTORS[test.category]
            finding = detector.analyze(
                test=test,
                result=result,
                baseline=baseline,
                control_result=control_result,
                followup_result=followup_result,
            )
            findings.append(finding)
            log.info("  -> %s (%s)", finding.confidence.value, finding.severity.value)

        return ScanResult(tests_executed=executed, findings=findings)

    @staticmethod
    def _finding_for(test, confidence: Confidence, evidence: str) -> Finding:
        severity = Severity.MEDIUM if confidence == Confidence.SUSPECTED else Severity.INFO
        return Finding(
            test_id=test.test_id, category=test.category,
            confidence=confidence, severity=severity,
            evidence=evidence, payload=test.payload,
        )

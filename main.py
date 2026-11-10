"""Entry point: run the full scan against the configured C++ target and
write a JSON report.

Usage:
    python main.py
"""
from analyzer import Analyzer
from config import CONFIG
from logger import setup_logger
from models import Confidence
from reporter import Reporter

log = setup_logger()


def main() -> None:
    log.info("Starting dynamic SQLi scan against %s", CONFIG.target_executable)

    scan = Analyzer().run_all()

    if scan.aborted:
        log.error("Scan aborted before testing could run: %s", scan.abort_reason)
        print(f"\nScan aborted: {scan.abort_reason}")
        return

    report_path = Reporter().write(scan)
    log.info("Report written to %s", report_path)

    confirmed = [f for f in scan.findings if f.confidence == Confidence.CONFIRMED]
    suspected = [f for f in scan.findings if f.confidence == Confidence.SUSPECTED]
    inconclusive = [f for f in scan.findings if f.confidence == Confidence.INCONCLUSIVE]

    # Tests executed vs. vulnerabilities detected are reported separately —
    # "N tests executed" is not the same claim as "N vulnerabilities found".
    print(
        f"\n{scan.tests_executed} test(s) executed.\n"
        f"Vulnerabilities detected: {len(confirmed)} confirmed, {len(suspected)} suspected.\n"
        f"{len(inconclusive)} test(s) inconclusive (insufficient evidence, not a vulnerability "
        f"claim). Full details: {report_path}"
    )


if __name__ == "__main__":
    main()

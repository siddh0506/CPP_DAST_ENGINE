"""Builds and writes the structured JSON security report."""
import json
from datetime import datetime, timezone
from pathlib import Path

from config import CONFIG
from models import ScanResult


class Reporter:
    def __init__(self, path: Path | None = None):
        self.path = path or CONFIG.report_path

    def build(self, scan: ScanResult) -> dict:
        counts: dict[str, int] = {}
        for f in scan.findings:
            counts[f.confidence.value] = counts.get(f.confidence.value, 0) + 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": str(CONFIG.target_executable),
            "aborted": scan.aborted,
            "abort_reason": scan.abort_reason,
            "tests_executed": scan.tests_executed,
            "confidence_summary": counts,
            "findings": [json.loads(f.model_dump_json()) for f in scan.findings],
        }

    def write(self, scan: ScanResult) -> Path:
        report = self.build(scan)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return self.path

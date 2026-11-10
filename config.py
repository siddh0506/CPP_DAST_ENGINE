"""Central configuration for the dynamic SQLi test harness."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Config:

    # --- Target under test -------------------------------------------------

    target_executable: Path = Path(
        "./target/campus_utility_secure.exe"
    )

    target_args_template: list[str] = field(default_factory=list)

    input_mode: str = "stdin"

    # Sequential input workflow.
    # {payload} is replaced with the current test payload.
    #
    # Campus Utility:
    #   1 -> Select Student Lookup
    #   {payload} -> Student ID / SQLi payload
    #
    # For a simple application, use ("{payload}",).

    stdin_sequence_template: tuple[str, ...] = (
        "1",
        "{payload}"
    )

    # --- Execution limits -------------------------------------------------

    execution_timeout_s: float = 5.0
    max_output_bytes: int = 64_000

    # --- Target database --------------------------------------------------

    db_engine: Optional[str] = None
    db_path: Optional[Path] = None

    # --- Time-based blind detection --------------------------------------

    verified_time_delay_function: Optional[str] = None
    time_based_delay_s: float = 3.0
    time_based_tolerance_s: float = 1.0

    # --- Logging / reporting ---------------------------------------------

    log_file: Path = Path("./logs/sqli_scan.log")
    log_level: str = "INFO"
    report_path: Path = Path("./reports/report.json")


CONFIG = Config()
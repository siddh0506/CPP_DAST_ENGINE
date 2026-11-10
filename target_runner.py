
"""Controlled execution of the C++ target via subprocess.

This module is the ONLY place that launches the target.

Features:
- Command-line argument input
- Direct stdin input
- Sequential stdin input for menu-driven applications
- Execution timeout handling
- Output capture and truncation
- Process launch error handling

Never uses shell=True.
"""

import subprocess
import time
from pathlib import Path

from config import CONFIG
from logger import setup_logger
from models import ExecutionResult


log = setup_logger()

VALID_INPUT_MODES = {"arg", "stdin"}


class TargetRunner:
    """Configurable adapter for executing C++ targets."""

    def __init__(
        self,
        executable: Path | None = None,
        input_mode: str | None = None
    ):

        self.executable = executable or CONFIG.target_executable
        self.input_mode = input_mode or CONFIG.input_mode

        if self.input_mode not in VALID_INPUT_MODES:
            raise ValueError(
                f"Invalid input_mode '{self.input_mode}'. "
                f"Must be one of {VALID_INPUT_MODES}."
            )

        if CONFIG.execution_timeout_s <= 0:
            raise ValueError(
                "execution_timeout_s must be positive."
            )

        if CONFIG.max_output_bytes <= 0:
            raise ValueError(
                "max_output_bytes must be positive."
            )

        if not self.executable.exists():
            log.warning(
                "Target executable not found at %s",
                self.executable
            )

    def _build_stdin(self, payload: str) -> str:
        """Build stdin input using the configured sequence template.

        Example configuration:

            stdin_sequence_template = (
                "1",
                "{payload}"
            )

        Generated stdin:

            1
            1' OR '1'='1
        """

        template = CONFIG.stdin_sequence_template

        if not template:
            raise ValueError(
                "stdin_sequence_template cannot be empty."
            )

        if template.count("{payload}") != 1:
            raise ValueError(
                "stdin_sequence_template must contain "
                "exactly one '{payload}' placeholder."
            )

        input_lines = [
            item.replace("{payload}", payload)
            for item in template
        ]

        return "\n".join(input_lines) + "\n"

    def run(self, test_id: str, payload: str) -> ExecutionResult:
        """Execute the target once with the supplied payload."""

        command = [str(self.executable)] + list(
            CONFIG.target_args_template
        )

        stdin_data = None

        if self.input_mode == "arg":

            command.append(payload)

        else:

            stdin_data = self._build_stdin(payload)

        start = time.perf_counter()

        try:

            proc = subprocess.run(
                command,
                input=stdin_data,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=CONFIG.execution_timeout_s,
                shell=False
            )

            duration = time.perf_counter() - start

            return ExecutionResult(
                test_id=test_id,
                command=command,
                stdin_sent=stdin_data,
                stdout=self._truncate(proc.stdout or ""),
                stderr=self._truncate(proc.stderr or ""),
                return_code=proc.returncode,
                duration_s=duration
            )

        except subprocess.TimeoutExpired as exc:

            duration = time.perf_counter() - start

            partial_out = (
                exc.stdout
                if isinstance(exc.stdout, str)
                else ""
            )

            partial_err = (
                exc.stderr
                if isinstance(exc.stderr, str)
                else ""
            )

            return ExecutionResult(
                test_id=test_id,
                command=command,
                stdin_sent=stdin_data,
                stdout=self._truncate(partial_out),
                stderr=self._truncate(partial_err),
                return_code=None,
                duration_s=duration,
                timed_out=True
            )

        except (
            FileNotFoundError,
            PermissionError,
            NotADirectoryError,
            OSError
        ) as exc:

            duration = time.perf_counter() - start

            log.error(
                "Failed to launch target: %s",
                exc
            )

            return ExecutionResult(
                test_id=test_id,
                command=command,
                stdin_sent=stdin_data,
                stdout="",
                stderr="",
                return_code=None,
                duration_s=duration,
                error=str(exc)
            )

    def run_named_operation(
        self,
        operation_name: str,
        payload: str
    ) -> ExecutionResult:

        """Placeholder for future target-specific operations."""

        raise NotImplementedError(
            f"Operation '{operation_name}' is not wired into "
            "TargetRunner yet. Second-order testing requires "
            "implementing this against the actual target."
        )

    @staticmethod
    def _truncate(text: str) -> str:
        """Limit captured output size."""

        limit = CONFIG.max_output_bytes

        encoded = text.encode(
            "utf-8",
            errors="ignore"
        )

        if len(encoded) <= limit:
            return text

        # Preserve the configured byte limit.
        truncated = encoded[:limit].decode(
            "utf-8",
            errors="ignore"
        )

        return truncated + "\n...[truncated]"

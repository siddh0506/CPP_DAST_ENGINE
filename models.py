"""Shared data models for test cases, execution results and findings."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class VulnCategory(str, Enum):
    CLASSIC = "classic"
    ERROR_BASED = "error_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    UNION_BASED = "union_based"
    SECOND_ORDER = "second_order"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    INCONCLUSIVE = "inconclusive"
    NEGATIVE = "negative"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecondOrderStage(BaseModel):
    """Describes what a real second-order test requires: a store step, plus
    a *separate* target operation that later reads the stored value back
    through a new query. Sending a placeholder string (e.g. "read_profile")
    to the same entry point the store step used does NOT exercise this —
    `read_operation` names the actual target operation needed, and
    `implemented` stays False until that operation is wired into
    TargetRunner against the real C++ application.
    """
    store_payload: str
    read_operation: str  # logical name of the missing target read-back operation
    implemented: bool = False


class TestCase(BaseModel):
    """A single injection probe to send to the target."""
    test_id: str
    category: VulnCategory
    payload: str
    description: str
    # Paired payload used for boolean/classic true-vs-false comparisons.
    control_payload: Optional[str] = None
    # Only populated for SECOND_ORDER tests.
    second_order: Optional[SecondOrderStage] = None

    # --- NEW FIELDS (backward-compatible, both default to None/unset) ---
    #
    # Rationale: the test-case brief calls for 18 fine-grained attack
    # classes (tautology, comment-based, LIKE-based, stacked query, etc.)
    # and per-case database compatibility, but VulnCategory only has 6
    # top-level buckets and TestCase had no compatibility field. Rather
    # than widen VulnCategory or rename anything, we add two purely
    # additive, optional fields:
    #
    #   - subcategory: the finer attack-class label (free text here,
    #     validated against SUBCATEGORIES below at the application layer
    #     so it stays a soft/open set rather than a breaking enum).
    #   - db_compat: which database engines the payload is valid/meaningful
    #     against. "generic" means plain SQL with no engine-specific syntax.
    #
    # Both default to None, so:
    #   - Every existing TestCase(...) call site (including second_order_01)
    #     continues to work with zero changes.
    #   - Code that does `TestCase(**{...})` from the old 5-field shape is
    #     unaffected.
    #   - Any code that calls `.dict()` / `.model_dump()` will now see two
    #     extra keys; code that does strict schema comparison against an
    #     old field list would need updating — flagged as an integration
    #     risk in Part 5 of the catalogue deliverable, since detectors.py /
    #     analyzer.py / target_runner.py were not available to verify
    #     against directly.
    #   - get_by_category() is untouched: it only reads `.category`.
    subcategory: Optional[str] = None
    db_compat: Optional[list[str]] = None


# Soft, open reference list of subcategory labels used across the catalogue.
# Not enforced by pydantic (kept as plain strings on TestCase) so new labels
# can be introduced without another model change; useful for validation
# scripts and for anyone filtering test_cases.py by subcategory.
SUBCATEGORIES = {
    "tautology",
    "quote_delimiter",
    "comment_based",
    "comparison_operator",
    "error_based",
    "boolean_based",
    "time_blind",
    "second_order",
    "encoding",
    "numeric",
    "null_based",
    "type_conversion",
    "stacked_query",
    "metadata_exposure",
    "conditional_expression",
    "like_based",
    "union_based",
}

# Soft reference list of database compatibility tags.
DB_ENGINES = {"sqlite", "mysql", "postgresql", "mssql", "generic"}


class ExecutionResult(BaseModel):
    """Raw observation of running the target once."""
    test_id: str
    command: list[str]
    stdin_sent: Optional[str] = None
    stdout: str
    stderr: str
    return_code: Optional[int]
    duration_s: float
    timed_out: bool = False
    error: Optional[str] = None  # process-launch level error (not app error)


class Finding(BaseModel):
    """A classified detection result ready for reporting."""
    test_id: str
    category: VulnCategory
    confidence: Confidence
    severity: Severity
    evidence: str
    payload: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanResult(BaseModel):
    """Outcome of a full run: distinguishes tests actually executed from
    vulnerabilities detected, and flags whether the run was aborted before
    testing could meaningfully start (e.g. bad baseline)."""
    tests_executed: int
    findings: list[Finding] = Field(default_factory=list)
    aborted: bool = False
    abort_reason: Optional[str] = None
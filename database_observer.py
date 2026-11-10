"""Optional DB-state observation to strengthen evidence (especially for
second-order tests) beyond process stdout/stderr.

The C++ target's DB engine has NOT been confirmed. This module defines a
reusable observer interface plus a safe default that honestly reports it
cannot observe anything, rather than guessing at a schema or engine. Add a
concrete subclass (e.g. SQLiteObserver) only once CONFIG.db_engine is set
and the real connection details are known.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from config import CONFIG


class DatabaseObserver(ABC):
    """Takes comparable "before"/"after" snapshots of DB-visible state
    around a test, so detectors can use real state changes as evidence
    instead of relying solely on the target's stdout/stderr."""

    @abstractmethod
    def snapshot(self, label: str) -> dict[str, Any]:
        """Return an engine-specific, comparable snapshot of relevant state."""

    @abstractmethod
    def diff(self, before: dict[str, Any], after: dict[str, Any]) -> list[str]:
        """Return human-readable differences between two snapshots."""


class NullDatabaseObserver(DatabaseObserver):
    """Default observer while the target's DB engine is unconfirmed. Never
    pretends to have observed state it has no access to."""

    def snapshot(self, label: str) -> dict[str, Any]:
        return {"label": label, "observed": False, "reason": "DB engine not yet confirmed"}

    def diff(self, before: dict[str, Any], after: dict[str, Any]) -> list[str]:
        return ["DB-state observation unavailable: CONFIG.db_engine is not configured."]


def get_observer() -> DatabaseObserver:
    """Factory. Swap in a concrete, engine-specific observer here once
    CONFIG.db_engine is confirmed and a matching class is implemented —
    e.g.:

        if CONFIG.db_engine == "sqlite":
            return SQLiteObserver(CONFIG.db_path)

    Until then this always returns the safe no-op default.
    """
    if CONFIG.db_engine is None:
        return NullDatabaseObserver()
    # A concrete engine was configured but no observer implementation exists
    # yet — fail loudly instead of silently falling back to SQLite.
    raise NotImplementedError(
        f"No DatabaseObserver implemented for db_engine='{CONFIG.db_engine}' yet."
    )

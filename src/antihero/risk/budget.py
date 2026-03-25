"""Risk budget — cumulative risk tracking with threshold enforcement.

The risk budget tracks the total risk accumulated during a session.
When the cumulative risk exceeds the threshold, subsequent actions are denied.

    R_{t+1} = R_t + r(alpha_t)
    R_t >= theta => deny
"""

from __future__ import annotations

import threading
import time


class RiskBudget:
    """Thread-safe cumulative risk tracker.

    Args:
        threshold: Maximum allowed cumulative risk. Default 1.0.
    """

    def __init__(self, threshold: float = 1.0) -> None:
        self._threshold = threshold
        self._current: float = 0.0
        self._lock = threading.Lock()

    @property
    def threshold(self) -> float:
        """The maximum allowed cumulative risk."""
        return self._threshold

    @property
    def current(self) -> float:
        """Current cumulative risk value."""
        with self._lock:
            return self._current

    @property
    def remaining(self) -> float:
        """Remaining risk budget."""
        with self._lock:
            return max(0.0, self._threshold - self._current)

    def peek(self, risk: float) -> float:
        """Return what the cumulative risk would be after adding this risk."""
        with self._lock:
            return self._current + risk

    def would_exceed(self, risk: float) -> bool:
        """Check if adding this risk would exceed the threshold."""
        with self._lock:
            return (self._current + risk) > self._threshold

    def commit(self, risk: float) -> float:
        """Add risk to the budget. Returns new cumulative value."""
        with self._lock:
            self._current += risk
            return self._current

    def reset(self) -> None:
        """Reset the budget to zero."""
        with self._lock:
            self._current = 0.0


class ContainerRiskBudgetManager:
    """Manages per-container risk budgets with TTL cleanup.

    PTC sandboxes have ~4.5min lifetimes. Each container gets its own
    risk budget so that a single sandbox can't accumulate unbounded risk
    across tool-call loops.

    Args:
        default_threshold: Default risk threshold for new container budgets.
        ttl_seconds: How long a container budget lives before cleanup.
    """

    def __init__(
        self,
        default_threshold: float = 1.0,
        ttl_seconds: float = 300.0,
    ) -> None:
        self._default_threshold = default_threshold
        self._ttl_seconds = ttl_seconds
        self._budgets: dict[str, tuple[RiskBudget, float]] = {}
        self._lock = threading.Lock()

    def get_budget(self, container_id: str) -> RiskBudget:
        """Get or create a risk budget for a container."""
        with self._lock:
            entry = self._budgets.get(container_id)
            if entry is not None:
                return entry[0]
            budget = RiskBudget(threshold=self._default_threshold)
            self._budgets[container_id] = (budget, time.monotonic())
            return budget

    def cleanup_expired(self) -> int:
        """Remove budgets older than TTL. Returns count removed."""
        now = time.monotonic()
        with self._lock:
            expired = [
                cid
                for cid, (_, created_at) in self._budgets.items()
                if (now - created_at) > self._ttl_seconds
            ]
            for cid in expired:
                del self._budgets[cid]
            return len(expired)

    @property
    def active_count(self) -> int:
        """Number of active container budgets."""
        with self._lock:
            return len(self._budgets)

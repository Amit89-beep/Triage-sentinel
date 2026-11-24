"""Circuit breaker and budget tracking guardrails."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, Optional, Set, Tuple
from triage_sentinel.models.schemas import CircuitState


class CircuitBreakerOpenError(Exception):
    """Raised when an execution is attempted on an open circuit."""
    pass


class BudgetExceededError(Exception):
    """Raised when orchestrator limits are exceeded."""
    pass


class LoopDetectedError(Exception):
    """Raised when an identical tool call action is detected repeatedly."""
    pass


class ToolCircuitBreaker:
    """State machine tracking per-tool health: CLOSED -> OPEN -> HALF_OPEN."""

    def __init__(
        self,
        tool_name: str,
        failure_threshold: int = 3,
        cooldown_seconds: float = 5.0,
    ) -> None:
        self.tool_name = tool_name
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.consecutive_failures = 0
        self.state = CircuitState.CLOSED
        self.last_failure_timestamp: Optional[float] = None
        self.total_trips = 0

    def get_state(self) -> CircuitState:
        """Evaluates current state, taking cooldown into account."""
        if self.state == CircuitState.OPEN:
            if self.last_failure_timestamp is not None:
                elapsed = time.monotonic() - self.last_failure_timestamp
                if elapsed >= self.cooldown_seconds:
                    self.state = CircuitState.HALF_OPEN
        return self.state

    def can_execute(self) -> bool:
        """Returns True if invocation is permitted."""
        state = self.get_state()
        return state in (CircuitState.CLOSED, CircuitState.HALF_OPEN)

    def record_success(self) -> None:
        """Transitions state to CLOSED on success."""
        self.consecutive_failures = 0
        self.state = CircuitState.CLOSED

    def record_failure(self) -> None:
        """Increments failures and trips to OPEN if threshold reached."""
        self.consecutive_failures += 1
        self.last_failure_timestamp = time.monotonic()

        if self.consecutive_failures >= self.failure_threshold or self.state == CircuitState.HALF_OPEN:
            if self.state != CircuitState.OPEN:
                self.total_trips += 1
            self.state = CircuitState.OPEN

    def reset(self) -> None:
        """Manual reset to clean CLOSED state."""
        self.consecutive_failures = 0
        self.state = CircuitState.CLOSED
        self.last_failure_timestamp = None


class RunBudgetTracker:
    """Tracks resource consumption and flags loops via action fingerprinting."""

    def __init__(
        self,
        max_steps: int = 6,
        max_tokens: int = 12000,
        max_wall_seconds: float = 30.0,
    ) -> None:
        self.max_steps = max_steps
        self.max_tokens = max_tokens
        self.max_wall_seconds = max_wall_seconds

        self.current_steps = 0
        self.tokens_consumed = 0
        self.start_time = time.monotonic()
        self.executed_fingerprints: Set[str] = set()

    def record_step(self, tokens_used: int = 0) -> None:
        """Increments step count and tokens consumed."""
        self.current_steps += 1
        self.tokens_consumed += tokens_used

    def check_budget(self) -> Tuple[bool, Optional[str]]:
        """Verifies if the run is still within operational limits.

        Returns (is_ok, reason_if_exceeded).
        """
        elapsed = time.monotonic() - self.start_time

        if self.current_steps >= self.max_steps:
            return False, f"Maximum steps budget exceeded ({self.current_steps}/{self.max_steps})"

        if self.tokens_consumed >= self.max_tokens:
            return False, f"Token budget exceeded ({self.tokens_consumed}/{self.max_tokens})"

        if elapsed >= self.max_wall_seconds:
            return False, f"Wall-clock timeout exceeded ({elapsed:.1f}s/{self.max_wall_seconds}s)"

        return True, None

    @staticmethod
    def fingerprint_action(tool_name: str, canonical_args: Dict[str, Any]) -> str:
        """Creates a deterministic SHA256 digest of tool name and sorted arguments."""
        canonical_str = json.dumps(
            {"tool": tool_name, "args": canonical_args},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def register_action(
        self, tool_name: str, canonical_args: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """Registers a tool call action. Returns (False, error) if loop detected."""
        fp = self.fingerprint_action(tool_name, canonical_args)
        if fp in self.executed_fingerprints:
            return False, f"Loop detected: Identical call to '{tool_name}' with identical arguments already executed."

        self.executed_fingerprints.add(fp)
        return True, None

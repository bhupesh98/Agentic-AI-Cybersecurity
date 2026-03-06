"""
LLMBudgetManager — sliding-window token and call-rate limiter.

Enforces per-minute LLM call and token budgets with priority-based
routing so CRITICAL threats always get LLM analysis while LOW-priority
flows are handled by ML + memory alone.
"""

import logging
import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Fallback defaults if settings cannot be imported
_DEFAULT_TOKEN_BUDGET = 50_000
_DEFAULT_CALL_BUDGET = 20


class LLMBudgetManager:
    """
    Controls LLM resource consumption via a sliding one-minute window.

    Priority routing:
    - CRITICAL → always approved
    - HIGH      → approved if >50 % of both token + call budgets remain
    - MEDIUM    → probabilistic: approved proportional to remaining budget
    - LOW       → always denied (use ML + memory)

    Thread-safety note: this class is not thread-safe.  For concurrent
    workloads wrap with an asyncio.Lock or threading.Lock.
    """

    def __init__(
        self,
        token_budget_per_minute: Optional[int] = None,
        max_llm_calls_per_minute: Optional[int] = None,
    ):
        try:
            from config import settings  # type: ignore

            self.token_budget = token_budget_per_minute or settings.BUDGET_TOKENS_PER_MINUTE
            self.call_budget = max_llm_calls_per_minute or settings.BUDGET_MAX_LLM_CALLS_PER_MINUTE
        except Exception:
            self.token_budget = token_budget_per_minute or _DEFAULT_TOKEN_BUDGET
            self.call_budget = max_llm_calls_per_minute or _DEFAULT_CALL_BUDGET

        # Sliding window entries: (monotonic_timestamp,)
        self._call_window: Deque[float] = deque()
        # Sliding window entries: (monotonic_timestamp, tokens_used)
        self._token_window: Deque[Tuple[float, int]] = deque()

        # Lifetime counters (not windowed)
        self.total_calls: int = 0
        self.total_tokens_estimated: int = 0
        self.total_cost_estimate_usd: float = 0.0

        # Running cost rate: $0.002 per 1K tokens (conservative estimate)
        self._cost_per_1k_tokens: float = 0.002

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_llm_call(
        self,
        priority: str,
        estimated_tokens: int = 500,
    ) -> bool:
        """
        Request permission to make an LLM call.

        Args:
            priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
            estimated_tokens: Rough token estimate for budgeting.

        Returns:
            True if the call is approved; False if it should be skipped.
        """
        self._clean_window()
        calls_used = len(self._call_window)
        tokens_used = sum(t for _, t in self._token_window)
        calls_remaining = max(0, self.call_budget - calls_used)
        tokens_remaining = max(0, self.token_budget - tokens_used)

        p = priority.upper()

        if p == "CRITICAL":
            approved = True
        elif p == "HIGH":
            approved = (
                calls_remaining > self.call_budget * 0.5
                and tokens_remaining > self.token_budget * 0.5
            )
        elif p == "MEDIUM":
            import random

            call_ratio = calls_remaining / max(self.call_budget, 1)
            token_ratio = tokens_remaining / max(self.token_budget, 1)
            ratio = min(call_ratio, token_ratio)
            approved = random.random() < ratio
        else:  # LOW
            approved = False

        if approved:
            now = time.monotonic()
            self._call_window.append(now)
            self._token_window.append((now, estimated_tokens))
            self.total_calls += 1
            self.total_tokens_estimated += estimated_tokens
            self.total_cost_estimate_usd += (estimated_tokens / 1_000) * self._cost_per_1k_tokens
            logger.debug(
                "LLM call approved [%s] est_tokens=%d  calls_used=%d/%d",
                p,
                estimated_tokens,
                calls_used + 1,
                self.call_budget,
            )
        else:
            logger.debug(
                "LLM call denied [%s] calls=%d/%d tokens=%d/%d",
                p,
                calls_used,
                self.call_budget,
                tokens_used,
                self.token_budget,
            )

        return approved

    def get_budget_status(self) -> Dict[str, Any]:
        """Return current budget usage for dashboard display."""
        self._clean_window()
        calls_used = len(self._call_window)
        tokens_used = sum(t for _, t in self._token_window)
        return {
            "calls_this_minute": calls_used,
            "calls_budget": self.call_budget,
            "calls_remaining": max(0, self.call_budget - calls_used),
            "tokens_this_minute": tokens_used,
            "tokens_budget": self.token_budget,
            "tokens_remaining": max(0, self.token_budget - tokens_used),
            "total_calls": self.total_calls,
            "total_tokens_estimated": self.total_tokens_estimated,
            "total_cost_estimate_usd": round(self.total_cost_estimate_usd, 4),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _clean_window(self) -> None:
        """Evict entries older than 60 seconds from both windows."""
        cutoff = time.monotonic() - 60.0
        while self._call_window and self._call_window[0] < cutoff:
            self._call_window.popleft()
        while self._token_window and self._token_window[0][0] < cutoff:
            self._token_window.popleft()


# Module-level singleton
_budget_manager: Optional[LLMBudgetManager] = None


def get_budget_manager() -> LLMBudgetManager:
    """Return the module-level LLMBudgetManager singleton."""
    global _budget_manager
    if _budget_manager is None:
        _budget_manager = LLMBudgetManager()
    return _budget_manager

"""
Simulation Mode Manager.

When SIMULATION_MODE=True (the default):
  - FirewallManager.block_ip() logs "Would block IP X" instead of calling
    pfctl / iptables.
  - AlertManager.send_alert() logs "Would send email/Slack to Y" instead of
    actually performing SMTP or webhook calls.
  - ActionExecutor marks every ActionResult.simulated = True.

The SimulationMode context manager lets tests override the global flag
temporarily:

    with SimulationMode(enabled=False):
        # real actions here

Phase 1: Foundation — Feature 9 (simulation mode)
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level override (used by SimulationMode context manager)
# ---------------------------------------------------------------------------
_simulation_override: Optional[bool] = None


def is_simulation() -> bool:
    """Return True if simulation mode is currently active.

    Checks (in order):
    1. Thread-level override set by the SimulationMode context manager.
    2. config.settings.SIMULATION_MODE.
    3. Falls back to True (safe default) if config is unavailable.
    """
    if _simulation_override is not None:
        return _simulation_override
    try:
        from config import settings
        return settings.SIMULATION_MODE
    except Exception:
        return True  # safe default — never accidentally fire real actions


def log_simulation_action(action: str, details: str = "") -> str:
    """Log (and return) a simulation notice instead of executing a real action.

    Args:
        action: Short description of the action that *would* be taken.
        details: Optional extra context (IP, recipient, etc.).

    Returns:
        The formatted simulation message (callers can include it in results).
    """
    msg = f"[SIMULATION] {action}"
    if details:
        msg += f" — {details}"
    logger.info(msg)
    return msg


class SimulationMode:
    """Context manager to temporarily override the simulation flag.

    Example::

        with SimulationMode(enabled=False):
            firewall.block_ip("1.2.3.4", "test")   # real action
        # back to settings.SIMULATION_MODE after the block
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._previous: Optional[bool] = None

    def __enter__(self) -> "SimulationMode":
        global _simulation_override
        self._previous = _simulation_override
        _simulation_override = self.enabled
        return self

    def __exit__(self, *args) -> None:
        global _simulation_override
        _simulation_override = self._previous

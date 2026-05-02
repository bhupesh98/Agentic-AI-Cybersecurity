"""
Actions Module - Autonomous Response System.

Implements Phase 3 (Response Automation) of the Agentic AI Cybersecurity System.
Provides the ACTION component of OODA loop (Observe-Orient-Decide-ACT).
"""

from .action_executor import (
    # Enums
    ActionType,
    ActionPriority,
    ActionStatus,

    # Data Models
    Action,
    BlockIPAction,
    UnblockIPAction,
    AlertAction,
    IsolateHostAction,
    ActionResult,

    # Core Classes
    ActionQueue,
    ActionExecutor,

    # Global Instance
    get_action_executor
)

from .firewall_manager import (
    FirewallManager,
    BlockedIP,
    get_firewall_manager,
    detect_os,
    check_sudo_access
)

from .alert_manager import (
    AlertManager,
    Alert,
    get_alert_manager
)

from .action_verifier import (
    ActionVerifier,
    get_action_verifier
)

from .response_policies import (
    PolicyEngine,
    ResponsePolicy,
    ThreatContext,
    get_policy_engine,
    # Constants
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW
)

__all__ = [
    # Enums
    'ActionType',
    'ActionPriority',
    'ActionStatus',

    # Data Models
    'Action',
    'BlockIPAction',
    'UnblockIPAction',
    'AlertAction',
    'IsolateHostAction',
    'ActionResult',

    # Core Classes
    'ActionQueue',
    'ActionExecutor',

    # Firewall
    'FirewallManager',
    'BlockedIP',
    'get_firewall_manager',
    'detect_os',
    'check_sudo_access',

    # Alerts
    'AlertManager',
    'Alert',
    'get_alert_manager',

    # Verification
    'ActionVerifier',
    'get_action_verifier',

    # Policies
    'PolicyEngine',
    'ResponsePolicy',
    'ThreatContext',
    'get_policy_engine',
    'SEVERITY_CRITICAL',
    'SEVERITY_HIGH',
    'SEVERITY_MEDIUM',
    'SEVERITY_LOW',

    # Global Instances
    'get_action_executor',
]

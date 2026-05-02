"""
Mock Action Handlers for Testing

Provides simulated action handlers that log actions without
actually modifying system (firewall, network, etc.)

Use this for safe testing and demonstration purposes.

Location: src/actions/mock_handlers.py

"""

import logging

from .action_executor import (
    ActionResult,
    ActionType,
    BlockIPAction,
    UnblockIPAction,
    AlertAction,
    IsolateHostAction
)

logger = logging.getLogger(__name__)


def mock_block_ip_handler(action: BlockIPAction) -> ActionResult:
    """
    Mock handler for IP blocking.
    
    Simulates blocking an IP without actually modifying firewall.
    """
    logger.info(f"🚫 [MOCK] Blocking IP: {action.target}")
    logger.info(f"   Duration: {action.duration_minutes} minutes")
    logger.info(f"   Reason: {action.reason}")

    # Simulate some processing time
    import time
    time.sleep(0.1)

    return ActionResult(
        action_id=action.action_id,
        success=True,
        execution_time_ms=100.0,
        output=f"Successfully blocked {action.target} for {action.duration_minutes} minutes",
        verification_passed=True
    )


def mock_unblock_ip_handler(action: UnblockIPAction) -> ActionResult:
    """Mock handler for IP unblocking."""
    logger.info(f"✅ [MOCK] Unblocking IP: {action.target}")

    import time
    time.sleep(0.05)

    return ActionResult(
        action_id=action.action_id,
        success=True,
        execution_time_ms=50.0,
        output=f"Successfully unblocked {action.target}",
        verification_passed=True
    )


def mock_alert_handler(action: AlertAction) -> ActionResult:
    """Mock handler for sending alerts."""
    logger.info(f"📧 [MOCK] Sending {action.alert_type} alert")
    logger.info(f"   Severity: {action.severity}")
    logger.info(f"   Recipients: {', '.join(action.recipients)}")
    logger.info(f"   Message: {action.message[:100]}...")

    import time
    time.sleep(0.05)

    return ActionResult(
        action_id=action.action_id,
        success=True,
        execution_time_ms=50.0,
        output=f"Alert sent to {len(action.recipients)} recipients",
        verification_passed=True
    )


def mock_isolate_host_handler(action: IsolateHostAction) -> ActionResult:
    """Mock handler for host isolation."""
    logger.info(f"🔒 [MOCK] Isolating host: {action.target}")
    logger.info(f"   Level: {action.isolation_level}")

    import time
    time.sleep(0.2)

    return ActionResult(
        action_id=action.action_id,
        success=True,
        execution_time_ms=200.0,
        output=f"Host {action.target} isolated at {action.isolation_level} level",
        verification_passed=True
    )


def register_mock_handlers(executor):
    """
    Register all mock handlers with action executor.
    
    Args:
        executor: ActionExecutor instance
    """
    executor.register_handler(ActionType.BLOCK_IP, mock_block_ip_handler)
    executor.register_handler(ActionType.UNBLOCK_IP, mock_unblock_ip_handler)
    executor.register_handler(ActionType.ALERT_EMAIL, mock_alert_handler)
    executor.register_handler(ActionType.ALERT_SLACK, mock_alert_handler)
    executor.register_handler(ActionType.ALERT_SMS, mock_alert_handler)
    executor.register_handler(ActionType.ISOLATE_HOST,
                              mock_isolate_host_handler)

    logger.info("✅ Registered all mock action handlers")


if __name__ == "__main__":
    # Test mock handlers
    from .action_executor import get_action_executor, BlockIPAction, ActionPriority

    print("Testing mock handlers...")

    executor = get_action_executor()
    register_mock_handlers(executor)

    # Submit test action
    action = BlockIPAction(
        action_id="test-mock-001",
        priority=ActionPriority.HIGH,
        target="10.0.0.99",
        reason="Test mock action",
        duration_minutes=10
    )

    executor.submit_action(action)
    result = executor.execute_next()

    print(f"\nResult: {result.success}")
    print(f"Output: {result.output}")
    print("\n✅ Mock handlers test complete!")

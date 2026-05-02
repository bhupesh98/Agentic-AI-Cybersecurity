"""
Action Verifier - Verify that actions were executed successfully.

After an action is executed (block IP, send alert), we need to verify:
- Did the firewall rule get applied?
- Did the email actually send?
- Is the IP still blocked after N seconds?

This implements the verification part of autonomous response.

Phase 3 - Day 4: Response Automation
"""

import logging
import time
from typing import Tuple
from datetime import datetime


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# ACTION VERIFIER
# ============================================================================

class ActionVerifier:
    """
    Verifies that actions were executed successfully.
    
    Provides multiple verification strategies:
    - Immediate verification (right after execution)
    - Delayed verification (after N seconds)
    - Persistent verification (check multiple times)
    """

    def __init__(self):
        """Initialize action verifier"""
        self.logger = logging.getLogger(__name__ + ".ActionVerifier")
        self.verification_history = []
        self.logger.info("✅ ActionVerifier initialized")

    def verify_firewall_block(
        self,
        firewall_manager,
        ip_address: str,
        immediate: bool = True,
        delay_seconds: int = 2
    ) -> Tuple[bool, str]:
        """
        Verify firewall block was applied.
        
        Args:
            firewall_manager: FirewallManager instance
            ip_address: IP that should be blocked
            immediate: If True, check immediately. If False, wait delay_seconds
            delay_seconds: How long to wait before checking
            
        Returns:
            (verified, message) tuple
        """
        if not immediate:
            self.logger.info(
                f"⏳ Waiting {delay_seconds}s before verification...")
            time.sleep(delay_seconds)

        try:
            # Get list of blocked IPs from firewall
            active_blocks = firewall_manager.list_active_blocks()

            if ip_address in active_blocks:
                msg = f"✅ Verified: {ip_address} is blocked in firewall"
                self.logger.info(msg)

                # Record verification
                self._record_verification(
                    action_type="block_ip",
                    target=ip_address,
                    verified=True,
                    method="firewall_query"
                )

                return (True, msg)
            else:
                msg = f"❌ Verification failed: {ip_address} NOT in firewall blocks"
                self.logger.warning(msg)

                self._record_verification(
                    action_type="block_ip",
                    target=ip_address,
                    verified=False,
                    method="firewall_query"
                )

                return (False, msg)

        except Exception as e:
            msg = f"❌ Verification error: {str(e)}"
            self.logger.error(msg)
            return (False, msg)

    def verify_firewall_unblock(
        self,
        firewall_manager,
        ip_address: str
    ) -> Tuple[bool, str]:
        """
        Verify IP was unblocked.
        
        Args:
            firewall_manager: FirewallManager instance
            ip_address: IP that should be unblocked
            
        Returns:
            (verified, message) tuple
        """
        try:
            active_blocks = firewall_manager.list_active_blocks()

            if ip_address not in active_blocks:
                msg = f"✅ Verified: {ip_address} is NOT blocked (unblock successful)"
                self.logger.info(msg)

                self._record_verification(
                    action_type="unblock_ip",
                    target=ip_address,
                    verified=True,
                    method="firewall_query"
                )

                return (True, msg)
            else:
                msg = f"❌ Verification failed: {ip_address} still blocked"
                self.logger.warning(msg)

                self._record_verification(
                    action_type="unblock_ip",
                    target=ip_address,
                    verified=False,
                    method="firewall_query"
                )

                return (False, msg)

        except Exception as e:
            msg = f"❌ Verification error: {str(e)}"
            self.logger.error(msg)
            return (False, msg)

    def verify_alert_sent(
        self,
        alert_manager,
        alert_id: str
    ) -> Tuple[bool, str]:
        """
        Verify alert was sent successfully.
        
        Args:
            alert_manager: AlertManager instance
            alert_id: ID of alert to verify
            
        Returns:
            (verified, message) tuple
        """
        try:
            # Get recent alerts from database
            recent_alerts = alert_manager.get_recent_alerts(limit=20)

            # Find our alert
            alert = None
            for a in recent_alerts:
                if a['alert_id'] == alert_id:
                    alert = a
                    break

            if not alert:
                msg = f"⚠️  Alert {alert_id} not found in database"
                self.logger.warning(msg)
                return (False, msg)

            # Check status
            if alert['status'] == 'sent':
                msg = f"✅ Verified: Alert {alert_id} was sent successfully"
                self.logger.info(msg)

                self._record_verification(
                    action_type="alert",
                    target=alert_id,
                    verified=True,
                    method="database_query"
                )

                return (True, msg)
            else:
                msg = f"❌ Alert {alert_id} status: {alert['status']}"
                self.logger.warning(msg)

                self._record_verification(
                    action_type="alert",
                    target=alert_id,
                    verified=False,
                    method="database_query"
                )

                return (False, msg)

        except Exception as e:
            msg = f"❌ Verification error: {str(e)}"
            self.logger.error(msg)
            return (False, msg)

    def verify_persistent(
        self,
        firewall_manager,
        ip_address: str,
        check_count: int = 3,
        interval_seconds: int = 5
    ) -> Tuple[bool, str]:
        """
        Verify block persists over time (check multiple times).
        
        Useful for detecting if blocks are being removed unexpectedly.
        
        Args:
            firewall_manager: FirewallManager instance
            ip_address: IP that should stay blocked
            check_count: Number of times to check
            interval_seconds: Seconds between checks
            
        Returns:
            (verified, message) tuple
        """
        self.logger.info(
            f"🔍 Persistent verification: {check_count} checks over {check_count * interval_seconds}s")

        success_count = 0

        for i in range(check_count):
            if i > 0:
                time.sleep(interval_seconds)

            active_blocks = firewall_manager.list_active_blocks()

            if ip_address in active_blocks:
                success_count += 1
                self.logger.info(
                    f"   Check {i+1}/{check_count}: ✅ Still blocked")
            else:
                self.logger.warning(
                    f"   Check {i+1}/{check_count}: ❌ Not blocked!")

        if success_count == check_count:
            msg = f"✅ Persistent verification passed: {success_count}/{check_count} checks"
            self.logger.info(msg)
            return (True, msg)
        else:
            msg = f"⚠️  Persistent verification partial: {success_count}/{check_count} checks"
            self.logger.warning(msg)
            return (False, msg)

    def verify_action_result(
        self,
        action_executor,
        action_id: str
    ) -> Tuple[bool, str]:
        """
        Verify action by checking execution result in database.
        
        Args:
            action_executor: ActionExecutor instance
            action_id: ID of action to verify
            
        Returns:
            (verified, message) tuple
        """
        try:
            # Get recent actions
            recent_actions = action_executor.get_recent_actions(limit=50)

            # Find our action
            action = None
            for a in recent_actions:
                if a['action_id'] == action_id:
                    action = a
                    break

            if not action:
                msg = f"⚠️  Action {action_id} not found"
                return (False, msg)

            # Check status
            if action['status'] == 'completed' and action['success'] == 1:
                msg = f"✅ Verified: Action {action_id} completed successfully"
                self.logger.info(msg)

                self._record_verification(
                    action_type=action['action_type'],
                    target=action['target'],
                    verified=True,
                    method="database_query"
                )

                return (True, msg)
            else:
                msg = f"❌ Action {action_id} status: {action['status']}"
                self.logger.warning(msg)

                self._record_verification(
                    action_type=action['action_type'],
                    target=action['target'],
                    verified=False,
                    method="database_query"
                )

                return (False, msg)

        except Exception as e:
            msg = f"❌ Verification error: {str(e)}"
            self.logger.error(msg)
            return (False, msg)

    def _record_verification(
        self,
        action_type: str,
        target: str,
        verified: bool,
        method: str
    ):
        """Record verification attempt"""
        record = {
            'timestamp': datetime.utcnow().isoformat(),
            'action_type': action_type,
            'target': target,
            'verified': verified,
            'method': method
        }

        self.verification_history.append(record)

    def get_verification_stats(self) -> dict:
        """Get verification statistics"""
        total = len(self.verification_history)
        if total == 0:
            return {
                'total': 0,
                'verified': 0,
                'failed': 0,
                'success_rate': 0.0
            }

        verified = sum(1 for v in self.verification_history if v['verified'])
        failed = total - verified

        return {
            'total': total,
            'verified': verified,
            'failed': failed,
            'success_rate': verified / total if total > 0 else 0.0
        }

    def get_verification_history(self, limit: int = 10) -> list:
        """Get recent verification history"""
        return self.verification_history[-limit:]


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_verifier_instance = None


def get_action_verifier() -> ActionVerifier:
    """Get or create global action verifier instance"""
    global _verifier_instance

    if _verifier_instance is None:
        _verifier_instance = ActionVerifier()

    return _verifier_instance


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("Testing Action Verifier...")
    print("=" * 70)

    verifier = get_action_verifier()

    print("\n✅ ActionVerifier initialized")
    print("\nThis module works with FirewallManager and AlertManager")
    print("Run the integration tests to see verification in action:")
    print("\n  sudo python3 test_complete_response.py")

    print("\n" + "=" * 70)
    print("✅ Action verifier test complete!")

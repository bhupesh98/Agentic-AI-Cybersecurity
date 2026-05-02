"""
Action Executor - Main action execution engine for autonomous response.

This module implements the ACTION part of OODA loop (Observe-Orient-Decide-ACT).
It provides the framework for executing autonomous security responses without
human intervention.

Phase 3 - Response Automation
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
import uuid
import sqlite3
from pathlib import Path


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================

class ActionType(Enum):
    """Types of actions the system can take"""
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    BLOCK_PORT = "block_port"
    ALERT_EMAIL = "alert_email"
    ALERT_SLACK = "alert_slack"
    ALERT_SMS = "alert_sms"
    ISOLATE_HOST = "isolate_host"
    LOG_INCIDENT = "log_incident"
    RATE_LIMIT = "rate_limit"


class ActionPriority(Enum):
    """Action priority levels - determines execution order"""
    CRITICAL = 0  # Execute immediately (DoS, active breach)
    HIGH = 1      # Execute ASAP (brute force, malware)
    MEDIUM = 2    # Execute soon (suspicious activity)
    LOW = 3       # Execute when convenient (logging, reporting)


class ActionStatus(Enum):
    """Action execution status"""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class Action:
    """
    Base action that can be executed by the system.
    
    All specific actions (BlockIPAction, AlertAction, etc.) inherit from this.
    """
    action_id: str
    # Default, overridden by child classes
    action_type: ActionType = ActionType.LOG_INCIDENT
    priority: ActionPriority = ActionPriority.MEDIUM
    created_at: datetime = field(default_factory=datetime.utcnow)
    target: str = ""
    reason: str = ""
    context: Dict[str, Any] = field(default_factory=dict)  # Additional context

    # Execution tracking
    status: ActionStatus = ActionStatus.PENDING
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3

    def to_dict(self) -> Dict[str, Any]:
        """Convert action to dictionary for logging/storage"""
        data = asdict(self)
        # Convert enums to strings
        data['action_type'] = self.action_type.value
        data['priority'] = self.priority.value
        data['status'] = self.status.value
        # Convert datetimes to ISO strings
        data['created_at'] = self.created_at.isoformat()
        data['executed_at'] = self.executed_at.isoformat(
        ) if self.executed_at else None
        data['completed_at'] = self.completed_at.isoformat(
        ) if self.completed_at else None
        return data


@dataclass
class BlockIPAction(Action):
    """
    Action to block an IP address using firewall.
    
    Attributes:
        duration_minutes: How long to block (0 = permanent)
        ports: Specific ports to block (None = all ports)
        protocol: TCP, UDP, or None (all protocols)
    """
    duration_minutes: int = 10  # Default: 10 minutes
    ports: Optional[List[int]] = None
    protocol: Optional[str] = None  # 'TCP', 'UDP', or None

    def __post_init__(self):
        """Set action type after initialization"""
        self.action_type = ActionType.BLOCK_IP


@dataclass
class UnblockIPAction(Action):
    """Action to unblock a previously blocked IP"""

    def __post_init__(self):
        self.action_type = ActionType.UNBLOCK_IP


@dataclass
class AlertAction(Action):
    """
    Action to send an alert notification.
    
    Attributes:
        severity: CRITICAL, HIGH, MEDIUM, LOW
        recipients: List of recipients (emails, slack channels, phone numbers)
        message: Alert message body
        alert_type: email, slack, or sms
    """
    severity: str = "HIGH"
    recipients: List[str] = field(default_factory=list)
    message: str = ""
    alert_type: str = "email"  # 'email', 'slack', 'sms'

    def __post_init__(self):
        """Set action type based on alert_type"""
        if self.alert_type == "email":
            self.action_type = ActionType.ALERT_EMAIL
        elif self.alert_type == "slack":
            self.action_type = ActionType.ALERT_SLACK
        elif self.alert_type == "sms":
            self.action_type = ActionType.ALERT_SMS


@dataclass
class IsolateHostAction(Action):
    """
    Action to isolate a compromised host from network.
    
    More advanced than IP blocking - quarantines entire host.
    """
    isolation_level: str = "partial"  # 'partial', 'full'
    # IPs still allowed to communicate
    allow_list: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.action_type = ActionType.ISOLATE_HOST


@dataclass
class ActionResult:
    """
    Result of action execution.
    
    Records what happened when action was executed.
    """
    action_id: str
    success: bool
    execution_time_ms: float
    output: str = ""
    error: Optional[str] = None
    verification_passed: bool = False
    simulated: bool = False
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'action_id': self.action_id,
            'success': self.success,
            'execution_time_ms': self.execution_time_ms,
            'output': self.output,
            'error': self.error,
            'verification_passed': self.verification_passed,
            'simulated': self.simulated,
            'timestamp': self.timestamp.isoformat()
        }


# ============================================================================
# ACTION QUEUE
# ============================================================================

class ActionQueue:
    """
    Priority queue for actions.
    
    Ensures CRITICAL actions execute before LOW priority actions.
    Uses FIFO within same priority level.
    """

    def __init__(self):
        self.queues = {
            ActionPriority.CRITICAL: [],
            ActionPriority.HIGH: [],
            ActionPriority.MEDIUM: [],
            ActionPriority.LOW: []
        }
        self.logger = logging.getLogger(__name__ + ".ActionQueue")

    def add(self, action: Action):
        """Add action to appropriate priority queue"""
        self.queues[action.priority].append(action)
        self.logger.info(
            f"Added {action.action_type.value} action to {action.priority.name.lower()} queue")

    def get_next(self) -> Optional[Action]:
        """Get next action to execute (highest priority first)"""
        for priority in [ActionPriority.CRITICAL, ActionPriority.HIGH,
                         ActionPriority.MEDIUM, ActionPriority.LOW]:
            if self.queues[priority]:
                action = self.queues[priority].pop(0)
                self.logger.info(
                    f"Dequeued {action.action_type.value} action (priority: {priority.name.lower()})")
                return action
        return None

    def get_pending_count(self) -> int:
        """Get total number of pending actions"""
        return sum(len(q) for q in self.queues.values())

    def get_counts_by_priority(self) -> Dict[str, int]:
        """Get count of actions by priority"""
        return {
            priority.name.lower(): len(queue)
            for priority, queue in self.queues.items()
        }

    def clear(self):
        """Clear all queues (emergency use only)"""
        for queue in self.queues.values():
            queue.clear()
        self.logger.warning("All action queues cleared")


# ============================================================================
# ACTION EXECUTOR
# ============================================================================

class ActionExecutor:
    """
    Main action execution engine.
    
    Coordinates execution of all actions, handles retries, logging, and verification.
    This is the core of the autonomous response system.
    """

    def __init__(self, db_path: str = "data/actions/actions.db"):
        """
        Initialize action executor.
        
        Args:
            db_path: Path to SQLite database for action logging
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.queue = ActionQueue()
        self.logger = logging.getLogger(__name__ + ".ActionExecutor")

        # Action handlers (will be set by specific managers)
        self.handlers = {}

        # Statistics
        self.stats = {
            'total_executed': 0,
            'successful': 0,
            'failed': 0,
            'retries': 0
        }

        # Initialize database
        self._init_database()

        self.logger.info(f"✅ ActionExecutor initialized (DB: {self.db_path})")

    def _init_database(self):
        """Create actions database table"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS actions (
                action_id TEXT PRIMARY KEY,
                action_type TEXT NOT NULL,
                priority TEXT NOT NULL,
                target TEXT NOT NULL,
                reason TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                executed_at TEXT,
                completed_at TEXT,
                execution_time_ms REAL,
                success INTEGER,
                error_message TEXT,
                retry_count INTEGER DEFAULT 0,
                context_json TEXT
            )
        """)

        conn.commit()
        conn.close()

        self.logger.info("✅ Actions database initialized")

    def register_handler(self, action_type: ActionType, handler_func):
        """
        Register a handler function for specific action type.
        
        Args:
            action_type: Type of action (e.g., ActionType.BLOCK_IP)
            handler_func: Function that executes the action
                          Signature: func(action: Action) -> ActionResult
        
        Example:
            executor.register_handler(ActionType.BLOCK_IP, firewall_manager.block_ip)
        """
        self.handlers[action_type] = handler_func
        self.logger.info(f"✅ Registered handler for {action_type.value}")

    def submit_action(self, action: Action):
        """
        Submit action for execution.
        
        Action is added to priority queue and will be executed when
        executor processes the queue.
        
        Args:
            action: Action to execute
        """
        # Generate action_id if not set
        if not hasattr(action, 'action_id') or not action.action_id:
            action.action_id = f"action-{uuid.uuid4().hex[:12]}"

        # Set created_at if not set
        if not hasattr(action, 'created_at') or not action.created_at:
            action.created_at = datetime.utcnow()

        # Add to queue
        self.queue.add(action)

        # Log to database
        self._log_action(action)

        self.logger.info(
            f"📥 Action submitted: {action.action_type.value} for {action.target}")

    def execute_next(self) -> Optional[ActionResult]:
        """
        Execute next action from queue.
        
        Returns:
            ActionResult if action was executed, None if queue is empty
        """
        action = self.queue.get_next()
        if not action:
            return None

        return self.execute_action(action)

    def execute_action(self, action: Action) -> ActionResult:
        """
        Execute a single action.
        
        Args:
            action: Action to execute
            
        Returns:
            ActionResult with execution details
        """
        start_time = datetime.utcnow()
        action.status = ActionStatus.EXECUTING
        action.executed_at = start_time

        self.logger.info(
            f"▶️  Executing: {action.action_type.value} for {action.target}")

        # Simulation mode guard — skip real execution when SIMULATION_MODE=True
        try:
            from src.simulation.simulation_manager import is_simulation, log_simulation_action
            if is_simulation():
                sim_msg = log_simulation_action(
                    f"Execute {action.action_type.value}",
                    f"target={action.target}"
                )
                result = ActionResult(
                    action_id=action.action_id,
                    success=True,
                    execution_time_ms=0.1,
                    output=sim_msg,
                    simulated=True,
                    verification_passed=True,
                )
                action.status = ActionStatus.COMPLETED
                action.completed_at = datetime.utcnow()
                self._update_action_status(action, result)
                self.stats['successful'] += 1
                self.stats['total_executed'] += 1
                return result
        except ImportError:
            pass  # simulation module not available, proceed normally

        try:
            # Get handler for this action type
            handler = self.handlers.get(action.action_type)

            if not handler:
                # No handler registered - log as failed
                error_msg = f"No handler registered for {action.action_type.value}"
                self.logger.error(f"❌ {error_msg}")

                result = ActionResult(
                    action_id=action.action_id,
                    success=False,
                    execution_time_ms=0,
                    error=error_msg
                )

                action.status = ActionStatus.FAILED
                action.error_message = error_msg
                action.completed_at = datetime.utcnow()

                self._update_action_status(action, result)
                self.stats['failed'] += 1

                return result

            # Execute handler
            result = handler(action)

            # Calculate execution time
            end_time = datetime.utcnow()
            result.execution_time_ms = (
                end_time - start_time).total_seconds() * 1000

            # Update action status
            if result.success:
                action.status = ActionStatus.COMPLETED
                action.completed_at = end_time
                self.stats['successful'] += 1
                self.logger.info(
                    f"✅ Action completed successfully ({result.execution_time_ms:.1f}ms)")
            else:
                # Check if should retry
                if action.retry_count < action.max_retries:
                    action.status = ActionStatus.RETRYING
                    action.retry_count += 1
                    self.queue.add(action)  # Re-queue for retry
                    self.stats['retries'] += 1
                    self.logger.warning(
                        f"⚠️  Action failed, retry {action.retry_count}/{action.max_retries}")
                else:
                    action.status = ActionStatus.FAILED
                    action.error_message = result.error
                    action.completed_at = end_time
                    self.stats['failed'] += 1
                    self.logger.error(
                        f"❌ Action failed after {action.max_retries} retries")

            # Update database
            self._update_action_status(action, result)
            self.stats['total_executed'] += 1

            return result

        except Exception as e:
            # Unhandled exception
            error_msg = f"Unhandled exception: {str(e)}"
            self.logger.error(f"❌ {error_msg}", exc_info=True)

            result = ActionResult(
                action_id=action.action_id,
                success=False,
                execution_time_ms=(datetime.utcnow() -
                                   start_time).total_seconds() * 1000,
                error=error_msg
            )

            action.status = ActionStatus.FAILED
            action.error_message = error_msg
            action.completed_at = datetime.utcnow()

            self._update_action_status(action, result)
            self.stats['failed'] += 1

            return result

    def execute_all_pending(self) -> List[ActionResult]:
        """
        Execute all pending actions in queue.
        
        Returns:
            List of ActionResults
        """
        results = []
        pending_count = self.queue.get_pending_count()

        self.logger.info(f"⚡ Executing {pending_count} pending actions...")

        while self.queue.get_pending_count() > 0:
            result = self.execute_next()
            if result:
                results.append(result)

        self.logger.info(f"✅ Executed {len(results)} actions")

        return results

    def _log_action(self, action: Action):
        """Log action to database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO actions (
                    action_id, action_type, priority, target, reason,
                    status, created_at, context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action.action_id,
                action.action_type.value,
                action.priority.value,
                action.target,
                action.reason,
                action.status.value,
                action.created_at.isoformat(),
                str(action.context)
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to log action to database: {e}")

    def _update_action_status(self, action: Action, result: ActionResult):
        """Update action status in database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE actions SET
                    status = ?,
                    executed_at = ?,
                    completed_at = ?,
                    execution_time_ms = ?,
                    success = ?,
                    error_message = ?,
                    retry_count = ?
                WHERE action_id = ?
            """, (
                action.status.value,
                action.executed_at.isoformat() if action.executed_at else None,
                action.completed_at.isoformat() if action.completed_at else None,
                result.execution_time_ms,
                1 if result.success else 0,
                action.error_message,
                action.retry_count,
                action.action_id
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to update action status: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return {
            **self.stats,
            'pending_count': self.queue.get_pending_count(),
            'pending_by_priority': self.queue.get_counts_by_priority(),
            'success_rate': self.stats['successful'] / max(1, self.stats['total_executed'])
        }

    def get_recent_actions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent actions from database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM actions
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()
            conn.close()

            return [dict(row) for row in rows]

        except Exception as e:
            self.logger.error(f"Failed to get recent actions: {e}")
            return []


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_executor_instance = None


def get_action_executor() -> ActionExecutor:
    """Get or create global action executor instance"""
    global _executor_instance

    if _executor_instance is None:
        _executor_instance = ActionExecutor()

    return _executor_instance


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    # Quick test
    print("Testing Action Executor...")

    executor = get_action_executor()

    # Create test action
    action = BlockIPAction(
        action_id="test-001",
        priority=ActionPriority.HIGH,
        target="192.168.1.100",
        reason="Test action - port scan detected",
        duration_minutes=5
    )

    # Submit action
    executor.submit_action(action)

    # Check stats
    stats = executor.get_statistics()
    print(f"\nStatistics: {stats}")

    print("\n✅ Action executor test complete!")

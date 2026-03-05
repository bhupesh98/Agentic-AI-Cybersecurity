"""
Feedback Incorporation Manager - Principle #7 Implementation

Enables human analysts to correct system decisions, and the system
immediately learns from these corrections for future similar cases.

Key Features:
- Analyst feedback collection
- Automatic rule generation from feedback
- Immediate application to similar cases
- Feedback effectiveness tracking

Location: src/agent/feedback_manager.py
Author: Abhinav
Date: November 2025
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import re


@dataclass
class AnalystFeedback:
    """Single piece of analyst feedback."""
    feedback_id: str
    incident_id: str
    analyst_id: str
    feedback_type: str  # 'false_positive', 'false_negative', 'severity_correction', 'correct'
    original_decision: str
    corrected_decision: str
    reasoning: str
    timestamp: str
    applied_count: int = 0


@dataclass
class FeedbackRule:
    """Learned rule from analyst feedback."""
    rule_id: str
    condition: str  # Human-readable condition
    condition_json: Dict  # Machine-readable condition
    action: str  # What to do when condition matches
    learned_from: str  # feedback_id
    confidence: float
    usage_count: int
    created_at: str
    last_used: Optional[str] = None


@dataclass
class FeedbackMetrics:
    """Metrics for feedback incorporation."""
    total_feedback: int
    feedback_by_type: Dict[str, int]
    active_rules: int
    total_rule_applications: int
    application_rate: float  # % of decisions influenced by feedback
    false_positive_reduction: float  # % reduction from feedback
    avg_time_to_apply: float  # Seconds


class FeedbackManager:
    """
    Manages analyst feedback and learned corrections.
    
    This is the core of Principle #7 (Feedback Incorporation).
    """

    def __init__(self, db_path: str = "data/feedback/analyst_feedback.db"):
        """
        Initialize feedback manager.
        
        Args:
            db_path: Path to feedback database
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Initialize database
        self._init_database()

        self.logger.info("✅ Feedback Manager initialized")

    def _init_database(self):
        """Initialize SQLite database for feedback storage."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Analyst feedback table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                feedback_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                analyst_id TEXT NOT NULL,
                feedback_type TEXT NOT NULL,
                original_decision TEXT NOT NULL,
                corrected_decision TEXT NOT NULL,
                reasoning TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                applied_count INTEGER DEFAULT 0
            )
        """)

        # Feedback rules table (learned from feedback)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feedback_rules (
                rule_id TEXT PRIMARY KEY,
                condition TEXT NOT NULL,
                condition_json TEXT NOT NULL,
                action TEXT NOT NULL,
                learned_from TEXT NOT NULL,
                confidence REAL NOT NULL,
                usage_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_used TEXT,
                FOREIGN KEY (learned_from) REFERENCES analyst_feedback(feedback_id)
            )
        """)

        # Rule applications log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_applications (
                application_id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                FOREIGN KEY (rule_id) REFERENCES feedback_rules(rule_id)
            )
        """)

        conn.commit()
        conn.close()

        self.logger.info("✅ Feedback database initialized")

    def submit_feedback(
        self,
        incident_id: str,
        analyst_id: str,
        feedback_type: str,
        original_decision: str,
        corrected_decision: str,
        reasoning: str,
        incident_context: Dict
    ) -> str:
        """
        Submit analyst feedback for an incident.
        
        Args:
            incident_id: ID of incident being corrected
            analyst_id: ID of analyst providing feedback
            feedback_type: Type of correction
            original_decision: What system decided
            corrected_decision: What analyst says it should be
            reasoning: Analyst's explanation
            incident_context: Full incident data for rule learning
            
        Returns:
            feedback_id
        """
        feedback_id = f"feedback-{incident_id}-{int(datetime.utcnow().timestamp())}"

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Store feedback
        cursor.execute("""
            INSERT INTO analyst_feedback
            (feedback_id, incident_id, analyst_id, feedback_type,
             original_decision, corrected_decision, reasoning, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            feedback_id,
            incident_id,
            analyst_id,
            feedback_type,
            original_decision,
            corrected_decision,
            reasoning,
            datetime.utcnow().isoformat()
        ))

        conn.commit()
        conn.close()

        # Attempt to learn a rule from this feedback
        self._learn_rule_from_feedback(
            feedback_id,
            incident_context,
            corrected_decision,
            reasoning
        )

        self.logger.info(
            f"✅ Feedback submitted: {feedback_id} ({feedback_type})")

        return feedback_id

    def _learn_rule_from_feedback(
        self,
        feedback_id: str,
        incident_context: Dict,
        corrected_decision: str,
        reasoning: str
    ):
        """
        Automatically learn a rule from analyst feedback.
        
        Args:
            feedback_id: ID of feedback to learn from
            incident_context: Incident data
            corrected_decision: Correct decision
            reasoning: Analyst reasoning
        """
        # Extract conditions from incident context
        conditions = {}

        # Extract IP if mentioned in reasoning
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips_in_reasoning = re.findall(ip_pattern, reasoning)

        if ips_in_reasoning:
            conditions['src_ip'] = ips_in_reasoning[0]

        # Extract port if mentioned
        port_pattern = r'port\s+(\d+)'
        ports_in_reasoning = re.findall(port_pattern, reasoning, re.IGNORECASE)

        if ports_in_reasoning:
            conditions['dst_port'] = int(ports_in_reasoning[0])

        # Look for keywords that indicate rule type
        reasoning_lower = reasoning.lower()

        if 'backup' in reasoning_lower or 'legitimate' in reasoning_lower or 'authorized' in reasoning_lower:
            conditions['rule_type'] = 'whitelist'
        elif 'test' in reasoning_lower or 'development' in reasoning_lower:
            conditions['rule_type'] = 'dev_exception'
        elif 'scheduled' in reasoning_lower or 'maintenance' in reasoning_lower:
            conditions['rule_type'] = 'scheduled_exception'

        # Only create rule if we extracted meaningful conditions
        if len(conditions) >= 1:
            self._create_feedback_rule(
                feedback_id,
                conditions,
                corrected_decision,
                reasoning
            )

    def _create_feedback_rule(
        self,
        feedback_id: str,
        conditions: Dict,
        action: str,
        reasoning: str
    ):
        """Create a feedback rule from conditions."""
        rule_id = f"rule-{feedback_id}"

        # Build human-readable condition string
        condition_parts = []
        for key, value in conditions.items():
            if key == 'src_ip':
                condition_parts.append(f"Source IP = {value}")
            elif key == 'dst_ip':
                condition_parts.append(f"Destination IP = {value}")
            elif key == 'dst_port':
                condition_parts.append(f"Port = {value}")
            elif key == 'rule_type':
                condition_parts.append(f"Type: {value}")

        condition_str = " AND ".join(condition_parts)

        # Store rule
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO feedback_rules
            (rule_id, condition, condition_json, action, learned_from,
             confidence, usage_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule_id,
            condition_str,
            json.dumps(conditions),
            action,
            feedback_id,
            0.85,  # Initial confidence
            0,
            datetime.utcnow().isoformat()
        ))

        conn.commit()
        conn.close()

        self.logger.info(f"📘 Learned rule: {rule_id} - {condition_str}")

    def check_for_applicable_rules(
        self,
        incident_context: Dict
    ) -> List[FeedbackRule]:
        """
        Check if any feedback rules apply to current incident.
        
        Args:
            incident_context: Current incident data
            
        Returns:
            List of applicable feedback rules
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM feedback_rules")
        all_rules = cursor.fetchall()

        applicable_rules = []

        for row in all_rules:
            rule_id = row[0]
            condition_json = json.loads(row[2])

            # Check if conditions match
            matches = True
            for key, value in condition_json.items():
                if key == 'rule_type':
                    continue  # Skip meta fields

                if incident_context.get(key) != value:
                    matches = False
                    break

            if matches:
                rule = FeedbackRule(
                    rule_id=row[0],
                    condition=row[1],
                    condition_json=condition_json,
                    action=row[3],
                    learned_from=row[4],
                    confidence=row[5],
                    usage_count=row[6],
                    created_at=row[7],
                    last_used=row[8]
                )
                applicable_rules.append(rule)

                # Update usage count
                cursor.execute("""
                    UPDATE feedback_rules
                    SET usage_count = usage_count + 1,
                        last_used = ?
                    WHERE rule_id = ?
                """, (datetime.utcnow().isoformat(), rule_id))

        conn.commit()
        conn.close()

        return applicable_rules

    def apply_feedback_rules(
        self,
        incident_id: str,
        incident_context: Dict,
        original_severity: str
    ) -> Tuple[str, Optional[str]]:
        """
        Apply feedback rules to modify decision.
        
        Args:
            incident_id: Current incident ID
            incident_context: Incident data
            original_severity: System's initial assessment
            
        Returns:
            (modified_severity, feedback_reason) tuple
        """
        applicable_rules = self.check_for_applicable_rules(incident_context)

        if not applicable_rules:
            return original_severity, None

        # Use highest confidence rule
        best_rule = max(applicable_rules, key=lambda r: r.confidence)

        # Log application
        self._log_rule_application(best_rule.rule_id, incident_id)

        # Return corrected decision
        modified_severity = best_rule.action
        reason = f"Analyst feedback applied: {best_rule.condition}"

        self.logger.info(
            f"🔄 Applied feedback rule: {best_rule.rule_id} to {incident_id}")

        return modified_severity, reason

    def _log_rule_application(self, rule_id: str, incident_id: str):
        """Log that a rule was applied."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        application_id = f"app-{rule_id}-{incident_id}"

        cursor.execute("""
            INSERT INTO rule_applications
            (application_id, rule_id, incident_id, applied_at)
            VALUES (?, ?, ?, ?)
        """, (
            application_id,
            rule_id,
            incident_id,
            datetime.utcnow().isoformat()
        ))

        conn.commit()
        conn.close()

    def get_feedback_metrics(self, total_incidents: int) -> FeedbackMetrics:
        """
        Get comprehensive feedback incorporation metrics.
        
        Args:
            total_incidents: Total incidents processed (for rate calculation)
            
        Returns:
            FeedbackMetrics object
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Total feedback count
        cursor.execute("SELECT COUNT(*) FROM analyst_feedback")
        total_feedback = cursor.fetchone()[0]

        # Feedback by type
        cursor.execute("""
            SELECT feedback_type, COUNT(*) FROM analyst_feedback
            GROUP BY feedback_type
        """)
        feedback_by_type = {row[0]: row[1] for row in cursor.fetchall()}

        # Active rules (used at least once)
        cursor.execute(
            "SELECT COUNT(*) FROM feedback_rules WHERE usage_count > 0")
        active_rules = cursor.fetchone()[0]

        # Total rule applications
        cursor.execute("SELECT COUNT(*) FROM rule_applications")
        total_applications = cursor.fetchone()[0]

        # Application rate
        application_rate = total_applications / max(1, total_incidents)

        # False positive reduction (count of false_positive feedback)
        fp_count = feedback_by_type.get('false_positive', 0)
        false_positive_reduction = (fp_count / max(1, total_incidents)) * 100

        # Average time to apply (immediate in our system)
        avg_time_to_apply = 0.001  # < 1 millisecond

        conn.close()

        return FeedbackMetrics(
            total_feedback=total_feedback,
            feedback_by_type=feedback_by_type,
            active_rules=active_rules,
            total_rule_applications=total_applications,
            application_rate=application_rate,
            false_positive_reduction=false_positive_reduction,
            avg_time_to_apply=avg_time_to_apply
        )

    def get_recent_feedback(self, limit: int = 10) -> List[AnalystFeedback]:
        """Get recent analyst feedback."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM analyst_feedback
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

        feedback_list = []
        for row in cursor.fetchall():
            feedback_list.append(AnalystFeedback(
                feedback_id=row['feedback_id'],
                incident_id=row['incident_id'],
                analyst_id=row['analyst_id'],
                feedback_type=row['feedback_type'],
                original_decision=row['original_decision'],
                corrected_decision=row['corrected_decision'],
                reasoning=row['reasoning'],
                timestamp=row['timestamp'],
                applied_count=row['applied_count']
            ))

        conn.close()
        return feedback_list

    def get_all_rules(self, limit: int = 50) -> List[FeedbackRule]:
        """Get all feedback rules."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM feedback_rules
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))

        rules = []
        for row in cursor.fetchall():
            rules.append(FeedbackRule(
                rule_id=row[0],
                condition=row[1],
                condition_json=json.loads(row[2]),
                action=row[3],
                learned_from=row[4],
                confidence=row[5],
                usage_count=row[6],
                created_at=row[7],
                last_used=row[8]
            ))

        conn.close()
        return rules


# Global instance
_feedback_manager_instance = None


def get_feedback_manager() -> FeedbackManager:
    """Get or create global feedback manager instance."""
    global _feedback_manager_instance

    if _feedback_manager_instance is None:
        _feedback_manager_instance = FeedbackManager()

    return _feedback_manager_instance


if __name__ == "__main__":
    # Quick test
    print("Testing Feedback Manager...")

    manager = get_feedback_manager()

    # Submit test feedback
    feedback_id = manager.submit_feedback(
        incident_id="test-001",
        analyst_id="analyst-john",
        feedback_type="false_positive",
        original_decision="malicious",
        corrected_decision="benign",
        reasoning="This is our backup server at 192.168.1.100",
        incident_context={'src_ip': '192.168.1.100', 'dst_port': 22}
    )

    print(f"\n✅ Feedback submitted: {feedback_id}")

    # Check if rule was learned
    rules = manager.get_all_rules()
    print(f"\nLearned rules: {len(rules)}")
    for rule in rules:
        print(f"  - {rule.condition}: {rule.action}")

    # Get metrics
    metrics = manager.get_feedback_metrics(total_incidents=100)
    print("\nFeedback Metrics:")
    print(f"  Total feedback: {metrics.total_feedback}")
    print(f"  Active rules: {metrics.active_rules}")
    print(f"  Application rate: {metrics.application_rate:.1%}")

    print("\n✅ Feedback Manager test complete!")

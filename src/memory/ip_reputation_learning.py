"""
IP Reputation Learning Enhancement - Self-Learning Implementation (Principle #1)

Extends the existing memory system with advanced IP reputation learning:
- Automatic whitelist/blacklist generation
- Response escalation based on learned reputation
- Behavioral pattern recognition

This component integrates with memory_manager.py to enhance self-learning.

Location: src/memory/ip_reputation_learning.py
Author: Abhinav
Date: November 2025
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ReputationRule:
    """Learned rule about IP behavior."""
    rule_id: str
    ip_address: str
    rule_type: str  # 'whitelist', 'blacklist', 'escalate', 'monitor'
    reason: str
    confidence: float
    created_at: str
    usage_count: int
    last_used: Optional[str] = None


class IPReputationLearning:
    """
    Advanced IP reputation learning system.
    
    Learns from IP behavior patterns and automatically creates rules
    for faster, more accurate threat response.
    """

    def __init__(self, memory_manager):
        """
        Initialize IP reputation learning.
        
        Args:
            memory_manager: Instance of MemoryManager
        """
        self.memory = memory_manager
        self.logger = logging.getLogger(__name__)

        # Learning thresholds
        self.whitelist_threshold = 20  # 20 benign incidents → whitelist
        self.blacklist_threshold = 3   # 3 critical incidents → blacklist
        self.escalation_threshold = 0.8  # Threat score > 0.8 → auto-escalate

        # Initialize learned rules storage
        self._init_rules_storage()

        self.logger.info("✅ IP Reputation Learning initialized")

    def _init_rules_storage(self):
        """Initialize database table for learned rules."""
        conn = self.memory._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learned_reputation_rules (
                rule_id TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                reason TEXT NOT NULL,
                confidence REAL NOT NULL,
                created_at TEXT NOT NULL,
                usage_count INTEGER DEFAULT 0,
                last_used TEXT
            )
        """)

        # Index for fast IP lookup
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rule_ip
            ON learned_reputation_rules(ip_address)
        """)

        conn.commit()
        conn.close()

        self.logger.info("✅ Learned rules storage initialized")

    def analyze_and_learn(self, ip_address: str) -> Optional[ReputationRule]:
        """
        Analyze IP reputation and create learned rule if patterns detected.
        
        Args:
            ip_address: IP to analyze
            
        Returns:
            Newly created rule if learning occurred, None otherwise
        """
        reputation = self.memory.get_ip_reputation(ip_address)

        if not reputation:
            return None

        # Check if we should learn a new rule
        new_rule = None

        # Rule 1: Whitelist known-good IPs
        if (reputation.incident_count >= self.whitelist_threshold and
            reputation.benign_count / max(1, reputation.incident_count) > 0.95 and
                reputation.threat_score < 0.1):

            new_rule = self._create_rule(
                ip_address,
                'whitelist',
                f"Consistent benign behavior over {reputation.incident_count} incidents",
                confidence=0.95
            )
            self.logger.info(
                f"📘 Learned: {ip_address} whitelisted (95% benign)")

        # Rule 2: Blacklist persistent attackers
        elif (reputation.critical_severity_count >= self.blacklist_threshold or
              reputation.threat_score > 0.9):

            new_rule = self._create_rule(
                ip_address,
                'blacklist',
                f"Persistent attacker: {reputation.critical_severity_count} critical incidents, threat score {reputation.threat_score:.2f}",
                confidence=0.90
            )
            self.logger.warning(
                f"🚫 Learned: {ip_address} blacklisted (persistent attacker)")

        # Rule 3: Auto-escalate high-threat IPs
        elif (reputation.threat_score > self.escalation_threshold and
              reputation.incident_count >= 5):

            new_rule = self._create_rule(
                ip_address,
                'escalate',
                f"High threat score {reputation.threat_score:.2f} over {reputation.incident_count} incidents",
                confidence=0.85
            )
            self.logger.info(
                f"⚡ Learned: {ip_address} auto-escalate (high threat)")

        # Rule 4: Monitor suspicious but not confirmed IPs
        elif (reputation.threat_score > 0.5 and
              reputation.incident_count >= 3 and
              reputation.incident_count < 10):

            new_rule = self._create_rule(
                ip_address,
                'monitor',
                f"Moderate threat score {reputation.threat_score:.2f}, monitoring required",
                confidence=0.70
            )
            self.logger.info(
                f"👁️ Learned: {ip_address} monitoring (suspicious)")

        return new_rule

    def _create_rule(
        self,
        ip_address: str,
        rule_type: str,
        reason: str,
        confidence: float
    ) -> ReputationRule:
        """Create and store a new learned rule."""
        rule_id = f"rule-{ip_address.replace('.', '-')}-{rule_type}"

        # Check if rule already exists
        conn = self.memory._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT rule_id FROM learned_reputation_rules
            WHERE ip_address = ? AND rule_type = ?
        """, (ip_address, rule_type))

        existing = cursor.fetchone()

        if existing:
            # Rule already exists, just return it
            cursor.execute("""
                SELECT * FROM learned_reputation_rules WHERE rule_id = ?
            """, (existing[0],))
            row = cursor.fetchone()
            conn.close()

            return ReputationRule(
                rule_id=row[0],
                ip_address=row[1],
                rule_type=row[2],
                reason=row[3],
                confidence=row[4],
                created_at=row[5],
                usage_count=row[6],
                last_used=row[7]
            )

        # Create new rule
        rule = ReputationRule(
            rule_id=rule_id,
            ip_address=ip_address,
            rule_type=rule_type,
            reason=reason,
            confidence=confidence,
            created_at=datetime.utcnow().isoformat(),
            usage_count=0
        )

        cursor.execute("""
            INSERT INTO learned_reputation_rules
            (rule_id, ip_address, rule_type, reason, confidence, created_at, usage_count)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            rule.rule_id,
            rule.ip_address,
            rule.rule_type,
            rule.reason,
            rule.confidence,
            rule.created_at,
            rule.usage_count
        ))

        conn.commit()
        conn.close()

        return rule

    def get_learned_rule(self, ip_address: str) -> Optional[ReputationRule]:
        """
        Get learned rule for an IP address.
        
        Args:
            ip_address: IP to query
            
        Returns:
            Most recent/relevant learned rule, or None
        """
        conn = self.memory._get_connection()
        cursor = conn.cursor()

        # Get most confident rule for this IP
        cursor.execute("""
            SELECT * FROM learned_reputation_rules
            WHERE ip_address = ?
            ORDER BY confidence DESC, created_at DESC
            LIMIT 1
        """, (ip_address,))

        row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        # Update usage count
        cursor.execute("""
            UPDATE learned_reputation_rules
            SET usage_count = usage_count + 1,
                last_used = ?
            WHERE rule_id = ?
        """, (datetime.utcnow().isoformat(), row[0]))

        conn.commit()
        conn.close()

        return ReputationRule(
            rule_id=row[0],
            ip_address=row[1],
            rule_type=row[2],
            reason=row[3],
            confidence=row[4],
            created_at=row[5],
            usage_count=row[6] + 1,  # Incremented
            last_used=datetime.utcnow().isoformat()
        )

    def apply_learned_rules(
        self,
        ip_address: str,
        base_severity: str
    ) -> Tuple[str, Optional[str]]:
        """
        Apply learned rules to modify threat assessment.
        
        Args:
            ip_address: IP being analyzed
            base_severity: Initial severity assessment
            
        Returns:
            (modified_severity, rule_reason) tuple
        """
        rule = self.get_learned_rule(ip_address)

        if not rule:
            return base_severity, None

        # Apply rule logic
        if rule.rule_type == 'whitelist':
            return 'low', f"Whitelisted: {rule.reason}"

        elif rule.rule_type == 'blacklist':
            return 'critical', f"Blacklisted: {rule.reason}"

        elif rule.rule_type == 'escalate':
            # Escalate severity by one level
            severity_map = {
                'low': 'medium',
                'medium': 'high',
                'high': 'critical',
                'critical': 'critical'
            }
            escalated = severity_map.get(base_severity, 'high')
            return escalated, f"Auto-escalated: {rule.reason}"

        elif rule.rule_type == 'monitor':
            # Don't change severity but add monitoring flag
            return base_severity, f"Monitoring: {rule.reason}"

        return base_severity, None

    def get_learning_statistics(self) -> Dict:
        """Get statistics about learned rules."""
        conn = self.memory._get_connection()
        cursor = conn.cursor()

        # Count rules by type
        cursor.execute("""
            SELECT rule_type, COUNT(*) as count
            FROM learned_reputation_rules
            GROUP BY rule_type
        """)

        rule_counts = {row[0]: row[1] for row in cursor.fetchall()}

        # Total rules
        cursor.execute("SELECT COUNT(*) FROM learned_reputation_rules")
        total_rules = cursor.fetchone()[0]

        # Total rule applications
        cursor.execute("SELECT SUM(usage_count) FROM learned_reputation_rules")
        total_applications = cursor.fetchone()[0] or 0

        # Most used rules
        cursor.execute("""
            SELECT ip_address, rule_type, usage_count, reason
            FROM learned_reputation_rules
            ORDER BY usage_count DESC
            LIMIT 5
        """)

        top_rules = [
            {
                'ip': row[0],
                'type': row[1],
                'usage': row[2],
                'reason': row[3]
            }
            for row in cursor.fetchall()
        ]

        conn.close()

        return {
            'total_rules': total_rules,
            'rule_counts': rule_counts,
            'total_applications': total_applications,
            'application_rate': total_applications / max(1, self.memory.get_statistics().total_incidents),
            'top_rules': top_rules
        }

    def get_all_learned_rules(self, limit: int = 50) -> List[ReputationRule]:
        """Get all learned rules."""
        conn = self.memory._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM learned_reputation_rules
            ORDER BY created_at DESC
            LIMIT ?
        """, (limit,))

        rules = []
        for row in cursor.fetchall():
            rules.append(ReputationRule(
                rule_id=row[0],
                ip_address=row[1],
                rule_type=row[2],
                reason=row[3],
                confidence=row[4],
                created_at=row[5],
                usage_count=row[6],
                last_used=row[7]
            ))

        conn.close()
        return rules


if __name__ == "__main__":
    # Quick test
    print("Testing IP Reputation Learning...")

    from src.memory import get_memory_manager

    memory = get_memory_manager()
    learning = IPReputationLearning(memory)

    # Test with a sample IP
    test_ip = "10.0.0.99"
    rule = learning.analyze_and_learn(test_ip)

    if rule:
        print(f"\n✅ Learned rule for {test_ip}:")
        print(f"   Type: {rule.rule_type}")
        print(f"   Reason: {rule.reason}")
        print(f"   Confidence: {rule.confidence:.2f}")
    else:
        print(f"\n⚠️  No rule learned yet for {test_ip}")

    # Get statistics
    stats = learning.get_learning_statistics()
    print("\nLearning Statistics:")
    print(f"  Total rules: {stats['total_rules']}")
    print(f"  Total applications: {stats['total_applications']}")
    print(f"  Application rate: {stats['application_rate']:.1%}")

    print("\n✅ IP Reputation Learning test complete!")

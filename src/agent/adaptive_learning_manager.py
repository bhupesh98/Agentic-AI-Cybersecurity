"""
Adaptive Learning Manager - Self-Learning Implementation (Principle #1)

Implements autonomous threshold adjustment for routing decisions.
The system learns optimal thresholds based on performance feedback
WITHOUT retraining ML models.

Key Capabilities:
- Adaptive routing threshold adjustment
- Performance-based learning
- Automatic threshold optimization
- Learning history tracking

Location: src/agent/adaptive_learning_manager.py
Author: Abhinav
Date: November 2025
"""

import sqlite3
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class ThresholdConfig:
    """Configuration for a single routing threshold."""
    threshold_name: str
    current_value: float
    initial_value: float
    min_value: float
    max_value: float
    adjustment_step: float
    last_updated: str
    total_adjustments: int
    performance_history: List[Dict]  # List of {value, performance, timestamp}

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class LearningMetrics:
    """Metrics tracking self-learning performance."""
    total_adjustments: int
    thresholds_learned: int
    average_improvement: float
    best_threshold_value: float
    learning_velocity: float  # Adjustments per 100 incidents
    performance_gain: float  # Improvement from initial baseline


class AdaptiveLearningManager:
    """
    Manages adaptive learning for routing thresholds.
    
    This is the core of Principle #1 (Self-Learning) implementation.
    """

    def __init__(self, db_path: str = "data/learning/adaptive_thresholds.db"):
        """
        Initialize adaptive learning manager.
        
        Args:
            db_path: Path to learning database
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

        # Initialize database
        self._init_database()

        # Load or create default thresholds
        self._init_thresholds()

        # Performance tracking
        self.decisions_since_update = 0
        self.update_frequency = 50  # Adjust after every 50 decisions

        self.logger.info("✅ Adaptive Learning Manager initialized")

    def _init_database(self):
        """Initialize SQLite database for learning storage."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Thresholds table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS thresholds (
                threshold_name TEXT PRIMARY KEY,
                current_value REAL NOT NULL,
                initial_value REAL NOT NULL,
                min_value REAL NOT NULL,
                max_value REAL NOT NULL,
                adjustment_step REAL NOT NULL,
                last_updated TEXT NOT NULL,
                total_adjustments INTEGER DEFAULT 0,
                performance_history TEXT  -- JSON array
            )
        """)

        # Learning events table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS learning_events (
                event_id TEXT PRIMARY KEY,
                threshold_name TEXT NOT NULL,
                old_value REAL NOT NULL,
                new_value REAL NOT NULL,
                reason TEXT NOT NULL,
                performance_before REAL,
                performance_after REAL,
                timestamp TEXT NOT NULL
            )
        """)

        # Performance metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS performance_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                threshold_name TEXT NOT NULL,
                threshold_value REAL NOT NULL,
                true_positives INTEGER,
                false_positives INTEGER,
                false_negatives INTEGER,
                true_negatives INTEGER,
                precision REAL,
                recall REAL,
                f1_score REAL,
                timestamp TEXT NOT NULL
            )
        """)

        conn.commit()
        conn.close()

        self.logger.info("✅ Learning database initialized")

    def _init_thresholds(self):
        """Initialize default thresholds if they don't exist."""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Check if thresholds exist
        cursor.execute("SELECT COUNT(*) FROM thresholds")
        count = cursor.fetchone()[0]

        if count == 0:
            # Create default thresholds
            default_thresholds = [
                {
                    'threshold_name': 'ml_to_llm_confidence',
                    'current_value': 0.85,
                    'initial_value': 0.85,
                    'min_value': 0.70,
                    'max_value': 0.95,
                    'adjustment_step': 0.02,
                    'last_updated': datetime.utcnow().isoformat(),
                    'total_adjustments': 0,
                    'performance_history': '[]'
                },
                {
                    'threshold_name': 'context_suspicion_trigger',
                    'current_value': 0.60,
                    'initial_value': 0.60,
                    'min_value': 0.40,
                    'max_value': 0.80,
                    'adjustment_step': 0.05,
                    'last_updated': datetime.utcnow().isoformat(),
                    'total_adjustments': 0,
                    'performance_history': '[]'
                },
                {
                    'threshold_name': 'model_agreement_required',
                    'current_value': 0.67,  # 2 out of 3 models
                    'initial_value': 0.67,
                    'min_value': 0.50,
                    'max_value': 1.00,
                    'adjustment_step': 0.17,  # Jump by 1 model agreement
                    'last_updated': datetime.utcnow().isoformat(),
                    'total_adjustments': 0,
                    'performance_history': '[]'
                }
            ]

            for threshold in default_thresholds:
                cursor.execute("""
                    INSERT INTO thresholds VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    threshold['threshold_name'],
                    threshold['current_value'],
                    threshold['initial_value'],
                    threshold['min_value'],
                    threshold['max_value'],
                    threshold['adjustment_step'],
                    threshold['last_updated'],
                    threshold['total_adjustments'],
                    threshold['performance_history']
                ))

            conn.commit()
            self.logger.info(
                f"✅ Initialized {len(default_thresholds)} default thresholds")

        conn.close()

    def get_threshold(self, threshold_name: str) -> float:
        """
        Get current threshold value.
        
        Args:
            threshold_name: Name of threshold to retrieve
            
        Returns:
            Current threshold value
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute(
            "SELECT current_value FROM thresholds WHERE threshold_name = ?",
            (threshold_name,)
        )
        result = cursor.fetchone()
        conn.close()

        if result:
            return result[0]
        else:
            self.logger.warning(
                f"Threshold '{threshold_name}' not found, returning default 0.85")
            return 0.85

    def record_decision_outcome(
        self,
        threshold_name: str,
        ml_confidence: float,
        context_score: float,
        # 'true_positive', 'false_positive', 'true_negative', 'false_negative'
        actual_outcome: str,
        llm_was_used: bool
    ):
        """
        Record outcome of a routing decision for learning.
        
        Args:
            threshold_name: Which threshold was used
            ml_confidence: ML model confidence
            context_score: Context suspicion score
            actual_outcome: Ground truth outcome
            llm_was_used: Whether LLM analysis was triggered
        """
        self.decisions_since_update += 1

        # Store outcome for analysis
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Check if we should analyze and potentially adjust
        if self.decisions_since_update >= self.update_frequency:
            self._analyze_and_adjust(threshold_name, cursor)
            self.decisions_since_update = 0

        conn.close()

    def _analyze_and_adjust(self, threshold_name: str, cursor: sqlite3.Cursor):
        """
        Analyze recent performance and adjust threshold if beneficial.
        
        Args:
            threshold_name: Threshold to analyze
            cursor: Database cursor
        """
        # Get current threshold config
        cursor.execute(
            "SELECT * FROM thresholds WHERE threshold_name = ?",
            (threshold_name,)
        )
        row = cursor.fetchone()

        if not row:
            return

        current_value = row[1]
        min_value = row[3]
        max_value = row[4]
        adjustment_step = row[5]

        # Get recent performance snapshots
        cursor.execute("""
            SELECT precision, recall, f1_score, threshold_value
            FROM performance_snapshots
            WHERE threshold_name = ?
            ORDER BY timestamp DESC
            LIMIT 5
        """, (threshold_name,))

        snapshots = cursor.fetchall()

        if len(snapshots) < 2:
            # Not enough data to make decision
            return

        # Calculate average recent performance
        recent_avg_f1 = sum(s[2] for s in snapshots[:3]) / \
            3 if len(snapshots) >= 3 else snapshots[0][2]

        # Simple learning rule: if F1 is declining, try adjusting
        if len(snapshots) >= 3:
            # Current - 2 iterations ago
            trend = snapshots[0][2] - snapshots[2][2]

            if trend < -0.02:  # Performance declining
                # Try opposite direction
                new_value = current_value + adjustment_step
                if new_value <= max_value:
                    self._update_threshold(
                        cursor,
                        threshold_name,
                        current_value,
                        new_value,
                        "Performance declining, increasing threshold"
                    )
                    self.logger.info(
                        f"📈 Self-Learning: Adjusted '{threshold_name}' from {current_value:.3f} to {new_value:.3f}")

            elif trend > 0.02:  # Performance improving
                # Continue in same direction (small nudge)
                # Compare to initial
                direction = 1 if current_value > row[2] else -1
                new_value = current_value + (adjustment_step * direction * 0.5)

                if min_value <= new_value <= max_value:
                    self._update_threshold(
                        cursor,
                        threshold_name,
                        current_value,
                        new_value,
                        "Performance improving, continuing adjustment"
                    )
                    self.logger.info(
                        f"📈 Self-Learning: Fine-tuned '{threshold_name}' from {current_value:.3f} to {new_value:.3f}")

    def _update_threshold(
        self,
        cursor: sqlite3.Cursor,
        threshold_name: str,
        old_value: float,
        new_value: float,
        reason: str
    ):
        """Update threshold value and record learning event."""
        # Update threshold
        cursor.execute("""
            UPDATE thresholds
            SET current_value = ?,
                last_updated = ?,
                total_adjustments = total_adjustments + 1
            WHERE threshold_name = ?
        """, (new_value, datetime.utcnow().isoformat(), threshold_name))

        # Record learning event
        event_id = f"learn-{threshold_name}-{int(datetime.utcnow().timestamp())}"
        cursor.execute("""
            INSERT INTO learning_events
            (event_id, threshold_name, old_value, new_value, reason, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            event_id,
            threshold_name,
            old_value,
            new_value,
            reason,
            datetime.utcnow().isoformat()
        ))

        cursor.connection.commit()

    def record_performance_snapshot(
        self,
        threshold_name: str,
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        true_negatives: int
    ):
        """
        Record performance snapshot for learning analysis.
        
        Args:
            threshold_name: Which threshold this performance relates to
            true_positives: Count of TP
            false_positives: Count of FP
            false_negatives: Count of FN
            true_negatives: Count of TN
        """
        # Calculate metrics
        precision = true_positives / max(1, true_positives + false_positives)
        recall = true_positives / max(1, true_positives + false_negatives)
        f1_score = 2 * (precision * recall) / max(0.001, precision + recall)

        # Get current threshold value
        threshold_value = self.get_threshold(threshold_name)

        # Store snapshot
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        snapshot_id = f"snap-{threshold_name}-{int(datetime.utcnow().timestamp())}"

        cursor.execute("""
            INSERT INTO performance_snapshots
            (snapshot_id, threshold_name, threshold_value, true_positives,
             false_positives, false_negatives, true_negatives, precision,
             recall, f1_score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot_id,
            threshold_name,
            threshold_value,
            true_positives,
            false_positives,
            false_negatives,
            true_negatives,
            precision,
            recall,
            f1_score,
            datetime.utcnow().isoformat()
        ))

        conn.commit()
        conn.close()

    def get_learning_metrics(self) -> LearningMetrics:
        """
        Get comprehensive learning metrics.
        
        Returns:
            LearningMetrics object with current learning statistics
        """
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Total adjustments across all thresholds
        cursor.execute("SELECT SUM(total_adjustments) FROM thresholds")
        total_adjustments = cursor.fetchone()[0] or 0

        # Number of thresholds that have been adjusted
        cursor.execute(
            "SELECT COUNT(*) FROM thresholds WHERE total_adjustments > 0")
        thresholds_learned = cursor.fetchone()[0]

        # Calculate average improvement
        cursor.execute("""
            SELECT t.threshold_name, t.initial_value, t.current_value,
                   p1.f1_score as initial_f1,
                   p2.f1_score as current_f1
            FROM thresholds t
            LEFT JOIN (
                SELECT threshold_name, f1_score
                FROM performance_snapshots
                WHERE timestamp = (
                    SELECT MIN(timestamp) FROM performance_snapshots ps2
                    WHERE ps2.threshold_name = performance_snapshots.threshold_name
                )
            ) p1 ON t.threshold_name = p1.threshold_name
            LEFT JOIN (
                SELECT threshold_name, f1_score
                FROM performance_snapshots
                WHERE timestamp = (
                    SELECT MAX(timestamp) FROM performance_snapshots ps2
                    WHERE ps2.threshold_name = performance_snapshots.threshold_name
                )
            ) p2 ON t.threshold_name = p2.threshold_name
        """)

        improvements = []
        best_threshold = 0.85

        for row in cursor.fetchall():
            if row[3] and row[4]:  # If we have both initial and current F1
                improvement = row[4] - row[3]
                improvements.append(improvement)
                if row[4] > 0.9:  # Good performance
                    best_threshold = row[2]  # current_value

        avg_improvement = sum(improvements) / \
            len(improvements) if improvements else 0.0

        # Learning velocity (adjustments per 100 incidents)
        cursor.execute("SELECT COUNT(*) FROM performance_snapshots")
        total_snapshots = cursor.fetchone()[0]
        learning_velocity = (total_adjustments / max(1, total_snapshots)) * 100

        # Performance gain
        performance_gain = avg_improvement * 100  # Convert to percentage

        conn.close()

        return LearningMetrics(
            total_adjustments=total_adjustments,
            thresholds_learned=thresholds_learned,
            average_improvement=avg_improvement,
            best_threshold_value=best_threshold,
            learning_velocity=learning_velocity,
            performance_gain=performance_gain
        )

    def get_learning_history(self, limit: int = 10) -> List[Dict]:
        """
        Get recent learning events.
        
        Args:
            limit: Number of events to return
            
        Returns:
            List of learning event dictionaries
        """
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM learning_events
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

        events = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return events


# Global instance
_learning_manager_instance = None


def get_learning_manager() -> AdaptiveLearningManager:
    """Get or create global learning manager instance."""
    global _learning_manager_instance

    if _learning_manager_instance is None:
        _learning_manager_instance = AdaptiveLearningManager()

    return _learning_manager_instance


if __name__ == "__main__":
    # Quick test
    print("Testing Adaptive Learning Manager...")

    manager = get_learning_manager()

    # Get threshold
    threshold = manager.get_threshold('ml_to_llm_confidence')
    print(f"\nCurrent ML-to-LLM threshold: {threshold:.3f}")

    # Simulate some learning
    manager.record_performance_snapshot(
        'ml_to_llm_confidence',
        true_positives=45,
        false_positives=3,
        false_negatives=2,
        true_negatives=50
    )

    # Get metrics
    metrics = manager.get_learning_metrics()
    print(f"\nLearning Metrics:")
    print(f"  Total adjustments: {metrics.total_adjustments}")
    print(f"  Thresholds learned: {metrics.thresholds_learned}")
    print(f"  Average improvement: {metrics.average_improvement:.3f}")

    print("\n✅ Adaptive Learning Manager test complete!")

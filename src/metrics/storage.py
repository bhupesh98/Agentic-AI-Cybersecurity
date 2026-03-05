"""
Metrics Storage Manager.

Handles persistent storage of Agentic AI metrics to:
- SQLite database (structured storage)
- JSON files (dashboard consumption)
- CSV files (analysis/plotting)

Completely separate from incident database to avoid coupling.

Author: Abhinav
Date: November 2025
"""

import sqlite3
import json
import csv
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import logging

from src.metrics.models import (
    AgenticAIMetricsSummary,
    SelfLearningMetrics,
    ContextualAwarenessMetrics,
    GoalDirectedMetrics,
    ToolUtilizationMetrics,
    PlanningReasoningMetrics,
    MemoryManagementMetrics,
    FeedbackIncorporationMetrics
)


class MetricsStorageManager:
    """
    Manages persistent storage of Agentic AI metrics.
    
    Storage locations:
    - SQLite: data/metrics/metrics.db
    - JSON exports: data/metrics/exports/
    - CSV exports: data/metrics/exports/
    """

    def __init__(
        self,
        db_path: str = "data/metrics/metrics.db",
        export_dir: str = "data/metrics/exports"
    ):
        """
        Initialize metrics storage manager.
        
        Args:
            db_path: Path to SQLite metrics database
            export_dir: Directory for JSON/CSV exports
        """
        self.db_path = db_path
        self.export_dir = export_dir

        # Setup logging
        self.logger = logging.getLogger(__name__)

        # Ensure directories exist
        self._create_directories()

        # Initialize database
        self._initialize_database()

        self.logger.info(f"✅ Metrics Storage Manager initialized")
        self.logger.info(f"   Database: {self.db_path}")
        self.logger.info(f"   Exports: {self.export_dir}")

    def _create_directories(self):
        """Create necessary directories for storage."""
        # Database directory
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            Path(db_dir).mkdir(parents=True, exist_ok=True)

        # Export directory
        Path(self.export_dir).mkdir(parents=True, exist_ok=True)

        self.logger.info("✅ Storage directories created")

    def _initialize_database(self):
        """Create database tables if they don't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Main metrics summary table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics_summary (
                    session_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    overall_agentic_score REAL,
                    
                    -- Quick status indicators
                    principles_active INTEGER,
                    principles_partial INTEGER,
                    principles_baseline INTEGER,
                    
                    -- Metadata
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Self-Learning metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS self_learning_metrics (
                    session_id TEXT PRIMARY KEY,
                    
                    -- Adaptive threshold learning
                    threshold_adjustments INTEGER DEFAULT 0,
                    thresholds_learned INTEGER DEFAULT 0,
                    avg_threshold_improvement REAL DEFAULT 0.0,
                    learning_velocity REAL DEFAULT 0.0,
                    
                    -- IP reputation learning
                    learned_reputation_rules INTEGER DEFAULT 0,
                    whitelist_rules INTEGER DEFAULT 0,
                    blacklist_rules INTEGER DEFAULT 0,
                    escalation_rules INTEGER DEFAULT 0,
                    total_rule_applications INTEGER DEFAULT 0,
                    
                    -- Performance tracking
                    baseline_performance REAL DEFAULT 0.872,
                    current_performance REAL DEFAULT 0.0,
                    performance_gain_percent REAL DEFAULT 0.0,
                    
                    -- Learning efficiency
                    incidents_processed INTEGER DEFAULT 0,
                    adaptations_per_100_incidents REAL DEFAULT 0.0,
                    
                    -- Metadata
                    status TEXT DEFAULT 'active',
                    last_updated TEXT,
                    notes TEXT DEFAULT 'Adaptive threshold + IP reputation learning active',
                    
                    FOREIGN KEY (session_id) REFERENCES metrics_summary(session_id)
                )
            """)

            # Contextual Awareness metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS contextual_awareness_metrics (
                    session_id TEXT PRIMARY KEY,
                    total_decisions INTEGER,
                    decisions_with_context INTEGER,
                    context_incorporation_rate REAL,
                    context_flags_generated INTEGER,
                    unique_context_types INTEGER,
                    temporal_context_used INTEGER,
                    asset_context_used INTEGER,
                    user_context_used INTEGER,
                    network_context_used INTEGER,
                    context_decision_accuracy REAL,
                    avg_suspicion_score REAL,
                    fp_reduction_rate REAL,
                    status TEXT,
                    last_updated TEXT,
                    target REAL,
                    FOREIGN KEY (session_id) REFERENCES metrics_summary(session_id)
                )
            """)

            # Goal-Directed Behavior metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS goal_directed_metrics (
                    session_id TEXT PRIMARY KEY,
                    total_sessions INTEGER,
                    successful_sessions INTEGER,
                    goal_completion_rate REAL,
                    ml_detection_completed INTEGER,
                    llm_analysis_completed INTEGER,
                    memory_lookup_completed INTEGER,
                    response_plan_completed INTEGER,
                    storage_completed INTEGER,
                    policy_adherence_score REAL,
                    resource_efficiency REAL,
                    status TEXT,
                    last_updated TEXT,
                    target REAL,
                    FOREIGN KEY (session_id) REFERENCES metrics_summary(session_id)
                )
            """)

            # Tool Utilization metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_utilization_metrics (
                    session_id TEXT PRIMARY KEY,
                    tools_available_json TEXT,
                    tool_details_json TEXT,
                    overall_effectiveness REAL,
                    tool_diversity_index REAL,
                    multi_tool_chains INTEGER,
                    single_tool_uses INTEGER,
                    status TEXT,
                    last_updated TEXT,
                    target REAL,
                    FOREIGN KEY (session_id) REFERENCES metrics_summary(session_id)
                )
            """)

            # Planning & Reasoning metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS planning_reasoning_metrics (
                    session_id TEXT PRIMARY KEY,
                    total_decisions INTEGER,
                    decisions_with_reasoning INTEGER,
                    reasoning_completeness REAL,
                    avg_reasoning_length_words REAL,
                    avg_reasoning_steps REAL,
                    plans_generated INTEGER,
                    avg_plan_depth REAL,
                    plan_completion_rate REAL,
                    explanation_completeness REAL,
                    decision_quality_score REAL,
                    avg_decision_confidence REAL,
                    status TEXT,
                    last_updated TEXT,
                    target REAL,
                    FOREIGN KEY (session_id) REFERENCES metrics_summary(session_id)
                )
            """)

            # Memory Management metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS memory_management_metrics (
                    session_id TEXT PRIMARY KEY,
                    total_queries INTEGER,
                    memory_used_count INTEGER,
                    memory_utilization_rate REAL,
                    retrieval_accuracy REAL,
                    unique_ips_tracked INTEGER,
                    repeat_offenders_detected INTEGER,
                    avg_query_time_ms REAL,
                    avg_storage_time_ms REAL,
                    total_incidents_stored INTEGER,
                    cross_incident_correlation_rate REAL,
                    unique_attack_patterns INTEGER,
                    status TEXT,
                    last_updated TEXT,
                    target_utilization REAL,
                    target_accuracy REAL,
                    FOREIGN KEY (session_id) REFERENCES metrics_summary(session_id)
                )
            """)

            # Feedback Incorporation metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feedback_incorporation_metrics (
                    session_id TEXT PRIMARY KEY,
                    
                    -- Feedback collection
                    total_feedback INTEGER DEFAULT 0,
                    false_positive_corrections INTEGER DEFAULT 0,
                    false_negative_corrections INTEGER DEFAULT 0,
                    severity_corrections INTEGER DEFAULT 0,
                    correct_confirmations INTEGER DEFAULT 0,
                    
                    -- Learned rules
                    feedback_rules_created INTEGER DEFAULT 0,
                    active_feedback_rules INTEGER DEFAULT 0,
                    
                    -- Applications
                    total_decisions INTEGER DEFAULT 0,
                    decisions_influenced_by_feedback INTEGER DEFAULT 0,
                    total_rule_applications INTEGER DEFAULT 0,
                    
                    -- Effectiveness
                    false_positive_reduction_count INTEGER DEFAULT 0,
                    false_positive_reduction_percent REAL DEFAULT 0.0,
                    
                    -- Timeliness
                    avg_time_to_apply_ms REAL DEFAULT 1.0,
                    
                    -- Top rules
                    most_used_rule_id TEXT DEFAULT '',
                    most_used_rule_applications INTEGER DEFAULT 0,
                    
                    -- Metadata
                    status TEXT DEFAULT 'active',
                    last_updated TEXT,
                    target REAL DEFAULT 0.50,
                    notes TEXT DEFAULT 'Analyst feedback system active',
                    
                    FOREIGN KEY (session_id) REFERENCES metrics_summary(session_id)
                )
            """)

            conn.commit()
            conn.close()

            self.logger.info("✅ Metrics database initialized with all tables")

        except Exception as e:
            self.logger.error(f"❌ Failed to initialize database: {e}")
            raise

    def save_metrics_summary(self, summary: AgenticAIMetricsSummary) -> bool:
        """
        Save complete metrics summary to database.
        
        Args:
            summary: AgenticAIMetricsSummary object
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Count principle statuses (updated: 6 active, 1 partial, 0 baseline)
            principles_active = sum([
                1 for p in [
                    summary.self_learning,
                    summary.goal_directed,
                    summary.tool_utilization,
                    summary.planning_reasoning,
                    summary.memory_management,
                    summary.feedback_incorporation
                ] if p.status.value == "active"
            ])

            principles_partial = 1 if summary.contextual_awareness.status.value == "partial" else 0
            principles_baseline = 0  # All principles now active or partial

            # Insert summary
            cursor.execute("""
                INSERT OR REPLACE INTO metrics_summary 
                (session_id, timestamp, overall_agentic_score, 
                 principles_active, principles_partial, principles_baseline)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                summary.session_id,
                summary.timestamp,
                summary.calculate_overall_agentic_score(),
                principles_active,
                principles_partial,
                principles_baseline
            ))

            # Save each principle's metrics
            self._save_self_learning(
                cursor, summary.session_id, summary.self_learning)
            self._save_contextual_awareness(
                cursor, summary.session_id, summary.contextual_awareness)
            self._save_goal_directed(
                cursor, summary.session_id, summary.goal_directed)
            self._save_tool_utilization(
                cursor, summary.session_id, summary.tool_utilization)
            self._save_planning_reasoning(
                cursor, summary.session_id, summary.planning_reasoning)
            self._save_memory_management(
                cursor, summary.session_id, summary.memory_management)
            self._save_feedback_incorporation(
                cursor, summary.session_id, summary.feedback_incorporation)

            conn.commit()
            conn.close()

            self.logger.info(
                f"✅ Saved metrics for session: {summary.session_id}")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to save metrics: {e}")
            return False

    def _save_self_learning(self, cursor, session_id: str, metrics: SelfLearningMetrics):
        """Save Self-Learning metrics."""
        data = metrics.to_dict()
        cursor.execute("""
            INSERT OR REPLACE INTO self_learning_metrics
            (session_id, threshold_adjustments, thresholds_learned, avg_threshold_improvement,
             learning_velocity, learned_reputation_rules, whitelist_rules, blacklist_rules,
             escalation_rules, total_rule_applications, baseline_performance,
             current_performance, performance_gain_percent, incidents_processed,
             adaptations_per_100_incidents, status, last_updated, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            data['threshold_adjustments'],
            data['thresholds_learned'],
            data['avg_threshold_improvement'],
            data['learning_velocity'],
            data['learned_reputation_rules'],
            data['whitelist_rules'],
            data['blacklist_rules'],
            data['escalation_rules'],
            data['total_rule_applications'],
            data['baseline_performance'],
            data['current_performance'],
            data['performance_gain_percent'],
            data['incidents_processed'],
            data['adaptations_per_100_incidents'],
            data['status'],
            data['last_updated'],
            data['notes']
        ))

    def _save_contextual_awareness(self, cursor, session_id: str, metrics: ContextualAwarenessMetrics):
        """Save Contextual Awareness metrics."""
        data = metrics.to_dict()
        cursor.execute("""
            INSERT OR REPLACE INTO contextual_awareness_metrics
            (session_id, total_decisions, decisions_with_context, context_incorporation_rate,
             context_flags_generated, unique_context_types, temporal_context_used,
             asset_context_used, user_context_used, network_context_used,
             context_decision_accuracy, avg_suspicion_score, fp_reduction_rate,
             status, last_updated, target)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            data['total_decisions'],
            data['decisions_with_context'],
            data['context_incorporation_rate'],
            data['context_flags_generated'],
            data['unique_context_types'],
            data['temporal_context_used'],
            data['asset_context_used'],
            data['user_context_used'],
            data['network_context_used'],
            data['context_decision_accuracy'],
            data['avg_suspicion_score'],
            data['fp_reduction_rate'],
            data['status'],
            data['last_updated'],
            data['target']
        ))

    def _save_goal_directed(self, cursor, session_id: str, metrics: GoalDirectedMetrics):
        """Save Goal-Directed Behavior metrics."""
        data = metrics.to_dict()
        cursor.execute("""
            INSERT OR REPLACE INTO goal_directed_metrics
            (session_id, total_sessions, successful_sessions, goal_completion_rate,
             ml_detection_completed, llm_analysis_completed, memory_lookup_completed,
             response_plan_completed, storage_completed, policy_adherence_score,
             resource_efficiency, status, last_updated, target)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            data['total_sessions'],
            data['successful_sessions'],
            data['goal_completion_rate'],
            data['ml_detection_completed'],
            data['llm_analysis_completed'],
            data['memory_lookup_completed'],
            data['response_plan_completed'],
            data['storage_completed'],
            data['policy_adherence_score'],
            data['resource_efficiency'],
            data['status'],
            data['last_updated'],
            data['target']
        ))

    def _save_tool_utilization(self, cursor, session_id: str, metrics: ToolUtilizationMetrics):
        """Save Tool Utilization metrics."""
        data = metrics.to_dict()
        cursor.execute("""
            INSERT OR REPLACE INTO tool_utilization_metrics
            (session_id, tools_available_json, tool_details_json, overall_effectiveness,
             tool_diversity_index, multi_tool_chains, single_tool_uses,
             status, last_updated, target)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            json.dumps(data['tools_available']),
            json.dumps(data['tool_details']),
            data['overall_effectiveness'],
            data['tool_diversity_index'],
            data['multi_tool_chains'],
            data['single_tool_uses'],
            data['status'],
            data['last_updated'],
            data['target']
        ))

    def _save_planning_reasoning(self, cursor, session_id: str, metrics: PlanningReasoningMetrics):
        """Save Planning & Reasoning metrics."""
        data = metrics.to_dict()
        cursor.execute("""
            INSERT OR REPLACE INTO planning_reasoning_metrics
            (session_id, total_decisions, decisions_with_reasoning, reasoning_completeness,
             avg_reasoning_length_words, avg_reasoning_steps, plans_generated,
             avg_plan_depth, plan_completion_rate, explanation_completeness,
             decision_quality_score, avg_decision_confidence, status, last_updated, target)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            data['total_decisions'],
            data['decisions_with_reasoning'],
            data['reasoning_completeness'],
            data['avg_reasoning_length_words'],
            data['avg_reasoning_steps'],
            data['plans_generated'],
            data['avg_plan_depth'],
            data['plan_completion_rate'],
            data['explanation_completeness'],
            data['decision_quality_score'],
            data['avg_decision_confidence'],
            data['status'],
            data['last_updated'],
            data['target']
        ))

    def _save_memory_management(self, cursor, session_id: str, metrics: MemoryManagementMetrics):
        """Save Memory Management metrics."""
        data = metrics.to_dict()
        cursor.execute("""
            INSERT OR REPLACE INTO memory_management_metrics
            (session_id, total_queries, memory_used_count, memory_utilization_rate,
             retrieval_accuracy, unique_ips_tracked, repeat_offenders_detected,
             avg_query_time_ms, avg_storage_time_ms, total_incidents_stored,
             cross_incident_correlation_rate, unique_attack_patterns,
             status, last_updated, target_utilization, target_accuracy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            data['total_queries'],
            data['memory_used_count'],
            data['memory_utilization_rate'],
            data['retrieval_accuracy'],
            data['unique_ips_tracked'],
            data['repeat_offenders_detected'],
            data['avg_query_time_ms'],
            data['avg_storage_time_ms'],
            data['total_incidents_stored'],
            data['cross_incident_correlation_rate'],
            data['unique_attack_patterns'],
            data['status'],
            data['last_updated'],
            data['target_utilization'],
            data['target_accuracy']
        ))

    def _save_feedback_incorporation(self, cursor, session_id: str, metrics: FeedbackIncorporationMetrics):
        """Save Feedback Incorporation metrics."""
        data = metrics.to_dict()
        cursor.execute("""
            INSERT OR REPLACE INTO feedback_incorporation_metrics
            (session_id, total_feedback, false_positive_corrections, false_negative_corrections,
             severity_corrections, correct_confirmations, feedback_rules_created,
             active_feedback_rules, total_decisions, decisions_influenced_by_feedback,
             total_rule_applications, false_positive_reduction_count,
             false_positive_reduction_percent, avg_time_to_apply_ms,
             most_used_rule_id, most_used_rule_applications, status, last_updated, target, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            data['total_feedback'],
            data['false_positive_corrections'],
            data['false_negative_corrections'],
            data['severity_corrections'],
            data['correct_confirmations'],
            data['feedback_rules_created'],
            data['active_feedback_rules'],
            data['total_decisions'],
            data['decisions_influenced_by_feedback'],
            data['total_rule_applications'],
            data['false_positive_reduction_count'],
            data['false_positive_reduction_percent'],
            data['avg_time_to_apply_ms'],
            data.get('most_used_rule_id', ''),
            data.get('most_used_rule_applications', 0),
            data['status'],
            data['last_updated'],
            data['target'],
            data['notes']
        ))

    def export_to_json(self, summary: AgenticAIMetricsSummary, filename: Optional[str] = None) -> str:
        """
        Export metrics to JSON file.
        
        Args:
            summary: AgenticAIMetricsSummary object
            filename: Optional custom filename
            
        Returns:
            Path to exported file
        """
        try:
            if filename is None:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                filename = f"metrics_{summary.session_id}_{timestamp}.json"

            filepath = os.path.join(self.export_dir, filename)

            with open(filepath, 'w') as f:
                json.dump(summary.to_dict(), f, indent=2)

            self.logger.info(f"✅ Exported metrics to JSON: {filepath}")
            return filepath

        except Exception as e:
            self.logger.error(f"❌ Failed to export JSON: {e}")
            return ""

    def export_to_csv(self, summary: AgenticAIMetricsSummary, filename: Optional[str] = None) -> str:
        """
        Export metrics to CSV file (flattened structure).
        
        Args:
            summary: AgenticAIMetricsSummary object
            filename: Optional custom filename
            
        Returns:
            Path to exported file
        """
        try:
            if filename is None:
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                filename = f"metrics_{summary.session_id}_{timestamp}.csv"

            filepath = os.path.join(self.export_dir, filename)

            # Flatten nested dictionary
            flat_data = self._flatten_dict(summary.to_dict())

            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Value'])
                for key, value in flat_data.items():
                    writer.writerow([key, value])

            self.logger.info(f"✅ Exported metrics to CSV: {filepath}")
            return filepath

        except Exception as e:
            self.logger.error(f"❌ Failed to export CSV: {e}")
            return ""

    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def get_latest_metrics(self) -> Optional[Dict[str, Any]]:
        """
        Retrieve the most recent metrics summary from database.
        
        Returns:
            Dictionary with latest metrics or None
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT session_id, timestamp, overall_agentic_score,
                       principles_active, principles_partial, principles_baseline
                FROM metrics_summary
                ORDER BY timestamp DESC
                LIMIT 1
            """)

            row = cursor.fetchone()
            conn.close()

            if row:
                return {
                    'session_id': row[0],
                    'timestamp': row[1],
                    'overall_agentic_score': row[2],
                    'principles_active': row[3],
                    'principles_partial': row[4],
                    'principles_baseline': row[5]
                }

            return None

        except Exception as e:
            self.logger.error(f"❌ Failed to retrieve latest metrics: {e}")
            return None

    def get_all_sessions(self) -> List[str]:
        """
        Get list of all session IDs in database.
        
        Returns:
            List of session IDs
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT session_id FROM metrics_summary ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            conn.close()

            return [row[0] for row in rows]

        except Exception as e:
            self.logger.error(f"❌ Failed to retrieve sessions: {e}")
            return []

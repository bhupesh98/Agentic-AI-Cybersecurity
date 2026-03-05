"""
Dashboard Data Loader - Data Access Layer (UPDATED FOR PROJECT STRUCTURE)
===========================================================================

Reads data from:
1. data/dashboard_state.json (real-time state from test script)
2. data/metrics/metrics.db (detailed metrics)
3. data/memory/incidents.db (threat history)

Location: src/dashboard/dashboard_data_loader.py
Author: Abhinav
Date: November 2025
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import time


class DashboardDataLoader:
    """
    Centralized data access for dashboard.
    
    Handles all file I/O and database queries.
    Thread-safe with retry logic.
    """

    def __init__(self):
        """Initialize data loader with correct project paths."""
        # Get project root (2 levels up from src/dashboard/)
        self.project_root = Path(__file__).parent.parent.parent

        # Data paths matching Directory-Structure.txt
        self.dashboard_state_file = self.project_root / "data" / "dashboard_state.json"
        self.metrics_db = self.project_root / "data" / "metrics" / "metrics.db"
        self.memory_db = self.project_root / "data" / "memory" / "incidents.db"

        # Cache for expensive queries
        self._cache = {}
        self._cache_timeout = {}

    # ========================================================================
    # REAL-TIME STATE (from dashboard_state.json)
    # ========================================================================

    def get_live_state(self) -> Optional[Dict]:
        """
        Read current state from JSON file (written by test script).
        
        Returns:
            State dictionary or None if file doesn't exist/is locked
        """
        if not self.dashboard_state_file.exists():
            return None

        # Retry logic for file locks
        for attempt in range(3):
            try:
                with open(self.dashboard_state_file, 'r') as f:
                    state = json.load(f)
                return state
            except (json.JSONDecodeError, FileNotFoundError, PermissionError):
                if attempt < 2:
                    time.sleep(0.1)  # Wait 100ms and retry
                else:
                    return None

    def get_live_stats(self) -> Dict:
        """
        Get live statistics from state file.
        
        Returns:
            Dictionary with current stats
        """
        state = self.get_live_state()

        if not state:
            return {
                'total_flows': 0,
                'malicious_detected': 0,
                'benign_detected': 0,
                'emails_sent': 0,
                'llm_analyses': 0,
                'memory_lookups': 0,
                'learning_events': 0,
                'errors': 0
            }

        return state.get('stats', {})

    def get_live_progress(self) -> Dict:
        """
        Get current progress metrics.
        
        Returns:
            Dictionary with progress info
        """
        state = self.get_live_state()

        if not state:
            return {
                'total_flows': 0,
                'detection_rate': 0.0,
                'agentic_score': 0.0
            }

        return state.get('progress', {})

    def get_last_update_time(self) -> str:
        """Get timestamp of last update."""
        state = self.get_live_state()
        if state and 'timestamp' in state:
            return state['timestamp']
        return datetime.utcnow().isoformat()

    # ========================================================================
    # RECENT THREATS (from memory database)
    # ========================================================================

    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """
        Get most recent threat detections.
        
        Args:
            limit: Number of recent threats to return
            
        Returns:
            List of threat dictionaries
        """
        if not self.memory_db.exists():
            return []

        try:
            conn = sqlite3.connect(str(self.memory_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # First check what columns exist
            cursor.execute("PRAGMA table_info(incidents)")
            available_cols = [row[1] for row in cursor.fetchall()]

            # Build column list based on what's available
            columns = []
            if 'incident_id' in available_cols:
                columns.append('incident_id')
            if 'src_ip' in available_cols:
                columns.append('src_ip')
            elif 'source_ip' in available_cols:
                columns.append('source_ip as src_ip')

            if 'dst_ip' in available_cols:
                columns.append('dst_ip')
            elif 'dest_ip' in available_cols or 'destination_ip' in available_cols:
                columns.append('COALESCE(dest_ip, destination_ip) as dst_ip')

            if 'src_port' in available_cols:
                columns.append('src_port')
            elif 'source_port' in available_cols:
                columns.append('source_port as src_port')

            if 'dst_port' in available_cols:
                columns.append('dst_port')
            elif 'dest_port' in available_cols or 'destination_port' in available_cols:
                columns.append(
                    'COALESCE(dest_port, destination_port) as dst_port')

            # Add other columns
            for col in ['protocol', 'ml_prediction', 'ml_confidence', 'llm_severity',
                        'llm_analysis', 'context_flags', 'timestamp', 'detected_at']:
                if col in available_cols:
                    columns.append(col)

            query = f"""
                SELECT {', '.join(columns)}
                FROM incidents
                WHERE ml_prediction = 'malicious'
                ORDER BY detected_at DESC
                LIMIT ?
            """

            cursor.execute(query, (limit,))

            threats = []
            for row in cursor.fetchall():
                threats.append({
                    'incident_id': row.get('incident_id', 'unknown'),
                    'src_ip': row.get('src_ip', 'unknown'),
                    'dst_ip': row.get('dst_ip', 'unknown'),
                    'src_port': row.get('src_port', 0),
                    'dst_port': row.get('dst_port', 0),
                    'protocol': row.get('protocol', 'TCP'),
                    'ml_confidence': row.get('ml_confidence', 0.0),
                    'llm_severity': row.get('llm_severity') or 'MEDIUM',
                    'llm_analysis': row.get('llm_analysis') or 'Malicious activity detected',
                    'context_flags': row.get('context_flags') or '',
                    'timestamp': row.get('detected_at') or row.get('timestamp', '')
                })

            conn.close()
            return threats

        except Exception:
            # Silent failure
            return []

    # ========================================================================
    # METRICS (from metrics database)
    # ========================================================================

    def get_latest_metrics_summary(self) -> Optional[Dict]:
        """
        Get latest metrics summary from database.
        
        Returns:
            Metrics summary dictionary or None
        """
        if not self.metrics_db.exists():
            return None

        # Check cache
        cache_key = 'metrics_summary'
        if self._is_cached(cache_key, timeout=5.0):  # 5 second cache
            return self._cache[cache_key]

        try:
            conn = sqlite3.connect(str(self.metrics_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Check what tables exist
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            # Try metric_summaries first (new schema)
            if 'metric_summaries' in tables:
                cursor.execute("""
                    SELECT session_id, timestamp, overall_agentic_score
                    FROM metric_summaries
                    ORDER BY timestamp DESC
                    LIMIT 1
                """)

                row = cursor.fetchone()
                if not row:
                    conn.close()
                    return None

                session_id = row['session_id']

                # Get principle metrics
                cursor.execute("""
                    SELECT 
                        principle_name,
                        principle_score,
                        metrics_json
                    FROM principle_metrics
                    WHERE session_id = ?
                """, (session_id,))

                principles = {}
                for p_row in cursor.fetchall():
                    principles[p_row['principle_name']] = {
                        'score': p_row['principle_score'],
                        'metrics': json.loads(p_row['metrics_json']) if p_row['metrics_json'] else {}
                    }

                summary = {
                    'session_id': session_id,
                    'timestamp': row['timestamp'],
                    'overall_score': row['overall_agentic_score'],
                    'principles': principles
                }

            # Fallback: try metrics table (old schema)
            elif 'metrics' in tables:
                cursor.execute("""
                    SELECT session_id, timestamp
                    FROM metrics
                    ORDER BY timestamp DESC
                    LIMIT 1
                """)

                row = cursor.fetchone()
                if not row:
                    conn.close()
                    return None

                # Return simplified summary
                summary = {
                    'session_id': row['session_id'],
                    'timestamp': row['timestamp'],
                    'overall_score': 0.0,
                    'principles': {}
                }
            else:
                conn.close()
                return None

            conn.close()

            # Cache it
            self._cache[cache_key] = summary
            self._cache_timeout[cache_key] = time.time()

            return summary

        except Exception:
            # Silently handle errors
            return None

    def get_principle_scores(self) -> Dict[str, float]:
        """
        Get current scores for all 7 principles.
        
        Returns:
            Dictionary mapping principle name to score (0.0-1.0)
        """
        # Default scores (will be updated as test runs)
        default_scores = {
            'Self-Learning': 0.0,
            'Contextual Awareness': 0.0,
            'Goal-Directed Behavior': 0.0,
            'Tool Utilization': 0.0,
            'Planning & Reasoning': 0.0,
            'Memory Management': 0.0,
            'Feedback Incorporation': 0.0
        }

        # Try to get from live state first (most recent)
        state = self.get_live_state()
        if state and 'progress' in state:
            progress = state['progress']

            # Look for principle scores in progress
            found_scores = {}
            for key, value in progress.items():
                key_lower = key.lower()

                # Try to match principle names
                if 'self' in key_lower and 'learn' in key_lower:
                    found_scores['Self-Learning'] = float(value)
                elif 'context' in key_lower:
                    found_scores['Contextual Awareness'] = float(value)
                elif 'goal' in key_lower:
                    found_scores['Goal-Directed Behavior'] = float(value)
                elif 'tool' in key_lower:
                    found_scores['Tool Utilization'] = float(value)
                elif 'plan' in key_lower or 'reason' in key_lower:
                    found_scores['Planning & Reasoning'] = float(value)
                elif 'memory' in key_lower:
                    found_scores['Memory Management'] = float(value)
                elif 'feedback' in key_lower:
                    found_scores['Feedback Incorporation'] = float(value)

            # If we found any scores, update defaults and return
            if found_scores:
                default_scores.update(found_scores)
                return default_scores

        # Fall back to database
        summary = self.get_latest_metrics_summary()

        if summary and 'principles' in summary:
            # Extract scores from database
            for name, data in summary['principles'].items():
                name_lower = name.lower()

                if 'self' in name_lower and 'learn' in name_lower:
                    default_scores['Self-Learning'] = data['score']
                elif 'context' in name_lower:
                    default_scores['Contextual Awareness'] = data['score']
                elif 'goal' in name_lower:
                    default_scores['Goal-Directed Behavior'] = data['score']
                elif 'tool' in name_lower:
                    default_scores['Tool Utilization'] = data['score']
                elif 'plan' in name_lower or 'reason' in name_lower:
                    default_scores['Planning & Reasoning'] = data['score']
                elif 'memory' in name_lower:
                    default_scores['Memory Management'] = data['score']
                elif 'feedback' in name_lower:
                    default_scores['Feedback Incorporation'] = data['score']

        return default_scores

    # ========================================================================
    # TIME SERIES DATA (for charts)
    # ========================================================================

    def get_detection_timeline(self, minutes: int = 10) -> Tuple[List[str], List[int]]:
        """
        Get detection counts over time for charting.
        
        Args:
            minutes: Number of minutes of history to return
            
        Returns:
            Tuple of (timestamps, counts)
        """
        if not self.memory_db.exists():
            return ([], [])

        try:
            conn = sqlite3.connect(str(self.memory_db))
            cursor = conn.cursor()

            # Get malicious detections in time buckets
            cursor.execute("""
                SELECT 
                    strftime('%Y-%m-%d %H:%M', detected_at) as minute,
                    COUNT(*) as count
                FROM incidents
                WHERE ml_prediction = 'malicious'
                    AND detected_at >= datetime('now', '-' || ? || ' minutes')
                GROUP BY minute
                ORDER BY minute ASC
            """, (minutes,))

            rows = cursor.fetchall()
            conn.close()

            if not rows:
                return ([], [])

            timestamps = [row[0] for row in rows]
            counts = [row[1] for row in rows]

            return (timestamps, counts)

        except Exception as e:
            print(f"Error loading timeline: {e}")
            return ([], [])

    # ========================================================================
    # EMAIL LOG
    # ========================================================================

    def get_recent_emails(self, limit: int = 10) -> List[Dict]:
        """
        Get recent email alerts sent.
        
        Args:
            limit: Number of emails to return
            
        Returns:
            List of email dictionaries
        """
        # Try to read from alerts database if it exists
        alerts_db = self.project_root / "data" / "actions" / "actions.db"

        if not alerts_db.exists():
            return []

        try:
            conn = sqlite3.connect(str(alerts_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # First check what columns exist
            cursor.execute("PRAGMA table_info(actions)")
            columns = [row[1] for row in cursor.fetchall()]

            # Build query based on available columns
            select_cols = ['action_id', 'action_type', 'target', 'created_at']

            if 'executed_at' in columns:
                select_cols.append('executed_at')
            if 'success' in columns:
                select_cols.append('success')
            if 'output' in columns:
                select_cols.append('output')
            elif 'result' in columns:
                select_cols.append('result as output')

            query = f"""
                SELECT {', '.join(select_cols)}
                FROM actions
                WHERE action_type = 'alert_email'
                ORDER BY created_at DESC
                LIMIT ?
            """

            cursor.execute(query, (limit,))

            emails = []
            for row in cursor.fetchall():
                email_dict = {
                    'action_id': row['action_id'],
                    'target': row['target'],
                    'timestamp': row.get('executed_at') or row['created_at'],
                    'success': bool(row.get('success', True)),
                    'output': row.get('output', 'Email sent successfully')
                }
                emails.append(email_dict)

            conn.close()
            return emails

        except Exception:
            # Silently handle errors (don't spam console)
            return []

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _is_cached(self, key: str, timeout: float) -> bool:
        """Check if cached data is still valid."""
        if key not in self._cache:
            return False

        if key not in self._cache_timeout:
            return False

        age = time.time() - self._cache_timeout[key]
        return age < timeout

    def health_check(self) -> Dict[str, bool]:
        """
        Check if all data sources are accessible.
        
        Returns:
            Dictionary with availability status
        """
        return {
            'dashboard_state': self.dashboard_state_file.exists(),
            'metrics_db': self.metrics_db.exists(),
            'memory_db': self.memory_db.exists()
        }


# ============================================================================
# CONVENIENCE FUNCTION
# ============================================================================

def get_data_loader() -> DashboardDataLoader:
    """
    Get singleton data loader instance.
    
    Returns:
        DashboardDataLoader instance
    """
    return DashboardDataLoader()

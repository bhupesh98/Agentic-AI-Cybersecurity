"""
Dashboard Data Loader - Data Access Layer (UPDATED FOR PROJECT STRUCTURE)
===========================================================================

Reads data from:
1. data/dashboard_state.json (real-time state from test script)
2. data/metrics/metrics.db (detailed metrics)
3. data/memory/incidents.db (threat history)

Location: src/dashboard/dashboard_data_loader.py

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
                if str(state.get('timestamp', '')).startswith('2025'):
                    return None
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

            query = """
                SELECT
                    incident_id AS incident_id,
                    session_id AS session_id,
                    flow_id AS flow_id,
                    src_ip AS src_ip,
                    dst_ip AS dst_ip,
                    src_port AS src_port,
                    dst_port AS dst_port,
                    protocol AS protocol,
                    ml_prediction AS ml_prediction,
                    ml_confidence AS ml_confidence,
                    ensemble_agreement AS ensemble_agreement,
                    context_flags AS context_flags,
                    suspicion_score AS suspicion_score,
                    llm_severity AS llm_severity,
                    llm_confidence AS llm_confidence,
                    llm_analysis AS llm_analysis,
                    llm_reasoning AS llm_reasoning,
                    recommended_actions AS recommended_actions,
                    response_plan AS response_plan,
                    action_taken AS action_taken,
                    notes AS notes,
                    detected_at AS detected_at,
                    timestamp AS timestamp
                FROM incidents
                ORDER BY COALESCE(detected_at, timestamp, created_at) DESC
                LIMIT ?
            """

            cursor.execute(query, (limit,))

            threats = []
            for row in cursor.fetchall():
                item = dict(row)
                threats.append({
                    'incident_id': item.get('incident_id', 'unknown'),
                    'session_id': item.get('session_id', ''),
                    'flow_id': item.get('flow_id', ''),
                    'src_ip': item.get('src_ip', 'unknown'),
                    'dst_ip': item.get('dst_ip', 'unknown'),
                    'src_port': item.get('src_port', 0),
                    'dst_port': item.get('dst_port', 0),
                    'protocol': item.get('protocol', 'TCP'),
                    'ml_prediction': item.get('ml_prediction', 'unknown'),
                    'ml_confidence': item.get('ml_confidence', 0.0),
                    'ensemble_agreement': item.get('ensemble_agreement', 0.0),
                    'llm_severity': (item.get('llm_severity') or 'MEDIUM').upper(),
                    'severity': (item.get('llm_severity') or 'MEDIUM').upper(),
                    'llm_confidence': item.get('llm_confidence', 0.0),
                    'confidence_score': item.get('llm_confidence') or item.get('ml_confidence') or 0.0,
                    'llm_analysis': item.get('llm_analysis') or 'Threat activity detected',
                    'llm_reasoning': item.get('llm_reasoning') or '',
                    'recommended_actions': self._loads_json(item.get('recommended_actions'), []),
                    'response_plan': self._loads_json(item.get('response_plan'), item.get('response_plan') or ''),
                    'attack_type': self._derive_attack_type(item),
                    'context_flags': item.get('context_flags') or '',
                    'response_taken': item.get('action_taken') or 'Pending',
                    'notes': item.get('notes') or '',
                    'timestamp': item.get('detected_at') or item.get('timestamp', ''),
                    'detected_at': item.get('detected_at') or item.get('timestamp', ''),
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

            # Current schema
            if 'metrics_summary' in tables:
                cursor.execute("""
                    SELECT session_id, timestamp, overall_agentic_score
                    FROM metrics_summary
                    ORDER BY timestamp DESC
                    LIMIT 1
                """)

                row = cursor.fetchone()
                if not row:
                    conn.close()
                    return None

                session_id = row['session_id']
                principles = {}

                principle_queries = {
                    'Self-Learning': ("self_learning_metrics", "learning_velocity"),
                    'Contextual Awareness': ("contextual_awareness_metrics", "context_incorporation_rate"),
                    'Goal-Directed Behavior': ("goal_directed_metrics", "goal_completion_rate"),
                    'Tool Utilization': ("tool_utilization_metrics", "overall_effectiveness"),
                    'Planning & Reasoning': ("planning_reasoning_metrics", "decision_quality_score"),
                    'Memory Management': ("memory_management_metrics", "memory_utilization_rate"),
                    'Feedback Incorporation': ("feedback_incorporation_metrics", "target"),
                }

                for name, (table, score_col) in principle_queries.items():
                    if table not in tables:
                        continue
                    cursor.execute(
                        f"SELECT * FROM {table} WHERE session_id = ? LIMIT 1",
                        (session_id,),
                    )
                    p_row = cursor.fetchone()
                    if not p_row:
                        continue
                    data = dict(p_row)
                    principles[name] = {
                        'score': float(data.get(score_col) or 0.0),
                        'metrics': data,
                    }

                summary = {
                    'session_id': session_id,
                    'timestamp': row['timestamp'],
                    'overall_score': row['overall_agentic_score'],
                    'principles': principles
                }

            # Legacy schema
            elif 'metric_summaries' in tables:
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

    def get_incident_summary(self, incident_id: str) -> Optional[Dict]:
        """Return an on-demand investigation summary for one incident."""
        threats = self.get_recent_threats(limit=1000)
        incident = next((item for item in threats if item.get('incident_id') == incident_id), None)
        if not incident:
            return None

        traces = []
        try:
            from src.tracing.decision_trace_manager import DecisionTraceManager
            tm = DecisionTraceManager()
            traces = [
                entry.to_dict()
                for entry in tm.get_full_trace(incident.get('session_id', ''))
                if incident.get('flow_id', '') in entry.input_summary
                or incident.get('attack_type', '') in entry.input_summary
                or incident.get('src_ip', '') in entry.input_summary
            ]
        except Exception:
            traces = []

        chain_context = []
        try:
            from src.correlation import IncidentCorrelationEngine
            engine = IncidentCorrelationEngine()
            for chain in engine.get_recent_chains(limit=50):
                if incident_id in str(chain.get('chain_data', '')):
                    chain_context.append(chain)
        except Exception:
            chain_context = []

        actions = incident.get('recommended_actions') or []
        response_plan = incident.get('response_plan') or {}
        reasoning = incident.get('llm_reasoning') or incident.get('llm_analysis') or ''
        summary = (
            f"{incident.get('attack_type')} was detected from {incident.get('src_ip')} "
            f"to {incident.get('dst_ip')} at {incident.get('detected_at')}. "
            f"The incident is rated {incident.get('severity')} with "
            f"{float(incident.get('confidence_score') or 0):.0%} confidence. "
            f"Simulation response: {incident.get('response_taken')}. "
            f"Primary reasoning: {reasoning[:500]}"
        )

        return {
            'incident': incident,
            'summary': summary,
            'reasoning': reasoning,
            'response_plan': response_plan,
            'recommended_actions': actions,
            'decision_traces': traces,
            'attack_chains': chain_context,
        }

    @staticmethod
    def _derive_attack_type(row: Dict) -> str:
        """Infer a dashboard label from the current incident schema."""
        flow_id = str(row.get('flow_id') or '').replace('-', ' ').replace('_', ' ')
        analysis = str(row.get('llm_analysis') or '')
        flags = str(row.get('context_flags') or '')
        text = f"{flow_id} {analysis} {flags}".lower()

        patterns = [
            ('exfil', 'Data Exfiltration'),
            ('lateral', 'Lateral Movement'),
            ('credential', 'Credential Access'),
            ('collection', 'Collection'),
            ('privilege', 'Privilege Escalation'),
            ('evasion', 'Defense Evasion'),
            ('persistence', 'Persistence'),
            ('discovery', 'Discovery'),
            ('recon', 'Reconnaissance'),
            ('scan', 'Reconnaissance'),
            ('initial access', 'Initial Access'),
            ('brute', 'Initial Access'),
            ('execution', 'Execution'),
            ('c2', 'Command and Control'),
            ('command', 'Command and Control'),
        ]
        for needle, label in patterns:
            if needle in text:
                return label
        return 'Suspicious Network Activity'

    @staticmethod
    def _loads_json(value, default):
        if value in (None, ''):
            return default
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except Exception:
            return default


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

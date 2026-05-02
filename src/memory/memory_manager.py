"""
Hybrid Memory Manager: SQLite + FAISS Vector Search.

Combines structured relational storage with semantic similarity search
for intelligent incident correlation and retrieval.


"""

import sqlite3
import numpy as np
import os
import logging
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pathlib import Path

# FAISS for vector similarity search
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False
    logging.warning(
        "FAISS not installed. Vector similarity search will be disabled.")

# Sentence transformers for embedding generation
try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logging.warning(
        "Sentence transformers not installed. Embeddings will be disabled.")

from .models import IncidentRecord, IPReputation, ThreatPattern, MemoryStats

logger = logging.getLogger(__name__)

# Redis for hot-cache (optional — falls back to SQLite-only if unavailable)
try:
    import redis as _redis_lib
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


def _normalize_timestamp(timestamp_str: str) -> str:
    """
    Normalize timestamp string to handle various formats.
    
    Handles:
    - 'Z' suffix (UTC indicator)
    - '+00:00' timezone
    - Double timezone issues (e.g., '+00:00+00:00' or '+00:00Z')
    - Mixed formats
    
    Returns normalized timestamp in ISO format with '+00:00' timezone.
    """
    if not timestamp_str:
        return timestamp_str
    
    # Remove any trailing 'Z' first
    if timestamp_str.endswith('Z'):
        timestamp_str = timestamp_str[:-1]
    
    # Handle double timezone patterns
    # Pattern 1: '+00:00+00:00'
    while '+00:00+00:00' in timestamp_str:
        timestamp_str = timestamp_str.replace('+00:00+00:00', '+00:00')
    
    # Pattern 2: '+00:00Z' (shouldn't happen after removing Z, but just in case)
    timestamp_str = timestamp_str.replace('+00:00Z', '+00:00')
    timestamp_str = timestamp_str.replace('Z+00:00', '+00:00')
    
    # If no timezone info, add '+00:00' (assume UTC)
    if '+' not in timestamp_str and '-' not in timestamp_str[-6:]:
        # Check if it ends with timezone pattern
        if not (timestamp_str[-6:].startswith('+') or timestamp_str[-6:].startswith('-')):
            timestamp_str = timestamp_str + '+00:00'
    
    return timestamp_str


def _parse_timestamp_safe(timestamp_str: str) -> datetime:
    """
    Safely parse timestamp string to datetime object.
    
    Handles various timestamp formats and normalizes them.
    """
    normalized = _normalize_timestamp(timestamp_str)
    return datetime.fromisoformat(normalized)


class MemoryManager:
    """
    Hybrid memory system combining SQLite and FAISS.
    
    - SQLite: Structured incident data, IP reputation, metadata
    - FAISS: Vector embeddings for semantic similarity search
    """

    def __init__(self, db_path: Optional[str] = None, faiss_index_path: Optional[str] = None):
        """
        Initialize Memory Manager.
        
        Args:
            db_path: Path to SQLite database (default: data/memory/incidents.db)
            faiss_index_path: Path to FAISS index file (default: data/memory/faiss_index.bin)
        """
        # Set up paths
        if db_path is None:
            memory_dir = Path(__file__).parent.parent.parent / "data" / "memory"
            memory_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(memory_dir / "incidents.db")
        
        if faiss_index_path is None:
            memory_dir = Path(db_path).parent
            faiss_index_path = str(memory_dir / "faiss_index.bin")
        
        self.db_path = db_path
        self.faiss_index_path = faiss_index_path

        # ── Redis hot cache (optional) ────────────────────────────────────────
        self._redis: "Any | None" = None
        self._redis_ttl = 3600  # seconds
        if REDIS_AVAILABLE:
            self._init_redis()
        
        # Initialize database
        self._init_database()
        
        # Initialize FAISS
        self.faiss_index = None
        self.embedding_model = None
        if FAISS_AVAILABLE:
            self._init_faiss()
        
        logger.info("✅ Memory Manager initialized successfully")

    def _init_redis(self) -> None:
        """Connect to Redis for hot-cache — silently skipped if unavailable."""
        try:
            from config import settings as _s  # type: ignore
            url = _s.REDIS_URL or ""
        except Exception:
            url = os.getenv("REDIS_URL", "")
        if not url:
            return
        try:
            self._redis = _redis_lib.from_url(  # type: ignore[attr-defined]
                url, socket_connect_timeout=2, socket_timeout=2, decode_responses=True
            )
            self._redis.ping()
            logger.info("✅ Redis hot cache connected: %s", url)
        except Exception as exc:
            logger.warning("Redis unavailable — using SQLite-only mode: %s", exc)
            self._redis = None

    def _init_database(self):
        """Initialize SQLite database with schema."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        
        # Read and execute schema
        schema_path = Path(__file__).parent / "schema.sql"
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                schema = f.read()
            conn.executescript(schema)
        else:
            logger.warning(f"Schema file not found: {schema_path}")
        
        # Create threat_patterns table if it doesn't exist (for pattern detection)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS threat_patterns (
                pattern_key TEXT PRIMARY KEY,
                pattern_type TEXT NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                incident_ids TEXT DEFAULT '[]'
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"✅ SQLite database initialized: {self.db_path}")
    
    def _init_faiss(self):
        """Initialize FAISS index for vector similarity search."""
        if not FAISS_AVAILABLE:
            return
        
        # Load or create index
        if os.path.exists(self.faiss_index_path):
            try:
                self.faiss_index = faiss.read_index(self.faiss_index_path)
                logger.info(f"✅ FAISS index loaded: {self.faiss_index.ntotal} vectors")
            except Exception as e:
                logger.warning(f"Failed to load FAISS index: {e}")
                self.faiss_index = None
        
        if self.faiss_index is None:
            # Create new index (384 dimensions for all-MiniLM-L6-v2)
            dimension = 384
            self.faiss_index = faiss.IndexFlatL2(dimension)
            logger.info("✅ Created new FAISS index")
        
        # Load embedding model
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
                logger.info("✅ Embedding model loaded: all-MiniLM-L6-v2")
            except Exception as e:
                logger.warning(f"Failed to load embedding model: {e}")
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def _generate_embedding(self, text: str) -> Optional[np.ndarray]:
        """Generate embedding vector for text."""
        if not SENTENCE_TRANSFORMERS_AVAILABLE or self.embedding_model is None:
            return None
        
        try:
            embedding = self.embedding_model.encode(text, convert_to_numpy=True)
            return embedding
        except Exception as e:
            logger.warning(f"Failed to generate embedding: {e}")
            return None
    
    def store_incident(self, incident: IncidentRecord) -> str:
        """
        Store incident in both SQLite and FAISS.
        
        Args:
            incident: Complete incident record
            
        Returns:
            incident_id
        """
        start_time = datetime.utcnow()

        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Generate embedding for threat description
            threat_text = f"{incident.llm_analysis} {incident.llm_reasoning or ''}"
            embedding = self._generate_embedding(threat_text)

            if embedding is not None and self.faiss_index is not None:
                # Add to FAISS
                embedding_id = self.faiss_index.ntotal
                self.faiss_index.add(embedding.reshape(1, -1))
                incident.embedding_id = embedding_id

                # Save FAISS index
                faiss.write_index(self.faiss_index, self.faiss_index_path)

            # Store in SQLite
            incident_dict = incident.to_dict()

            columns = ', '.join(incident_dict.keys())
            placeholders = ', '.join(['?' for _ in incident_dict])
            query = f"INSERT OR REPLACE INTO incidents ({columns}) VALUES ({placeholders})"

            cursor.execute(query, list(incident_dict.values()))

            # Update IP reputation
            self._update_ip_reputation(cursor, incident)

            # Detect and store patterns
            self._detect_and_store_patterns(cursor, incident)

            # Create correlations with recent incidents
            self._create_correlations(cursor, incident)

            conn.commit()

            # Write lightweight record to Redis hot cache
            if self._redis is not None:
                try:
                    cache_key = f"incident:{incident.incident_id}"
                    self._redis.setex(
                        cache_key,
                        self._redis_ttl,
                        json.dumps({
                            "incident_id": incident.incident_id,
                            "src_ip": incident.src_ip,
                            "severity": incident.llm_severity,
                            "threat_type": (incident.llm_analysis or "")[:120],
                            "detected_at": str(incident.timestamp),
                        }),
                    )
                    # Track per-IP recent incident list
                    ip_key = f"ip_incidents:{incident.src_ip}"
                    self._redis.lpush(ip_key, incident.incident_id)
                    self._redis.expire(ip_key, self._redis_ttl)
                    self._redis.ltrim(ip_key, 0, 49)  # keep last 50 per IP
                except Exception as _re:
                    logger.debug("Redis write skipped: %s", _re)

            # Track performance
            elapsed = (datetime.utcnow() - start_time).total_seconds() * 1000
            logger.info(
                f"✅ Stored incident {incident.incident_id} (took {elapsed:.1f}ms)")

            return incident.incident_id

        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to store incident: {e}")
            raise
        finally:
            conn.close()
    
    def _update_ip_reputation(self, cursor: sqlite3.Cursor, incident: IncidentRecord):
        """Update IP reputation based on incident."""
        # Get or create reputation record
        cursor.execute(
            "SELECT * FROM ip_reputation WHERE ip_address = ?",
            (incident.src_ip,))
        row = cursor.fetchone()

        if row:
            # Update existing
            rep = IPReputation.from_dict(dict(row))
            rep.incident_count += 1
            rep.last_seen = incident.timestamp
            
            # Update severity counts based on LLM severity
            severity = incident.llm_severity.lower() if incident.llm_severity else 'unknown'
            if severity == 'medium':
                rep.medium_severity_count += 1
            elif severity == 'high':
                rep.high_severity_count += 1
            elif severity == 'critical':
                rep.critical_severity_count += 1
            
            # Update malicious/benign counts
            if incident.llm_severity and incident.llm_severity.lower() not in ['benign', 'low', 'unknown']:
                rep.malicious_count += 1
            else:
                rep.benign_count += 1
        else:
            # Create new
            severity = incident.llm_severity.lower() if incident.llm_severity else 'unknown'
            rep = IPReputation(
                ip_address=incident.src_ip,
                incident_count=1,
                first_seen=incident.timestamp,
                last_seen=incident.timestamp,
                medium_severity_count=1 if severity == 'medium' else 0,
                high_severity_count=1 if severity == 'high' else 0,
                critical_severity_count=1 if severity == 'critical' else 0,
                malicious_count=1 if severity not in ['benign', 'low', 'unknown'] else 0,
                benign_count=1 if severity in ['benign', 'low', 'unknown'] else 0,
                threat_score=0.5  # Default neutral
            )

        # Calculate threat score based on severity distribution
        if rep.incident_count > 0:
            high_severity_count = rep.high_severity_count + rep.critical_severity_count
            severity_ratio = high_severity_count / rep.incident_count
            rep.threat_score = min(1.0, 0.3 + (severity_ratio * 0.7))

        # Store - convert keys to uppercase to match schema
        rep_dict = rep.to_dict()
        # Convert keys to uppercase for schema compatibility
        rep_dict_upper = {k.upper(): v for k, v in rep_dict.items()}
        columns = ', '.join(rep_dict_upper.keys())
        placeholders = ', '.join(['?' for _ in rep_dict_upper])
        query = f"INSERT OR REPLACE INTO ip_reputation ({columns}) VALUES ({placeholders})"
        cursor.execute(query, list(rep_dict_upper.values()))
    
    def _detect_and_store_patterns(self, cursor: sqlite3.Cursor, incident: IncidentRecord):
        """Detect and store attack patterns."""
        # Simple pattern detection based on ports and protocols
        pattern_id = f"{incident.protocol}:{incident.dst_port}"
        pattern_name = f"{incident.protocol} traffic to port {incident.dst_port}"
        pattern_type = "network_activity"  # Default type
        
        cursor.execute(
            "SELECT * FROM attack_patterns WHERE pattern_id = ?",
            (pattern_id,))
        row = cursor.fetchone()

        if row:
            # Update existing pattern
            pattern = ThreatPattern.from_dict(dict(row))
            pattern.occurrence_count += 1
            pattern.last_detected = incident.timestamp
            
            # Update incident IDs
            incident_ids = json.loads(pattern.incident_ids)
            if incident.incident_id not in incident_ids:
                incident_ids.append(incident.incident_id)
            pattern.incident_ids = json.dumps(incident_ids)
            
            # Update indicators
            pattern.indicators['last_port'] = incident.dst_port
            pattern.indicators['last_protocol'] = incident.protocol
        else:
            # Create new pattern
            pattern = ThreatPattern(
                pattern_id=pattern_id,
                pattern_name=pattern_name,
                pattern_type=pattern_type,
                occurrence_count=1,
                first_detected=incident.timestamp,
                last_detected=incident.timestamp,
                incident_ids=json.dumps([incident.incident_id]),
                indicators={
                    'port': incident.dst_port,
                    'protocol': incident.protocol,
                    'target_ip': incident.dst_ip
                }
            )

        # Store - convert keys to uppercase to match schema
        pattern_dict = pattern.to_dict()
        # Convert keys to uppercase for schema compatibility
        pattern_dict_upper = {k.upper(): v for k, v in pattern_dict.items()}
        columns = ', '.join(pattern_dict_upper.keys())
        placeholders = ', '.join(['?' for _ in pattern_dict_upper])
        query = f"INSERT OR REPLACE INTO attack_patterns ({columns}) VALUES ({placeholders})"
        cursor.execute(query, list(pattern_dict_upper.values()))

    def _create_correlations(self, cursor: sqlite3.Cursor, incident: IncidentRecord):
        """Create correlations with recent incidents from same IP."""
        # Find incidents from same IP in last 24 hours
        # Normalize and parse timestamp safely
        incident_time = _parse_timestamp_safe(incident.timestamp)
        
        time_threshold = (incident_time - timedelta(hours=24)).isoformat() + 'Z'

        cursor.execute("""
            SELECT incident_id, timestamp, llm_severity
            FROM incidents
            WHERE src_ip = ? AND timestamp > ? AND incident_id != ?
            ORDER BY timestamp DESC
            LIMIT 5
        """, (incident.src_ip, time_threshold, incident.incident_id))

        related_incidents = cursor.fetchall()

        for related in related_incidents:
            correlation_id = f"corr-{incident.incident_id}-{related['incident_id']}"

            # Calculate time difference
            # Safely parse both timestamps
            time1 = _parse_timestamp_safe(incident.timestamp)
            time2 = _parse_timestamp_safe(related['timestamp'])

            # If one is naive and one is aware, make both naive
            if time1.tzinfo is None and time2.tzinfo is not None:
                time2 = time2.replace(tzinfo=None)
            elif time1.tzinfo is not None and time2.tzinfo is None:
                time1 = time1.replace(tzinfo=None)

            time_diff = abs((time1 - time2).total_seconds())

            # Store correlation - use uppercase column names to match schema
            cursor.execute("""
                INSERT OR REPLACE INTO incident_correlations (
                    CORRELATION_ID, INCIDENT_ID_1, INCIDENT_ID_2,
                    TIME_DIFF_SECONDS, SIMILARITY_SCORE, CORRELATION_TYPE
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                correlation_id,
                incident.incident_id,
                related['incident_id'],
                int(time_diff),
                0.8,  # Default similarity for same IP
                'same_ip'  # Correlation type
            ))

    def get_memory_context(self, incident: IncidentRecord) -> 'MemoryContext':
        """
        Get memory context for an incident.
        
        Queries:
        - Similar past incidents (FAISS)
        - IP reputation (Redis hot cache first, then SQLite)
        - Related incidents
        - Attack patterns
        
        Returns:
            MemoryContext object
        """
        from .models import MemoryContext
        
        # Initialize context with required fields
        context = MemoryContext(
            current_incident_id=incident.incident_id,
            current_src_ip=incident.src_ip,
            current_dst_ip=incident.dst_ip
        )

        # ── Redis hot cache: recent incidents for this IP ─────────────────────
        if self._redis is not None:
            try:
                ip_key = f"ip_incidents:{incident.src_ip}"
                recent_ids = self._redis.lrange(ip_key, 0, 4)  # up to 5 recent
                if recent_ids:
                    cached = []
                    for inc_id in recent_ids:
                        raw = self._redis.get(f"incident:{inc_id}")
                        if raw:
                            cached.append(json.loads(raw))
                    if cached:
                        context.similar_incidents = cached
                        logger.debug(
                            "Redis cache hit: %d recent incidents for %s",
                            len(cached), incident.src_ip,
                        )
            except Exception as _re:
                logger.debug("Redis read skipped: %s", _re)

        try:
            # Query similar incidents using FAISS
            if self.faiss_index is not None and incident.embedding_id is not None:
                similar_incidents = self._query_similar_incidents(incident)
                context.similar_incidents = similar_incidents

            # Get IP reputation
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM ip_reputation WHERE ip_address = ?",
                (incident.src_ip,))
            row = cursor.fetchone()
            if row:
                context.ip_reputation = IPReputation.from_dict(dict(row))
                context.is_repeat_offender = context.ip_reputation.incident_count > 1
                context.incidents_from_this_ip = context.ip_reputation.incident_count
            else:
                context.incidents_from_this_ip = 0
                context.is_repeat_offender = False
            conn.close()

            # Get related incidents (stored in similar_incidents, not separate field)
            # The similar_incidents list already contains related incidents from FAISS
            # Additional correlations can be added if needed
            
            # Get total incidents count for statistics
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM incidents")
            row = cursor.fetchone()
            if row:
                # Handle both tuple and dict row formats
                if isinstance(row, tuple):
                    context.total_incidents_in_memory = row[0]
                else:
                    context.total_incidents_in_memory = row.get('total', 0) if hasattr(row, 'get') else row[0]
            conn.close()

        except Exception as e:
            logger.error(f"Failed to get memory context: {e}")
            import traceback
            logger.error(traceback.format_exc())

        return context

    def _query_similar_incidents(
        self, current_incident: IncidentRecord, k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Query FAISS for similar incidents.
        
        Args:
            current_incident: Incident to find similarities for
            k: Number of similar incidents to return
            
        Returns:
            List of similar incident dictionaries
        """
        if not FAISS_AVAILABLE or self.faiss_index is None:
            return []

        if current_incident.embedding_id is None:
            return []

        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            similar_incidents = []
            # Normalize and parse timestamp safely
            current_time = _parse_timestamp_safe(current_incident.timestamp)

            # Query FAISS
            query_vector = np.array([current_incident.embedding_id], dtype=np.int64)
            distances, indices = self.faiss_index.search(
                query_vector.reshape(1, -1), k + 1)  # +1 to exclude self

            # Debug: Log all similarity scores
            all_similarities = list(zip(indices[0], distances[0]))
            self.logger.debug(
                f"FAISS returned {len(all_similarities)} candidates")

            for idx, distance in all_similarities:
                if idx == current_incident.embedding_id:
                    continue  # Skip self

                # Get incident from database
                cursor.execute(
                    "SELECT * FROM incidents WHERE embedding_id = ?",
                    (int(idx),))
                row = cursor.fetchone()

                if not row:
                    continue

                # Calculate time difference
                # Safely parse timestamp
                timestamp_str = row['TIMESTAMP']
                incident_time = _parse_timestamp_safe(timestamp_str)
                time_diff = int((current_time - incident_time).total_seconds())

                # Determine matching features
                matching_features = []
                if row['SRC_IP'] == current_incident.src_ip:
                    matching_features.append('same_source_ip')
                if row['DST_PORT'] == current_incident.dst_port:
                    matching_features.append('same_destination_port')
                if row['PROTOCOL'] == current_incident.protocol:
                    matching_features.append('same_protocol')

                similar_incidents.append({
                    'incident_id': row['INCIDENT_ID'],
                    'timestamp': row['TIMESTAMP'],
                    'similarity_score': float(1.0 / (1.0 + distance)),
                    'time_difference_seconds': time_diff,
                    'matching_features': matching_features,
                    'llm_severity': row.get('LLM_SEVERITY', 'unknown')
                })

            conn.close()
            return similar_incidents

        except Exception as e:
            logger.error(f"Failed to query similar incidents: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []
    
    def get_statistics(self) -> MemoryStats:
        """
        Get system-wide memory statistics.
        
        Returns:
            MemoryStats object with current memory system statistics
        """
        from .models import MemoryStats
        
        stats = MemoryStats()
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get total incidents
            cursor.execute("SELECT COUNT(*) FROM INCIDENTS")
            row = cursor.fetchone()
            stats.total_incidents = row[0] if row else 0
            
            # Get total unique IPs
            cursor.execute("SELECT COUNT(DISTINCT SRC_IP) FROM INCIDENTS")
            row = cursor.fetchone()
            stats.total_unique_ips = row[0] if row else 0
            
            # Get total patterns
            cursor.execute("SELECT COUNT(*) FROM ATTACK_PATTERNS")
            row = cursor.fetchone()
            stats.total_patterns = row[0] if row else 0
            
            # Get severity breakdown
            cursor.execute("""
                SELECT LLM_SEVERITY, COUNT(*) as count
                FROM INCIDENTS
                GROUP BY LLM_SEVERITY
            """)
            rows = cursor.fetchall()
            for row in rows:
                severity = (row[0] if row else '').lower()
                count = row[1] if row and len(row) > 1 else 0
                if severity == 'critical':
                    stats.critical_incidents = count
                elif severity == 'high':
                    stats.high_incidents = count
                elif severity == 'medium':
                    stats.medium_incidents = count
                elif severity in ['low', 'benign']:
                    stats.low_incidents = count
            
            # Get top threat IPs
            cursor.execute("""
                SELECT IP_ADDRESS, THREAT_SCORE
                FROM IP_REPUTATION
                ORDER BY THREAT_SCORE DESC
                LIMIT 10
            """)
            rows = cursor.fetchall()
            stats.top_threat_ips = [
                (row[0] if row else '', row[1] if row and len(row) > 1 else 0.0)
                for row in rows
            ]
            
            conn.close()
            
            # Calculate memory utilization rate (simplified - would need tracking)
            # For now, set to 0.0 or calculate based on incidents with memory context
            stats.memory_utilization_rate = 0.0  # Placeholder - would need tracking
            
        except Exception as e:
            logger.error(f"Failed to get memory statistics: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return stats


# ============================================================================
# MEMORY CONTEXT
# ============================================================================

class MemoryContext:
    """Context retrieved from memory system."""

    def __init__(self):
        self.similar_incidents: List[Dict[str, Any]] = []
        self.ip_reputation: Optional[IPReputation] = None
        self.related_incidents: List[Dict[str, Any]] = []
        self.is_repeat_offender: bool = False

    def has_context(self) -> bool:
        """Check if context has any information."""
        return (
            len(self.similar_incidents) > 0 or
            self.ip_reputation is not None or
            len(self.related_incidents) > 0
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'similar_incidents_count': len(self.similar_incidents),
            'is_repeat_offender': self.is_repeat_offender,
            'ip_reputation': self.ip_reputation.to_dict() if self.ip_reputation else None,
            'related_incidents_count': len(self.related_incidents)
        }


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_global_memory_manager: Optional[MemoryManager] = None


def get_memory_manager(force_reload: bool = False) -> MemoryManager:
    """Get global memory manager instance."""
    global _global_memory_manager
    
    if _global_memory_manager is None or force_reload:
        _global_memory_manager = MemoryManager()
    
    return _global_memory_manager

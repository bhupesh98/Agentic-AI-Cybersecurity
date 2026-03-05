"""
Memory System Data Models.

Defines data structures for incident storage, retrieval, and correlation.

Author: Abhinav
Date: November 2025
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
import json


@dataclass
class IncidentRecord:
    """Complete incident record for memory storage."""

    # Identifiers
    incident_id: str
    session_id: str
    flow_id: str

    # Temporal
    timestamp: str
    detected_at: str

    # Network information
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    # Detection results
    ml_prediction: str
    ml_confidence: float
    ensemble_agreement: float

    # Context analysis
    context_flags: List[str]
    context_reasons: List[str]
    suspicion_score: float

    # LLM analysis
    llm_severity: str
    llm_confidence: float
    llm_analysis: str
    llm_reasoning: Optional[str] = None
    recommended_actions: List[str] = field(default_factory=list)

    # Response
    response_plan: Optional[str] = None
    action_taken: Optional[str] = None
    was_successful: Optional[bool] = None

    # Embeddings
    embedding_id: Optional[int] = None
    embedding_vector: Optional[List[float]] = None

    # Metadata
    notes: Optional[str] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'incident_id': self.incident_id,
            'session_id': self.session_id,
            'flow_id': self.flow_id,
            'timestamp': self.timestamp,
            'detected_at': self.detected_at,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'ml_prediction': self.ml_prediction,
            'ml_confidence': self.ml_confidence,
            'ensemble_agreement': self.ensemble_agreement,
            'context_flags': json.dumps(self.context_flags),
            'context_reasons': json.dumps(self.context_reasons),
            'suspicion_score': self.suspicion_score,
            'llm_severity': self.llm_severity,
            'llm_confidence': self.llm_confidence,
            'llm_analysis': self.llm_analysis,
            'llm_reasoning': self.llm_reasoning,
            'recommended_actions': json.dumps(self.recommended_actions),
            'response_plan': self.response_plan,
            'action_taken': self.action_taken,
            'was_successful': 1 if self.was_successful else 0 if self.was_successful is not None else None,
            'embedding_id': self.embedding_id,
            'notes': self.notes,
            'created_at': self.created_at or datetime.utcnow().isoformat() + 'Z'
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IncidentRecord':
        """Create from database dictionary."""
        return cls(
            incident_id=data['incident_id'],
            session_id=data['session_id'],
            flow_id=data['flow_id'],
            timestamp=data['timestamp'],
            detected_at=data['detected_at'],
            src_ip=data['src_ip'],
            dst_ip=data['dst_ip'],
            src_port=data['src_port'],
            dst_port=data['dst_port'],
            protocol=data['protocol'],
            ml_prediction=data['ml_prediction'],
            ml_confidence=data['ml_confidence'],
            ensemble_agreement=data['ensemble_agreement'],
            context_flags=json.loads(
                data['context_flags']) if data['context_flags'] else [],
            context_reasons=json.loads(
                data['context_reasons']) if data['context_reasons'] else [],
            suspicion_score=data['suspicion_score'],
            llm_severity=data['llm_severity'],
            llm_confidence=data['llm_confidence'],
            llm_analysis=data['llm_analysis'],
            llm_reasoning=data.get('llm_reasoning'),
            recommended_actions=json.loads(data['recommended_actions']) if data.get(
                'recommended_actions') else [],
            response_plan=data.get('response_plan'),
            action_taken=data.get('action_taken'),
            was_successful=bool(data['was_successful']) if data.get(
                'was_successful') is not None else None,
            embedding_id=data.get('embedding_id'),
            notes=data.get('notes'),
            created_at=data.get('created_at')
        )


@dataclass
class IPReputation:
    """IP address reputation tracking."""

    ip_address: str

    # Statistics
    incident_count: int = 0
    malicious_count: int = 0
    benign_count: int = 0
    medium_severity_count: int = 0  # LLM-detected medium severity
    high_severity_count: int = 0  # LLM-detected high severity
    critical_severity_count: int = 0  # LLM-detected critical severity

    # Temporal
    first_seen: str = ""
    last_seen: str = ""

    # Scoring (dual scoring system)
    ml_threat_score: float = 0.0  # ML-only threat score (for comparison)
    threat_score: float = 0.0  # Hybrid ML+LLM threat score

    # Attack patterns
    attack_types: List[str] = field(default_factory=list)
    targeted_assets: List[str] = field(default_factory=list)

    # Metadata
    notes: Optional[str] = None
    updated_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'ip_address': self.ip_address,
            'incident_count': self.incident_count,
            'malicious_count': self.malicious_count,
            'benign_count': self.benign_count,
            'medium_severity_count': self.medium_severity_count,
            'high_severity_count': self.high_severity_count,
            'critical_severity_count': self.critical_severity_count,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'ml_threat_score': self.ml_threat_score,
            'threat_score': self.threat_score,
            'attack_types': json.dumps(self.attack_types),
            'targeted_assets': json.dumps(self.targeted_assets),
            'notes': self.notes,
            'updated_at': self.updated_at or datetime.now(timezone.utc).isoformat().replace('+00:00', '') + 'Z'
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPReputation':
        """Create from database dictionary. Handles both uppercase and lowercase column names."""
        # Helper to get value with fallback to uppercase
        def get_val(key: str, default=None):
            return data.get(key, data.get(key.upper(), default))
        
        return cls(
            ip_address=get_val('ip_address', ''),
            incident_count=get_val('incident_count', 0),
            malicious_count=get_val('malicious_count', 0),
            benign_count=get_val('benign_count', 0),
            medium_severity_count=get_val('medium_severity_count', 0),
            high_severity_count=get_val('high_severity_count', 0),
            critical_severity_count=get_val('critical_severity_count', 0),
            first_seen=get_val('first_seen', ''),
            last_seen=get_val('last_seen', ''),
            ml_threat_score=get_val('ml_threat_score', 0.0),
            threat_score=get_val('threat_score', 0.0),
            attack_types=json.loads(get_val('attack_types', '[]')) if get_val('attack_types') else [],
            targeted_assets=json.loads(get_val('targeted_assets', '[]')) if get_val('targeted_assets') else [],
            notes=get_val('notes'),
            updated_at=get_val('updated_at')
        )


@dataclass
class SimilarIncident:
    """Similar incident result from memory search."""

    incident_id: str
    similarity_score: float
    time_diff_seconds: int

    # Incident details
    src_ip: str
    dst_ip: str
    llm_severity: str
    llm_analysis: str
    timestamp: str

    # What made it similar
    matching_features: List[str] = field(default_factory=list)

    def get_time_ago_str(self) -> str:
        """Human-readable time difference."""
        seconds = abs(self.time_diff_seconds)

        if seconds < 60:
            return f"{seconds} seconds ago"
        elif seconds < 3600:
            return f"{seconds // 60} minutes ago"
        elif seconds < 86400:
            return f"{seconds // 3600} hours ago"
        else:
            return f"{seconds // 86400} days ago"


@dataclass
class MemoryContext:
    """Memory context provided to LLM for response planning."""

    # Current threat info
    current_incident_id: str
    current_src_ip: str
    current_dst_ip: str

    # IP reputation
    ip_reputation: Optional[IPReputation] = None
    is_repeat_offender: bool = False

    # Similar incidents
    similar_incidents: List[SimilarIncident] = field(default_factory=list)

    # Patterns
    detected_patterns: List[str] = field(default_factory=list)

    # Statistics
    total_incidents_in_memory: int = 0
    incidents_from_this_ip: int = 0

    def has_context(self) -> bool:
        """Check if there's any useful memory context."""
        return (
            self.is_repeat_offender or
            len(self.similar_incidents) > 0 or
            len(self.detected_patterns) > 0 or
            (self.ip_reputation and self.ip_reputation.threat_score > 0.5)
        )

    def to_llm_prompt_text(self) -> str:
        """Format memory context for LLM prompt."""
        if not self.has_context():
            return "No relevant historical context found."

        lines = ["Historical Context:"]

        # IP reputation
        if self.ip_reputation and self.ip_reputation.incident_count > 0:
            lines.append(f"\nIP Reputation for {self.current_src_ip}:")
            lines.append(
                f"  - Previous incidents: {self.ip_reputation.incident_count}")
            lines.append(
                f"  - Malicious classifications: {self.ip_reputation.malicious_count}")
            lines.append(
                f"  - Threat score: {self.ip_reputation.threat_score:.2f}/1.0")
            lines.append(f"  - First seen: {self.ip_reputation.first_seen}")
            lines.append(f"  - Last seen: {self.ip_reputation.last_seen}")

            if self.ip_reputation.attack_types:
                lines.append(
                    f"  - Known attack types: {', '.join(self.ip_reputation.attack_types)}")

        # Similar incidents
        if self.similar_incidents:
            lines.append(
                f"\nSimilar Past Incidents ({len(self.similar_incidents)} found):")
            # Top 3
            for i, incident in enumerate(self.similar_incidents[:3], 1):
                lines.append(f"\n  {i}. Incident #{incident.incident_id}")
                lines.append(
                    f"     - Similarity: {incident.similarity_score:.1%}")
                lines.append(f"     - Occurred: {incident.get_time_ago_str()}")
                lines.append(
                    f"     - Severity: {incident.llm_severity.upper()}")
                lines.append(
                    f"     - Description: {incident.llm_analysis[:150]}...")
                if incident.matching_features:
                    lines.append(
                        f"     - Matched on: {', '.join(incident.matching_features)}")

        # Patterns
        if self.detected_patterns:
            lines.append("\nDetected Attack Patterns:")
            for pattern in self.detected_patterns:
                lines.append(f"  - {pattern}")

        # Summary stats
        lines.append("\nMemory Statistics:")
        lines.append(
            f"  - Total incidents in memory: {self.total_incidents_in_memory}")
        lines.append(
            f"  - Incidents from this IP: {self.incidents_from_this_ip}")

        return "\n".join(lines)


@dataclass
class MemoryStats:
    """System-wide memory statistics."""

    total_incidents: int = 0
    total_unique_ips: int = 0
    total_patterns: int = 0

    # Severity breakdown
    critical_incidents: int = 0
    high_incidents: int = 0
    medium_incidents: int = 0
    low_incidents: int = 0

    # Top threats
    top_threat_ips: List[tuple] = field(
        default_factory=list)  # (ip, threat_score)
    top_attack_types: List[tuple] = field(
        default_factory=list)  # (type, count)

    # Performance
    avg_query_time_ms: float = 0.0
    avg_storage_time_ms: float = 0.0

    # Memory utilization
    memory_utilization_rate: float = 0.0  # % of decisions that used memory

    def __str__(self) -> str:
        """String representation for logging."""
        return (
            f"Memory Stats: {self.total_incidents} incidents, "
            f"{self.total_unique_ips} unique IPs, "
            f"{self.memory_utilization_rate:.1%} utilization"
        )


@dataclass
class ThreatIncident:
    """
    Simplified incident model for test compatibility.
    
    This is a convenience wrapper that can be converted to IncidentRecord
    for storage in the memory system.
    """
    
    incident_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    ml_prediction: str
    ml_confidence: float
    llm_severity: str
    llm_analysis: str
    llm_reasoning: str = ""
    context_flags: List[str] = field(default_factory=list)
    response_actions: List[str] = field(default_factory=list)
    is_resolved: bool = False
    
    # Optional fields with defaults
    session_id: Optional[str] = None
    flow_id: Optional[str] = None
    ensemble_agreement: float = 0.0
    context_reasons: List[str] = field(default_factory=list)
    suspicion_score: float = 0.0
    llm_confidence: float = 0.0
    recommended_actions: List[str] = field(default_factory=list)
    response_plan: Optional[str] = None
    action_taken: Optional[str] = None
    was_successful: Optional[bool] = None
    
    def to_incident_record(self, session_id: Optional[str] = None, flow_id: Optional[str] = None) -> IncidentRecord:
        """
        Convert ThreatIncident to IncidentRecord for storage.
        
        Args:
            session_id: Session ID (uses self.session_id if not provided)
            flow_id: Flow ID (uses self.flow_id or incident_id if not provided)
            
        Returns:
            IncidentRecord instance
        """
        return IncidentRecord(
            incident_id=self.incident_id,
            session_id=session_id or self.session_id or "unknown-session",
            flow_id=flow_id or self.flow_id or self.incident_id,
            timestamp=self.timestamp,
            detected_at=self.timestamp,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            ml_prediction=self.ml_prediction,
            ml_confidence=self.ml_confidence,
            ensemble_agreement=self.ensemble_agreement if self.ensemble_agreement > 0 else self.ml_confidence,
            context_flags=self.context_flags,
            context_reasons=self.context_reasons if self.context_reasons else self.context_flags.copy(),
            suspicion_score=self.suspicion_score if self.suspicion_score > 0 else self.ml_confidence,
            llm_severity=self.llm_severity,
            llm_confidence=self.llm_confidence if self.llm_confidence > 0 else self.ml_confidence,
            llm_analysis=self.llm_analysis,
            llm_reasoning=self.llm_reasoning or self.llm_analysis,
            recommended_actions=self.recommended_actions if self.recommended_actions else self.response_actions.copy(),
            response_plan=self.response_plan,
            action_taken=self.action_taken or (", ".join(self.response_actions) if self.response_actions else None),
            was_successful=self.was_successful if self.was_successful is not None else (not self.is_resolved),
            notes=None,
            created_at=None
        )


@dataclass
class ThreatPattern:
    """Threat pattern detected from multiple incidents."""
    
    pattern_id: str  # Primary key, e.g., "TCP:445"
    pattern_name: str = ""  # Human-readable name
    pattern_type: str = ""  # e.g., "lateral_movement", "exfiltration"
    indicators: Dict[str, Any] = field(default_factory=dict)  # JSON object with pattern indicators
    incident_ids: str = "[]"  # JSON array of incident IDs
    occurrence_count: int = 1
    first_detected: str = ""
    last_detected: str = ""
    created_at: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            'pattern_id': self.pattern_id,
            'pattern_name': self.pattern_name,
            'pattern_type': self.pattern_type,
            'indicators': json.dumps(self.indicators),
            'incident_ids': self.incident_ids,
            'occurrence_count': self.occurrence_count,
            'first_detected': self.first_detected,
            'last_detected': self.last_detected,
            'created_at': self.created_at or datetime.now(timezone.utc).isoformat().replace('+00:00', '') + 'Z'
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ThreatPattern':
        """Create from database dictionary. Handles both uppercase and lowercase column names."""
        # Helper to get value with fallback to uppercase
        def get_val(key: str, default=None):
            return data.get(key, data.get(key.upper(), default))
        
        return cls(
            pattern_id=get_val('pattern_id', ''),
            pattern_name=get_val('pattern_name', ''),
            pattern_type=get_val('pattern_type', ''),
            indicators=json.loads(get_val('indicators', '{}')) if get_val('indicators') else {},
            incident_ids=get_val('incident_ids', '[]'),
            occurrence_count=get_val('occurrence_count', 1),
            first_detected=get_val('first_detected', ''),
            last_detected=get_val('last_detected', ''),
            created_at=get_val('created_at')
        )

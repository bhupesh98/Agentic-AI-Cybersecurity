"""
Agent State Management for Agentic Cybersecurity System.

This module defines the state schema used by LangGraph to pass data between nodes.
Based on Phase 1 requirements from immediate-guide.txt.

Author: Abhinav
Date: November 2025
"""

from typing import TypedDict, List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


# ============================================================================
# ENUMS
# ============================================================================

class AgentPhase(Enum):
    """Current phase of agent execution"""
    INITIALIZATION = "initialization"
    DATA_COLLECTION = "data_collection"
    ML_DETECTION = "ml_detection"
    LLM_ANALYSIS = "llm_analysis"
    MEMORY_LOOKUP = "memory_lookup"  # Phase 2: Memory system
    RESPONSE_PLANNING = "response_planning"
    EXECUTION = "execution"
    COMPLETED = "completed"
    ERROR = "error"


class ThreatLevel(Enum):
    """Threat severity levels"""
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class NetworkFlow:
    """
    Represents a single network flow.
    Simplified for Phase 1 - will be enhanced in later phases.
    """
    flow_id: str
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    duration: float = 0.0

    # Feature vector (for ML models - 78 features from your trained models)
    features: Optional[List[float]] = None

    # Labels (if available from dataset)
    label: Optional[str] = None
    is_malicious: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/storage"""
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "duration": self.duration,
            "label": self.label,
            "is_malicious": self.is_malicious
        }


@dataclass
class MLPrediction:
    """
    ML model prediction results.
    Stores predictions from the trained ensemble (RF + XGBoost).
    """
    flow_id: str
    timestamp: str

    # Individual model predictions
    rf_prediction: str  # "benign" or "malicious"
    rf_confidence: float
    xgb_prediction: str
    xgb_confidence: float

    # Ensemble result
    ensemble_prediction: str
    ensemble_confidence: float

    # Model agreement
    models_agree: bool
    agreement_score: float  # 0.0 to 1.0


@dataclass
class IncidentMemory:
    """
    Stored memory of past incidents.
    Used for Principle #6 - Memory Management.
    """
    incident_id: str
    timestamp: str
    src_ip: str
    attack_type: str
    severity: str
    action_taken: str
    was_successful: bool
    notes: str = ""


# ============================================================================
# AGENT STATE (LangGraph State Schema)
# ============================================================================

class AgentState(TypedDict):
    """
    Main state object passed between LangGraph nodes.
    
    This is the core data structure that flows through the entire agent workflow.
    Phase 1 focuses on: network flows, ML predictions, LLM analysis, and basic memory.
    """

    # ========== WORKFLOW MANAGEMENT ==========
    current_phase: AgentPhase
    session_id: str
    start_time: str
    messages: List[str]  # Log messages as we progress
    errors: List[Dict[str, Any]]  # Any errors encountered

    # ========== INPUT DATA ==========
    raw_network_flows: List[NetworkFlow]  # Collected network traffic

    # ========== ML DETECTION (Phase 1 - Day 2) ==========
    ml_predictions: List[MLPrediction]  # Predictions from your trained models
    detected_threats: List[Dict[str, Any]]  # Flows flagged as malicious

    # ========== LLM ANALYSIS (Phase 1 - Day 1) ==========
    llm_analysis: Dict[str, Any]  # LLM's contextual analysis
    llm_reasoning: str  # LLM's explanation of its decision

    # ========== MEMORY (Phase 1 - Day 3) ==========
    past_incidents: List[IncidentMemory]  # Retrieved from memory database
    memory_correlations: List[Dict[str, Any]]  # Connections to past incidents

    # ========== MEMORY PHASE 2 ==========
    # Memory context from Phase 2 memory system
    memory_contexts: List[Dict[str, Any]]
    stored_incident_ids: List[str]  # IDs of incidents stored in this run

    # ========== RESPONSE PLAN ==========
    response_plan: Dict[str, Any]  # Multi-step response plan generated by LLM
    actions_taken: List[Dict[str, Any]]  # Actions executed

    # ========== CONTEXT (for Phase 2) ==========
    context: Dict[str, Any]  # Contextual information (time, user, asset, etc.)

    # ========== METRICS ==========
    metrics: Dict[str, Any]  # Performance and Agentic AI metrics

    # ========== MULTI-AGENT ARCHITECTURE (Phase 2 refactor) ==========
    threat_intel_context: Dict[str, Any]   # enrichment from ThreatIntelAgent
    investigation_report: Dict[str, Any]   # structured report from InvestigationAgent
    decision_trace: List[Dict[str, Any]]   # accumulated per-session trace entries
    governance_decisions: List[Dict[str, Any]]  # approval/override records
    playbook: Dict[str, Any]               # dynamic playbook from ResponseAgent


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_initial_state(session_id: str) -> AgentState:
    """
    Create a fresh agent state for a new session.
    
    Args:
        session_id: Unique identifier for this agent session
        
    Returns:
        Initialized AgentState
    """
    return AgentState(
        current_phase=AgentPhase.INITIALIZATION,
        session_id=session_id,
        start_time=datetime.utcnow().isoformat(),
        messages=[],
        errors=[],
        raw_network_flows=[],
        ml_predictions=[],
        detected_threats=[],
        llm_analysis={},
        llm_reasoning="",
        past_incidents=[],
        memory_correlations=[],
        memory_contexts=[],  # Phase 2 memory system
        stored_incident_ids=[],  # Phase 2 memory system
        response_plan={},
        actions_taken=[],
        context={},
        metrics={},
        # Multi-agent fields
        threat_intel_context={},
        investigation_report={},
        decision_trace=[],
        governance_decisions=[],
        playbook={},
    )


def update_phase(state: AgentState, new_phase: AgentPhase) -> AgentState:
    """
    Update the current phase of agent execution.
    
    Args:
        state: Current agent state
        new_phase: Phase to transition to
        
    Returns:
        Updated state
    """
    state["current_phase"] = new_phase
    state["messages"].append(f"Phase transition: {new_phase.value}")
    return state


def log_error(state: AgentState, error: Exception, phase: str) -> AgentState:
    """
    Log an error to the state.
    
    Args:
        state: Current agent state
        error: Exception that occurred
        phase: Phase where error occurred
        
    Returns:
        Updated state
    """
    error_dict = {
        "timestamp": datetime.utcnow().isoformat(),
        "phase": phase,
        "error_type": type(error).__name__,
        "error_message": str(error)
    }
    state["errors"].append(error_dict)
    state["messages"].append(f"ERROR in {phase}: {str(error)}")
    return state


def add_message(state: AgentState, message: str) -> AgentState:
    """
    Add a message to the state log.
    
    Args:
        state: Current agent state
        message: Message to log
        
    Returns:
        Updated state
    """
    state["messages"].append(f"[{datetime.utcnow().isoformat()}] {message}")
    return state

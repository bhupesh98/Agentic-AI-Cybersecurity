"""
Agent Package for Agentic Cybersecurity System.

This package contains the core agent orchestration logic using LangGraph.

Modules:
    - state_management: Agent state schema and helper functions
    - workflow_graph: LangGraph workflow definition
    - nodes: Individual workflow nodes (to be created in future phases)
"""

from .state_management import (
    AgentState,
    AgentPhase,
    ThreatLevel,
    NetworkFlow,
    MLPrediction,
    IncidentMemory,
    create_initial_state,
    update_phase,
    log_error,
    add_message
)

from .workflow_graph import (
    create_workflow,
    run_agent,
    visualize_workflow
)

from .adaptive_learning_manager import (
    AdaptiveLearningManager,
    get_learning_manager,
    LearningMetrics,
    ThresholdConfig
)

from .feedback_manager import (
    FeedbackManager,
    get_feedback_manager,
    AnalystFeedback,
    FeedbackRule,
    FeedbackMetrics
)

__all__ = [
    # State management
    "AgentState",
    "AgentPhase",
    "ThreatLevel",
    "NetworkFlow",
    "MLPrediction",
    "IncidentMemory",
    "create_initial_state",
    "update_phase",
    "log_error",
    "add_message",
    # Workflow
    "create_workflow",
    "run_agent",
    "visualize_workflow",
    # Adaptive Learning
    "AdaptiveLearningManager",
    "get_learning_manager",
    "LearningMetrics",
    "ThresholdConfig",
    # Feedback Management
    "FeedbackManager",
    "get_feedback_manager",
    "AnalystFeedback",
    "FeedbackRule",
    "FeedbackMetrics",
]

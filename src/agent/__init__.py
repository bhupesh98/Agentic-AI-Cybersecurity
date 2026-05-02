"""
Agent Package for Agentic Cybersecurity System.

This package contains the core agent orchestration logic using LangGraph.

Modules:
    - state_management: Agent state schema and helper functions
    - workflow_graph: LangGraph workflow definition
    - nodes: Individual workflow nodes (to be created in future phases)
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
        add_message,
    )
    from .workflow_graph import create_workflow, run_agent, visualize_workflow
    from .adaptive_learning_manager import (
        AdaptiveLearningManager,
        get_learning_manager,
        LearningMetrics,
        ThresholdConfig,
    )
    from .feedback_manager import (
        FeedbackManager,
        get_feedback_manager,
        AnalystFeedback,
        FeedbackRule,
        FeedbackMetrics,
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

_EXPORTS = {
    "AgentState": (".state_management", "AgentState"),
    "AgentPhase": (".state_management", "AgentPhase"),
    "ThreatLevel": (".state_management", "ThreatLevel"),
    "NetworkFlow": (".state_management", "NetworkFlow"),
    "MLPrediction": (".state_management", "MLPrediction"),
    "IncidentMemory": (".state_management", "IncidentMemory"),
    "create_initial_state": (".state_management", "create_initial_state"),
    "update_phase": (".state_management", "update_phase"),
    "log_error": (".state_management", "log_error"),
    "add_message": (".state_management", "add_message"),
    "create_workflow": (".workflow_graph", "create_workflow"),
    "run_agent": (".workflow_graph", "run_agent"),
    "visualize_workflow": (".workflow_graph", "visualize_workflow"),
    "AdaptiveLearningManager": (".adaptive_learning_manager", "AdaptiveLearningManager"),
    "get_learning_manager": (".adaptive_learning_manager", "get_learning_manager"),
    "LearningMetrics": (".adaptive_learning_manager", "LearningMetrics"),
    "ThresholdConfig": (".adaptive_learning_manager", "ThresholdConfig"),
    "FeedbackManager": (".feedback_manager", "FeedbackManager"),
    "get_feedback_manager": (".feedback_manager", "get_feedback_manager"),
    "AnalystFeedback": (".feedback_manager", "AnalystFeedback"),
    "FeedbackRule": (".feedback_manager", "FeedbackRule"),
    "FeedbackMetrics": (".feedback_manager", "FeedbackMetrics"),
}


def __getattr__(name: str):
    """Lazy package exports avoid double-import warnings with ``python -m``."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    import importlib

    module_name, attr_name = _EXPORTS[name]
    module = importlib.import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value

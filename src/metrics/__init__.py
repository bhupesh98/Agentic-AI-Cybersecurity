"""
Metrics Module for Agentic AI System.

Provides comprehensive measurement of 7 Agentic AI principles:
1. Self-Learning (baseline tracking)
2. Contextual Awareness (partial implementation)
3. Goal-Directed Behavior (active)
4. Tool Utilization (active)
5. Planning & Reasoning (active)
6. Memory Management (active)
7. Feedback Incorporation (baseline tracking)

IMPORTANT NOTE:
Current formulas are PRELIMINARY versions for rapid integration.
They will be refined to match research-grade formulations from
the comprehensive framework document in Week 3.

Usage:
    from src.metrics import get_metrics_collector
    
    collector = get_metrics_collector()
    collector.record_context_analysis(flags=['off_hours'], score=0.75)
    collector.save_metrics()

Author: Abhinav
Date: November 2025
"""

from src.metrics.collector import MetricsCollector, get_metrics_collector
from src.metrics.storage import MetricsStorageManager
from src.metrics.models import (
    AgenticAIMetricsSummary,
    SelfLearningMetrics,
    ContextualAwarenessMetrics,
    GoalDirectedMetrics,
    ToolUtilizationMetrics,
    PlanningReasoningMetrics,
    MemoryManagementMetrics,
    FeedbackIncorporationMetrics,
    PrincipleStatus,
    MetricStatus
)

__all__ = [
    # Main interface
    'get_metrics_collector',
    'MetricsCollector',
    'MetricsStorageManager',

    # Data models
    'AgenticAIMetricsSummary',
    'SelfLearningMetrics',
    'ContextualAwarenessMetrics',
    'GoalDirectedMetrics',
    'ToolUtilizationMetrics',
    'PlanningReasoningMetrics',
    'MemoryManagementMetrics',
    'FeedbackIncorporationMetrics',

    # Enums
    'PrincipleStatus',
    'MetricStatus'
]

__version__ = '1.0.0-preliminary'
__author__ = 'Rishabh'

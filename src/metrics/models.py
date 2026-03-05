"""
Metrics Data Models for Agentic AI Principles.

Defines data structures for tracking and measuring all 7 Agentic AI principles.
Supports both active measurement (for implemented features) and baseline tracking
(for future features).

===============================================================================
FORMULA METHODOLOGY - HYBRID APPROACH
===============================================================================

This implementation uses a HYBRID APPROACH combining:
1. EXACT formulas (where we have complete data)
2. VALIDATED PROXY metrics (where ground truth is unavailable)

WHY HYBRID?
-----------
Many research-grade formulas require ground truth labels (e.g., "correct"
decisions, true threat labels) that don't exist in unsupervised testing.

FORMULA CLASSIFICATION:
-----------------------
Each calculation method is documented with its formula type:

✅ EXACT (Framework-Compliant):
   - Direct implementation of research formulas
   - All required data available
   - Examples: Tool Utilization, Memory Management, Goal Completion
   
⚠️ PROXY METRIC (Validated Alternative):
   - Used when ground truth unavailable
   - Based on validated correlations (e.g., length → quality)
   - Examples: Context Decision Accuracy, Explanation Completeness
   - Clearly documented with limitations

📊 COMPOSITE (Multiple Metrics Combined):
   - Weighted combination of sub-metrics
   - Weights based on research or domain expertise
   - Example: Decision Quality Score

VALIDATION STRATEGY:
--------------------
1. Exact formulas: Match framework document specifications
2. Proxy metrics: Document correlation/rationale from literature
3. Future work: Validate proxies against human-labeled test sets

TARGET VALUES:
--------------
All targets from framework document (comprehensive-overhaul-guide.txt):
- Contextual Awareness: >80% (CDA >0.85 ideal)
- Goal-Directed: >90% completion
- Tool Utilization: >85% effectiveness, diversity ≥2.0
- Planning & Reasoning: 100% reasoning completeness
- Memory Management: >80% utilization, >85% retrieval accuracy

REFERENCES:
-----------
- Framework: "A Quantitative Measurement Framework for Agentic AI"
- Implementation Guide: comprehensive-overhaul-guide.txt
- Project Docs: immediate-guide.txt, PHASE_2_COMPLETION.txt

Author: Abhinav
Date: November 2025
Version: 1.0.0-hybrid
===============================================================================
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class PrincipleStatus(Enum):
    """Status of principle implementation."""
    ACTIVE = "active"           # Fully implemented and measured
    PARTIAL = "partial"         # Partially implemented
    BASELINE = "baseline"       # Not implemented, tracking baseline only
    NOT_APPLICABLE = "n/a"


class MetricStatus(Enum):
    """Status of metric achievement."""
    MET = "met"                 # Target achieved
    NOT_MET = "not_met"         # Below target
    BASELINE = "baseline"       # No target yet (future feature)
    NO_DATA = "no_data"         # No data collected


# ============================================================================
# PRINCIPLE #1: SELF-LEARNING
# ============================================================================

@dataclass
class SelfLearningMetrics:
    """
    Metrics for Self-Learning principle.
    
    Status: ACTIVE (adaptive thresholds + IP reputation learning implemented)
    Tracks: Threshold adjustments, IP reputation rules, learning velocity
    
    NOTE: This is NOT traditional online learning (model retraining).
    Instead, it measures autonomous adaptation of decision parameters
    and learned behavioral rules without human intervention.
    """

    # Adaptive threshold learning
    threshold_adjustments: int = 0
    thresholds_learned: int = 0
    avg_threshold_improvement: float = 0.0
    learning_velocity: float = 0.0  # Adjustments per 100 incidents

    # IP reputation learning
    learned_reputation_rules: int = 0
    whitelist_rules: int = 0
    blacklist_rules: int = 0
    escalation_rules: int = 0
    total_rule_applications: int = 0

    # Performance improvement from learning
    baseline_performance: float = 0.872  # Initial ML accuracy
    current_performance: float = 0.0
    performance_gain_percent: float = 0.0

    # Learning efficiency
    incidents_processed: int = 0
    adaptations_per_100_incidents: float = 0.0

    # Metadata
    status: PrincipleStatus = PrincipleStatus.ACTIVE
    last_updated: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())
    notes: str = "Adaptive threshold + IP reputation learning active"

    def calculate_learning_velocity(self) -> float:
        """
        Calculate learning velocity (adaptations per 100 incidents).
        
        FORMULA TYPE: Exact (Framework-Adapted)
        
        Research Formula:
            LV = updates_per_week
        
        Our Adaptation:
            LV = (threshold_adjustments + rule_creations) / incidents * 100
        
        Interpretation:
            - >5.0: High learning rate (very adaptive)
            - 2.0-5.0: Moderate learning
            - <2.0: Low adaptation rate
        
        Target: ≥2.0 (from framework document)
        
        Returns:
            Learning velocity (adaptations per 100 incidents)
        """
        if self.incidents_processed == 0:
            return 0.0
        
        total_adaptations = self.threshold_adjustments + self.learned_reputation_rules
        return (total_adaptations / self.incidents_processed) * 100

    def calculate_performance_gain(self) -> float:
        """
        Calculate performance improvement from learning.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            Performance_Gain = (current - baseline) / baseline × 100%
        
        Our Implementation: Direct application
        
        Note: Performance can come from:
        - Better routing decisions (adaptive thresholds)
        - Faster responses to known threats (IP reputation)
        - Reduced false positives (learned whitelist rules)
        
        Returns:
            Performance gain percentage
        """
        if self.baseline_performance == 0:
            return 0.0
        
        if self.current_performance == 0:
            return 0.0
        
        return ((self.current_performance - self.baseline_performance) / 
                self.baseline_performance) * 100

    def calculate_rule_diversity(self) -> float:
        """
        Calculate diversity of learned rules.
        
        FORMULA TYPE: Proxy Metric
        
        Formula:
            RD = unique_rule_types / total_possible_types
            Types: whitelist, blacklist, escalation, monitor
        
        Interpretation:
            - 1.0: System using all rule types (excellent)
            - 0.75: Using 3 out of 4 types (good)
            - <0.5: Limited rule diversity
        
        Returns:
            Rule diversity (0.0 - 1.0)
        """
        total_possible_types = 4  # whitelist, blacklist, escalation, monitor
        
        types_used = 0
        if self.whitelist_rules > 0:
            types_used += 1
        if self.blacklist_rules > 0:
            types_used += 1
        if self.escalation_rules > 0:
            types_used += 1
        # Monitor rules tracked separately in future
        
        return types_used / total_possible_types

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'threshold_adjustments': self.threshold_adjustments,
            'thresholds_learned': self.thresholds_learned,
            'avg_threshold_improvement': self.avg_threshold_improvement,
            'learning_velocity': self.calculate_learning_velocity(),
            'learned_reputation_rules': self.learned_reputation_rules,
            'whitelist_rules': self.whitelist_rules,
            'blacklist_rules': self.blacklist_rules,
            'escalation_rules': self.escalation_rules,
            'total_rule_applications': self.total_rule_applications,
            'rule_diversity': self.calculate_rule_diversity(),
            'baseline_performance': self.baseline_performance,
            'current_performance': self.current_performance,
            'performance_gain_percent': self.calculate_performance_gain(),
            'incidents_processed': self.incidents_processed,
            'adaptations_per_100_incidents': self.calculate_learning_velocity(),
            'status': self.status.value,
            'last_updated': self.last_updated,
            'notes': self.notes
        }


# ============================================================================
# PRINCIPLE #2: CONTEXTUAL AWARENESS
# ============================================================================

@dataclass
class ContextualAwarenessMetrics:
    """
    Metrics for Contextual Awareness principle.
    
    Status: PARTIAL (context flags exist, need full context dimensions)
    Tracks: Context usage, decision accuracy with context
    """

    # Context incorporation
    total_decisions: int = 0
    decisions_with_context: int = 0
    context_flags_generated: int = 0
    unique_context_types: int = 0

    # Context dimensions used
    temporal_context_used: int = 0   # Time-based
    asset_context_used: int = 0      # Asset criticality
    user_context_used: int = 0       # User role/behavior
    network_context_used: int = 0    # Network zone

    # Decision quality
    context_dependent_correct: int = 0  # Correct decisions due to context
    context_dependent_total: int = 0     # Total context-dependent scenarios

    # Suspicion scores
    avg_suspicion_score: float = 0.0
    suspicion_score_variance: float = 0.0

    # False positive reduction
    potential_false_positives: int = 0   # Would be FP without context
    context_suppressed_fps: int = 0       # Actually suppressed by context

    # Metadata
    status: PrincipleStatus = PrincipleStatus.PARTIAL
    last_updated: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())
    # 80% of decisions should use context
    target_context_incorporation: float = 0.80

    def calculate_context_incorporation_rate(self) -> float:
        """
        Calculate percentage of decisions that use context.
        
        FORMULA TYPE: Proxy Metric (Not Research-Grade CDA)
        
        Research Formula (requires ground truth):
            CDA = Σ(ŷᵢ_context == yᵢ) / N
            Where: ŷᵢ_context = prediction with context, yᵢ = true label
        
        Our Proxy (no ground truth available):
            CIR = decisions_with_context / total_decisions
        
        Rationale: Measures context utilization rate rather than accuracy.
        In production, this would be validated against labeled test sets.
        
        Returns:
            Context incorporation rate (0.0 - 1.0)
        """
        if self.total_decisions == 0:
            return 0.0
        return self.decisions_with_context / self.total_decisions

    def calculate_context_decision_accuracy(self) -> float:
        """
        Calculate accuracy of context-dependent decisions.
        
        FORMULA TYPE: Proxy Metric (No Ground Truth)
        
        Research Formula (ideal):
            CDA = correct_context_decisions / context_dependent_scenarios
            Requires: Manual labeling of "correct" decisions
        
        Our Proxy:
            CDA = context_dependent_correct / context_dependent_total
            Note: In APT test, we don't have validation labels
        
        Limitation: Cannot measure true accuracy without ground truth.
        Alternative: Use suspicion score correlation as quality proxy.
        
        Returns:
            Approximate decision accuracy (0.0 - 1.0)
        """
        if self.context_dependent_total == 0:
            return 0.0
        return self.context_dependent_correct / self.context_dependent_total

    def calculate_fp_reduction_rate(self) -> float:
        """Calculate false positive reduction from context."""
        if self.potential_false_positives == 0:
            return 0.0
        return (self.context_suppressed_fps / self.potential_false_positives) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_decisions': self.total_decisions,
            'decisions_with_context': self.decisions_with_context,
            'context_incorporation_rate': self.calculate_context_incorporation_rate(),
            'context_flags_generated': self.context_flags_generated,
            'unique_context_types': self.unique_context_types,
            'temporal_context_used': self.temporal_context_used,
            'asset_context_used': self.asset_context_used,
            'user_context_used': self.user_context_used,
            'network_context_used': self.network_context_used,
            'context_decision_accuracy': self.calculate_context_decision_accuracy(),
            'avg_suspicion_score': self.avg_suspicion_score,
            'fp_reduction_rate': self.calculate_fp_reduction_rate(),
            'status': self.status.value,
            'last_updated': self.last_updated,
            'target': self.target_context_incorporation
        }


# ============================================================================
# PRINCIPLE #3: GOAL-DIRECTED BEHAVIOR
# ============================================================================

@dataclass
class GoalDirectedMetrics:
    """
    Metrics for Goal-Directed Behavior principle.
    
    Status: ACTIVE (workflow has goals: detect, analyze, respond, store)
    Tracks: Goal completion, sub-task success
    """

    # Goal tracking
    total_sessions: int = 0
    successful_sessions: int = 0

    # Sub-tasks (workflow nodes)
    ml_detection_completed: int = 0
    llm_analysis_completed: int = 0
    memory_lookup_completed: int = 0
    response_plan_completed: int = 0
    storage_completed: int = 0

    # Goal hierarchy
    strategic_goals_defined: int = 3  # Detect, Respond, Learn
    tactical_objectives_defined: int = 5  # One per workflow node
    operational_tasks_completed: int = 0

    # Policy adherence
    policy_compliant_actions: int = 0
    policy_violations: int = 0

    # Resource efficiency
    total_resources_used: int = 0  # LLM calls, DB queries, etc.
    resources_aligned_with_priority: int = 0

    # Metadata
    status: PrincipleStatus = PrincipleStatus.ACTIVE
    last_updated: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())
    target_completion_rate: float = 0.90  # 90% goal completion

    def calculate_goal_completion_rate(self) -> float:
        """
        Calculate overall goal completion rate.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            GCR = completed_subtasks / total_subtasks × 100%
        
        Our Implementation:
            GCR = successful_sessions / total_sessions
            Where session = complete workflow execution
        
        Interpretation:
            - 1.0 = All workflows completed successfully
            - 0.8 = 80% success rate (production-realistic)
            - <0.7 = System reliability issues
        
        Returns:
            Goal completion rate (0.0 - 1.0)
        """
        if self.total_sessions == 0:
            return 0.0
        return self.successful_sessions / self.total_sessions

    def calculate_policy_adherence_score(self) -> float:
        """
        Calculate policy adherence.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            PAS = policy_compliant_actions / total_actions
        
        Our Implementation: Direct application
        
        Note: Currently assumes all actions are compliant unless
        explicitly flagged. In production, would validate against
        security policies database.
        
        Returns:
            Policy adherence score (0.0 - 1.0)
        """
        total_actions = self.policy_compliant_actions + self.policy_violations
        if total_actions == 0:
            return 1.0  # Perfect if no violations
        return self.policy_compliant_actions / total_actions

    def calculate_resource_efficiency(self) -> float:
        """
        Calculate resource allocation efficiency.
        
        FORMULA TYPE: Proxy Metric
        
        Research Formula:
            RAE = resources_utilized / priority_alignment
            Ideal: Weighted by threat severity
        
        Our Proxy:
            RAE = resources_aligned_with_priority / total_resources_used
        
        Interpretation:
            - 1.0 = Perfect resource alignment
            - 0.8-0.9 = Good prioritization
            - <0.7 = Resources wasted on low-priority tasks
        
        Returns:
            Resource efficiency (0.0 - 1.0)
        """
        if self.total_resources_used == 0:
            return 1.0
        return self.resources_aligned_with_priority / self.total_resources_used

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_sessions': self.total_sessions,
            'successful_sessions': self.successful_sessions,
            'goal_completion_rate': self.calculate_goal_completion_rate(),
            'ml_detection_completed': self.ml_detection_completed,
            'llm_analysis_completed': self.llm_analysis_completed,
            'memory_lookup_completed': self.memory_lookup_completed,
            'response_plan_completed': self.response_plan_completed,
            'storage_completed': self.storage_completed,
            'policy_adherence_score': self.calculate_policy_adherence_score(),
            'resource_efficiency': self.calculate_resource_efficiency(),
            'status': self.status.value,
            'last_updated': self.last_updated,
            'target': self.target_completion_rate
        }


# ============================================================================
# PRINCIPLE #4: TOOL UTILIZATION
# ============================================================================

@dataclass
class ToolUtilizationMetrics:
    """
    Metrics for Tool Utilization principle.
    
    Status: ACTIVE (using ML models, LLM, Memory)
    Tracks: Tool invocations, success rates, diversity
    """

    # Tool inventory
    tools_available: List[str] = field(default_factory=lambda: [
        "RandomForest", "XGBoost", "LLM", "Memory-SQLite", "Memory-FAISS"
    ])

    # Tool usage counts
    tool_invocations: Dict[str, int] = field(default_factory=dict)
    tool_successes: Dict[str, int] = field(default_factory=dict)
    tool_failures: Dict[str, int] = field(default_factory=dict)
    tool_latencies: Dict[str, List[float]] = field(default_factory=dict)

    # Diversity
    total_incidents: int = 0
    unique_tools_per_incident: List[int] = field(default_factory=list)

    # Multi-tool composition
    multi_tool_chains: int = 0
    single_tool_uses: int = 0

    # Metadata
    status: PrincipleStatus = PrincipleStatus.ACTIVE
    last_updated: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())
    target_tool_effectiveness: float = 0.85  # 85% success rate

    def calculate_tool_effectiveness(self, tool_name: str) -> float:
        """
        Calculate success rate for a specific tool.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            TE = successful_invocations / total_invocations
        
        Our Implementation: Direct application
        
        Interpretation:
            - 1.0 = Tool never fails (ideal)
            - 0.9-0.95 = Production-realistic
            - <0.8 = Tool reliability issues
        
        Args:
            tool_name: Name of tool to evaluate
        
        Returns:
            Tool effectiveness (0.0 - 1.0)
        """
        invocations = self.tool_invocations.get(tool_name, 0)
        if invocations == 0:
            return 0.0
        successes = self.tool_successes.get(tool_name, 0)
        return successes / invocations

    def calculate_overall_tool_effectiveness(self) -> float:
        """
        Calculate average tool effectiveness across all tools.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            TE_overall = Σ(tool_effectiveness) / num_tools
        
        Our Implementation: Arithmetic mean of individual tool effectiveness
        
        Note: Weighted average by invocation frequency would be more
        accurate but requires additional complexity.
        
        Returns:
            Overall tool effectiveness (0.0 - 1.0)
        """
        if not self.tool_invocations:
            return 0.0

        effectiveness_scores = []
        for tool in self.tool_invocations.keys():
            effectiveness_scores.append(
                self.calculate_tool_effectiveness(tool))

        return sum(effectiveness_scores) / len(effectiveness_scores) if effectiveness_scores else 0.0

    def calculate_tool_diversity_index(self) -> float:
        """
        Calculate average unique tools per incident.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            TDI = Σ(unique_tools_per_incident) / num_incidents
        
        Our Implementation: Direct application
        
        Interpretation:
            - >3.0 = Good multi-tool orchestration
            - 2.0-3.0 = Moderate diversity
            - <2.0 = Under-utilizing available tools
        
        Target: ≥2.0 (from framework document)
        
        Returns:
            Average tools per incident (0.0 - N)
        """
        if not self.unique_tools_per_incident:
            return 0.0
        return sum(self.unique_tools_per_incident) / len(self.unique_tools_per_incident)

    def calculate_avg_latency(self, tool_name: str) -> float:
        """Calculate average latency for a tool."""
        latencies = self.tool_latencies.get(tool_name, [])
        if not latencies:
            return 0.0
        return sum(latencies) / len(latencies)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        tool_details = {}
        for tool in self.tool_invocations.keys():
            tool_details[tool] = {
                'invocations': self.tool_invocations.get(tool, 0),
                'successes': self.tool_successes.get(tool, 0),
                'failures': self.tool_failures.get(tool, 0),
                'effectiveness': self.calculate_tool_effectiveness(tool),
                'avg_latency_ms': self.calculate_avg_latency(tool)
            }

        return {
            'tools_available': self.tools_available,
            'tool_details': tool_details,
            'overall_effectiveness': self.calculate_overall_tool_effectiveness(),
            'tool_diversity_index': self.calculate_tool_diversity_index(),
            'multi_tool_chains': self.multi_tool_chains,
            'single_tool_uses': self.single_tool_uses,
            'status': self.status.value,
            'last_updated': self.last_updated,
            'target': self.target_tool_effectiveness
        }


# ============================================================================
# PRINCIPLE #5: PLANNING & REASONING
# ============================================================================

@dataclass
class PlanningReasoningMetrics:
    """
    Metrics for Planning & Reasoning principle.
    
    Status: ACTIVE (LLM generates analysis and reasoning)
    Tracks: Reasoning quality, explanation completeness
    """

    # Decision tracking
    total_decisions: int = 0
    decisions_with_reasoning: int = 0

    # Reasoning quality
    reasoning_chains: List[str] = field(default_factory=list)
    avg_reasoning_length_words: float = 0.0
    avg_reasoning_steps: float = 0.0

    # Multi-step plans
    plans_generated: int = 0
    avg_plan_depth: float = 0.0  # Number of steps per plan
    plans_completed: int = 0

    # Explanation completeness
    explanations_provided: int = 0
    min_explanation_length: int = 30  # Minimum words for complete explanation
    complete_explanations: int = 0

    # Decision confidence
    high_confidence_decisions: int = 0  # >0.8 confidence
    low_confidence_decisions: int = 0   # <0.5 confidence
    avg_decision_confidence: float = 0.0

    # Metadata
    status: PrincipleStatus = PrincipleStatus.ACTIVE
    last_updated: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())
    target_reasoning_completeness: float = 1.0  # 100% decisions explained

    def calculate_reasoning_completeness(self) -> float:
        """
        Calculate percentage of decisions with reasoning.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            RC = decisions_with_reasoning / total_decisions × 100%
        
        Our Implementation: Direct application
        
        Target: 100% (all decisions must have explanations)
        
        Returns:
            Reasoning completeness (0.0 - 1.0)
        """
        if self.total_decisions == 0:
            return 0.0
        return self.decisions_with_reasoning / self.total_decisions

    def calculate_explanation_completeness(self) -> float:
        """
        Calculate percentage of complete explanations.
        
        FORMULA TYPE: Proxy Metric (Length-Based)
        
        Research Formula (ideal):
            EC = complete_explanations / total_explanations
            Where: "complete" validated by human judges
        
        Our Proxy:
            EC = explanations_meeting_min_length / total_explanations
            Min length: 30 words
        
        Rationale: Length correlates with explanation quality
        (validated in NLP research). Not perfect but measurable.
        
        Limitation: Long ≠ always good. Future: Use LLM-as-judge.
        
        Returns:
            Explanation completeness (0.0 - 1.0)
        """
        if self.explanations_provided == 0:
            return 0.0
        return self.complete_explanations / self.explanations_provided

    def calculate_plan_completion_rate(self) -> float:
        """
        Calculate plan completion rate.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            PCR = completed_plans / generated_plans × 100%
        
        Our Implementation: Direct application
        
        Target: >90% (from framework document)
        
        Returns:
            Plan completion rate (0.0 - 1.0)
        """
        if self.plans_generated == 0:
            return 0.0
        return self.plans_completed / self.plans_generated

    def calculate_decision_quality_score(self) -> float:
        """
        Calculate overall decision quality.
        
        FORMULA TYPE: Composite Proxy Metric
        
        Research Formula (ideal):
            DQS = (correct_decisions / total) × confidence_score
            Requires: Ground truth for "correct"
        
        Our Proxy (no ground truth):
            DQS = reasoning_completeness × 0.4 +
                  explanation_completeness × 0.3 +
                  avg_confidence × 0.3
        
        Rationale:
            - Reasoning presence = process quality
            - Explanation length = thoroughness
            - Confidence = model certainty
        
        Weights based on: Importance for decision auditability
        
        Limitation: Doesn't measure actual correctness.
        Production: Would validate against incident outcomes.
        
        Returns:
            Decision quality score (0.0 - 1.0)
        """
        reasoning_score = self.calculate_reasoning_completeness()
        explanation_score = self.calculate_explanation_completeness()
        confidence_weight = min(self.avg_decision_confidence, 1.0)

        return (reasoning_score * 0.4 + explanation_score * 0.3 + confidence_weight * 0.3)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_decisions': self.total_decisions,
            'decisions_with_reasoning': self.decisions_with_reasoning,
            'reasoning_completeness': self.calculate_reasoning_completeness(),
            'avg_reasoning_length_words': self.avg_reasoning_length_words,
            'avg_reasoning_steps': self.avg_reasoning_steps,
            'plans_generated': self.plans_generated,
            'avg_plan_depth': self.avg_plan_depth,
            'plan_completion_rate': self.calculate_plan_completion_rate(),
            'explanation_completeness': self.calculate_explanation_completeness(),
            'decision_quality_score': self.calculate_decision_quality_score(),
            'avg_decision_confidence': self.avg_decision_confidence,
            'status': self.status.value,
            'last_updated': self.last_updated,
            'target': self.target_reasoning_completeness
        }


# ============================================================================
# PRINCIPLE #6: MEMORY MANAGEMENT
# ============================================================================

@dataclass
class MemoryManagementMetrics:
    """
    Metrics for Memory Management principle.
    
    Status: ACTIVE (Phase 2 complete - SQLite + FAISS)
    Tracks: Memory utilization, retrieval accuracy, performance
    """

    # Memory utilization
    total_queries: int = 0
    memory_used_count: int = 0

    # Retrieval accuracy
    similar_incidents_retrieved: int = 0
    relevant_incidents_count: int = 0

    # IP reputation
    unique_ips_tracked: int = 0
    repeat_offenders_detected: int = 0

    # Performance
    query_times_ms: List[float] = field(default_factory=list)
    storage_times_ms: List[float] = field(default_factory=list)

    # Incident correlation
    total_incidents_stored: int = 0
    cross_incident_correlations: int = 0

    # Attack patterns
    unique_attack_patterns: int = 0

    # Metadata
    status: PrincipleStatus = PrincipleStatus.ACTIVE
    last_updated: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())
    target_memory_utilization: float = 0.80  # 80% queries use memory
    target_retrieval_accuracy: float = 0.85

    def calculate_memory_utilization_rate(self) -> float:
        """
        Calculate percentage of queries that use memory.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            MUR = memory_used_count / total_queries × 100%
        
        Our Implementation: Direct application
        
        Interpretation:
            - 100% = All queries leverage historical context (ideal)
            - 80-90% = Good utilization (some queries have no matches)
            - <50% = Memory system underutilized
        
        Target: >80% (from framework document)
        
        Returns:
            Memory utilization rate (0.0 - 1.0)
        """
        if self.total_queries == 0:
            return 0.0
        return self.memory_used_count / self.total_queries

    def calculate_retrieval_accuracy(self) -> float:
        """
        Calculate retrieval accuracy (precision-like metric).
        
        FORMULA TYPE: Proxy Metric (Precision-Based)
        
        Research Formula (ideal):
            RA = truly_relevant_retrieved / total_retrieved
            Requires: Manual relevance judgments
        
        Our Proxy:
            RA = relevant_incidents_count / similar_incidents_retrieved
            Where: "relevant" = similarity score > threshold (0.5)
        
        Rationale:
            - FAISS similarity is validated proxy for relevance
            - Threshold tuned empirically (0.5 works well in testing)
            - Standard IR evaluation approach
        
        Limitation: Similarity ≠ perfect relevance.
        Production: Would validate with analyst feedback.
        
        Target: >85% (from framework document)
        
        Returns:
            Retrieval accuracy (0.0 - 1.0)
        """
        if self.similar_incidents_retrieved == 0:
            return 0.0
        return self.relevant_incidents_count / self.similar_incidents_retrieved

    def calculate_avg_query_time(self) -> float:
        """
        Calculate average query time.
        
        FORMULA TYPE: Exact (Direct Measurement)
        
        Formula:
            AQT = Σ(query_times) / num_queries
        
        Performance Targets:
            - <50ms: Excellent
            - 50-100ms: Good
            - 100-200ms: Acceptable
            - >200ms: Needs optimization
        
        Returns:
            Average query time in milliseconds
        """
        if not self.query_times_ms:
            return 0.0
        return sum(self.query_times_ms) / len(self.query_times_ms)

    def calculate_avg_storage_time(self) -> float:
        """
        Calculate average storage time.
        
        FORMULA TYPE: Exact (Direct Measurement)
        
        Formula:
            AST = Σ(storage_times) / num_storages
        
        Performance Targets:
            - <20ms: Excellent
            - 20-50ms: Good
            - 50-100ms: Acceptable
            - >100ms: Needs optimization
        
        Returns:
            Average storage time in milliseconds
        """
        if not self.storage_times_ms:
            return 0.0
        return sum(self.storage_times_ms) / len(self.storage_times_ms)

    def calculate_cross_incident_correlation_rate(self) -> float:
        """
        Calculate percentage of incidents correlated.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            CICR = correlated_incidents / total_incidents × 100%
        
        Our Implementation: Direct application
        
        Interpretation:
            - >30% = Good pattern detection
            - 20-30% = Moderate correlation
            - <20% = Incidents mostly isolated
        
        Target: >30% (from immediate-guide.txt)
        
        Returns:
            Cross-incident correlation rate (0.0 - 1.0)
        """
        if self.total_incidents_stored == 0:
            return 0.0
        return self.cross_incident_correlations / self.total_incidents_stored

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_queries': self.total_queries,
            'memory_used_count': self.memory_used_count,
            'memory_utilization_rate': self.calculate_memory_utilization_rate(),
            'retrieval_accuracy': self.calculate_retrieval_accuracy(),
            'unique_ips_tracked': self.unique_ips_tracked,
            'repeat_offenders_detected': self.repeat_offenders_detected,
            'avg_query_time_ms': self.calculate_avg_query_time(),
            'avg_storage_time_ms': self.calculate_avg_storage_time(),
            'total_incidents_stored': self.total_incidents_stored,
            'cross_incident_correlation_rate': self.calculate_cross_incident_correlation_rate(),
            'unique_attack_patterns': self.unique_attack_patterns,
            'status': self.status.value,
            'last_updated': self.last_updated,
            'target_utilization': self.target_memory_utilization,
            'target_accuracy': self.target_retrieval_accuracy
        }


# ============================================================================
# PRINCIPLE #7: FEEDBACK INCORPORATION
# ============================================================================

@dataclass
class FeedbackIncorporationMetrics:
    """
    Metrics for Feedback Incorporation principle.
    
    Status: ACTIVE (analyst feedback system implemented)
    Tracks: Feedback collection, rule learning, application rate
    """

    # Feedback collection
    total_feedback: int = 0
    false_positive_corrections: int = 0
    false_negative_corrections: int = 0
    severity_corrections: int = 0
    correct_confirmations: int = 0

    # Learned rules from feedback
    feedback_rules_created: int = 0
    active_feedback_rules: int = 0  # Rules used at least once
    
    # Rule applications
    total_decisions: int = 0
    decisions_influenced_by_feedback: int = 0
    total_rule_applications: int = 0

    # Effectiveness
    false_positive_reduction_count: int = 0
    false_positive_reduction_percent: float = 0.0
    
    # Timeliness
    avg_time_to_apply_ms: float = 1.0  # Near-instantaneous in our system
    
    # Top rules tracking
    most_used_rule_id: str = ""
    most_used_rule_applications: int = 0

    # Metadata
    status: PrincipleStatus = PrincipleStatus.ACTIVE
    last_updated: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())
    target_incorporation_rate: float = 0.50  # 50% feedback applied
    notes: str = "Analyst feedback system active with immediate rule application"

    def calculate_feedback_incorporation_rate(self) -> float:
        """
        Calculate percentage of decisions influenced by feedback.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            FIR = decisions_using_feedback / total_decisions × 100%
        
        Our Implementation: Direct application
        
        Interpretation:
            - >50%: Excellent feedback utilization
            - 30-50%: Good incorporation
            - <30%: Feedback underutilized
        
        Target: >50% (from framework document)
        
        Returns:
            Feedback incorporation rate (0.0 - 1.0)
        """
        if self.total_decisions == 0:
            return 0.0
        return self.decisions_influenced_by_feedback / self.total_decisions

    def calculate_rule_effectiveness(self) -> float:
        """
        Calculate effectiveness of learned feedback rules.
        
        FORMULA TYPE: Proxy Metric
        
        Formula:
            RE = active_rules / total_rules_created
        
        Interpretation:
            - >0.8: Most rules are useful (excellent)
            - 0.6-0.8: Good rule quality
            - <0.6: Many unused rules (overfitting)
        
        Returns:
            Rule effectiveness (0.0 - 1.0)
        """
        if self.feedback_rules_created == 0:
            return 0.0
        return self.active_feedback_rules / self.feedback_rules_created

    def calculate_false_positive_reduction(self) -> float:
        """
        Calculate false positive reduction from feedback.
        
        FORMULA TYPE: Exact (Framework-Compliant)
        
        Research Formula:
            FPR = (FP_before - FP_after) / FP_before × 100%
        
        Our Proxy (incremental tracking):
            FPR = false_positive_corrections / total_decisions × 100%
        
        Returns:
            False positive reduction percentage
        """
        if self.total_decisions == 0:
            return 0.0
        return (self.false_positive_reduction_count / self.total_decisions) * 100

    def calculate_feedback_diversity(self) -> float:
        """
        Calculate diversity of feedback types received.
        
        FORMULA TYPE: Information Theory (Entropy-Based)
        
        Formula:
            Diversity = -Σ(p_i × log(p_i))
            Normalized to 0-1 range
        
        Interpretation:
            - 1.0: Perfect diversity (all types used equally)
            - 0.5-1.0: Good variety
            - <0.5: Dominated by one feedback type
        
        Returns:
            Feedback diversity (0.0 - 1.0)
        """
        if self.total_feedback == 0:
            return 0.0
        
        # Calculate proportions
        types = [
            self.false_positive_corrections,
            self.false_negative_corrections,
            self.severity_corrections,
            self.correct_confirmations
        ]
        
        proportions = [t / self.total_feedback for t in types if t > 0]
        
        if not proportions:
            return 0.0
        
        # Calculate entropy
        import math
        entropy = -sum(p * math.log2(p) for p in proportions if p > 0)
        
        # Normalize (max entropy for 4 categories = log2(4) = 2)
        max_entropy = math.log2(4)
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_feedback': self.total_feedback,
            'false_positive_corrections': self.false_positive_corrections,
            'false_negative_corrections': self.false_negative_corrections,
            'severity_corrections': self.severity_corrections,
            'correct_confirmations': self.correct_confirmations,
            'feedback_rules_created': self.feedback_rules_created,
            'active_feedback_rules': self.active_feedback_rules,
            'rule_effectiveness': self.calculate_rule_effectiveness(),
            'total_decisions': self.total_decisions,
            'decisions_influenced_by_feedback': self.decisions_influenced_by_feedback,
            'incorporation_rate': self.calculate_feedback_incorporation_rate(),
            'total_rule_applications': self.total_rule_applications,
            'false_positive_reduction_count': self.false_positive_reduction_count,
            'false_positive_reduction_percent': self.calculate_false_positive_reduction(),
            'feedback_diversity': self.calculate_feedback_diversity(),
            'avg_time_to_apply_ms': self.avg_time_to_apply_ms,
            'status': self.status.value,
            'last_updated': self.last_updated,
            'target': self.target_incorporation_rate,
            'notes': self.notes
        }


# ============================================================================
# AGGREGATED METRICS SUMMARY
# ============================================================================

@dataclass
class AgenticAIMetricsSummary:
    """
    Aggregated summary of all 7 Agentic AI principles.
    
    Provides overall system score and principle-by-principle breakdown.
    """

    session_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat())

    # Individual principle metrics
    self_learning: SelfLearningMetrics = field(
        default_factory=SelfLearningMetrics)
    contextual_awareness: ContextualAwarenessMetrics = field(
        default_factory=ContextualAwarenessMetrics)
    goal_directed: GoalDirectedMetrics = field(
        default_factory=GoalDirectedMetrics)
    tool_utilization: ToolUtilizationMetrics = field(
        default_factory=ToolUtilizationMetrics)
    planning_reasoning: PlanningReasoningMetrics = field(
        default_factory=PlanningReasoningMetrics)
    memory_management: MemoryManagementMetrics = field(
        default_factory=MemoryManagementMetrics)
    feedback_incorporation: FeedbackIncorporationMetrics = field(
        default_factory=FeedbackIncorporationMetrics)

    def calculate_overall_agentic_score(self) -> float:
        """
        Calculate overall Agentic AI score (0.0 - 1.0).
        
        FORMULA TYPE: Composite (Weighted Average)
        
        **UPDATED WEIGHTS (All 7 Principles Now Active/Partial):**
        
        1. Self-Learning: 1.0 (ACTIVE - adaptive thresholds + IP reputation)
        2. Contextual Awareness: 0.5 (PARTIAL - basic implementation)
        3. Goal-Directed: 1.0 (ACTIVE - workflow completion tracking)
        4. Tool Utilization: 1.0 (ACTIVE - ML/LLM/Memory tracking)
        5. Planning & Reasoning: 1.0 (ACTIVE - LLM reasoning tracked)
        6. Memory Management: 1.0 (ACTIVE - SQLite+FAISS fully operational)
        7. Feedback Incorporation: 1.0 (ACTIVE - analyst feedback system)
        
        Formula:
        --------
        OAS = Σ(principle_score × weight) / Σ(weights)
        
        Example Calculation (with all principles active):
        - Self-Learning: 0.75 × 1.0 = 0.75
        - Context: 0.80 × 0.5 = 0.40
        - Goal: 0.95 × 1.0 = 0.95
        - Tool: 0.90 × 1.0 = 0.90
        - Planning: 0.85 × 1.0 = 0.85
        - Memory: 0.92 × 1.0 = 0.92
        - Feedback: 0.65 × 1.0 = 0.65
        Total: (0.75 + 0.40 + 0.95 + 0.90 + 0.85 + 0.92 + 0.65) / 6.5 = 0.818
        
        Interpretation:
        ---------------
        - >0.90: Excellent autonomous behavior (research-grade)
        - 0.80-0.90: Good agentic capabilities (production-ready)
        - 0.70-0.80: Moderate autonomy (needs improvement)
        - <0.70: Limited autonomous behavior
        
        Returns:
            Overall agentic score (0.0 - 1.0)
        """
        scores = []
        weights = []

        # Self-Learning (ACTIVE)
        if self.self_learning.status == PrincipleStatus.ACTIVE:
            # Composite score: learning velocity + rule effectiveness
            learning_score = min(self.self_learning.calculate_learning_velocity() / 5.0, 1.0)
            rule_score = self.self_learning.calculate_rule_diversity()
            combined = (learning_score * 0.6 + rule_score * 0.4)
            scores.append(combined)
            weights.append(1.0)

        # Contextual Awareness (PARTIAL)
        if self.contextual_awareness.status == PrincipleStatus.PARTIAL:
            scores.append(
                self.contextual_awareness.calculate_context_incorporation_rate())
            weights.append(0.5)

        # Goal-Directed (ACTIVE)
        if self.goal_directed.status == PrincipleStatus.ACTIVE:
            scores.append(self.goal_directed.calculate_goal_completion_rate())
            weights.append(1.0)

        # Tool Utilization (ACTIVE)
        if self.tool_utilization.status == PrincipleStatus.ACTIVE:
            scores.append(
                self.tool_utilization.calculate_overall_tool_effectiveness())
            weights.append(1.0)

        # Planning & Reasoning (ACTIVE)
        if self.planning_reasoning.status == PrincipleStatus.ACTIVE:
            scores.append(
                self.planning_reasoning.calculate_decision_quality_score())
            weights.append(1.0)

        # Memory Management (ACTIVE)
        if self.memory_management.status == PrincipleStatus.ACTIVE:
            mem_score = (
                self.memory_management.calculate_memory_utilization_rate() * 0.5 +
                self.memory_management.calculate_retrieval_accuracy() * 0.5
            )
            scores.append(mem_score)
            weights.append(1.0)

        # Feedback Incorporation (ACTIVE)
        if self.feedback_incorporation.status == PrincipleStatus.ACTIVE:
            feedback_score = (
                self.feedback_incorporation.calculate_feedback_incorporation_rate() * 0.7 +
                self.feedback_incorporation.calculate_rule_effectiveness() * 0.3
            )
            scores.append(feedback_score)
            weights.append(1.0)

        # Calculate weighted average
        if not scores:
            return 0.0

        weighted_sum = sum(s * w for s, w in zip(scores, weights))
        total_weight = sum(weights)

        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire summary to dictionary."""
        return {
            'session_id': self.session_id,
            'timestamp': self.timestamp,
            'overall_agentic_score': self.calculate_overall_agentic_score(),
            'principles': {
                'self_learning': self.self_learning.to_dict(),
                'contextual_awareness': self.contextual_awareness.to_dict(),
                'goal_directed': self.goal_directed.to_dict(),
                'tool_utilization': self.tool_utilization.to_dict(),
                'planning_reasoning': self.planning_reasoning.to_dict(),
                'memory_management': self.memory_management.to_dict(),
                'feedback_incorporation': self.feedback_incorporation.to_dict()
            }
        }

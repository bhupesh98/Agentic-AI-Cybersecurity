"""
Metrics Collector - Central Coordinator for Agentic AI Metrics.

Singleton class that collects metrics from all system components and
aggregates them into the 7 Agentic AI principles.

This is the main interface that existing code will use to record metrics.


"""

import os
import logging
from typing import Dict, Any, List
from datetime import datetime

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
from src.metrics.storage import MetricsStorageManager


class MetricsCollector:
    """
    Central metrics collection coordinator.
    
    Singleton pattern ensures only one instance exists across the system.
    Fail-safe design: if metrics collection fails, core system continues.
    
    Usage:
        collector = get_metrics_collector()
        collector.record_context_analysis(flags=['off_hours'], score=0.7)
    """

    _instance = None
    _initialized = False

    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            cls._instance = super(MetricsCollector, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize metrics collector (only once)."""
        if self._initialized:
            return

        # Check if metrics are enabled
        self.enabled = os.getenv("ENABLE_METRICS", "true").lower() == "true"

        # Setup logging
        self.logger = logging.getLogger(__name__)

        if not self.enabled:
            self.logger.info(
                "⚠️ Metrics collection DISABLED (ENABLE_METRICS=false)")
            self._initialized = True
            return

        # Initialize storage
        self.storage = MetricsStorageManager()

        # Current session ID
        self.session_id = self._generate_session_id()

        # Initialize principle metrics
        self.self_learning = SelfLearningMetrics()
        self.contextual_awareness = ContextualAwarenessMetrics()
        self.goal_directed = GoalDirectedMetrics()
        self.tool_utilization = ToolUtilizationMetrics()
        self.planning_reasoning = PlanningReasoningMetrics()
        self.memory_management = MemoryManagementMetrics()
        self.feedback_incorporation = FeedbackIncorporationMetrics()

        # Temporary buffers for calculations
        self._suspicion_scores = []
        self._reasoning_texts = []
        self._reasoning_word_counts = []
        self._reasoning_step_counts = []

        # Import managers for integration
        try:
            from src.agent import get_learning_manager, get_feedback_manager
            from src.memory import get_memory_manager

            self.learning_manager = get_learning_manager()
            self.feedback_manager = get_feedback_manager()
            self.memory_manager = get_memory_manager()

            # Import IP reputation learning
            from src.memory.ip_reputation_learning import IPReputationLearning
            self.ip_learning = IPReputationLearning(self.memory_manager)

            self.logger.info("✅ Integrated with learning and feedback managers")
        except ImportError as e:
            self.logger.warning(f"⚠️ Could not import managers: {e}")
            self.learning_manager = None
            self.feedback_manager = None
            self.memory_manager = None
            self.ip_learning = None

        self._initialized = True
        self.logger.info(
            f"✅ Metrics Collector initialized (session: {self.session_id})")

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return f"session-{timestamp}"

    def _safe_execute(self, func, *args, **kwargs):
        """
        Safely execute a function with error handling.
        If metrics collection fails, log error but don't crash.
        """
        if not self.enabled:
            return

        try:
            func(*args, **kwargs)
        except Exception as e:
            self.logger.warning(f"⚠️ Metrics collection failed: {e}")
            # Core system continues normally

    # ========================================================================
    # PRINCIPLE #1: SELF-LEARNING
    # ========================================================================

    def record_threshold_adjustment(
        self,
        threshold_name: str,
        old_value: float,
        new_value: float,
        reason: str
    ):
        """
        Record adaptive threshold adjustment.
        
        Args:
            threshold_name: Name of threshold adjusted
            old_value: Previous value
            new_value: New value
            reason: Reason for adjustment
        """
        def _record():
            self.self_learning.threshold_adjustments += 1

            # Track unique thresholds learned
            # (simplified - in production would track set of threshold names)
            self.self_learning.thresholds_learned = max(
                self.self_learning.thresholds_learned,
                self.self_learning.threshold_adjustments
            )

            # Calculate improvement (absolute change)
            improvement = abs(new_value - old_value)
            if self.self_learning.avg_threshold_improvement == 0.0:
                self.self_learning.avg_threshold_improvement = improvement
            else:
                total = self.self_learning.threshold_adjustments
                self.self_learning.avg_threshold_improvement = (
                    (self.self_learning.avg_threshold_improvement * (total - 1) + improvement) / total
                )

            self.logger.debug(
                f"📊 Threshold adjusted: {threshold_name} {old_value:.3f}→{new_value:.3f}"
            )

        self._safe_execute(_record)

    def record_reputation_rule_learned(
        self,
        ip_address: str,
        rule_type: str,
        reason: str
    ):
        """
        Record IP reputation rule learning.
        
        Args:
            ip_address: IP address for rule
            rule_type: Type of rule (whitelist, blacklist, escalate, monitor)
            reason: Reason for learning this rule
        """
        def _record():
            self.self_learning.learned_reputation_rules += 1

            # Track by rule type
            if rule_type == 'whitelist':
                self.self_learning.whitelist_rules += 1
            elif rule_type == 'blacklist':
                self.self_learning.blacklist_rules += 1
            elif rule_type == 'escalate':
                self.self_learning.escalation_rules += 1

            self.logger.debug(
                f"📊 Reputation rule learned: {ip_address} → {rule_type}"
            )

        self._safe_execute(_record)

    def record_reputation_rule_application(self, ip_address: str, rule_type: str):
        """
        Record application of a learned reputation rule.
        
        Args:
            ip_address: IP address
            rule_type: Type of rule applied
        """
        def _record():
            self.self_learning.total_rule_applications += 1

            self.logger.debug(
                f"📊 Reputation rule applied: {ip_address} ({rule_type})"
            )

        self._safe_execute(_record)

    def update_self_learning_from_managers(self):
        """
        Sync self-learning metrics from adaptive learning and IP reputation managers.
        
        Call this periodically to pull latest stats from managers.
        """
        def _record():
            if not self.learning_manager or not self.ip_learning:
                return

            # Get adaptive learning metrics
            learning_metrics = self.learning_manager.get_learning_metrics()

            self.self_learning.threshold_adjustments = learning_metrics.total_adjustments
            self.self_learning.thresholds_learned = learning_metrics.thresholds_learned
            self.self_learning.avg_threshold_improvement = learning_metrics.average_improvement
            self.self_learning.learning_velocity = learning_metrics.learning_velocity

            # Get IP reputation learning stats
            ip_stats = self.ip_learning.get_learning_statistics()

            self.self_learning.learned_reputation_rules = ip_stats['total_rules']
            self.self_learning.whitelist_rules = ip_stats['rule_counts'].get('whitelist', 0)
            self.self_learning.blacklist_rules = ip_stats['rule_counts'].get('blacklist', 0)
            self.self_learning.escalation_rules = ip_stats['rule_counts'].get('escalate', 0)
            self.self_learning.total_rule_applications = ip_stats['total_applications']

            # Update incidents processed
            if self.memory_manager:
                stats = self.memory_manager.get_statistics()
                self.self_learning.incidents_processed = stats.total_incidents

            self.logger.debug("📊 Self-learning metrics synced from managers")

        self._safe_execute(_record)

    # ========================================================================
    # PRINCIPLE #2: CONTEXTUAL AWARENESS
    # ========================================================================

    def record_context_analysis(
        self,
        flags: List[str],
        suspicion_score: float,
        used_context: bool = True
    ):
        """
        Record context analysis from contextual_analysis_node.
        
        Args:
            flags: List of context flags (e.g., ['off_hours', 'suspicious_port'])
            suspicion_score: Calculated suspicion score (0.0 - 1.0)
            used_context: Whether context influenced decision
        """
        def _record():
            self.contextual_awareness.total_decisions += 1

            if used_context:
                self.contextual_awareness.decisions_with_context += 1

            self.contextual_awareness.context_flags_generated += len(flags)

            # Track unique context types
            unique_types = set(flags)
            self.contextual_awareness.unique_context_types = len(unique_types)

            # Track context dimensions
            for flag in flags:
                if 'time' in flag.lower() or 'hour' in flag.lower():
                    self.contextual_awareness.temporal_context_used += 1
                elif 'asset' in flag.lower() or 'server' in flag.lower():
                    self.contextual_awareness.asset_context_used += 1
                elif 'user' in flag.lower() or 'account' in flag.lower():
                    self.contextual_awareness.user_context_used += 1
                elif 'network' in flag.lower() or 'zone' in flag.lower():
                    self.contextual_awareness.network_context_used += 1

            # Track suspicion scores
            self._suspicion_scores.append(suspicion_score)
            self.contextual_awareness.avg_suspicion_score = sum(
                self._suspicion_scores) / len(self._suspicion_scores)

            self.logger.debug(
                f"📊 Context analysis recorded: {len(flags)} flags, score: {suspicion_score:.2f}")

        self._safe_execute(_record)

    # ========================================================================
    # PRINCIPLE #3: GOAL-DIRECTED BEHAVIOR
    # ========================================================================

    def record_workflow_start(self):
        """Record start of workflow session."""
        def _record():
            self.goal_directed.total_sessions += 1
            self.logger.debug("📊 Workflow session started")

        self._safe_execute(_record)

    def record_workflow_completion(self, success: bool = True):
        """
        Record workflow completion.
        
        Args:
            success: Whether workflow completed successfully
        """
        def _record():
            if success:
                self.goal_directed.successful_sessions += 1

            self.logger.debug(
                f"📊 Workflow completed: {'success' if success else 'failed'}")

        self._safe_execute(_record)

    def record_node_completion(self, node_name: str):
        """
        Record completion of a workflow node (sub-task).
        
        Args:
            node_name: Name of completed node
        """
        def _record():
            if 'ml_detect' in node_name.lower():
                self.goal_directed.ml_detection_completed += 1
            elif 'llm_analysis' in node_name.lower():
                self.goal_directed.llm_analysis_completed += 1
            elif 'memory' in node_name.lower():
                self.goal_directed.memory_lookup_completed += 1
            elif 'response' in node_name.lower() or 'plan' in node_name.lower():
                self.goal_directed.response_plan_completed += 1
            elif 'storage' in node_name.lower():
                self.goal_directed.storage_completed += 1

            self.goal_directed.operational_tasks_completed += 1
            self.goal_directed.policy_compliant_actions += 1  # Assume compliant unless noted

            self.logger.debug(f"📊 Node completed: {node_name}")

        self._safe_execute(_record)

    def record_resource_usage(self, resource_type: str, aligned_with_priority: bool = True):
        """
        Record resource usage (LLM calls, DB queries, etc.).
        
        Args:
            resource_type: Type of resource used
            aligned_with_priority: Whether usage aligned with priority
        """
        def _record():
            self.goal_directed.total_resources_used += 1
            if aligned_with_priority:
                self.goal_directed.resources_aligned_with_priority += 1

            self.logger.debug(f"📊 Resource used: {resource_type}")

        self._safe_execute(_record)

    # ========================================================================
    # PRINCIPLE #4: TOOL UTILIZATION
    # ========================================================================

    def record_tool_invocation(
        self,
        tool_name: str,
        success: bool = True,
        latency_ms: float = 0.0
    ):
        """
        Record tool invocation.
        
        Args:
            tool_name: Name of tool (e.g., "RandomForest", "LLM", "Memory-SQLite")
            success: Whether invocation was successful
            latency_ms: Execution latency in milliseconds
        """
        def _record():
            # Initialize tracking for new tools
            if tool_name not in self.tool_utilization.tool_invocations:
                self.tool_utilization.tool_invocations[tool_name] = 0
                self.tool_utilization.tool_successes[tool_name] = 0
                self.tool_utilization.tool_failures[tool_name] = 0
                self.tool_utilization.tool_latencies[tool_name] = []

            self.tool_utilization.tool_invocations[tool_name] += 1

            if success:
                self.tool_utilization.tool_successes[tool_name] += 1
            else:
                self.tool_utilization.tool_failures[tool_name] += 1

            if latency_ms > 0:
                self.tool_utilization.tool_latencies[tool_name].append(
                    latency_ms)

            self.logger.debug(
                f"📊 Tool invocation: {tool_name} ({'success' if success else 'failed'})")

        self._safe_execute(_record)

    def record_incident_tools(self, tools_used: List[str]):
        """
        Record tools used for an incident (for diversity calculation).
        
        Args:
            tools_used: List of tool names used for this incident
        """
        def _record():
            self.tool_utilization.total_incidents += 1
            unique_tools = len(set(tools_used))
            self.tool_utilization.unique_tools_per_incident.append(
                unique_tools)

            if unique_tools > 1:
                self.tool_utilization.multi_tool_chains += 1
            else:
                self.tool_utilization.single_tool_uses += 1

            self.logger.debug(f"📊 Incident tools: {unique_tools} unique tools")

        self._safe_execute(_record)

    # ========================================================================
    # PRINCIPLE #5: PLANNING & REASONING
    # ========================================================================

    def record_reasoning(
        self,
        reasoning_text: str,
        has_explanation: bool = True,
        confidence: float = 0.0
    ):
        """
        Record LLM reasoning chain.
        
        Args:
            reasoning_text: The reasoning/explanation text
            has_explanation: Whether explanation was provided
            confidence: Confidence score of decision
        """
        def _record():
            self.planning_reasoning.total_decisions += 1

            if has_explanation and reasoning_text:
                self.planning_reasoning.decisions_with_reasoning += 1
                self.planning_reasoning.explanations_provided += 1

                # Calculate word count
                word_count = len(reasoning_text.split())
                self._reasoning_word_counts.append(word_count)

                # Count steps (lines that look like numbered steps)
                steps = len(
                    [line for line in reasoning_text.split('\n') if line.strip()])
                self._reasoning_step_counts.append(steps)

                # Check if complete explanation
                if word_count >= self.planning_reasoning.min_explanation_length:
                    self.planning_reasoning.complete_explanations += 1

                # Update averages
                self.planning_reasoning.avg_reasoning_length_words = (
                    sum(self._reasoning_word_counts) /
                    len(self._reasoning_word_counts)
                )
                self.planning_reasoning.avg_reasoning_steps = (
                    sum(self._reasoning_step_counts) /
                    len(self._reasoning_step_counts)
                )

            # Track confidence
            if confidence >= 0.8:
                self.planning_reasoning.high_confidence_decisions += 1
            elif confidence < 0.5:
                self.planning_reasoning.low_confidence_decisions += 1

            # Update average confidence
            if self.planning_reasoning.avg_decision_confidence == 0.0:
                self.planning_reasoning.avg_decision_confidence = confidence
            else:
                total = self.planning_reasoning.total_decisions
                self.planning_reasoning.avg_decision_confidence = (
                    (self.planning_reasoning.avg_decision_confidence *
                     (total - 1) + confidence) / total
                )

            self.logger.debug(
                f"📊 Reasoning recorded: {len(reasoning_text)} chars, confidence: {confidence:.2f}")

        self._safe_execute(_record)

    def record_plan_generation(self, plan_steps: int, completed: bool = True):
        """
        Record multi-step plan generation.
        
        Args:
            plan_steps: Number of steps in plan
            completed: Whether plan was completed
        """
        def _record():
            self.planning_reasoning.plans_generated += 1

            if completed:
                self.planning_reasoning.plans_completed += 1

            # Update average plan depth
            if self.planning_reasoning.avg_plan_depth == 0.0:
                self.planning_reasoning.avg_plan_depth = plan_steps
            else:
                total = self.planning_reasoning.plans_generated
                self.planning_reasoning.avg_plan_depth = (
                    (self.planning_reasoning.avg_plan_depth *
                     (total - 1) + plan_steps) / total
                )

            self.logger.debug(f"📊 Plan generated: {plan_steps} steps")

        self._safe_execute(_record)

    # ========================================================================
    # PRINCIPLE #6: MEMORY MANAGEMENT
    # ========================================================================

    def record_memory_query(self, used_memory: bool = True):
        """
        Record memory system query.
        
        Args:
            used_memory: Whether memory was actually used
        """
        def _record():
            self.memory_management.total_queries += 1
            if used_memory:
                self.memory_management.memory_used_count += 1

            self.logger.debug(
                f"📊 Memory query: {'used' if used_memory else 'unused'}")

        self._safe_execute(_record)

    def record_memory_retrieval(self, retrieved_count: int, relevant_count: int):
        """
        Record memory retrieval results.
        
        Args:
            retrieved_count: Number of similar incidents retrieved
            relevant_count: Number that were actually relevant
        """
        def _record():
            self.memory_management.similar_incidents_retrieved += retrieved_count
            self.memory_management.relevant_incidents_count += relevant_count

            self.logger.debug(
                f"📊 Memory retrieval: {relevant_count}/{retrieved_count} relevant")

        self._safe_execute(_record)

    def record_memory_storage(self, storage_time_ms: float):
        """
        Record memory storage operation.
        
        Args:
            storage_time_ms: Time taken to store in milliseconds
        """
        def _record():
            self.memory_management.storage_times_ms.append(storage_time_ms)
            self.memory_management.total_incidents_stored += 1

            self.logger.debug(f"📊 Memory storage: {storage_time_ms:.1f}ms")

        self._safe_execute(_record)

    def record_memory_performance(self, query_time_ms: float):
        """
        Record memory query performance.
        
        Args:
            query_time_ms: Query time in milliseconds
        """
        def _record():
            self.memory_management.query_times_ms.append(query_time_ms)

            self.logger.debug(f"📊 Memory query time: {query_time_ms:.1f}ms")

        self._safe_execute(_record)

    def update_memory_stats(self, stats: Dict[str, Any]):
        """
        Update memory management metrics from memory manager's stats dict.
        
        Args:
            stats: Stats dictionary from MemoryManager.get_statistics()
        """
        def _record():
            # Extract stats that exist
            if 'total_incidents' in stats:
                self.memory_management.total_incidents_stored = stats['total_incidents']

            if 'unique_ips' in stats:
                self.memory_management.unique_ips_tracked = stats['unique_ips']

            if 'attack_patterns' in stats:
                self.memory_management.unique_attack_patterns = stats['attack_patterns']

            if 'memory_utilization_rate' in stats:
                # If memory manager calculates this, use it
                utilization = stats['memory_utilization_rate']
                # Back-calculate total queries and used count
                if utilization > 0:
                    self.memory_management.memory_used_count = int(
                        self.memory_management.total_incidents_stored * utilization
                    )

            self.logger.debug("📊 Memory stats updated from memory manager")

        self._safe_execute(_record)

    # ========================================================================
    # PRINCIPLE #7: FEEDBACK INCORPORATION
    # ========================================================================

    def record_analyst_feedback(
        self,
        incident_id: str,
        feedback_type: str,
        original_decision: str,
        corrected_decision: str,
        reasoning: str
    ):
        """
        Record analyst feedback submission.
        
        Args:
            incident_id: ID of incident being corrected
            feedback_type: Type of feedback
            original_decision: System's decision
            corrected_decision: Correct decision
            reasoning: Analyst's reasoning
        """
        def _record():
            self.feedback_incorporation.total_feedback += 1
            self.feedback_incorporation.total_decisions += 1

            # Track by feedback type
            if feedback_type == 'false_positive':
                self.feedback_incorporation.false_positive_corrections += 1
                self.feedback_incorporation.false_positive_reduction_count += 1
            elif feedback_type == 'false_negative':
                self.feedback_incorporation.false_negative_corrections += 1
            elif feedback_type == 'severity_correction':
                self.feedback_incorporation.severity_corrections += 1
            elif feedback_type == 'correct':
                self.feedback_incorporation.correct_confirmations += 1

            self.logger.debug(
                f"📊 Feedback recorded: {incident_id} ({feedback_type})"
            )

        self._safe_execute(_record)

    def record_feedback_rule_created(self, rule_id: str, conditions: Dict):
        """
        Record creation of feedback rule.
        
        Args:
            rule_id: ID of new rule
            conditions: Rule conditions
        """
        def _record():
            self.feedback_incorporation.feedback_rules_created += 1

            self.logger.debug(f"📊 Feedback rule created: {rule_id}")

        self._safe_execute(_record)

    def record_feedback_rule_application(
        self,
        rule_id: str,
        incident_id: str,
        modified_decision: str
    ):
        """
        Record application of a feedback rule.
        
        Args:
            rule_id: ID of rule applied
            incident_id: Incident it was applied to
            modified_decision: Decision after applying feedback
        """
        def _record():
            self.feedback_incorporation.decisions_influenced_by_feedback += 1
            self.feedback_incorporation.total_rule_applications += 1

            # Update most used rule tracking
            if self.feedback_incorporation.most_used_rule_id == rule_id:
                self.feedback_incorporation.most_used_rule_applications += 1
            elif (self.feedback_incorporation.most_used_rule_applications == 0 or
                  self.feedback_incorporation.most_used_rule_id == ""):
                self.feedback_incorporation.most_used_rule_id = rule_id
                self.feedback_incorporation.most_used_rule_applications = 1

            self.logger.debug(
                f"📊 Feedback rule applied: {rule_id} to {incident_id}"
            )

        self._safe_execute(_record)

    def update_feedback_from_manager(self):
        """
        Sync feedback metrics from feedback manager.
        
        Call this periodically to pull latest stats.
        """
        def _record():
            if not self.feedback_manager or not self.memory_manager:
                return

            # Get memory stats for total incidents
            stats = self.memory_manager.get_statistics()
            total_incidents = stats.total_incidents

            # Get feedback metrics
            feedback_metrics = self.feedback_manager.get_feedback_metrics(
                total_incidents=total_incidents
            )

            self.feedback_incorporation.total_feedback = feedback_metrics.total_feedback
            self.feedback_incorporation.false_positive_corrections = (
                feedback_metrics.feedback_by_type.get('false_positive', 0)
            )
            self.feedback_incorporation.false_negative_corrections = (
                feedback_metrics.feedback_by_type.get('false_negative', 0)
            )
            self.feedback_incorporation.severity_corrections = (
                feedback_metrics.feedback_by_type.get('severity_correction', 0)
            )
            self.feedback_incorporation.correct_confirmations = (
                feedback_metrics.feedback_by_type.get('correct', 0)
            )

            self.feedback_incorporation.feedback_rules_created = (
                feedback_metrics.active_rules  # Approximation
            )
            self.feedback_incorporation.active_feedback_rules = feedback_metrics.active_rules
            self.feedback_incorporation.total_rule_applications = (
                feedback_metrics.total_rule_applications
            )
            self.feedback_incorporation.total_decisions = total_incidents
            self.feedback_incorporation.decisions_influenced_by_feedback = (
                int(total_incidents * feedback_metrics.application_rate)
            )

            self.feedback_incorporation.false_positive_reduction_percent = (
                feedback_metrics.false_positive_reduction
            )
            self.feedback_incorporation.avg_time_to_apply_ms = (
                feedback_metrics.avg_time_to_apply * 1000  # Convert to ms
            )

            self.logger.debug("📊 Feedback metrics synced from manager")

        self._safe_execute(_record)

    # ========================================================================
    # EXPORT & PERSISTENCE
    # ========================================================================

    def get_summary(self) -> AgenticAIMetricsSummary:
        """
        Get current metrics summary.
        
        Returns:
            AgenticAIMetricsSummary object with all collected metrics
        """
        return AgenticAIMetricsSummary(
            session_id=self.session_id,
            timestamp=datetime.utcnow().isoformat(),
            self_learning=self.self_learning,
            contextual_awareness=self.contextual_awareness,
            goal_directed=self.goal_directed,
            tool_utilization=self.tool_utilization,
            planning_reasoning=self.planning_reasoning,
            memory_management=self.memory_management,
            feedback_incorporation=self.feedback_incorporation
        )

    def save_metrics(self) -> bool:
        """
        Save collected metrics to database and export files.
        
        UPDATED: Now syncs from Self-Learning and Feedback managers first.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            return False

        try:
            # Sync from managers BEFORE creating summary
            self.update_self_learning_from_managers()
            self.update_feedback_from_manager()

            summary = self.get_summary()

            # Save to database
            success = self.storage.save_metrics_summary(summary)

            if success:
                # Export to JSON
                self.storage.export_to_json(summary)
                # Export to CSV
                self.storage.export_to_csv(summary)

                self.logger.info(
                    f"✅ Metrics saved and exported (session: {self.session_id})")

            return success

        except Exception as e:
            self.logger.error(f"❌ Failed to save metrics: {e}")
            return False

    def print_summary(self):
        """Print metrics summary to console."""
        if not self.enabled:
            print("⚠️ Metrics collection disabled")
            return

        # Sync from managers first
        self.update_self_learning_from_managers()
        self.update_feedback_from_manager()

        summary = self.get_summary()

        print("\n" + "="*70)
        print("📊 AGENTIC AI METRICS SUMMARY")
        print("="*70)
        print(f"Session: {self.session_id}")
        print(
            f"Overall Agentic Score: {summary.calculate_overall_agentic_score():.3f}")
        print(f"\nPrinciples Active: {6} | Partial: {1} | Baseline: {0}")
        print("="*70)

        print("\n✅ ACTIVE PRINCIPLES:")

        # Self-Learning
        learning_velocity = self.self_learning.calculate_learning_velocity()
        print(f"  • Self-Learning: {learning_velocity:.2f} adaptations/100 incidents")
        print(f"    - Threshold adjustments: {self.self_learning.threshold_adjustments}")
        print(f"    - Learned rules: {self.self_learning.learned_reputation_rules}")

        # Goal-Directed
        print(
            f"  • Goal-Directed: {self.goal_directed.calculate_goal_completion_rate():.2%} completion")

        # Tool Utilization
        print(
            f"  • Tool Utilization: {self.tool_utilization.calculate_overall_tool_effectiveness():.2%} effectiveness")

        # Planning & Reasoning
        print(
            f"  • Planning & Reasoning: {self.planning_reasoning.calculate_decision_quality_score():.2%} quality")

        # Memory Management
        print(
            f"  • Memory Management: {self.memory_management.calculate_memory_utilization_rate():.2%} utilization")

        # Feedback Incorporation
        feedback_rate = self.feedback_incorporation.calculate_feedback_incorporation_rate()
        print(f"  • Feedback Incorporation: {feedback_rate:.2%} incorporation rate")
        print(f"    - Total feedback: {self.feedback_incorporation.total_feedback}")
        print(f"    - Active rules: {self.feedback_incorporation.active_feedback_rules}")

        print("\n⏳ PARTIAL PRINCIPLES:")
        print(
            f"  • Contextual Awareness: {self.contextual_awareness.calculate_context_incorporation_rate():.2%} incorporation")

        print("="*70 + "\n")


# ============================================================================
# GLOBAL ACCESSOR FUNCTION
# ============================================================================

_global_collector = None


def get_metrics_collector() -> MetricsCollector:
    """
    Get the global metrics collector instance.
    
    Returns:
        MetricsCollector singleton instance
    """
    global _global_collector
    if _global_collector is None:
        _global_collector = MetricsCollector()
    return _global_collector

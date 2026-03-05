"""
Enhanced Workflow Integration - Phase 3 Complete

This module enhances the existing workflow with:
1. Real action execution (firewall, alerts)
2. Policy-based decision making
3. LLM-guided response selection
4. Action verification
5. Metrics tracking for autonomous response

Author: Abhinav
Date: November 2025
"""

import uuid
from datetime import datetime

# Import existing workflow
from src.agent.state_management import AgentState, AgentPhase, update_phase

# Import action system (Phase 3)
from src.actions import (
    get_action_executor,
    get_firewall_manager,
    get_alert_manager,
    get_action_verifier,
    get_policy_engine,
    BlockIPAction,
    AlertAction,
    ActionPriority,
    ActionResult,
    ThreatContext,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW
)

# Import metrics
try:
    from src.metrics import get_metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False


# ============================================================================
# ENHANCED RESPONSE NODE
# ============================================================================

def enhanced_respond_node(state: AgentState) -> AgentState:
    """
    Enhanced response planning with policy engine + LLM guidance.
    
    Flow:
        1. Extract threat info from LLM analysis
        2. Build threat context (including memory)
        3. Get policy suggestions
        4. (Optional) Ask LLM to refine actions
        5. Select final actions
        6. Queue actions for execution
    """
    print("\n" + "="*80)
    print("📋 ENHANCED RESPONSE PLANNING NODE")
    print("="*80)

    state = update_phase(state, AgentPhase.RESPONSE_PLANNING)
    state["messages"].append(
        "Enhanced Response Planning: Selecting autonomous actions")

    try:
        # Get components
        policy_engine = get_policy_engine()

        # Extract threat information from LLM analysis
        llm_result = state.get('llm_result', {})
        if not llm_result:
            state["messages"].append(
                "⚠️  No LLM analysis found, using default response")
            llm_result = {'threat_level': 'MEDIUM',
                          'reasoning': 'No analysis available'}

        # Get memory context
        memory_contexts = state.get('memory_contexts', [])
        is_repeat_offender = len(memory_contexts) > 0
        previous_attacks = len(memory_contexts)

        # Build threat context
        ml_predictions = state.get('ml_predictions', [])
        if ml_predictions:
            # Use first prediction (or could aggregate)
            pred = ml_predictions[0]
            source_ip = pred.get('source_ip', 'unknown')
            threat_type = pred.get('predicted_label', 'unknown')
            ml_confidence = pred.get('confidence', 0.5)
        else:
            source_ip = "unknown"
            threat_type = "unknown"
            ml_confidence = 0.5

        # Map LLM threat level to severity
        llm_threat_level = llm_result.get('threat_level', 'MEDIUM').upper()
        severity_map = {
            'CRITICAL': SEVERITY_CRITICAL,
            'HIGH': SEVERITY_HIGH,
            'MEDIUM': SEVERITY_MEDIUM,
            'LOW': SEVERITY_LOW
        }
        severity = severity_map.get(llm_threat_level, SEVERITY_MEDIUM)

        context = ThreatContext(
            source_ip=source_ip,
            threat_type=threat_type,
            severity=severity,
            ml_confidence=ml_confidence,
            llm_analysis=llm_result.get('reasoning', ''),
            is_repeat_offender=is_repeat_offender,
            previous_attacks=previous_attacks,
            attack_in_progress=True
        )

        print("\n🎯 Threat Context:")
        print(f"   Source IP: {context.source_ip}")
        print(f"   Type: {context.threat_type}")
        print(f"   Severity: {context.severity}")
        print(f"   ML Confidence: {context.ml_confidence:.2%}")
        print(f"   Repeat Offender: {context.is_repeat_offender}")

        # Get policy suggestions
        policy_suggestion = policy_engine.suggest_actions(context)

        print("\n📋 Policy Suggestion:")
        print(f"   Policy: {policy_suggestion['policy']}")
        print(f"   Actions: {policy_suggestion['actions']}")
        print(f"   Parameters: {policy_suggestion['parameters']}")

        # Store policy suggestion
        state['policy_suggestion'] = policy_suggestion
        state['threat_context'] = context.to_dict()

        # Create action list
        selected_actions = []

        # Map policy actions to actual Action objects
        import os
        recipient_email = os.getenv('SMTP_USERNAME', 'admin@example.com')

        for action_type in policy_suggestion['actions']:
            action_id = f"action-{uuid.uuid4().hex[:8]}"

            if action_type == 'block_ip':
                duration = policy_suggestion['parameters'].get(
                    'block_duration', 10)
                action = BlockIPAction(
                    action_id=action_id,
                    priority=ActionPriority.HIGH if severity == SEVERITY_HIGH else ActionPriority.CRITICAL,
                    target=source_ip,
                    reason=f"{threat_type} detected by Agentic AI",
                    duration_minutes=duration
                )
                selected_actions.append(action)
                print(f"   ✅ Queued: Block {source_ip} for {duration}min")

            elif action_type == 'alert_email':
                # Create email alert with LLM analysis
                alert_message = f"""
{threat_type} detected from {source_ip}

ML Confidence: {ml_confidence:.2%}
Severity: {severity}

LLM Analysis:
{llm_result.get('reasoning', 'No detailed analysis available')}

Automated Response:
- IP has been blocked for {policy_suggestion['parameters'].get('block_duration', 10)} minutes
- This action was taken automatically by the Agentic AI system

{f'⚠️ REPEAT OFFENDER: This IP has attacked {previous_attacks} times before' if is_repeat_offender else ''}
"""

                action = AlertAction(
                    action_id=action_id,
                    priority=ActionPriority.HIGH,
                    target=source_ip,
                    reason=f"{threat_type} - Autonomous Alert",
                    severity=severity,
                    recipients=[recipient_email],
                    message=alert_message,
                    alert_type="email",
                    context={
                        'threat_type': threat_type,
                        'source_ip': source_ip,
                        'ml_confidence': ml_confidence,
                        'severity': severity,
                        'llm_reasoning': llm_result.get('reasoning', ''),
                        'repeat_offender': is_repeat_offender,
                        'previous_attacks': previous_attacks
                    }
                )
                selected_actions.append(action)
                print(f"   ✅ Queued: Email alert to {recipient_email}")

        # Store selected actions in state
        state['selected_actions'] = selected_actions
        state["messages"].append(
            f"✅ Selected {len(selected_actions)} actions based on policy")

        print(f"\n✅ Response plan created: {len(selected_actions)} actions")
        print("="*80 + "\n")

        return state

    except Exception as e:
        import traceback
        print("\n❌ ERROR in enhanced_respond_node:")
        print(traceback.format_exc())
        state["messages"].append(f"❌ Response planning failed: {str(e)}")
        state['selected_actions'] = []
        return state


# ============================================================================
# ENHANCED EXECUTE NODE
# ============================================================================

def enhanced_execute_node(state: AgentState) -> AgentState:
    """
    Enhanced execution with REAL action execution.
    
    Flow:
        1. Get selected actions from state
        2. Submit to action executor
        3. Execute each action
        4. Verify execution
        5. Record results
        6. Update metrics
    """
    print("\n" + "="*80)
    print("⚡ ENHANCED EXECUTION NODE")
    print("="*80)

    state = update_phase(state, AgentPhase.EXECUTION)
    state["messages"].append(
        "Enhanced Execution: Executing autonomous actions")

    try:
        # Get components
        executor = get_action_executor()
        firewall = get_firewall_manager()
        alert_mgr = get_alert_manager()
        verifier = get_action_verifier()

        # Register handlers
        def block_ip_handler(action):
            start = datetime.utcnow()
            success, msg = firewall.block_ip(
                action.target,
                action.reason,
                action.duration_minutes
            )
            exec_time = (datetime.utcnow() - start).total_seconds() * 1000
            return ActionResult(
                action_id=action.action_id,
                success=success,
                execution_time_ms=exec_time,
                output=msg
            )

        def alert_handler(action):
            start = datetime.utcnow()

            # Get recipient from environment
            import os
            from dotenv import load_dotenv
            load_dotenv('.env')
            recipient = os.getenv('SMTP_USERNAME', 'admin@example.com')

            # Send email with LLM analysis
            success, msg = alert_mgr.send_email_alert(
                severity=action.severity,
                title=f"Security Alert: {action.reason}",
                message=action.message,
                recipients=[recipient],
                threat_details=action.context
            )
            exec_time = (datetime.utcnow() - start).total_seconds() * 1000
            return ActionResult(
                action_id=action.action_id,
                success=success,
                execution_time_ms=exec_time,
                output=msg
            )

        from src.actions import ActionType
        executor.register_handler(ActionType.BLOCK_IP, block_ip_handler)
        executor.register_handler(ActionType.ALERT_EMAIL, alert_handler)

        # Get selected actions
        selected_actions = state.get('selected_actions', [])

        if not selected_actions:
            state["messages"].append("⚠️  No actions to execute")
            print("⚠️  No actions selected\n")
        else:
            print(f"\n⚡ Executing {len(selected_actions)} actions...\n")

            results = []
            for action in selected_actions:
                # Submit and execute
                executor.submit_action(action)
                result = executor.execute_action(action)
                results.append(result)

                # Log result
                status = "✅" if result.success else "❌"
                print(
                    f"{status} {action.action_type.value}: {result.output} ({result.execution_time_ms:.1f}ms)")
                state["messages"].append(
                    f"{status} {action.action_type.value}: {result.success}")

                # Verify if it's a block action
                if action.action_type.value == 'block_ip' and result.success:
                    verified, msg = verifier.verify_firewall_block(
                        firewall,
                        action.target,
                        immediate=True
                    )
                    if verified:
                        print(f"   ✅ Verified: {msg}")
                        state["messages"].append("   ✅ Verification passed")

            # Store results
            state['execution_results'] = [r.to_dict() for r in results]

            # Calculate success rate
            success_count = sum(1 for r in results if r.success)
            success_rate = success_count / len(results) if results else 0

            print("\n📊 Execution Summary:")
            print(f"   Total actions: {len(results)}")
            print(f"   Successful: {success_count}")
            print(f"   Failed: {len(results) - success_count}")
            print(f"   Success rate: {success_rate:.1%}")

            state["messages"].append(
                f"📊 Execution complete: {success_count}/{len(results)} successful")

            # Update metrics
            if METRICS_AVAILABLE:
                try:
                    collector = get_metrics_collector()
                    # Track actions taken
                    for result in results:
                        if result.success:
                            collector.record_action_taken(
                                action_type=action.action_type.value,
                                success=True,
                                execution_time_ms=result.execution_time_ms
                            )
                except Exception as e:
                    print(f"⚠️  Metrics update failed: {e}")

        # Mark as completed
        state = update_phase(state, AgentPhase.COMPLETED)

        print("\n" + "="*80)
        print("✅ EXECUTION NODE COMPLETED")
        print("="*80 + "\n")

        # Save metrics
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()
                collector.record_workflow_completion(success=True)
                collector.save_metrics()
                state["messages"].append("✅ Metrics saved")
            except Exception:
                pass

        return state

    except Exception as e:
        import traceback
        print("\n❌ ERROR in enhanced_execute_node:")
        print(traceback.format_exc())
        state["messages"].append(f"❌ Execution failed: {str(e)}")
        state['execution_results'] = []
        return state


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("Enhanced Workflow Integration Module")
    print("=" * 70)
    print("\nThis module provides enhanced respond and execute nodes")
    print("that integrate with the Phase 3 action system.")
    print("\nTo test, run the complete APT test:")
    print("  sudo python3 test_apt_with_actions.py")
    print("\n" + "=" * 70)

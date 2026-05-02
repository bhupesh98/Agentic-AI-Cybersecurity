"""
Response Policies - Define rules for action selection.

This module provides:
1. Severity-based response policies
2. Context-aware action selection
3. Escalation rules for repeat offenders
4. Policy templates

These policies can be used by:
- Static rule engine (fast, simple)
- LLM decision engine (intelligent, adaptive)
- Hybrid approach (LLM with policy guidance)

Phase 3 - Day 4: Response Automation

"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# POLICY CONFIGURATION
# ============================================================================

# Severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# Action types
ACTION_BLOCK_IP = "block_ip"
ACTION_BLOCK_PORT = "block_port"
ACTION_ALERT_EMAIL = "alert_email"
ACTION_ALERT_SLACK = "alert_slack"
ACTION_ALERT_SMS = "alert_sms"
ACTION_LOG_INCIDENT = "log_incident"
ACTION_ISOLATE_HOST = "isolate_host"

# Default block durations (minutes)
BLOCK_DURATION_CRITICAL = 60    # 1 hour
BLOCK_DURATION_HIGH = 30        # 30 minutes
BLOCK_DURATION_MEDIUM = 10      # 10 minutes
BLOCK_DURATION_LOW = 5          # 5 minutes


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class ThreatContext:
    """
    Context information about a threat.
    
    Used by policy engine to make informed decisions.
    """
    source_ip: str
    threat_type: str
    severity: str
    ml_confidence: float
    llm_analysis: Optional[str] = None

    # Contextual factors
    is_repeat_offender: bool = False
    previous_attacks: int = 0
    time_of_day: str = "business_hours"  # business_hours, off_hours
    target_asset: Optional[str] = None
    attack_in_progress: bool = True

    # Memory correlation
    similar_incidents: int = 0
    known_attacker: bool = False

    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'source_ip': self.source_ip,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'ml_confidence': self.ml_confidence,
            'llm_analysis': self.llm_analysis,
            'is_repeat_offender': self.is_repeat_offender,
            'previous_attacks': self.previous_attacks,
            'time_of_day': self.time_of_day,
            'target_asset': self.target_asset,
            'attack_in_progress': self.attack_in_progress,
            'similar_incidents': self.similar_incidents,
            'known_attacker': self.known_attacker,
            'metadata': self.metadata
        }


@dataclass
class ResponsePolicy:
    """
    Defines what actions to take for a given situation.
    """
    name: str
    conditions: Dict[str, Any]
    actions: List[str]
    action_params: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    description: str = ""

    def matches(self, context: ThreatContext) -> bool:
        """Check if this policy applies to the given context"""
        # Check severity
        if 'severity' in self.conditions:
            if context.severity != self.conditions['severity']:
                return False

        # Check threat type
        if 'threat_type' in self.conditions:
            allowed_types = self.conditions['threat_type']
            if isinstance(allowed_types, list):
                if context.threat_type not in allowed_types:
                    return False
            elif context.threat_type != allowed_types:
                return False

        # Check repeat offender
        if 'repeat_offender' in self.conditions:
            if context.is_repeat_offender != self.conditions['repeat_offender']:
                return False

        # Check attack in progress
        if 'attack_in_progress' in self.conditions:
            if context.attack_in_progress != self.conditions['attack_in_progress']:
                return False

        return True


# ============================================================================
# POLICY TEMPLATES
# ============================================================================

# Standard severity-based policies
POLICY_CRITICAL = ResponsePolicy(
    name="critical_threat",
    conditions={'severity': SEVERITY_CRITICAL},
    actions=[ACTION_BLOCK_IP, ACTION_ALERT_EMAIL, ACTION_ALERT_SLACK],
    action_params={
        'block_duration': BLOCK_DURATION_CRITICAL,
        'alert_recipients': ['admin@example.com'],
        'alert_channels': ['security-critical']
    },
    priority=10,
    description="Critical threats: Block immediately + Alert all channels"
)

POLICY_HIGH = ResponsePolicy(
    name="high_threat",
    conditions={'severity': SEVERITY_HIGH},
    actions=[ACTION_BLOCK_IP, ACTION_ALERT_EMAIL],
    action_params={
        'block_duration': BLOCK_DURATION_HIGH,
        'alert_recipients': ['admin@example.com']
    },
    priority=8,
    description="High severity: Block + Email alert"
)

POLICY_MEDIUM = ResponsePolicy(
    name="medium_threat",
    conditions={'severity': SEVERITY_MEDIUM},
    actions=[ACTION_ALERT_EMAIL, ACTION_LOG_INCIDENT],
    action_params={
        'alert_recipients': ['admin@example.com']
    },
    priority=5,
    description="Medium severity: Alert only"
)

POLICY_LOW = ResponsePolicy(
    name="low_threat",
    conditions={'severity': SEVERITY_LOW},
    actions=[ACTION_LOG_INCIDENT],
    action_params={},
    priority=3,
    description="Low severity: Log only"
)

# Context-aware policies
POLICY_REPEAT_OFFENDER = ResponsePolicy(
    name="repeat_offender",
    conditions={'repeat_offender': True},
    actions=[ACTION_BLOCK_IP, ACTION_ALERT_EMAIL],
    action_params={
        'block_duration': BLOCK_DURATION_CRITICAL,  # Longer block
        'alert_recipients': ['admin@example.com'],
        'escalate': True
    },
    priority=12,  # Higher priority than standard policies
    description="Repeat offenders: Escalated response"
)

POLICY_OFF_HOURS = ResponsePolicy(
    name="off_hours_suspicious",
    conditions={
        'severity': SEVERITY_MEDIUM,
        'time_of_day': 'off_hours'
    },
    actions=[ACTION_BLOCK_IP, ACTION_ALERT_EMAIL],
    action_params={
        'block_duration': BLOCK_DURATION_MEDIUM,
        'alert_recipients': ['admin@example.com'],
        'reason': 'Suspicious activity during off-hours'
    },
    priority=9,
    description="Medium threats during off-hours: Escalate to block + alert"
)


# ============================================================================
# POLICY ENGINE
# ============================================================================

class PolicyEngine:
    """
    Policy-based action selection engine.
    
    Can work standalone or provide suggestions to LLM.
    """

    def __init__(self):
        """Initialize policy engine"""
        self.logger = logging.getLogger(__name__ + ".PolicyEngine")

        # Load default policies
        self.policies = [
            POLICY_REPEAT_OFFENDER,  # Highest priority
            POLICY_CRITICAL,
            POLICY_OFF_HOURS,
            POLICY_HIGH,
            POLICY_MEDIUM,
            POLICY_LOW
        ]

        # Sort by priority (highest first)
        self.policies.sort(key=lambda p: p.priority, reverse=True)

        self.logger.info(
            f"✅ PolicyEngine initialized with {len(self.policies)} policies")

    def add_policy(self, policy: ResponsePolicy):
        """Add a custom policy"""
        self.policies.append(policy)
        self.policies.sort(key=lambda p: p.priority, reverse=True)
        self.logger.info(f"✅ Added policy: {policy.name}")

    def get_matching_policies(self, context: ThreatContext) -> List[ResponsePolicy]:
        """Get all policies that match the given context"""
        matching = []

        for policy in self.policies:
            if policy.matches(context):
                matching.append(policy)
                self.logger.info(f"   ✅ Policy matched: {policy.name}")

        return matching

    def suggest_actions(self, context: ThreatContext) -> Dict[str, Any]:
        """
        Suggest actions based on policies.
        
        Returns highest priority matching policy.
        Can be used by LLM as guidance.
        
        Args:
            context: ThreatContext with threat information
            
        Returns:
            Dictionary with suggested actions and parameters
        """
        self.logger.info(
            f"🔍 Evaluating policies for {context.severity} threat")

        matching_policies = self.get_matching_policies(context)

        if not matching_policies:
            self.logger.warning(
                "⚠️  No matching policies found, using default")
            return {
                'policy': 'default',
                'actions': [ACTION_LOG_INCIDENT],
                'parameters': {},
                'reasoning': 'No specific policy matched, logging only'
            }

        # Return highest priority policy
        best_policy = matching_policies[0]

        self.logger.info(
            f"✅ Selected policy: {best_policy.name} (priority: {best_policy.priority})")

        # Apply escalation logic
        actions = best_policy.actions.copy()
        params = best_policy.action_params.copy()

        # Escalate for repeat offenders
        if context.is_repeat_offender:
            if ACTION_BLOCK_IP in actions and 'block_duration' in params:
                # Double the block duration
                params['block_duration'] = params['block_duration'] * 2
                self.logger.info(
                    f"   ⬆️  Escalated block duration to {params['block_duration']}min (repeat offender)")

        # Escalate for known attackers
        if context.known_attacker:
            if ACTION_BLOCK_IP not in actions:
                actions.append(ACTION_BLOCK_IP)
                params['block_duration'] = BLOCK_DURATION_HIGH
                self.logger.info("   ⬆️  Added block action (known attacker)")

        return {
            'policy': best_policy.name,
            'actions': actions,
            'parameters': params,
            'reasoning': best_policy.description,
            'context_factors': {
                'repeat_offender': context.is_repeat_offender,
                'known_attacker': context.known_attacker,
                'previous_attacks': context.previous_attacks
            }
        }

    def explain_suggestion(self, context: ThreatContext) -> str:
        """
        Generate human-readable explanation of suggested actions.
        
        Useful for LLM to understand policy reasoning.
        """
        suggestion = self.suggest_actions(context)

        explanation = f"""
Policy Analysis for Threat:
- Source: {context.source_ip}
- Type: {context.threat_type}
- Severity: {context.severity}
- ML Confidence: {context.ml_confidence:.2%}

Selected Policy: {suggestion['policy']}
Reasoning: {suggestion['reasoning']}

Recommended Actions:
"""

        for action in suggestion['actions']:
            explanation += f"  - {action}\n"

        if suggestion['parameters']:
            explanation += "\nParameters:\n"
            for key, value in suggestion['parameters'].items():
                explanation += f"  - {key}: {value}\n"

        if suggestion['context_factors']:
            explanation += "\nContext Factors:\n"
            for key, value in suggestion['context_factors'].items():
                if value:
                    explanation += f"  - {key}: {value}\n"

        return explanation.strip()

    def get_policy_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all loaded policies"""
        return [
            {
                'name': p.name,
                'priority': p.priority,
                'conditions': p.conditions,
                'actions': p.actions,
                'description': p.description
            }
            for p in self.policies
        ]


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

_policy_engine_instance = None


def get_policy_engine() -> PolicyEngine:
    """Get or create global policy engine instance"""
    global _policy_engine_instance

    if _policy_engine_instance is None:
        _policy_engine_instance = PolicyEngine()

    return _policy_engine_instance


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("Testing Policy Engine...")
    print("=" * 70)

    engine = get_policy_engine()

    print("\n✅ PolicyEngine initialized")
    print(f"   Loaded policies: {len(engine.policies)}")

    # Test Case 1: High severity threat
    print("\n" + "-" * 70)
    print("TEST 1: High Severity Port Scan")
    print("-" * 70)

    context1 = ThreatContext(
        source_ip="192.168.1.100",
        threat_type="Port Scan",
        severity=SEVERITY_HIGH,
        ml_confidence=0.95,
        attack_in_progress=True
    )

    suggestion1 = engine.suggest_actions(context1)
    print(f"\nPolicy: {suggestion1['policy']}")
    print(f"Actions: {suggestion1['actions']}")
    print(f"Parameters: {suggestion1['parameters']}")

    # Test Case 2: Repeat offender
    print("\n" + "-" * 70)
    print("TEST 2: Repeat Offender (Medium Severity)")
    print("-" * 70)

    context2 = ThreatContext(
        source_ip="192.168.1.100",
        threat_type="SSH Brute Force",
        severity=SEVERITY_MEDIUM,
        ml_confidence=0.88,
        is_repeat_offender=True,
        previous_attacks=3
    )

    suggestion2 = engine.suggest_actions(context2)
    print(f"\nPolicy: {suggestion2['policy']}")
    print(f"Actions: {suggestion2['actions']}")
    print(f"Parameters: {suggestion2['parameters']}")
    print(f"Context: {suggestion2['context_factors']}")

    # Test Case 3: Critical APT
    print("\n" + "-" * 70)
    print("TEST 3: Critical APT Attack")
    print("-" * 70)

    context3 = ThreatContext(
        source_ip="10.0.0.50",
        threat_type="APT - Data Exfiltration",
        severity=SEVERITY_CRITICAL,
        ml_confidence=0.92,
        known_attacker=True,
        attack_in_progress=True
    )

    explanation = engine.explain_suggestion(context3)
    print(f"\n{explanation}")

    print("\n" + "=" * 70)
    print("✅ Policy engine test complete!")

"""
PlaybookGenerator — produces structured, step-by-step response plans.

Two modes:
  (a) Rule-based: selects a template matching the threat type.
  (b) LLM-generated: used for novel threats via compressed context.

The output Playbook object is written to state['playbook'] by ResponseAgent.
"""

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PlaybookStep:
    step_number: int
    action: str         # e.g. "block_ip", "alert_email", "isolate_host"
    target: str         # placeholder like "{src_ip}" resolved at runtime
    description: str
    is_automated: bool
    requires_approval: bool


@dataclass
class Playbook:
    playbook_id: str
    title: str
    steps: List[PlaybookStep] = field(default_factory=list)
    severity: str = "MEDIUM"
    estimated_duration: str = "5 minutes"
    auto_executable_steps: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "title": self.title,
            "severity": self.severity,
            "estimated_duration": self.estimated_duration,
            "auto_executable_steps": self.auto_executable_steps,
            "steps": [
                {
                    "step_number": s.step_number,
                    "action": s.action,
                    "target": s.target,
                    "description": s.description,
                    "is_automated": s.is_automated,
                    "requires_approval": s.requires_approval,
                }
                for s in self.steps
            ],
        }


# ---------------------------------------------------------------------------
# Rule-based templates
# Each step uses {src_ip} / {dst_ip} placeholders resolved at generation time
# ---------------------------------------------------------------------------

_TEMPLATES: Dict[str, List[PlaybookStep]] = {
    "SSH_BRUTE": [
        PlaybookStep(1, "block_ip", "{src_ip}", "Block attacking IP at firewall", True, False),
        PlaybookStep(2, "alert_email", "admin", "Alert security team of brute-force attempt", True, False),
        PlaybookStep(3, "audit_logs", "{dst_ip}", "Review SSH authentication logs on target", False, False),
        PlaybookStep(4, "reset_credentials", "{dst_ip}", "Rotate credentials if compromise suspected", False, True),
    ],
    "PORT_SCAN": [
        PlaybookStep(1, "block_ip", "{src_ip}", "Block reconnaissance source IP", True, False),
        PlaybookStep(2, "alert_email", "admin", "Notify SOC of reconnaissance activity", True, False),
        PlaybookStep(3, "review_exposed_ports", "{dst_ip}", "Review exposed services for vulnerabilities", False, False),
    ],
    "DNS_TUNNELING": [
        PlaybookStep(1, "block_ip", "{src_ip}", "Block C2 / tunnelling source IP", True, False),
        PlaybookStep(2, "block_domain", "{dst_ip}", "Add suspicious domain to DNS sinkhole", True, True),
        PlaybookStep(3, "alert_email", "admin", "Alert security team — data exfil indicator", True, False),
        PlaybookStep(4, "forensic_capture", "{dst_ip}", "Capture DNS query logs for forensics", False, False),
    ],
    "DATA_EXFILTRATION": [
        PlaybookStep(1, "block_ip", "{src_ip}", "Block exfiltration destination", True, False),
        PlaybookStep(2, "isolate_host", "{dst_ip}", "Isolate potentially compromised host", False, True),
        PlaybookStep(3, "alert_email", "admin", "Critical alert — data exfiltration detected", True, False),
        PlaybookStep(4, "forensic_capture", "{dst_ip}", "Capture memory image for forensic analysis", False, True),
    ],
    "DDOS": [
        PlaybookStep(1, "rate_limit", "{src_ip}", "Apply rate limiting on attacking IPs", True, False),
        PlaybookStep(2, "block_ip", "{src_ip}", "Block top attacking source IPs", True, False),
        PlaybookStep(3, "alert_email", "admin", "Alert NOC and management of DDoS event", True, False),
        PlaybookStep(4, "review_capacity", "{dst_ip}", "Assess target service capacity and scaling options", False, True),
    ],
    "RANSOMWARE": [
        PlaybookStep(1, "isolate_host", "{dst_ip}", "Immediately isolate affected host from network", False, True),
        PlaybookStep(2, "block_ip", "{src_ip}", "Block C2 server communication", True, False),
        PlaybookStep(3, "alert_email", "admin", "Critical — ransomware detected, escalate immediately", True, False),
        PlaybookStep(4, "forensic_capture", "{dst_ip}", "Capture disk image before any remediation", False, True),
        PlaybookStep(5, "restore_backup", "{dst_ip}", "Restore from last known-good backup after forensics", False, True),
    ],
    "DEFAULT": [
        PlaybookStep(1, "block_ip", "{src_ip}", "Block suspicious source IP as precaution", True, False),
        PlaybookStep(2, "alert_email", "admin", "Notify security team of detected threat", True, False),
        PlaybookStep(3, "review_logs", "{dst_ip}", "Review related traffic and system logs", False, False),
    ],
}

_TEMPLATE_KEYWORDS: List[tuple] = [
    (["SSH", "BRUTE", "LOGIN", "AUTH_FAIL"], "SSH_BRUTE"),
    (["SCAN", "RECON", "PORT_SCAN", "PROBE"], "PORT_SCAN"),
    (["DNS_TUNNEL", "DNS_EXFIL", "COVERT"], "DNS_TUNNELING"),
    (["EXFIL", "DATA_THEFT", "TRANSFER"], "DATA_EXFILTRATION"),
    (["DDOS", "DOS", "FLOOD", "DENIAL"], "DDOS"),
    (["RANSOMWARE", "ENCRYPT", "WIPER"], "RANSOMWARE"),
]


class PlaybookGenerator:
    """
    Generates a Playbook for a given threat context.

    Tries rule-based template matching first; falls back to LLM generation
    for unknown threat types (requires LLM to be available).
    """

    def generate_playbook(
        self,
        threat_context: Dict[str, Any],
        investigation_report: Optional[Dict[str, Any]] = None,
        attack_chain: Optional[Any] = None,
    ) -> Playbook:
        """
        Generate a response playbook.

        Args:
            threat_context:      Dict with keys: threat_type, src_ip, dst_ip, severity.
            investigation_report: Optional dict from InvestigationAgent.
            attack_chain:        Optional AttackChain object from CorrelationEngine.

        Returns:
            Populated Playbook object.
        """
        investigation_report = investigation_report or {}
        threat_type = (
            str(threat_context.get("threat_type", ""))
            or str(investigation_report.get("threat_type", ""))
        ).upper()
        src_ip = threat_context.get("src_ip", "unknown")
        dst_ip = threat_context.get("dst_ip", "unknown")
        severity = str(threat_context.get("severity", "MEDIUM")).upper()

        template_key = self._match_template(threat_type)
        steps = self._resolve_steps(_TEMPLATES.get(template_key, _TEMPLATES["DEFAULT"]), src_ip, dst_ip)

        # Enhance steps if a multi-stage chain was detected
        if attack_chain and hasattr(attack_chain, "confidence") and attack_chain.confidence > 0.5:
            steps = self._add_apt_steps(steps, attack_chain)

        # LLM generation for completely novel threats
        if template_key == "DEFAULT" and investigation_report.get("confidence", 1.0) < 0.3:
            llm_steps = self._llm_generate(threat_context, investigation_report)
            if llm_steps:
                steps = llm_steps

        auto_count = sum(1 for s in steps if s.is_automated and not s.requires_approval)

        return Playbook(
            playbook_id=f"pb-{uuid.uuid4().hex[:8]}",
            title=f"{severity} {threat_type.replace('_', ' ').title()} Response Playbook",
            steps=steps,
            severity=severity,
            estimated_duration=self._estimate_duration(steps),
            auto_executable_steps=auto_count,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _match_template(threat_type: str) -> str:
        for keywords, key in _TEMPLATE_KEYWORDS:
            if any(kw in threat_type for kw in keywords):
                return key
        return "DEFAULT"

    @staticmethod
    def _resolve_steps(
        template: List[PlaybookStep], src_ip: str, dst_ip: str
    ) -> List[PlaybookStep]:
        resolved = []
        for step in template:
            resolved.append(
                PlaybookStep(
                    step_number=step.step_number,
                    action=step.action,
                    target=step.target.replace("{src_ip}", src_ip).replace("{dst_ip}", dst_ip),
                    description=step.description,
                    is_automated=step.is_automated,
                    requires_approval=step.requires_approval,
                )
            )
        return resolved

    @staticmethod
    def _add_apt_steps(
        steps: List[PlaybookStep], attack_chain: Any
    ) -> List[PlaybookStep]:
        """Append APT-specific investigation step for multi-stage chains."""
        next_num = max((s.step_number for s in steps), default=0) + 1
        stages_str = ", ".join(
            s.stage_name for s in getattr(attack_chain, "stages", [])[:4]
        )
        steps.append(
            PlaybookStep(
                step_number=next_num,
                action="apt_investigation",
                target=", ".join(getattr(attack_chain, "source_ips", [])[:3]),
                description=(
                    f"Conduct full APT investigation — detected chain: {stages_str}. "
                    f"Chain confidence: {getattr(attack_chain, 'confidence', 0):.0%}"
                ),
                is_automated=False,
                requires_approval=True,
            )
        )
        return steps

    @staticmethod
    def _llm_generate(
        threat_context: Dict[str, Any],
        investigation_report: Dict[str, Any],
    ) -> Optional[List[PlaybookStep]]:
        """Attempt LLM-based playbook generation for novel threats."""
        try:
            from src.llm_agent.llm_client import CyberSecurityLLM  # type: ignore
            from src.llm_agent.llm_budget_manager import get_budget_manager  # type: ignore

            budget = get_budget_manager()
            if not budget.request_llm_call("MEDIUM", estimated_tokens=300):
                return None

            llm = CyberSecurityLLM()
            if llm.llm is None:
                return None

            from langchain_core.messages import HumanMessage  # type: ignore

            prompt = (
                "Generate a 3-5 step security response playbook as JSON array of steps.\n"
                f"Threat: {threat_context.get('threat_type', 'unknown')}\n"
                f"Source IP: {threat_context.get('src_ip', 'unknown')}\n"
                f"Severity: {threat_context.get('severity', 'MEDIUM')}\n"
                "Each step: {\"step_number\": N, \"action\": \"...\", \"description\": \"...\", "
                "\"is_automated\": true/false}\n"
                "Return ONLY the JSON array."
            )
            response = llm.llm.invoke([HumanMessage(content=prompt)])
            import json as _json

            raw = response.content.strip().lstrip("```json").lstrip("```").rstrip("```")
            data = _json.loads(raw)
            steps = []
            for item in data[:5]:
                steps.append(
                    PlaybookStep(
                        step_number=int(item.get("step_number", len(steps) + 1)),
                        action=str(item.get("action", "review")),
                        target=threat_context.get("src_ip", "unknown"),
                        description=str(item.get("description", "")),
                        is_automated=bool(item.get("is_automated", False)),
                        requires_approval=not bool(item.get("is_automated", False)),
                    )
                )
            return steps or None
        except Exception as exc:
            logger.debug("LLM playbook generation failed: %s", exc)
            return None

    @staticmethod
    def _estimate_duration(steps: List[PlaybookStep]) -> str:
        manual = sum(1 for s in steps if not s.is_automated)
        automated = sum(1 for s in steps if s.is_automated)
        mins = automated * 1 + manual * 5
        return f"{mins} minutes"

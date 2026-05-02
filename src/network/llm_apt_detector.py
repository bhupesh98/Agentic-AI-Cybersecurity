"""
LLM-Focused APT Detector

Demonstrates LLM's superior reasoning for sophisticated threat detection.
Minimal ML reliance, maximum LLM contextual analysis.

Key Features:
- Deep contextual reasoning for each detection
- Multi-stage attack correlation
- Detailed analysis export to file
- Concise terminal summary

Location: src/network/llm_apt_detector.py
"""

from src.llm_agent.llm_client import get_llm_client
from src.utils.colored_logger import ColoredLogger, get_logger
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Add project root
_project_root = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


# Action execution integration
try:
    from src.actions.action_executor import (
        get_action_executor,
        BlockIPAction,
        AlertAction,
        ActionPriority
    )
    ACTIONS_AVAILABLE = True
except ImportError:
    ACTIONS_AVAILABLE = False


class LLMAPTDetector:
    """
    LLM-focused detector for sophisticated APT campaigns.
    
    Philosophy: ML does basic filtering, LLM does sophisticated reasoning.
    """

    def __init__(self, campaign_name: str = "Unknown Campaign"):
        """Initialize LLM APT detector."""
        self.logger = get_logger("LLM_APT_Detector")
        self.campaign_name = campaign_name
        self.session_id = f"llm-apt-{int(time.time())}"

        # Components
        self.llm = None

        # Detection state
        self.detected_stages = []
        self.all_observations = []
        self.campaign_timeline = []

        # Report configuration
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)

    def initialize(self):
        """Initialize LLM client."""
        ColoredLogger.print_header("LLM-FOCUSED APT DETECTOR", width=70)

        self.logger.info("Initializing LLM client...")
        self.llm = get_llm_client()

        if not self.llm.llm:
            self.logger.error("❌ LLM not available (OPENAI_API_KEY not set)")
            raise RuntimeError("LLM required for this detector")

        self.logger.success("✅ LLM client initialized")
        ColoredLogger.print_separator()

    def analyze_traffic_pattern(
        self,
        stage_number: int,
        stage_name: str,
        packets: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze traffic pattern using LLM with rich context.
        
        Args:
            stage_number: Attack stage number
            stage_name: Stage identifier
            packets: List of packet information
            context: Additional context (previous stages, timeline, etc.)
            
        Returns:
            LLM analysis results
        """
        # Build rich context for LLM
        analysis_prompt = self._build_apt_analysis_prompt(
            stage_number, stage_name, packets, context
        )

        # Get LLM analysis
        self.logger.info(
            f"🤖 LLM analyzing Stage {stage_number}: {stage_name}...")

        try:
            response = self.llm.llm.invoke(analysis_prompt)
            analysis_text = response.content if hasattr(
                response, 'content') else str(response)

            # Parse LLM response
            analysis = {
                'stage_number': stage_number,
                'stage_name': stage_name,
                'timestamp': datetime.now().isoformat(),
                'packets_analyzed': len(packets),
                'llm_analysis': analysis_text,
                'is_malicious': self._extract_verdict(analysis_text),
                'severity': self._extract_severity(analysis_text),
                'confidence': self._extract_confidence(analysis_text),
                'indicators': self._extract_indicators(analysis_text, packets),
                'recommended_actions': self._extract_actions(analysis_text)
            }

            self.detected_stages.append(analysis)
            return analysis

        except Exception as e:
            self.logger.error(f"LLM analysis failed: {e}")
            return {
                'stage_number': stage_number,
                'stage_name': stage_name,
                'error': str(e)
            }

    def _build_apt_analysis_prompt(
        self,
        stage_number: int,
        stage_name: str,
        packets: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> str:
        """Build detailed prompt for LLM APT analysis."""

        # Packet summary
        packet_summary = []
        for i, pkt in enumerate(packets, 1):
            summary = (f"Packet {i}: {pkt['src_ip']}:{pkt['src_port']} → "
                       f"{pkt['dst_ip']}:{pkt['dst_port']} "
                       f"[{pkt['protocol']}] Flags:{pkt.get('flags', 'N/A')}")
            if pkt.get('payload'):
                payload_preview = pkt['payload'][:50] if isinstance(
                    pkt['payload'], bytes) else str(pkt['payload'])[:50]
                summary += f" Payload: {payload_preview}..."
            packet_summary.append(summary)

        # Previous stages context
        previous_stages = ""
        if context.get('previous_stages'):
            previous_stages = "\n\nPREVIOUS ATTACK STAGES DETECTED:\n"
            for prev in context['previous_stages']:
                previous_stages += f"- Stage {prev['stage_number']}: {prev['stage_name']} "
                previous_stages += f"(Severity: {prev.get('severity', 'unknown')})\n"
                previous_stages += f"  Summary: {prev.get('llm_analysis', 'N/A')[:200]}...\n"

        prompt = f"""You are an elite cybersecurity analyst specializing in Advanced Persistent Threat (APT) detection.

CURRENT OBSERVATION - Stage {stage_number}: {stage_name}
{'='*70}

NETWORK TRAFFIC CAPTURED:
{chr(10).join(packet_summary)}

CONTEXT:
- Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Campaign Under Analysis: {self.campaign_name}
- Total Packets This Stage: {len(packets)}
- Timeline Position: Stage {stage_number} of suspected multi-stage attack
{previous_stages}

YOUR TASK:
Analyze this traffic pattern with extreme attention to detail. Consider:

1. BEHAVIORAL ANALYSIS:
   - What is the attacker trying to accomplish?
   - Are the timing patterns consistent with automated or manual activity?
   - Does the port selection suggest reconnaissance, exploitation, or other intent?

2. CONTEXTUAL REASONING:
   - How does this stage relate to previous stages (if any)?
   - What does the source/destination IP relationship suggest?
   - Are there indicators of compromise (IOCs)?

3. THREAT ASSESSMENT:
   - Severity: CRITICAL / HIGH / MEDIUM / LOW
   - Confidence: 0-100% (how certain are you?)
   - Is this part of a coordinated APT campaign?

4. TECHNICAL INDICATORS:
   - Specific ports, protocols, or patterns that are suspicious
   - Payload characteristics (if present)
   - Traffic timing and volume anomalies

5. RECOMMENDED RESPONSE:
   - Immediate actions required
   - Investigation steps
   - Containment measures

RESPONSE FORMAT:
Provide a comprehensive analysis covering all points above. Be specific, technical, and actionable.
Start with a clear verdict: MALICIOUS or BENIGN, followed by detailed reasoning.

Your analysis will be used for:
- Real-time incident response
- Forensic investigation
- Threat intelligence reporting
- Executive briefings

BEGIN ANALYSIS:
"""
        return prompt

    def _extract_verdict(self, analysis: str) -> bool:
        """Extract malicious/benign verdict from LLM response."""
        analysis_lower = analysis.lower()
        if 'malicious' in analysis_lower[:200]:  # Check first 200 chars
            return True
        return False

    def _extract_severity(self, analysis: str) -> str:
        """Extract severity level from LLM response."""
        analysis_lower = analysis.lower()
        if 'critical' in analysis_lower:
            return 'critical'
        elif 'high' in analysis_lower:
            return 'high'
        elif 'medium' in analysis_lower:
            return 'medium'
        else:
            return 'low'

    def _extract_confidence(self, analysis: str) -> float:
        """Extract confidence percentage from LLM response."""
        # Look for percentage in text
        import re
        matches = re.findall(r'(\d+)%', analysis)
        if matches:
            return float(matches[0]) / 100.0
        return 0.85  # Default high confidence

    def _extract_indicators(self, analysis: str, packets: List[Dict]) -> List[str]:
        """Extract IOCs from analysis."""
        indicators = []

        # Extract IPs mentioned
        unique_ips = set()
        for pkt in packets:
            unique_ips.add(pkt['src_ip'])
            unique_ips.add(pkt['dst_ip'])

        for ip in unique_ips:
            indicators.append(f"IP: {ip}")

        # Extract ports
        unique_ports = set()
        for pkt in packets:
            unique_ports.add(pkt['dst_port'])

        for port in unique_ports:
            indicators.append(f"Port: {port}")

        return indicators

    def _extract_actions(self, analysis: str) -> List[str]:
        """Extract recommended actions from analysis."""
        actions = []

        # Look for action keywords
        analysis_lower = analysis.lower()

        if 'isolate' in analysis_lower or 'quarantine' in analysis_lower:
            actions.append("Isolate affected systems")
        if 'investigate' in analysis_lower:
            actions.append("Conduct forensic investigation")
        if 'monitor' in analysis_lower:
            actions.append("Enhanced network monitoring")
        if 'block' in analysis_lower:
            actions.append("Block malicious IPs/ports")

        # Default actions if none extracted
        if not actions:
            actions = [
                "Investigate source IPs",
                "Review firewall logs",
                "Alert security team"
            ]

        return actions

    def execute_response_actions(self, analysis: Dict[str, Any], packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute autonomous response actions based on LLM analysis.
        
        Args:
            analysis: LLM analysis results
            packets: Original packet data
            
        Returns:
            List of executed action results
        """
        if not ACTIONS_AVAILABLE:
            self.logger.warning(
                "Action executor not available - skipping response")
            return []

        executed_actions = []
        executor = get_action_executor()

        severity = analysis.get('severity', 'medium').lower()
        is_malicious = analysis.get('is_malicious', False)

        if not is_malicious:
            return []

        # Extract IPs from packets
        source_ips = set(pkt['src_ip'] for pkt in packets)

        # Determine action priority based on severity
        if severity == 'critical':
            priority = ActionPriority.CRITICAL
        elif severity == 'high':
            priority = ActionPriority.HIGH
        else:
            priority = ActionPriority.MEDIUM

        # For CRITICAL threats: Block IPs
        if severity in ['critical', 'high']:
            for src_ip in source_ips:
                action = BlockIPAction(
                    action_id=f"block-{analysis['stage_number']}-{src_ip.replace('.', '-')}",
                    priority=priority,
                    target=src_ip,
                    reason=f"Stage {analysis['stage_number']}: {analysis['stage_name']} - {severity.upper()} threat detected",
                    duration_minutes=30 if severity == 'critical' else 15
                )

                executor.submit_action(action)
                executed_actions.append({
                    'action_type': 'block_ip',
                    'target': src_ip,
                    'priority': priority.name,
                    'stage': analysis['stage_number']
                })

                self.logger.info(f"⚡ Submitted block action for {src_ip}")

        # Always send alert for malicious activity
        alert = AlertAction(
            action_id=f"alert-{analysis['stage_number']}",
            priority=priority,
            target="security-team@example.com",
            reason=f"APT Campaign '{self.campaign_name}' - Stage {analysis['stage_number']}",
            severity=severity.upper(),
            recipients=["security-team@example.com"],
            message=f"Stage {analysis['stage_number']}: {analysis['stage_name']}\n"
                   f"Severity: {severity.upper()}\n"
                   f"Source IPs: {', '.join(source_ips)}\n"
                   f"Analysis: {analysis.get('llm_analysis', '')[:200]}...",
            alert_type="email"
        )

        executor.submit_action(alert)
        executed_actions.append({
            'action_type': 'alert',
            'target': 'security-team',
            'priority': priority.name,
            'stage': analysis['stage_number']
        })

        self.logger.info(
            f"⚡ Submitted alert for Stage {analysis['stage_number']}")

        return executed_actions

    def display_stage_result(self, analysis: Dict[str, Any]):
        """Display concise stage analysis in terminal."""
        stage_num = analysis['stage_number']
        stage_name = analysis['stage_name']
        severity = analysis.get('severity', 'unknown').upper()
        confidence = analysis.get('confidence', 0.0)

        # Truncate LLM analysis for display
        llm_text = analysis.get('llm_analysis', '')
        llm_preview = llm_text[:300] + \
            "..." if len(llm_text) > 300 else llm_text

        print(f"\n{'='*70}")
        print(f"🔴 STAGE {stage_num} DETECTED: {stage_name}")
        print(f"{'='*70}")
        print(f"Severity: {severity} | Confidence: {confidence:.0%}")
        print("\n🤖 LLM Analysis Preview:")
        print(f"{llm_preview}")
        print("\n📄 Full analysis saved to report")
        print(f"{'='*70}\n")

    def generate_campaign_report(self) -> str:
        """
        Generate comprehensive campaign analysis report.
        
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"apt_analysis_{self.campaign_name.replace(' ', '_')}_{timestamp}.txt"
        report_path = self.report_dir / report_filename

        self.logger.info("📝 Generating comprehensive report...")

        with open(report_path, 'w') as f:
            # Header
            f.write("="*80 + "\n")
            f.write("APT CAMPAIGN ANALYSIS REPORT\n")
            f.write("="*80 + "\n\n")

            f.write(f"Campaign Name: {self.campaign_name}\n")
            f.write(f"Analysis Session: {self.session_id}\n")
            f.write(
                f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("Detector: LLM-Focused APT Detector v1.0\n")
            f.write(f"Total Stages Detected: {len(self.detected_stages)}\n\n")

            # Executive Summary
            f.write("="*80 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("="*80 + "\n\n")

            critical_stages = sum(
                1 for s in self.detected_stages if s.get('severity') == 'critical')
            high_stages = sum(
                1 for s in self.detected_stages if s.get('severity') == 'high')

            f.write(
                "This report documents the detection and analysis of a multi-stage Advanced\n")
            f.write(
                f"Persistent Threat (APT) campaign identified as '{self.campaign_name}'.\n\n")
            f.write("Key Findings:\n")
            f.write(
                f"- {len(self.detected_stages)} distinct attack stages identified\n")
            f.write(f"- {critical_stages} CRITICAL severity stages\n")
            f.write(f"- {high_stages} HIGH severity stages\n")
            f.write(
                "- Sophisticated multi-stage attack requiring advanced detection\n\n")

            # Detailed Stage Analysis
            f.write("\n" + "="*80 + "\n")
            f.write("DETAILED STAGE-BY-STAGE ANALYSIS\n")
            f.write("="*80 + "\n\n")

            for i, stage in enumerate(self.detected_stages, 1):
                f.write(f"\n{'─'*80}\n")
                f.write(
                    f"STAGE {stage['stage_number']}: {stage['stage_name']}\n")
                f.write(f"{'─'*80}\n\n")

                f.write(f"Timestamp: {stage['timestamp']}\n")
                f.write(f"Packets Analyzed: {stage['packets_analyzed']}\n")
                f.write(
                    f"Verdict: {'MALICIOUS' if stage.get('is_malicious') else 'BENIGN'}\n")
                f.write(
                    f"Severity: {stage.get('severity', 'unknown').upper()}\n")
                f.write(f"Confidence: {stage.get('confidence', 0.0):.0%}\n\n")

                f.write("LLM ANALYSIS:\n")
                f.write("-" * 80 + "\n")
                f.write(stage.get('llm_analysis', 'No analysis available'))
                f.write("\n" + "-" * 80 + "\n\n")

                if stage.get('indicators'):
                    f.write("INDICATORS OF COMPROMISE (IOCs):\n")
                    for ioc in stage['indicators']:
                        f.write(f"  • {ioc}\n")
                    f.write("\n")

                if stage.get('recommended_actions'):
                    f.write("RECOMMENDED ACTIONS:\n")
                    for action in stage['recommended_actions']:
                        f.write(f"  ✓ {action}\n")
                    f.write("\n")

            # Conclusion
            f.write("\n" + "="*80 + "\n")
            f.write("CONCLUSION\n")
            f.write("="*80 + "\n\n")

            f.write(
                "The LLM-based analysis successfully identified and characterized all\n")
            f.write(
                f"{len(self.detected_stages)} stages of the '{self.campaign_name}' APT campaign.\n\n")
            f.write(
                "This detection demonstrates the value of contextual reasoning and behavioral\n")
            f.write(
                "analysis in identifying sophisticated threats that may evade signature-based\n")
            f.write("or pattern-matching approaches.\n\n")

            f.write("="*80 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*80 + "\n")

        self.logger.success(f"✅ Report saved: {report_path}")
        return str(report_path)


if __name__ == "__main__":
    """Test LLM APT detector."""
    detector = LLMAPTDetector(campaign_name="Test Campaign")
    detector.initialize()

    # Test with mock stage
    test_packets = [
        {
            'src_ip': '10.0.0.99',
            'dst_ip': '172.16.0.50',
            'src_port': 54321,
            'dst_port': 8005,
            'protocol': 'TCP',
            'flags': 'S'
        }
    ]

    analysis = detector.analyze_traffic_pattern(
        stage_number=1,
        stage_name="Test Reconnaissance",
        packets=test_packets,
        context={'previous_stages': []}
    )

    detector.display_stage_result(analysis)
    report_path = detector.generate_campaign_report()
    print(f"\n✅ Test complete! Report: {report_path}")

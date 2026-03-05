"""
Context Analyzer for Agentic Cybersecurity System.

This module analyzes contextual factors to identify suspicious patterns
that ML models might miss. Implements the "contextual awareness" principle.

"""

from typing import Dict, Any
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ContextAnalyzer:
    """
    Analyzes contextual factors to detect suspicious patterns.
    
    Even if ML says "benign", context can reveal suspicious behavior.
    """

    # Suspicious ports commonly used in attacks
    SUSPICIOUS_PORTS = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB"
    }

    # Off-hours range (midnight to 6 AM)
    OFF_HOURS_START = 0
    OFF_HOURS_END = 6

    def __init__(self):
        """Initialize the context analyzer."""
        self.flags_triggered = []

    def analyze_context(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a network flow for suspicious contextual patterns.
        
        Args:
            flow_data: Network flow information
            
        Returns:
            Dictionary with context analysis results
        """
        flags = []
        reasons = []

        # Check off-hours activity
        if self._is_off_hours(flow_data):
            flags.append("off_hours")
            reasons.append(
                f"Activity at {self._get_time_str(flow_data)} (off-hours)")

        # Check suspicious ports
        port_flag, port_reason = self._check_suspicious_ports(flow_data)
        if port_flag:
            flags.append("suspicious_port")
            reasons.append(port_reason)

        # Check traffic volume anomalies
        volume_flag, volume_reason = self._check_volume_anomaly(flow_data)
        if volume_flag:
            flags.append("volume_anomaly")
            reasons.append(volume_reason)

        # Check connection characteristics
        conn_flag, conn_reason = self._check_connection_pattern(flow_data)
        if conn_flag:
            flags.append("suspicious_connection")
            reasons.append(conn_reason)

        # Check protocol anomalies
        proto_flag, proto_reason = self._check_protocol_anomaly(flow_data)
        if proto_flag:
            flags.append("protocol_anomaly")
            reasons.append(proto_reason)

        # Compute overall suspicion score
        suspicion_score = len(flags) / 5.0  # Normalize to 0-1

        return {
            "flags": flags,
            "reasons": reasons,
            "suspicion_score": suspicion_score,
            "is_suspicious": len(flags) > 0,
            "flag_count": len(flags)
        }

    def _is_off_hours(self, flow_data: Dict[str, Any]) -> bool:
        """Check if activity occurs during off-hours."""
        try:
            timestamp = flow_data.get('timestamp', '')
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                hour = dt.hour
                return self.OFF_HOURS_START <= hour < self.OFF_HOURS_END
        except Exception:
            pass
        return False

    def _get_time_str(self, flow_data: Dict[str, Any]) -> str:
        """Get human-readable time string."""
        try:
            timestamp = flow_data.get('timestamp', '')
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.strftime('%H:%M')
        except Exception:
            pass
        return "unknown time"

    def _check_suspicious_ports(self, flow_data: Dict[str, Any]) -> tuple:
        """Check if destination port is commonly exploited."""
        dst_port = flow_data.get('dst_port', 0)

        if dst_port in self.SUSPICIOUS_PORTS:
            service = self.SUSPICIOUS_PORTS[dst_port]
            return True, f"Connection to {service} port {dst_port}"

        # Check unusual high ports (>50000)
        if dst_port > 50000:
            return True, f"Connection to unusual high port {dst_port}"

        return False, ""

    def _check_volume_anomaly(self, flow_data: Dict[str, Any]) -> tuple:
        """Check for unusual traffic volume patterns."""
        bytes_sent = flow_data.get('bytes_sent', 0)
        bytes_received = flow_data.get('bytes_received', 0)

        # Very asymmetric traffic (potential data exfiltration)
        if bytes_sent > 0 and bytes_received > 0:
            ratio = max(bytes_sent, bytes_received) / \
                min(bytes_sent, bytes_received)
            if ratio > 20:
                return True, f"Highly asymmetric traffic (ratio: {ratio:.1f}:1)"

        # Very large data transfer
        total_bytes = bytes_sent + bytes_received
        if total_bytes > 100000:  # >100KB
            return True, f"Large data transfer ({total_bytes:,} bytes)"

        return False, ""

    def _check_connection_pattern(self, flow_data: Dict[str, Any]) -> tuple:
        """Check for suspicious connection patterns."""
        duration = flow_data.get('duration', 0)
        packets_sent = flow_data.get('packets_sent', 0)
        packets_received = flow_data.get('packets_received', 0)

        # Very short duration with many packets (potential scanning)
        if duration < 0.5 and packets_sent > 50:
            return True, f"Rapid connection ({packets_sent} packets in {duration:.2f}s)"

        # Long duration with very few packets (potential persistence)
        if duration > 60 and (packets_sent + packets_received) < 10:
            return True, f"Long-lived connection with minimal traffic ({duration:.1f}s)"

        return False, ""

    def _check_protocol_anomaly(self, flow_data: Dict[str, Any]) -> tuple:
        """Check for protocol-level anomalies."""
        protocol = flow_data.get('protocol', '').upper()
        dst_port = flow_data.get('dst_port', 0)

        # ICMP on non-standard scenario (potential reconnaissance)
        if protocol == 'ICMP':
            return True, "ICMP traffic (potential network reconnaissance)"

        # UDP to typical TCP ports (potential evasion)
        if protocol == 'UDP' and dst_port in [80, 443, 22, 3389]:
            return True, f"UDP to typical TCP port {dst_port} (unusual)"

        return False, ""


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def check_suspicious_context(flow_data: Dict[str, Any]) -> bool:
    """
    Quick check if a flow has suspicious contextual patterns.
    
    Args:
        flow_data: Network flow information
        
    Returns:
        True if any context flags are triggered
    """
    analyzer = ContextAnalyzer()
    result = analyzer.analyze_context(flow_data)
    return result['is_suspicious']


def get_context_analysis(flow_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get full context analysis for a flow.
    
    Args:
        flow_data: Network flow information
        
    Returns:
        Full context analysis results
    """
    analyzer = ContextAnalyzer()
    return analyzer.analyze_context(flow_data)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    """Test the context analyzer."""
    print("=" * 60)
    print("Testing Context Analyzer")
    print("=" * 60)

    analyzer = ContextAnalyzer()

    # Test case 1: Off-hours SSH connection
    test_flow_1 = {
        'timestamp': '2025-11-19T03:15:00Z',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.50',
        'src_port': 50001,
        'dst_port': 22,
        'protocol': 'TCP',
        'bytes_sent': 5000,
        'bytes_received': 100,
        'packets_sent': 50,
        'packets_received': 5,
        'duration': 0.5
    }

    print("\n🧪 Test 1: Off-hours SSH connection")
    result_1 = analyzer.analyze_context(test_flow_1)
    print(f"  Suspicious: {result_1['is_suspicious']}")
    print(f"  Flags: {result_1['flags']}")
    print("  Reasons:")
    for reason in result_1['reasons']:
        print(f"    • {reason}")
    print(f"  Suspicion Score: {result_1['suspicion_score']:.2f}")

    # Test case 2: Normal daytime HTTPS
    test_flow_2 = {
        'timestamp': '2025-11-19T14:30:00Z',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.50',
        'src_port': 50002,
        'dst_port': 443,
        'protocol': 'TCP',
        'bytes_sent': 1500,
        'bytes_received': 500,
        'packets_sent': 10,
        'packets_received': 5,
        'duration': 1.5
    }

    print("\n🧪 Test 2: Normal daytime HTTPS")
    result_2 = analyzer.analyze_context(test_flow_2)
    print(f"  Suspicious: {result_2['is_suspicious']}")
    print(f"  Flags: {result_2['flags']}")
    print(f"  Suspicion Score: {result_2['suspicion_score']:.2f}")

    # Test case 3: Data exfiltration pattern
    test_flow_3 = {
        'timestamp': '2025-11-19T23:45:00Z',
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.50',
        'src_port': 50003,
        'dst_port': 55555,
        'protocol': 'TCP',
        'bytes_sent': 150000,
        'bytes_received': 500,
        'packets_sent': 200,
        'packets_received': 5,
        'duration': 2.0
    }

    print("\n🧪 Test 3: Potential data exfiltration")
    result_3 = analyzer.analyze_context(test_flow_3)
    print(f"  Suspicious: {result_3['is_suspicious']}")
    print(f"  Flags: {result_3['flags']}")
    print("  Reasons:")
    for reason in result_3['reasons']:
        print(f"    • {reason}")
    print(f"  Suspicion Score: {result_3['suspicion_score']:.2f}")

    print("\n" + "=" * 60)
    print("Context analyzer test complete!")
    print("=" * 60)

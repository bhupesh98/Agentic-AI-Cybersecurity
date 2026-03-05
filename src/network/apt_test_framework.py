"""
Comprehensive APT Testing Framework

This framework provides:
1. Realistic APT attack scenario generation
2. Detection stage tracking
3. Metrics collection and validation
4. Incident response documentation

Designed to be minimally invasive - uses existing infrastructure without modification.

Author: Abhinav
Date: December 2025
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from enum import Enum
import numpy as np

from ..agent import NetworkFlow


def _format_timestamp(dt: datetime) -> str:
    """
    Format datetime to ISO string with 'Z' suffix.
    Handles both timezone-aware and naive datetimes.
    """
    if dt.tzinfo is not None:
        # Timezone-aware: remove timezone info and add Z
        return dt.isoformat().replace('+00:00', '').replace('-00:00', '') + 'Z'
    else:
        # Naive: just add Z
        return dt.isoformat() + 'Z'


class APTStage(Enum):
    """APT Attack Lifecycle Stages (MITRE ATT&CK aligned)"""
    RECONNAISSANCE = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


@dataclass
class APTStageDefinition:
    """Definition of an APT attack stage"""
    stage: APTStage
    stage_number: int
    description: str
    expected_detection_stage: Optional[APTStage] = None  # When should it be detected?
    ml_detectable: bool = False
    llm_detectable: bool = True
    stealth_level: str = "medium"  # low, medium, high
    duration_minutes: float = 5.0
    network_flows: List[NetworkFlow] = field(default_factory=list)


@dataclass
class DetectionEvent:
    """Record of when and how an attack was detected"""
    detected_at_stage: APTStage
    detection_timestamp: datetime
    detection_method: str  # "ML", "LLM", "Context", "Memory"
    confidence: float
    flow_id: str
    severity: str
    reasoning: str
    time_from_attack_start: timedelta


@dataclass
class IncidentResponse:
    """Record of incident response actions taken"""
    action_type: str  # "block_ip", "alert", "isolate", etc.
    target: str
    timestamp: datetime
    success: bool
    execution_time_ms: float
    details: Dict[str, Any]


@dataclass
class APTTestResult:
    """Complete results from an APT test scenario"""
    scenario_name: str
    attacker_ip: str
    target_ip: str
    start_time: datetime
    end_time: datetime
    
    # Attack stages
    stages_executed: List[APTStageDefinition]
    
    # Detection tracking
    first_detection: Optional[DetectionEvent] = None
    all_detections: List[DetectionEvent] = field(default_factory=list)
    detection_stage: Optional[APTStage] = None  # At which stage was it first detected?
    
    # Response tracking
    responses: List[IncidentResponse] = field(default_factory=list)
    
    # Metrics
    time_to_detect_seconds: Optional[float] = None
    detection_accuracy: float = 0.0
    false_negatives: int = 0
    false_positives: int = 0
    
    # Summary
    detected: bool = False
    detection_method: Optional[str] = None
    overall_severity: str = "UNKNOWN"


class APTScenarioGenerator:
    """
    Generates realistic APT attack scenarios.
    
    Based on real-world APT groups:
    - APT28 (Fancy Bear) - Spear phishing, credential theft
    - APT29 (Cozy Bear) - Long-term persistence, stealth
    - Lazarus Group - Financial theft, destructive attacks
    
    Timeline Options:
    - realistic_timeline=False: Compressed timelines (minutes/hours) for rapid testing
    - realistic_timeline=True: Realistic timelines (days/weeks) matching real APT campaigns
    """
    
    def __init__(self):
        self.scenarios = {
            "APT28_Style": self._generate_apt28_scenario,
            "APT29_Style": self._generate_apt29_scenario,
            "Lazarus_Style": self._generate_lazarus_scenario,
            "Silent_Shadow": self._generate_silent_shadow_scenario,
        }
    
    def _get_time_delta(self, compressed_minutes: float, realistic_days: float, realistic_timeline: bool) -> timedelta:
        """
        Get time delta based on timeline mode.
        
        Args:
            compressed_minutes: Time in minutes for compressed timeline (testing)
            realistic_days: Time in days for realistic timeline (real APT)
            realistic_timeline: Whether to use realistic timeline
            
        Returns:
            timedelta object
        """
        if realistic_timeline:
            return timedelta(days=realistic_days)
        else:
            return timedelta(minutes=compressed_minutes)
    
    def generate_scenario(
        self,
        scenario_name: str,
        attacker_ip: str = "192.168.1.250",
        target_ip: str = "10.0.0.100",
        start_time: Optional[datetime] = None,
        realistic_timeline: bool = False
    ) -> List[APTStageDefinition]:
        """
        Generate a complete APT scenario.
        
        Args:
            scenario_name: Name of the scenario to generate
            attacker_ip: Attacker's IP address
            target_ip: Primary target IP
            start_time: When the attack starts (default: now)
            realistic_timeline: If True, use realistic APT timelines (days/weeks between stages).
                               If False, use compressed timelines (minutes/hours) for testing.
                               Default: False (compressed for faster testing)
            
        Returns:
            List of APTStageDefinition objects
            
        Note:
            Real APTs typically span 3-6 months. When realistic_timeline=True:
            - Reconnaissance: 2-4 weeks
            - Initial Access to Execution: 1-2 weeks
            - Persistence to Lateral Movement: 1-3 weeks
            - Collection to Exfiltration: 1-4 weeks
            
            When realistic_timeline=False (compressed):
            - Stages are minutes/hours apart for faster testing
            - This makes detection easier but allows rapid testing
            
            IMPORTANT: The realistic timeline mode sets timestamps that are days/weeks
            apart, but the test processes flows immediately without waiting. The test
            completes in minutes, not months! Timestamps are used for:
            - Calculating realistic time-to-detect metrics
            - Temporal correlation in the memory system
            - Realistic attack timeline representation in reports
        """
        if scenario_name not in self.scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}. Available: {list(self.scenarios.keys())}")
        
        if start_time is None:
            start_time = datetime.now(timezone.utc)
        
        return self.scenarios[scenario_name](attacker_ip, target_ip, start_time, realistic_timeline)
    
    def _generate_apt28_scenario(
        self,
        attacker_ip: str,
        target_ip: str,
        start_time: datetime,
        realistic_timeline: bool = False
    ) -> List[APTStageDefinition]:
        """
        APT28 (Fancy Bear) style attack:
        - Spear phishing with malicious attachment
        - Credential harvesting
        - Lateral movement via SMB
        - Data exfiltration
        """
        stages = []
        current_time = start_time
        
        # Stage 1: Reconnaissance - Email reconnaissance, target profiling
        stages.append(APTStageDefinition(
            stage=APTStage.RECONNAISSANCE,
            stage_number=1,
            description="Email reconnaissance and target profiling",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,  # More realistic - detect later
            ml_detectable=False,
            llm_detectable=False,  # Very stealthy - should NOT be detected
            stealth_level="high",
            duration_minutes=30.0 if not realistic_timeline else 14.0 * 24 * 60,  # 2 weeks
            network_flows=self._create_recon_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(30, 14, realistic_timeline)  # 2 weeks
        
        # Stage 2: Initial Access - Spear phishing with malicious attachment
        # NOTE: Real APTs evade detection at Initial Access. Detection here is unrealistic.
        stages.append(APTStageDefinition(
            stage=APTStage.INITIAL_ACCESS,
            stage_number=2,
            description="Spear phishing email with malicious attachment (Office macro)",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,  # More realistic - detect later
            ml_detectable=False,  # Should NOT be detected - looks like normal traffic
            llm_detectable=False,  # Should NOT be detected - sophisticated evasion
            stealth_level="high",  # High stealth - designed to evade
            duration_minutes=5.0 if not realistic_timeline else 1.0 * 24 * 60,  # 1 day
            network_flows=self._create_initial_access_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(5, 1, realistic_timeline)  # 1 day
        
        # Stage 3: Execution - Macro execution, payload download
        stages.append(APTStageDefinition(
            stage=APTStage.EXECUTION,
            stage_number=3,
            description="Malicious macro execution, payload download from C2",
            expected_detection_stage=APTStage.EXECUTION,
            ml_detectable=True,
            llm_detectable=True,
            stealth_level="medium",
            duration_minutes=2.0 if not realistic_timeline else 0.5 * 24 * 60,  # 12 hours
            network_flows=self._create_execution_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(2, 0.5, realistic_timeline)  # 12 hours
        
        # Stage 4: Credential Access - Credential harvesting
        stages.append(APTStageDefinition(
            stage=APTStage.CREDENTIAL_ACCESS,
            stage_number=4,
            description="Credential harvesting via Mimikatz-style tools",
            expected_detection_stage=APTStage.CREDENTIAL_ACCESS,
            ml_detectable=False,  # Hard to detect without endpoint monitoring
            llm_detectable=True,  # Network patterns might reveal it
            stealth_level="high",
            duration_minutes=10.0 if not realistic_timeline else 3.0 * 24 * 60,  # 3 days
            network_flows=self._create_credential_access_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(10, 3, realistic_timeline)  # 3 days
        
        # Stage 5: Lateral Movement - SMB enumeration and movement
        stages.append(APTStageDefinition(
            stage=APTStage.LATERAL_MOVEMENT,
            stage_number=5,
            description="Lateral movement via SMB to domain controller",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,
            ml_detectable=True,
            llm_detectable=True,
            stealth_level="medium",
            duration_minutes=15.0 if not realistic_timeline else 7.0 * 24 * 60,  # 1 week
            network_flows=self._create_lateral_movement_flows(target_ip, "10.0.0.1", current_time)  # DC
        ))
        current_time += self._get_time_delta(15, 7, realistic_timeline)  # 1 week
        
        # Stage 6: Collection - Data staging
        stages.append(APTStageDefinition(
            stage=APTStage.COLLECTION,
            stage_number=6,
            description="Data collection and staging for exfiltration",
            expected_detection_stage=APTStage.EXFILTRATION,  # May detect during exfil
            ml_detectable=False,
            llm_detectable=True,
            stealth_level="high",
            duration_minutes=20.0 if not realistic_timeline else 14.0 * 24 * 60,  # 2 weeks
            network_flows=self._create_collection_flows(target_ip, "10.0.0.1", current_time)
        ))
        current_time += self._get_time_delta(20, 14, realistic_timeline)  # 2 weeks
        
        # Stage 7: Exfiltration - Data exfiltration to external server
        stages.append(APTStageDefinition(
            stage=APTStage.EXFILTRATION,
            stage_number=7,
            description="Data exfiltration to external C2 server via HTTPS",
            expected_detection_stage=APTStage.EXFILTRATION,
            ml_detectable=True,  # Large outbound transfers
            llm_detectable=True,
            stealth_level="medium",
            duration_minutes=30.0 if not realistic_timeline else 7.0 * 24 * 60,  # 1 week
            network_flows=self._create_exfiltration_flows(target_ip, "203.0.113.50", current_time)
        ))
        
        return stages
    
    def _generate_apt29_scenario(
        self,
        attacker_ip: str,
        target_ip: str,
        start_time: datetime,
        realistic_timeline: bool = False
    ) -> List[APTStageDefinition]:
        """
        APT29 (Cozy Bear) style attack:
        - Long-term persistence
        - Stealthy C2 communication
        - Living-off-the-land techniques
        """
        stages = []
        current_time = start_time
        
        # Stage 1: Reconnaissance - Long-term passive reconnaissance
        recon_hours = 24 if not realistic_timeline else 21 * 24  # 3 weeks
        stages.append(APTStageDefinition(
            stage=APTStage.RECONNAISSANCE,
            stage_number=1,
            description="Passive reconnaissance over extended period",
            expected_detection_stage=APTStage.COMMAND_AND_CONTROL,  # More realistic - detect during C2
            ml_detectable=False,
            llm_detectable=False,  # Very stealthy
            stealth_level="high",
            duration_minutes=recon_hours * 60,
            network_flows=self._create_stealthy_recon_flows(attacker_ip, target_ip, current_time, hours=recon_hours)
        ))
        current_time += self._get_time_delta(24 * 60, 21, realistic_timeline)  # 3 weeks
        
        # Stage 2: Initial Access - Watering hole or supply chain
        # NOTE: Real APTs evade detection at Initial Access
        stages.append(APTStageDefinition(
            stage=APTStage.INITIAL_ACCESS,
            stage_number=2,
            description="Watering hole attack or supply chain compromise",
            expected_detection_stage=APTStage.COMMAND_AND_CONTROL,  # More realistic - detect during C2
            ml_detectable=False,
            llm_detectable=False,  # Should NOT be detected - very stealthy
            stealth_level="high",
            duration_minutes=10.0 if not realistic_timeline else 2.0 * 24 * 60,  # 2 days
            network_flows=self._create_watering_hole_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(10, 2, realistic_timeline)  # 2 days
        
        # Stage 3: Persistence - Long-term persistence mechanisms
        stages.append(APTStageDefinition(
            stage=APTStage.PERSISTENCE,
            stage_number=3,
            description="Establishing long-term persistence (scheduled tasks, services)",
            expected_detection_stage=APTStage.COMMAND_AND_CONTROL,  # May only detect during C2
            ml_detectable=False,
            llm_detectable=False,
            stealth_level="high",
            duration_minutes=5.0 if not realistic_timeline else 1.0 * 24 * 60,  # 1 day
            network_flows=self._create_persistence_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(5, 1, realistic_timeline)  # 1 day
        
        # Stage 4: Command and Control - Stealthy C2 beaconing
        stages.append(APTStageDefinition(
            stage=APTStage.COMMAND_AND_CONTROL,
            stage_number=4,
            description="Low-frequency C2 beaconing (DNS over HTTPS)",
            expected_detection_stage=APTStage.COMMAND_AND_CONTROL,
            ml_detectable=False,
            llm_detectable=True,  # Pattern analysis
            stealth_level="high",
            duration_minutes=60.0 if not realistic_timeline else 30.0 * 24 * 60,  # 30 days
            network_flows=self._create_stealthy_c2_flows(target_ip, "203.0.113.100", current_time)
        ))
        
        return stages
    
    def _generate_lazarus_scenario(
        self,
        attacker_ip: str,
        target_ip: str,
        start_time: datetime,
        realistic_timeline: bool = False
    ) -> List[APTStageDefinition]:
        """
        Lazarus Group style attack:
        - Financial theft focus
        - Destructive capabilities
        - Fast-moving attack
        """
        stages = []
        current_time = start_time
        
        # Stage 1: Initial Access - Spear phishing
        # NOTE: Real APTs evade detection at Initial Access
        stages.append(APTStageDefinition(
            stage=APTStage.INITIAL_ACCESS,
            stage_number=1,
            description="Spear phishing with financial lure",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,  # More realistic - detect later
            ml_detectable=False,  # Should NOT be detected
            llm_detectable=False,  # Should NOT be detected
            stealth_level="high",  # High stealth
            duration_minutes=5.0 if not realistic_timeline else 1.0 * 24 * 60,  # 1 day
            network_flows=self._create_initial_access_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(5, 1, realistic_timeline)  # 1 day
        
        # Stage 2: Discovery - Stealthy network discovery
        # NOTE: Real APTs perform discovery slowly and subtly
        stages.append(APTStageDefinition(
            stage=APTStage.DISCOVERY,
            stage_number=2,
            description="Stealthy network and system discovery",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,  # More realistic - detect later
            ml_detectable=False,  # Should NOT be detected - stealthy
            llm_detectable=False,  # Should NOT be detected - stealthy
            stealth_level="high",  # High stealth - slow and subtle
            duration_minutes=3.0 if not realistic_timeline else 0.5 * 24 * 60,  # 12 hours
            network_flows=self._create_discovery_flows(target_ip, current_time)
        ))
        current_time += self._get_time_delta(3, 0.5, realistic_timeline)  # 12 hours
        
        # Stage 3: Lateral Movement - Fast lateral movement
        stages.append(APTStageDefinition(
            stage=APTStage.LATERAL_MOVEMENT,
            stage_number=3,
            description="Rapid lateral movement to financial systems",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,
            ml_detectable=True,
            llm_detectable=True,
            stealth_level="low",
            duration_minutes=5.0 if not realistic_timeline else 2.0 * 24 * 60,  # 2 days
            network_flows=self._create_lateral_movement_flows(target_ip, "10.0.0.50", current_time)
        ))
        current_time += self._get_time_delta(5, 2, realistic_timeline)  # 2 days
        
        # Stage 4: Collection - Financial data collection
        stages.append(APTStageDefinition(
            stage=APTStage.COLLECTION,
            stage_number=4,
            description="Collection of financial data and credentials",
            expected_detection_stage=APTStage.EXFILTRATION,
            ml_detectable=False,
            llm_detectable=True,
            stealth_level="medium",
            duration_minutes=10.0 if not realistic_timeline else 7.0 * 24 * 60,  # 1 week
            network_flows=self._create_collection_flows(target_ip, "10.0.0.50", current_time)
        ))
        current_time += self._get_time_delta(10, 7, realistic_timeline)  # 1 week
        
        # Stage 5: Exfiltration - Rapid data exfiltration
        stages.append(APTStageDefinition(
            stage=APTStage.EXFILTRATION,
            stage_number=5,
            description="Rapid data exfiltration to external server",
            expected_detection_stage=APTStage.EXFILTRATION,
            ml_detectable=True,
            llm_detectable=True,
            stealth_level="low",  # Large volumes
            duration_minutes=5.0 if not realistic_timeline else 3.0 * 24 * 60,  # 3 days
            network_flows=self._create_exfiltration_flows(target_ip, "203.0.113.200", current_time)
        ))
        
        return stages
    
    def _generate_silent_shadow_scenario(
        self,
        attacker_ip: str,
        target_ip: str,
        start_time: datetime,
        realistic_timeline: bool = False
    ) -> List[APTStageDefinition]:
        """Silent Shadow - Custom multi-stage APT"""
        stages = []
        current_time = start_time
        
        # Stage 1: Reconnaissance
        stages.append(APTStageDefinition(
            stage=APTStage.RECONNAISSANCE,
            stage_number=1,
            description="Stealthy port scanning",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,  # More realistic - detect later
            ml_detectable=False,
            llm_detectable=False,  # Very stealthy
            stealth_level="high",
            duration_minutes=10.0 if not realistic_timeline else 14.0 * 24 * 60,  # 2 weeks
            network_flows=self._create_recon_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(10, 14, realistic_timeline)  # 2 weeks
        
        # Stage 2: Initial Access
        # NOTE: Real APTs evade detection at Initial Access
        stages.append(APTStageDefinition(
            stage=APTStage.INITIAL_ACCESS,
            stage_number=2,
            description="Zero-day exploit attempt",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,  # More realistic - detect later
            ml_detectable=False,
            llm_detectable=False,  # Should NOT be detected - zero-day is undetectable
            stealth_level="high",  # High stealth - zero-day
            duration_minutes=2.0 if not realistic_timeline else 1.0 * 24 * 60,  # 1 day
            network_flows=self._create_initial_access_flows(attacker_ip, target_ip, current_time)
        ))
        current_time += self._get_time_delta(2, 1, realistic_timeline)  # 1 day
        
        # Stage 3: Lateral Movement
        stages.append(APTStageDefinition(
            stage=APTStage.LATERAL_MOVEMENT,
            stage_number=3,
            description="Internal network scanning",
            expected_detection_stage=APTStage.LATERAL_MOVEMENT,
            ml_detectable=True,
            llm_detectable=True,
            stealth_level="medium",
            duration_minutes=5.0 if not realistic_timeline else 7.0 * 24 * 60,  # 1 week
            network_flows=self._create_lateral_movement_flows(target_ip, "10.0.0.105", current_time)
        ))
        current_time += self._get_time_delta(5, 7, realistic_timeline)  # 1 week
        
        # Stage 4: Exfiltration
        stages.append(APTStageDefinition(
            stage=APTStage.EXFILTRATION,
            stage_number=4,
            description="Data exfiltration",
            expected_detection_stage=APTStage.EXFILTRATION,
            ml_detectable=True,
            llm_detectable=True,
            stealth_level="medium",
            duration_minutes=10.0 if not realistic_timeline else 7.0 * 24 * 60,  # 1 week
            network_flows=self._create_exfiltration_flows("10.0.0.105", "203.0.113.200", current_time)
        ))
        
        return stages
    
    # Helper methods to create network flows for each stage
    def _create_recon_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """
        Create subtle reconnaissance flows that look like normal network activity.
        
        SOLUTION 2: Make reconnaissance more realistic and subtle.
        - Low volume, spread over time
        - Normal-looking ports (80, 443, 22, 3389)
        - Features that look benign
        - Longer intervals between probes
        """
        flows = []
        # Use fewer probes, more realistic ports, longer intervals
        target_ports = [80, 443, 22, 3389, 8080, 8443, 3306, 5432]  # Common services
        intervals = [300, 450, 600, 750, 900]  # 5-15 minute intervals (realistic APT timing)
        
        for i in range(min(5, len(target_ports))):  # Only 5 probes, not 10
            port = target_ports[i % len(target_ports)]
            interval = intervals[i % len(intervals)]
            
            flows.append(NetworkFlow(
                flow_id=f"recon-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=interval * i)),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=49152 + i,  # Normal ephemeral port range
                dst_port=port,  # Common service port
                protocol="TCP",
                bytes_sent=1500,  # Normal packet size
                bytes_received=1500,  # Normal response
                packets_sent=3,  # Normal handshake
                packets_received=3,  # Normal response
                duration=1.5,  # Normal connection duration
                # SOLUTION 2: Use very benign features (low variance, normal values)
                features=(np.random.randn(78) * 0.1 + 0.0).tolist(),  # Very subtle, near-zero
                label="Benign",  # Label as benign to make it harder to detect
                is_malicious=True  # But still mark as malicious for ground truth
            ))
        return flows
    
    def _create_initial_access_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """
        Create initial access flows (exploit attempt).
        
        CRITICAL: Real APTs use sophisticated evasion at Initial Access.
        These flows should look EXACTLY like normal traffic to avoid detection.
        
        Strategy:
        - Use common ports (443, 80, 25) - normal web/email traffic
        - Normal packet sizes and counts
        - Normal connection durations
        - Very subtle features (near-zero, normal distributions)
        - Label as benign to make ML miss it
        - The LLM should also find it benign-looking unless there's strong context
        """
        # Make it look like completely normal HTTPS traffic
        # Real APTs at Initial Access look like legitimate user activity
        flows = []
        for i in range(1):  # Single flow - less suspicious than multiple
            flows.append(NetworkFlow(
                flow_id=f"initial-access-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=i*10)),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=49152 + np.random.randint(0, 1000),  # Random normal ephemeral port
                dst_port=443,  # HTTPS - extremely common, looks completely normal
                protocol="TCP",
                bytes_sent=1200,  # Normal HTTPS request size
                bytes_received=45000,  # Normal HTTPS response (could be any web page)
                packets_sent=8,  # Normal TCP handshake + HTTPS request
                packets_received=25,  # Normal response packets
                duration=1.8,  # Normal connection duration (1-3 seconds is typical)
                # Use extremely benign features - should look like normal web traffic
                # Features should be near-zero with very low variance
                features=(np.random.randn(78) * 0.08 + 0.0).tolist(),  # Extremely subtle, near-zero
                label="Benign",  # Label as benign - this is normal-looking traffic
                is_malicious=False  # Mark as not malicious - ML should classify as benign
            ))
        return flows
    
    def _create_execution_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create execution flows (payload download)"""
        return [NetworkFlow(
            flow_id="execution-1",
            timestamp=_format_timestamp(start_time),
            src_ip=dst_ip,
            dst_ip="203.0.113.50",
            src_port=52100,
            dst_port=443,
            protocol="TCP",
            bytes_sent=500,
            bytes_received=50000,
            packets_sent=10,
            packets_received=50,
            duration=2.0,
            features=(np.random.randn(78) * 0.4).tolist(),
            label="Infiltration",
            is_malicious=True
        )]
    
    def _create_credential_access_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create credential access flows"""
        flows = []
        for i in range(5):
            flows.append(NetworkFlow(
                flow_id=f"cred-access-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=i*2)),
                src_ip=dst_ip,
                dst_ip="10.0.0.1",  # Domain controller
                src_port=52000 + i,
                dst_port=389,  # LDAP
                protocol="TCP",
                bytes_sent=1000,
                bytes_received=500,
                packets_sent=10,
                packets_received=5,
                duration=1.0,
                features=(np.random.randn(78) * 0.3).tolist(),
                label="Infiltration",
                is_malicious=True
            ))
        return flows
    
    def _create_lateral_movement_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create lateral movement flows"""
        flows = []
        for i in range(10):
            flows.append(NetworkFlow(
                flow_id=f"lateral-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=i*1.5)),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=52100 + i,
                dst_port=445,  # SMB
                protocol="TCP",
                bytes_sent=2000,
                bytes_received=1500,
                packets_sent=20,
                packets_received=15,
                duration=2.0,
                features=(np.random.randn(78) * 0.5).tolist(),
                label="Infiltration",
                is_malicious=True
            ))
        return flows
    
    def _create_collection_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create data collection flows"""
        flows = []
        for i in range(20):
            flows.append(NetworkFlow(
                flow_id=f"collection-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=i*1)),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=52200 + i,
                dst_port=445,
                protocol="TCP",
                bytes_sent=5000,
                bytes_received=10000,
                packets_sent=50,
                packets_received=100,
                duration=3.0,
                features=(np.random.randn(78) * 0.4).tolist(),
                label="Infiltration",
                is_malicious=True
            ))
        return flows
    
    def _create_exfiltration_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create data exfiltration flows"""
        flows = []
        for i in range(5):
            flows.append(NetworkFlow(
                flow_id=f"exfil-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=i*10)),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=52500 + i,
                dst_port=443,
                protocol="TCP",
                bytes_sent=2097152,  # 2 MB per flow
                bytes_received=1024,
                packets_sent=1500,
                packets_received=100,
                duration=10.0,
                features=(np.random.randn(78) * 0.6 + 0.3).tolist(),
                label="Exfiltration",
                is_malicious=True
            ))
        return flows
    
    def _create_stealthy_recon_flows(self, src_ip: str, dst_ip: str, start_time: datetime, hours: int) -> List[NetworkFlow]:
        """
        Create very stealthy reconnaissance flows (for APT29 style).
        
        SOLUTION 2: Extremely subtle - looks like normal browsing activity.
        """
        flows = []
        total_seconds = hours * 3600
        num_probes = 10  # Even fewer probes over long period
        interval = total_seconds / num_probes
        
        # Use realistic ports that look like normal web browsing
        target_ports = [80, 443, 8080, 8443]
        
        for i in range(num_probes):
            port = target_ports[i % len(target_ports)]
            flows.append(NetworkFlow(
                flow_id=f"stealth-recon-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=i*interval)),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=49152 + (i % 1000),  # Normal ephemeral range
                dst_port=port,
                protocol="TCP",
                bytes_sent=1500,  # Normal HTTP request size
                bytes_received=5000,  # Normal HTTP response
                packets_sent=5,  # Normal handshake + data
                packets_received=8,  # Normal response packets
                duration=2.0,  # Normal connection duration
                features=(np.random.randn(78) * 0.05).tolist(),  # Extremely subtle
                label="Benign",  # Label as benign
                is_malicious=True  # Ground truth
            ))
        return flows
    
    def _create_watering_hole_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create watering hole attack flows"""
        return [NetworkFlow(
            flow_id="watering-hole-1",
            timestamp=_format_timestamp(start_time),
            src_ip=dst_ip,
            dst_ip="198.51.100.50",  # Compromised website
            src_port=50001,
            dst_port=443,
            protocol="TCP",
            bytes_sent=500,
            bytes_received=50000,
            packets_sent=10,
            packets_received=50,
            duration=3.0,
            features=(np.random.randn(78) * 0.3).tolist(),
            label="Infiltration",
            is_malicious=True
        )]
    
    def _create_persistence_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create persistence establishment flows"""
        return [NetworkFlow(
            flow_id="persistence-1",
            timestamp=_format_timestamp(start_time),
            src_ip=dst_ip,
            dst_ip="203.0.113.100",
            src_port=50002,
            dst_port=443,
            protocol="TCP",
            bytes_sent=1000,
            bytes_received=2000,
            packets_sent=5,
            packets_received=10,
            duration=1.0,
            features=(np.random.randn(78) * 0.2).tolist(),
            label="Infiltration",
            is_malicious=True
        )]
    
    def _create_stealthy_c2_flows(self, src_ip: str, dst_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create stealthy C2 beaconing flows"""
        flows = []
        for i in range(4):
            flows.append(NetworkFlow(
                flow_id=f"c2-beacon-{i}",
                timestamp=_format_timestamp(start_time + timedelta(seconds=i*900)),  # Every 15 minutes
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=50003 + i,
                dst_port=443,
                protocol="TCP",
                bytes_sent=200,
                bytes_received=100,
                packets_sent=2,
                packets_received=1,
                duration=0.5,
                features=(np.random.randn(78) * 0.15).tolist(),  # Very benign
                label="Infiltration",
                is_malicious=True
            ))
        return flows
    
    def _create_discovery_flows(self, src_ip: str, start_time: datetime) -> List[NetworkFlow]:
        """Create stealthy discovery flows (more subtle than rapid scanning)"""
        flows = []
        # Fewer targets, spread over longer time
        targets = ["10.0.0.10", "10.0.0.20", "10.0.0.50"]
        for i, target in enumerate(targets):
            # Spread out over minutes, not seconds
            flow_time = start_time + timedelta(minutes=i*5)
            flows.append(NetworkFlow(
                flow_id=f"discovery-{i}",
                timestamp=_format_timestamp(flow_time),
                src_ip=src_ip,
                dst_ip=target,
                src_port=np.random.randint(49152, 65535),  # Random ephemeral port
                dst_port=445,  # Common SMB port (looks normal)
                protocol="TCP",
                bytes_sent=800,  # Lower volume
                bytes_received=400,
                packets_sent=5,  # Fewer packets
                packets_received=3,
                duration=0.5,
                # More benign-looking features (lower variance, near-zero values)
                features=(np.random.randn(78) * 0.05 + 0.01).tolist(),
                label="Benign",  # Not labeled as malicious
                is_malicious=False  # Should NOT be detected by ML
            ))
        return flows


# Export the main classes
__all__ = [
    'APTStage',
    'APTStageDefinition',
    'DetectionEvent',
    'IncidentResponse',
    'APTTestResult',
    'APTScenarioGenerator'
]


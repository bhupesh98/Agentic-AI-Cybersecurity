"""
Advanced Persistent Threat (APT) Campaign Generator

Generates sophisticated multi-stage attack scenarios that:
1. Evade simple ML pattern matching
2. Require contextual reasoning to detect
3. Demonstrate LLM's superior threat analysis capabilities

These attacks are designed to be HARD for ML, EASY for LLM.

Location: src/network/apt_campaign.py
Author: Abhinav
Date: November 2025
"""

import time
import random
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass
from scapy.all import IP, TCP, Raw, send
import logging


@dataclass
class AttackStage:
    """Single stage of APT campaign."""
    stage_number: int
    stage_name: str
    description: str
    packets: List[Dict[str, Any]]
    duration_seconds: int
    stealth_level: str  # "high", "medium", "low"
    ml_detection_likelihood: str  # "unlikely", "possible", "likely"
    llm_detection_likelihood: str  # "unlikely", "possible", "likely"


class APTCampaign:
    """
    Multi-stage APT attack campaign.
    
    Campaign: "Silent Shadow"
    - Stage 1: Reconnaissance (stealthy port scanning)
    - Stage 2: Initial Compromise (zero-day exploit)
    - Stage 3: Lateral Movement (internal scanning)
    - Stage 4: Data Exfiltration (encrypted outbound)
    - Stage 5: Persistence (C2 beaconing)
    """

    def __init__(
        self,
        attacker_ip: str = "10.0.0.99",
        target_network: str = "172.16.0.0/24",
        campaign_name: str = "Silent Shadow"
    ):
        """
        Initialize APT campaign.
        
        Args:
            attacker_ip: Adversary IP address
            target_network: Target network CIDR
            campaign_name: Campaign identifier
        """
        self.attacker_ip = attacker_ip
        self.target_network = target_network
        self.campaign_name = campaign_name
        self.logger = logging.getLogger(__name__)

        # Campaign timeline
        self.start_time = None
        self.stages_executed = []

    def generate_campaign(self) -> List[AttackStage]:
        """
        Generate complete APT campaign stages.
        
        Returns:
            List of AttackStage objects
        """
        stages = [
            self._stage1_reconnaissance(),
            self._stage2_initial_compromise(),
            self._stage3_lateral_movement(),
            self._stage4_data_exfiltration(),
            self._stage5_persistence()
        ]

        return stages

    def _stage1_reconnaissance(self) -> AttackStage:
        """
        Stage 1: Stealthy Reconnaissance
        
        Low-volume port scanning with long delays between probes.
        Targets unusual ports in sequential pattern.
        
        ML: Unlikely to detect (looks like normal traffic)
        LLM: Should detect (unusual port sequence, timing pattern)
        """
        packets = []

        # Target 10 sequential unusual ports with 5-second delays
        target_ip = "172.16.0.50"
        base_port = 8000

        for i in range(10):
            packets.append({
                'src_ip': self.attacker_ip,
                'dst_ip': target_ip,
                'src_port': random.randint(50000, 60000),
                'dst_port': base_port + i,  # Sequential pattern
                'protocol': 'TCP',
                'flags': 'S',  # SYN scan
                'payload': None,
                'delay_after': 5.0  # 5 seconds between probes
            })

        return AttackStage(
            stage_number=1,
            stage_name="Reconnaissance",
            description="Stealthy port scanning with sequential pattern targeting unusual ports",
            packets=packets,
            duration_seconds=50,  # 10 packets * 5 sec = 50s
            stealth_level="high",
            ml_detection_likelihood="unlikely",
            llm_detection_likelihood="likely"
        )

    def _stage2_initial_compromise(self) -> AttackStage:
        """
        Stage 2: Initial Compromise (Zero-Day Exploit)
        
        Exploit attempt on discovered service.
        Uses unusual payload patterns.
        
        ML: Unlikely to detect (no signature match)
        LLM: Should detect (exploit characteristics, context from Stage 1)
        """
        packets = []

        target_ip = "172.16.0.50"
        exploit_port = 8005  # Port discovered in recon

        # Exploit attempt with suspicious payload
        exploit_payload = b"\x90" * 100 + b"\xcc\xcc\xcc\xcc"  # NOP sled + shellcode marker

        packets.append({
            'src_ip': self.attacker_ip,
            'dst_ip': target_ip,
            'src_port': random.randint(50000, 60000),
            'dst_port': exploit_port,
            'protocol': 'TCP',
            'flags': 'PA',  # PUSH-ACK
            'payload': exploit_payload,
            'delay_after': 2.0
        })

        # Follow-up connection (successful compromise)
        packets.append({
            'src_ip': self.attacker_ip,
            'dst_ip': target_ip,
            'src_port': random.randint(50000, 60000),
            'dst_port': exploit_port,
            'protocol': 'TCP',
            'flags': 'PA',
            'payload': b"POST /upload HTTP/1.1\r\n\r\n",
            'delay_after': 5.0
        })

        return AttackStage(
            stage_number=2,
            stage_name="Initial Compromise",
            description="Zero-day exploit attempt followed by successful compromise",
            packets=packets,
            duration_seconds=7,
            stealth_level="medium",
            ml_detection_likelihood="unlikely",
            llm_detection_likelihood="likely"
        )

    def _stage3_lateral_movement(self) -> AttackStage:
        """
        Stage 3: Lateral Movement
        
        Internal network scanning from compromised host.
        Appears to come from internal IP.
        
        ML: Possible to detect (depends on training)
        LLM: Should detect (correlation with previous stages)
        """
        packets = []

        # Now attacker uses compromised host as source
        compromised_host = "172.16.0.50"

        # Scan internal network for SMB shares
        internal_targets = ["172.16.0.10", "172.16.0.20", "172.16.0.30"]

        for target in internal_targets:
            packets.append({
                'src_ip': compromised_host,  # From compromised host!
                'dst_ip': target,
                'src_port': random.randint(50000, 60000),
                'dst_port': 445,  # SMB
                'protocol': 'TCP',
                'flags': 'S',
                'payload': None,
                'delay_after': 3.0
            })

        return AttackStage(
            stage_number=3,
            stage_name="Lateral Movement",
            description="Internal network scanning from compromised host",
            packets=packets,
            duration_seconds=9,
            stealth_level="high",
            ml_detection_likelihood="possible",
            llm_detection_likelihood="likely"
        )

    def _stage4_data_exfiltration(self) -> AttackStage:
        """
        Stage 4: Data Exfiltration
        
        Encrypted data transfer to external server.
        Uses HTTPS to blend in.
        
        ML: Unlikely to detect (looks like normal HTTPS)
        LLM: Should detect (unusual volume, timing, context)
        """
        packets = []

        compromised_host = "172.16.0.50"
        exfil_server = "203.0.113.50"  # External C2 server

        # Large HTTPS POST requests (data exfiltration)
        for i in range(5):
            packets.append({
                'src_ip': compromised_host,
                'dst_ip': exfil_server,
                'src_port': random.randint(50000, 60000),
                'dst_port': 443,  # HTTPS
                'protocol': 'TCP',
                'flags': 'PA',
                'payload': b"POST /upload HTTP/1.1\r\nContent-Length: 1048576\r\n\r\n" + b"X" * 1024,
                'delay_after': 10.0  # 10 seconds between transfers
            })

        return AttackStage(
            stage_number=4,
            stage_name="Data Exfiltration",
            description="Encrypted data transfer to external C2 server",
            packets=packets,
            duration_seconds=50,
            stealth_level="high",
            ml_detection_likelihood="unlikely",
            llm_detection_likelihood="likely"
        )

    def _stage5_persistence(self) -> AttackStage:
        """
        Stage 5: Persistence (C2 Beaconing)
        
        Regular callbacks to C2 server.
        Low-frequency beacons to avoid detection.
        
        ML: Unlikely to detect (intermittent, low volume)
        LLM: Should detect (periodic pattern, context)
        """
        packets = []

        compromised_host = "172.16.0.50"
        c2_server = "203.0.113.50"

        # Beacons every 15 seconds (realistic C2 timing)
        for i in range(4):
            packets.append({
                'src_ip': compromised_host,
                'dst_ip': c2_server,
                'src_port': random.randint(50000, 60000),
                'dst_port': 443,
                'protocol': 'TCP',
                'flags': 'PA',
                'payload': b"GET /beacon?id=xyz123 HTTP/1.1\r\n\r\n",
                'delay_after': 15.0  # 15 seconds between beacons
            })

        return AttackStage(
            stage_number=5,
            stage_name="Persistence",
            description="C2 beaconing for persistent access",
            packets=packets,
            duration_seconds=60,
            stealth_level="high",
            ml_detection_likelihood="unlikely",
            llm_detection_likelihood="likely"
        )

    def execute_campaign(self, interface: str = "lo0", dry_run: bool = False) -> Dict[str, Any]:
        """
        Execute the complete APT campaign.
        
        Args:
            interface: Network interface to send packets on
            dry_run: If True, don't actually send packets (for testing)
            
        Returns:
            Campaign execution summary
        """
        self.start_time = datetime.now()
        stages = self.generate_campaign()

        self.logger.info(f"🚨 Starting APT Campaign: {self.campaign_name}")
        self.logger.info(f"   Attacker: {self.attacker_ip}")
        self.logger.info(f"   Stages: {len(stages)}")

        total_packets = 0

        for stage in stages:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Stage {stage.stage_number}: {stage.stage_name}")
            self.logger.info(f"{'='*60}")
            self.logger.info(f"Description: {stage.description}")
            self.logger.info(f"Duration: {stage.duration_seconds}s")
            self.logger.info(f"Stealth: {stage.stealth_level}")
            self.logger.info(f"ML Detection: {stage.ml_detection_likelihood}")
            self.logger.info(
                f"LLM Detection: {stage.llm_detection_likelihood}")

            if not dry_run:
                # Execute stage packets
                for i, pkt_info in enumerate(stage.packets, 1):
                    self.logger.info(f"  Packet {i}/{len(stage.packets)}: "
                                     f"{pkt_info['src_ip']}:{pkt_info['src_port']} → "
                                     f"{pkt_info['dst_ip']}:{pkt_info['dst_port']}")

                    # Build and send packet
                    try:
                        pkt = IP(src=pkt_info['src_ip'], dst=pkt_info['dst_ip']) / \
                            TCP(sport=pkt_info['src_port'],
                                dport=pkt_info['dst_port'],
                                flags=pkt_info['flags'])

                        if pkt_info['payload']:
                            pkt = pkt / Raw(load=pkt_info['payload'])

                        send(pkt, iface=interface, verbose=0)
                        total_packets += 1

                        # Delay before next packet
                        if pkt_info['delay_after'] > 0:
                            time.sleep(pkt_info['delay_after'])

                    except Exception as e:
                        self.logger.error(f"Failed to send packet: {e}")
            else:
                self.logger.info(
                    f"  [DRY RUN] Would send {len(stage.packets)} packets")
                total_packets += len(stage.packets)

            self.stages_executed.append(stage)

        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        summary = {
            'campaign_name': self.campaign_name,
            'attacker_ip': self.attacker_ip,
            'start_time': self.start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'stages_executed': len(self.stages_executed),
            'total_packets': total_packets,
            'dry_run': dry_run
        }

        self.logger.info(f"\n{'='*60}")
        self.logger.info("✅ Campaign Complete!")
        self.logger.info(f"   Duration: {duration:.1f}s")
        self.logger.info(f"   Packets: {total_packets}")
        self.logger.info(f"{'='*60}\n")

        return summary


if __name__ == "__main__":
    """Test APT campaign generation."""
    logging.basicConfig(level=logging.INFO)

    # Create campaign
    campaign = APTCampaign(
        attacker_ip="10.0.0.99",
        target_network="172.16.0.0/24",
        campaign_name="Silent Shadow"
    )

    # Dry run (don't actually send packets)
    summary = campaign.execute_campaign(dry_run=True)

    print("\n" + "="*60)
    print("APT CAMPAIGN SUMMARY")
    print("="*60)
    for key, value in summary.items():
        print(f"{key}: {value}")

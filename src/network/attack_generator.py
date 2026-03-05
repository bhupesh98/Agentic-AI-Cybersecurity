"""
Attack Generator for Real-Time Threat Simulation

Generates various cybersecurity attacks using Scapy on localhost.
Designed for single-machine demonstration with resource safety.

Attack Types:
1. SSH Brute Force - Rapid connection attempts
2. Port Scan - Sequential port probing
3. SYN Flood (DoS) - High-rate SYN packets
4. Slow HTTP - Low-rate persistent connections
5. Data Exfiltration - Large outbound transfer

Location: src/network/attack_generator.py
Author: Abhinav
Date: November 2025
"""

import sys
import os
from typing import Optional
import time
import random
from dataclasses import dataclass
from scapy.all import IP, TCP, Raw, send

# Add project root to path for imports
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.utils.colored_logger import get_logger, ColoredLogger  # noqa: E402


@dataclass
class AttackConfig:
    """Configuration for attack generation."""
    target_ip: str = "127.0.0.1"
    target_port: int = 22
    rate_limit: int = 50  # packets per second
    duration: int = 10  # seconds
    # total packets (overrides duration if set)
    max_packets: Optional[int] = None
    source_ip: str = "127.0.0.1"
    source_port_range: tuple = (50000, 60000)


class AttackGenerator:
    """
    Generates various network attacks for testing.
    
    Safety Features:
    - Rate limiting to prevent system overload
    - Duration limits
    - Localhost-only by default
    - Resource monitoring
    - Clean shutdown on Ctrl+C
    """

    def __init__(self, config: Optional[AttackConfig] = None):
        """
        Initialize attack generator.
        
        Args:
            config: Attack configuration (uses defaults if None)
        """
        self.config = config or AttackConfig()
        self.logger = get_logger("AttackGenerator")
        self.is_running = False
        self.packets_sent = 0
        self.start_time = None

    def _rate_limited_send(self, packet, delay: float):
        """
        Send packet with rate limiting.
        
        Args:
            packet: Scapy packet to send
            delay: Delay in seconds between packets
        """
        send(packet, verbose=0)
        self.packets_sent += 1
        time.sleep(delay)

    def _get_random_source_port(self) -> int:
        """Get random source port from configured range."""
        return random.randint(*self.config.source_port_range)

    # ========================================================================
    # ATTACK 1: SSH BRUTE FORCE
    # ========================================================================

    def ssh_brute_force(
        self,
        target_port: int = 22,
        attempts: int = 50,
        rate: int = 10
    ):
        """
        Simulate SSH brute force attack.
        
        Characteristics:
        - Multiple rapid SYN packets to SSH port
        - No successful handshakes
        - High connection attempt rate
        - Short duration
        
        Args:
            target_port: SSH port (default 22)
            attempts: Number of connection attempts
            rate: Attempts per second
        """
        ColoredLogger.attack_start(
            attack_type="SSH Brute Force",
            target=f"{self.config.target_ip}:{target_port}",
            rate=rate,
            duration=attempts // rate
        )

        self.is_running = True
        self.packets_sent = 0
        self.start_time = time.time()

        delay = 1.0 / rate

        try:
            for i in range(attempts):
                if not self.is_running:
                    break

                # Create SYN packet (connection attempt)
                src_port = self._get_random_source_port()
                packet = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                    TCP(sport=src_port, dport=target_port,
                        flags='S', seq=random.randint(1000, 9999))

                self._rate_limited_send(packet, delay)

                # Update progress
                elapsed = time.time() - self.start_time
                ColoredLogger.attack_progress(i + 1, attempts, elapsed)

            duration = time.time() - self.start_time
            ColoredLogger.attack_complete(
                "SSH Brute Force", self.packets_sent, duration)

        except KeyboardInterrupt:
            self.logger.warning("Attack interrupted by user")
        finally:
            self.is_running = False

    # ========================================================================
    # ATTACK 2: PORT SCAN
    # ========================================================================

    def port_scan(
        self,
        start_port: int = 20,
        end_port: int = 100,
        rate: int = 20
    ):
        """
        Simulate nmap-style port scan.
        
        Characteristics:
        - Sequential SYN packets to multiple ports
        - Reconnaissance pattern
        - Moderate rate
        
        Args:
            start_port: First port to scan
            end_port: Last port to scan
            rate: Scans per second
        """
        total_ports = end_port - start_port + 1

        ColoredLogger.attack_start(
            attack_type="Port Scan",
            target=f"{self.config.target_ip}:{start_port}-{end_port}",
            rate=rate,
            duration=total_ports // rate
        )

        self.is_running = True
        self.packets_sent = 0
        self.start_time = time.time()

        delay = 1.0 / rate
        src_port = self._get_random_source_port()

        try:
            for port in range(start_port, end_port + 1):
                if not self.is_running:
                    break

                # SYN packet to each port
                packet = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                    TCP(sport=src_port, dport=port, flags='S')

                self._rate_limited_send(packet, delay)

                # Update progress
                elapsed = time.time() - self.start_time
                ColoredLogger.attack_progress(
                    self.packets_sent, total_ports, elapsed)

            duration = time.time() - self.start_time
            ColoredLogger.attack_complete(
                "Port Scan", self.packets_sent, duration)

        except KeyboardInterrupt:
            self.logger.warning("Attack interrupted by user")
        finally:
            self.is_running = False

    # ========================================================================
    # ATTACK 3: SYN FLOOD (DoS)
    # ========================================================================

    def syn_flood(
        self,
        target_port: int = 80,
        duration: int = 10,
        rate: int = 100
    ):
        """
        Simulate SYN flood DoS attack.
        
        Characteristics:
        - High rate of SYN packets
        - Random source ports
        - No ACK responses
        - Sustained duration
        
        Args:
            target_port: Target port
            duration: Attack duration in seconds
            rate: Packets per second
        """
        total_packets = duration * rate

        ColoredLogger.attack_start(
            attack_type="SYN Flood (DoS)",
            target=f"{self.config.target_ip}:{target_port}",
            rate=rate,
            duration=duration
        )

        self.is_running = True
        self.packets_sent = 0
        self.start_time = time.time()

        delay = 1.0 / rate

        try:
            while self.is_running and (time.time() - self.start_time) < duration:
                # Random source port for each packet (harder to filter)
                src_port = self._get_random_source_port()
                packet = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                    TCP(sport=src_port, dport=target_port,
                        flags='S', seq=random.randint(1000, 9999))

                self._rate_limited_send(packet, delay)

                # Update progress
                elapsed = time.time() - self.start_time
                ColoredLogger.attack_progress(
                    self.packets_sent, total_packets, elapsed)

            duration = time.time() - self.start_time
            ColoredLogger.attack_complete(
                "SYN Flood", self.packets_sent, duration)

        except KeyboardInterrupt:
            self.logger.warning("Attack interrupted by user")
        finally:
            self.is_running = False

    # ========================================================================
    # ATTACK 4: SLOW HTTP ATTACK
    # ========================================================================

    def slow_http_attack(
        self,
        target_port: int = 80,
        connections: int = 20,
        interval: float = 2.0,
        duration: int = 30
    ):
        """
        Simulate Slowloris-style slow HTTP attack.
        
        Characteristics:
        - Low packet rate (stealthy)
        - Multiple persistent connections
        - Periodic keep-alive packets
        - Long duration
        
        Args:
            target_port: HTTP port (usually 80 or 443)
            connections: Number of parallel connections
            interval: Seconds between keep-alive packets
            duration: Total attack duration
        """
        ColoredLogger.attack_start(
            attack_type="Slow HTTP Attack",
            target=f"{self.config.target_ip}:{target_port}",
            rate=int(connections / interval),
            duration=duration
        )

        self.is_running = True
        self.packets_sent = 0
        self.start_time = time.time()

        # Create connections with random source ports
        connection_ports = [self._get_random_source_port()
                            for _ in range(connections)]

        try:
            # Establish connections (SYN)
            for src_port in connection_ports:
                packet = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                    TCP(sport=src_port, dport=target_port, flags='S')
                send(packet, verbose=0)
                self.packets_sent += 1

            # Send periodic keep-alive packets
            total_intervals = int(duration / interval)
            for i in range(total_intervals):
                if not self.is_running:
                    break

                time.sleep(interval)

                # Send partial HTTP request to each connection
                for src_port in connection_ports:
                    packet = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                        TCP(sport=src_port, dport=target_port, flags='PA') / \
                        Raw(load="X-a: b\r\n")
                    send(packet, verbose=0)
                    self.packets_sent += 1

                elapsed = time.time() - self.start_time
                ColoredLogger.attack_progress(i + 1, total_intervals, elapsed)

            duration = time.time() - self.start_time
            ColoredLogger.attack_complete(
                "Slow HTTP Attack", self.packets_sent, duration)

        except KeyboardInterrupt:
            self.logger.warning("Attack interrupted by user")
        finally:
            self.is_running = False

    # ========================================================================
    # ATTACK 5: DATA EXFILTRATION
    # ========================================================================

    def data_exfiltration(
        self,
        target_port: int = 443,
        total_bytes: int = 100000,
        rate: int = 50
    ):
        """
        Simulate data exfiltration attack.
        
        Characteristics:
        - Large outbound data transfer
        - Sustained connection
        - High bytes/second ratio
        - Often to unusual ports
        
        Args:
            target_port: Destination port (often 443 for HTTPS)
            total_bytes: Total bytes to exfiltrate
            rate: Packets per second
        """
        packet_size = 1000  # bytes per packet
        total_packets = total_bytes // packet_size

        ColoredLogger.attack_start(
            attack_type="Data Exfiltration",
            target=f"{self.config.target_ip}:{target_port}",
            rate=rate,
            duration=total_packets // rate
        )

        self.is_running = True
        self.packets_sent = 0
        self.start_time = time.time()

        delay = 1.0 / rate
        src_port = self._get_random_source_port()

        try:
            # Establish connection
            syn = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                TCP(sport=src_port, dport=target_port, flags='S')
            send(syn, verbose=0)
            self.packets_sent += 1

            # Send large amount of data
            for i in range(total_packets):
                if not self.is_running:
                    break

                # Packet with payload
                data = 'X' * packet_size  # Simulated sensitive data
                packet = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                    TCP(sport=src_port, dport=target_port, flags='PA') / \
                    Raw(load=data)

                self._rate_limited_send(packet, delay)

                elapsed = time.time() - self.start_time
                ColoredLogger.attack_progress(i + 1, total_packets, elapsed)

            # Close connection
            fin = IP(src=self.config.source_ip, dst=self.config.target_ip) / \
                TCP(sport=src_port, dport=target_port, flags='FA')
            send(fin, verbose=0)
            self.packets_sent += 1

            duration = time.time() - self.start_time
            ColoredLogger.attack_complete(
                "Data Exfiltration", self.packets_sent, duration)

        except KeyboardInterrupt:
            self.logger.warning("Attack interrupted by user")
        finally:
            self.is_running = False

    # ========================================================================
    # APT-STYLE MULTI-STAGE ATTACK
    # ========================================================================

    def apt_attack_sequence(self):
        """
        Simulate multi-stage APT attack.
        
        Stages:
        1. Reconnaissance (port scan)
        2. Initial compromise (SSH brute force)
        3. Lateral movement (internal scan)
        4. Data exfiltration
        """
        self.logger.info("Starting APT attack sequence...")

        # Stage 1: Reconnaissance
        self.logger.info("Stage 1: Reconnaissance")
        self.port_scan(start_port=20, end_port=100, rate=20)
        time.sleep(2)

        # Stage 2: Initial compromise
        self.logger.info("Stage 2: Initial Compromise")
        self.ssh_brute_force(attempts=30, rate=10)
        time.sleep(2)

        # Stage 3: Lateral movement
        self.logger.info("Stage 3: Lateral Movement")
        self.port_scan(start_port=20, end_port=50, rate=15)
        time.sleep(2)

        # Stage 4: Data exfiltration
        self.logger.info("Stage 4: Data Exfiltration")
        self.data_exfiltration(total_bytes=50000, rate=50)

        self.logger.success("APT attack sequence complete!")

    def stop(self):
        """Stop the current attack."""
        self.is_running = False


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    """Test attack generator."""
    import argparse

    parser = argparse.ArgumentParser(description="Network Attack Generator")
    parser.add_argument('--attack', type=str, default='ssh',
                        choices=['ssh', 'port', 'syn', 'http', 'exfil', 'apt'],
                        help='Attack type to generate')
    parser.add_argument('--rate', type=int, default=50,
                        help='Packets per second')
    parser.add_argument('--duration', type=int, default=10,
                        help='Attack duration in seconds')
    parser.add_argument('--target-port', type=int, default=22,
                        help='Target port')

    args = parser.parse_args()

    # Create generator
    config = AttackConfig(
        target_ip="127.0.0.1",
        source_ip="127.0.0.1",
        rate_limit=args.rate
    )

    generator = AttackGenerator(config)

    print("\n" + "="*70)
    print("ATTACK GENERATOR TEST".center(70))
    print("="*70)
    print("\n⚠️  WARNING: This will generate network traffic on localhost")
    print("⚠️  Make sure packet capture is running in another terminal!\n")

    try:
        if args.attack == 'ssh':
            generator.ssh_brute_force(
                target_port=args.target_port,
                attempts=args.rate * args.duration,
                rate=args.rate
            )
        elif args.attack == 'port':
            generator.port_scan(
                start_port=20,
                end_port=100,
                rate=args.rate
            )
        elif args.attack == 'syn':
            generator.syn_flood(
                target_port=args.target_port,
                duration=args.duration,
                rate=args.rate
            )
        elif args.attack == 'http':
            generator.slow_http_attack(
                target_port=80,
                connections=20,
                duration=args.duration
            )
        elif args.attack == 'exfil':
            generator.data_exfiltration(
                target_port=443,
                total_bytes=50000,
                rate=args.rate
            )
        elif args.attack == 'apt':
            generator.apt_attack_sequence()

    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        generator.stop()

    print("\n" + "="*70)
    print("✅ ATTACK GENERATOR TEST COMPLETE".center(70))
    print("="*70 + "\n")

"""
Packet Capture Module for Real-Time Network Flow Aggregation

Captures packets using Scapy and aggregates them into network flows.
Works on localhost/loopback for single-machine setup.

Location: src/network/packet_capture.py
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List, Callable
from datetime import datetime
import threading
import time


@dataclass
class NetworkFlow:
    """Represents an aggregated network flow (5-tuple)."""

    # Flow identifier (5-tuple)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # 'TCP', 'UDP', 'ICMP', etc.

    # Flow statistics
    start_time: float = field(default_factory=time.time)
    end_time: float = field(default_factory=time.time)
    packet_count: int = 0
    total_bytes: int = 0

    # Forward/Backward statistics
    fwd_packet_count: int = 0
    bwd_packet_count: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # TCP-specific flags
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0

    # Additional metadata
    first_packet_time: Optional[float] = None
    last_packet_time: Optional[float] = None

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        if self.first_packet_time and self.last_packet_time:
            return self.last_packet_time - self.first_packet_time
        return 0.0

    @property
    def flow_key(self) -> Tuple:
        """Unique flow identifier."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    def to_dict(self) -> Dict:
        """Convert flow to dictionary for ML model."""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'duration': self.duration,
            'packet_count': self.packet_count,
            'total_bytes': self.total_bytes,
            'fwd_packet_count': self.fwd_packet_count,
            'bwd_packet_count': self.bwd_packet_count,
            'fwd_bytes': self.fwd_bytes,
            'bwd_bytes': self.bwd_bytes,
            'syn_count': self.syn_count,
            'fin_count': self.fin_count,
            'rst_count': self.rst_count,
            'psh_count': self.psh_count,
            'ack_count': self.ack_count,
            'urg_count': self.urg_count,
            'start_time': datetime.fromtimestamp(self.start_time).isoformat(),
            'end_time': datetime.fromtimestamp(self.end_time).isoformat(),
        }


class PacketCaptureManager:
    """Manages real-time packet capture and flow aggregation."""

    def __init__(
        self,
        interface: str = "lo0",  # loopback interface on macOS
        flow_timeout: float = 60.0,  # seconds before flow expires
        max_flows: int = 10000,  # maximum concurrent flows to track
    ):
        """
        Initialize packet capture manager.
        
        Args:
            interface: Network interface to capture on ('lo0' for localhost)
            flow_timeout: Timeout in seconds before considering flow complete
            max_flows: Maximum number of concurrent flows to track
        """
        self.interface = interface
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows

        # Flow storage (thread-safe)
        self.flows: Dict[Tuple, NetworkFlow] = {}
        self.flows_lock = threading.Lock()

        # Completed flows ready for analysis
        self.completed_flows: List[NetworkFlow] = []
        self.completed_lock = threading.Lock()

        # Capture control
        self.is_capturing = False
        self.capture_thread: Optional[threading.Thread] = None
        self.cleanup_thread: Optional[threading.Thread] = None

        # Statistics
        self.total_packets_captured = 0
        self.total_flows_created = 0

        # Callback for real-time flow processing
        self.flow_callback: Optional[Callable[[NetworkFlow], None]] = None

    def _extract_flow_key(self, packet) -> Optional[Tuple]:
        """
        Extract 5-tuple flow key from packet.
        
        Args:
            packet: Scapy packet
            
        Returns:
            Tuple of (src_ip, dst_ip, src_port, dst_port, protocol) or None
        """
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Determine protocol and ports
        if packet.haslayer(TCP):
            protocol = 'TCP'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = 'UDP'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = 'ICMP'
            src_port = 0
            dst_port = 0
        else:
            protocol = 'OTHER'
            src_port = 0
            dst_port = 0

        return (src_ip, dst_ip, src_port, dst_port, protocol)

    def _process_packet(self, packet):
        """
        Process a single captured packet.
        
        Args:
            packet: Scapy packet
        """
        try:
            self.total_packets_captured += 1

            # Extract flow key
            flow_key = self._extract_flow_key(packet)
            if not flow_key:
                return

            current_time = time.time()
            packet_size = len(packet)

            with self.flows_lock:
                # Get or create flow
                if flow_key in self.flows:
                    flow = self.flows[flow_key]
                else:
                    # Check max flows limit
                    if len(self.flows) >= self.max_flows:
                        # Remove oldest flow - ROBUST None handling
                        oldest_key = min(
                            self.flows.keys(),
                            key=lambda k: (
                                self.flows[k].last_packet_time 
                                if self.flows[k].last_packet_time is not None 
                                else self.flows[k].first_packet_time 
                                if self.flows[k].first_packet_time is not None
                                else 0
                            )
                        )
                        self._finalize_flow(oldest_key)

                    # Create new flow - SET last_packet_time IMMEDIATELY
                    src_ip, dst_ip, src_port, dst_port, protocol = flow_key
                    flow = NetworkFlow(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol,
                        start_time=current_time,
                        first_packet_time=current_time,
                        last_packet_time=current_time  # ✅ FIX: Set immediately
                    )
                    self.flows[flow_key] = flow
                    self.total_flows_created += 1

                # Update flow statistics
                flow.packet_count += 1
                flow.total_bytes += packet_size
                flow.last_packet_time = current_time
                flow.end_time = current_time

                # Determine direction (forward vs backward)
                # Forward: src -> dst, Backward: dst -> src
                is_forward = True  # Simplified for now
                if is_forward:
                    flow.fwd_packet_count += 1
                    flow.fwd_bytes += packet_size
                else:
                    flow.bwd_packet_count += 1
                    flow.bwd_bytes += packet_size

                # Extract TCP flags if present
                if packet.haslayer(TCP):
                    tcp = packet[TCP]
                    if tcp.flags.S:  # SYN
                        flow.syn_count += 1
                    if tcp.flags.F:  # FIN
                        flow.fin_count += 1
                    if tcp.flags.R:  # RST
                        flow.rst_count += 1
                    if tcp.flags.P:  # PSH
                        flow.psh_count += 1
                    if tcp.flags.A:  # ACK
                        flow.ack_count += 1
                    if tcp.flags.U:  # URG
                        flow.urg_count += 1

        except Exception as e:
            print(f"Error processing packet: {e}")

    def _finalize_flow(self, flow_key: Tuple):
        """
        Finalize a flow and move to completed flows.
        
        Args:
            flow_key: Flow identifier tuple
        """
        if flow_key in self.flows:
            flow = self.flows.pop(flow_key)

            # Add to completed flows
            with self.completed_lock:
                self.completed_flows.append(flow)

            # Call callback if registered
            if self.flow_callback:
                try:
                    self.flow_callback(flow)
                except Exception as e:
                    print(f"Error in flow callback: {e}")

    def _cleanup_expired_flows(self):
        """Periodically cleanup expired flows."""
        while self.is_capturing:
            time.sleep(5)  # Check every 5 seconds

            current_time = time.time()
            expired_keys = []

            with self.flows_lock:
                for flow_key, flow in self.flows.items():
                    # ROBUST: Use last_packet_time, fall back to first_packet_time
                    packet_time = (
                        flow.last_packet_time 
                        if flow.last_packet_time is not None 
                        else flow.first_packet_time
                    )
                    
                    if packet_time is not None:
                        age = current_time - packet_time
                        if age > self.flow_timeout:
                            expired_keys.append(flow_key)

            # Finalize expired flows
            for flow_key in expired_keys:
                with self.flows_lock:
                    self._finalize_flow(flow_key)

    def start_capture(self, packet_count: Optional[int] = None):
        """
        Start packet capture in background thread.
        
        Args:
            packet_count: Number of packets to capture (None = infinite)
        """
        if self.is_capturing:
            print("⚠️  Capture already running!")
            return

        self.is_capturing = True

        print(f"🔍 Starting packet capture on interface: {self.interface}")
        print(f"📊 Flow timeout: {self.flow_timeout}s")
        print(f"💾 Max concurrent flows: {self.max_flows}")

        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(packet_count,),
            daemon=True
        )
        self.capture_thread.start()

        # Start cleanup thread
        self.cleanup_thread = threading.Thread(
            target=self._cleanup_expired_flows,
            daemon=True
        )
        self.cleanup_thread.start()

        print("✅ Capture started!")

    def _capture_loop(self, packet_count: Optional[int] = None):
        """Main capture loop."""
        try:
            if packet_count is None:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False
                    # NO filter parameter
                )
            else:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    count=packet_count
                    # NO filter parameter
                )
        except Exception as e:
            print(f"❌ Capture error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_capturing = False

    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_capturing:
            print("⚠️  No capture running!")
            return

        print("🛑 Stopping capture...")
        self.is_capturing = False

        if self.capture_thread:
            self.capture_thread.join(timeout=5)

        # Finalize all remaining flows
        with self.flows_lock:
            flow_keys = list(self.flows.keys())
            for flow_key in flow_keys:
                self._finalize_flow(flow_key)

        print("✅ Capture stopped!")

    def get_completed_flows(self, clear: bool = True) -> List[NetworkFlow]:
        """
        Get list of completed flows.
        
        Args:
            clear: Whether to clear the completed flows list
            
        Returns:
            List of NetworkFlow objects
        """
        with self.completed_lock:
            flows = self.completed_flows.copy()
            if clear:
                self.completed_flows.clear()
            return flows

    def register_callback(self, callback: Callable[[NetworkFlow], None]):
        """
        Register callback for real-time flow processing.
        
        Args:
            callback: Function that takes NetworkFlow as argument
        """
        self.flow_callback = callback

    def get_statistics(self) -> Dict:
        """Get capture statistics."""
        with self.flows_lock:
            active_flows = len(self.flows)

        with self.completed_lock:
            completed_flows = len(self.completed_flows)

        return {
            'is_capturing': self.is_capturing,
            'total_packets_captured': self.total_packets_captured,
            'total_flows_created': self.total_flows_created,
            'active_flows': active_flows,
            'completed_flows': completed_flows,
        }


# Test script
if __name__ == "__main__":
    print("=" * 60)
    print("PACKET CAPTURE TEST")
    print("=" * 60)

    # Create capture manager
    capture = PacketCaptureManager(
        interface="lo0",  # localhost
        flow_timeout=10.0  # 10 second timeout
    )

    # Register callback for real-time flow processing
    def flow_callback(flow: NetworkFlow):
        print(f"\n🔴 Flow detected: {flow.src_ip}:{flow.src_port} -> "
              f"{flow.dst_ip}:{flow.dst_port} [{flow.protocol}]")
        print(f"   Packets: {flow.packet_count}, Bytes: {flow.total_bytes}, "
              f"Duration: {flow.duration:.2f}s")

    capture.register_callback(flow_callback)

    # Start capture
    print("\n▶️  Starting capture for 30 seconds...")
    print("💡 Generate traffic: curl http://localhost:8000")
    capture.start_capture()

    # Run for 30 seconds
    try:
        for i in range(30):
            time.sleep(1)
            if i % 10 == 0:
                stats = capture.get_statistics()
                print(f"\n📊 Stats: {stats}")
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")

    # Stop capture
    capture.stop_capture()

    # Get completed flows
    flows = capture.get_completed_flows()
    print(f"\n✅ Captured {len(flows)} completed flows")

    # Show final statistics
    stats = capture.get_statistics()
    print("\n📊 Final Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")

# Alias for backward compatibility
PacketCapture = PacketCaptureManager

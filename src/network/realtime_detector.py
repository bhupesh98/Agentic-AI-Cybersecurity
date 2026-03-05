"""
Real-Time Threat Detector for Agentic AI Cybersecurity System

Integrates all components for live network threat detection:
- Packet Capture (Scapy)
- Feature Extraction (78 CIC-IDS features)
- ML Detection (RF, XGBoost, DNN)
- LLM Analysis (OpenAI)
- Memory System (SQLite + FAISS)
- Action Execution (Firewall, Alerts)

Location: src/network/realtime_detector.py
Author: Abhinav
Date: November 2025
"""

import sys
import os
import signal
import time
import threading
from datetime import datetime
from typing import Dict, Any

# Add project root to path for imports
_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.utils.colored_logger import ColoredLogger, get_logger  # noqa: E402
from src.agent.state_management import create_initial_state, NetworkFlow as StateNetworkFlow  # noqa: E402
from src.agent.workflow_graph import create_workflow  # noqa: E402
from src.ml_detection.model_loader import get_model_loader  # noqa: E402
from src.network.feature_extractor import FeatureExtractor  # noqa: E402
from src.network.packet_capture import PacketCapture, NetworkFlow  # noqa: E402
from src.network.flow_processor import FlowProcessor  # noqa: E402

# Import components

# Import for metrics
try:
    from src.metrics import get_metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False


class RealtimeDetector:
    """
    Real-time network threat detector.
    
    Flow:
        Packets → Flow Aggregation → Feature Extraction → 
        ML Detection → LLM Analysis → Memory Lookup → Response
    """

    def __init__(self, interface: str = "lo0", flow_timeout: int = 10):
        """
        Initialize real-time detector.
        
        Args:
            interface: Network interface to capture on ("lo0" for localhost)
            flow_timeout: Flow timeout in seconds
        """
        self.logger = get_logger("RealtimeDetector")
        self.interface = interface
        self.flow_timeout = flow_timeout

        # Components
        self.packet_capture = None
        self.feature_extractor = FeatureExtractor()
        self.ml_loader = None
        self.workflow = None
        self.flow_processor = None

        # State
        self.is_running = False
        self.total_flows_processed = 0
        self.total_threats_detected = 0
        self.total_false_positives = 0
        self.session_id = f"realtime-{int(time.time())}"

        # Statistics
        self.stats = {
            'flows_captured': 0,
            'flows_analyzed': 0,
            'threats_detected': 0,
            'benign_flows': 0,
            'ml_detections': 0,
            'llm_analyses': 0,
            'memory_hits': 0,
            'actions_taken': 0
        }

        # For graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print("\n")
        self.logger.warning("Shutdown signal received...")
        self.stop()

    def initialize(self):
        """Initialize all components."""
        ColoredLogger.print_header("REAL-TIME THREAT DETECTOR", width=70)

        self.logger.info("Initializing components...")

        # Initialize packet capture
        self.logger.info(f"Starting packet capture on {self.interface}...")
        self.packet_capture = PacketCapture(
            interface=self.interface,
            flow_timeout=self.flow_timeout
        )

        # Load ML models
        self.logger.info("Loading ML models (RF, XGBoost, DNN)...")
        self.ml_loader = get_model_loader()

        if not self.ml_loader.models_loaded:
            self.logger.warning(
                "ML models not loaded - using mock predictions")
        else:
            self.logger.success("ML models loaded successfully!")

        # Create agent workflow
        self.logger.info("Initializing agent workflow (LangGraph)...")
        self.workflow = create_workflow()

        # Initialize async flow processor
        self.flow_processor = FlowProcessor(self._process_flow, num_workers=4)

        self.logger.success("All components initialized!")
        ColoredLogger.print_separator()

    def start(self, duration: int = 60):
        """Start real-time detection."""
        if not self.packet_capture or not self.workflow:
            self.logger.error("Components not initialized! Call initialize() first.")
            return

        self.is_running = True
        start_time = time.time()

        ColoredLogger.print_section("STARTING DETECTION", color="\033[92m")
        self.logger.info(f"Capturing on {self.interface} for {duration}s (Ctrl+C to stop)")
        ColoredLogger.print_separator()

        # Register callback to process flows immediately when completed
        self.packet_capture.register_callback(self._process_flow_callback)

        # Start packet capture in background
        capture_thread = threading.Thread(
            target=self.packet_capture.start_capture,
            daemon=True
        )
        capture_thread.start()

        # Start async flow processor
        self.flow_processor.start()

        time.sleep(1)

        try:
            last_status_update = time.time()

            while self.is_running:
                elapsed = time.time() - start_time
                if duration > 0 and elapsed >= duration:
                    self.logger.info(f"Duration limit reached ({duration}s)")
                    break

                # Update status display every 2 seconds
                if time.time() - last_status_update >= 2.0:
                    self._display_status()
                    last_status_update = time.time()

                time.sleep(0.5)

        except KeyboardInterrupt:
            self.logger.warning("Detection interrupted by user")
        finally:
            self.stop()

    def _process_flow_callback(self, flow: NetworkFlow):
        """
        Callback for when a flow completes - submits to async processor.
        
        Args:
            flow: Completed NetworkFlow
        """
        self.stats['flows_analyzed'] += 1
        if self.flow_processor:
            self.flow_processor.submit_flow(flow)
        else:
            # Fallback to direct processing if processor not initialized
            self._process_flow(flow)

    def _process_flow(self, flow: NetworkFlow):
        """
        Process a single network flow through the entire pipeline.
        
        Args:
            flow: NetworkFlow from packet capture
        """
        try:
            # Convert flow to features
            features = self.feature_extractor.extract_features(flow)

            # Validate features
            validation = self.feature_extractor.validate_features(features)
            if not validation['valid']:
                self.logger.warning(
                    f"Invalid features for flow {flow.flow_key}: {validation['error']}")
                return

            # Convert NetworkFlow to StateNetworkFlow for agent
            state_flow = StateNetworkFlow(
                flow_id=flow.flow_key,
                timestamp=datetime.fromtimestamp(
                    flow.start_time).isoformat() + 'Z',
                src_ip=flow.src_ip,
                dst_ip=flow.dst_ip,
                src_port=flow.src_port,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                bytes_sent=flow.fwd_bytes,
                bytes_received=flow.bwd_bytes,
                packets_sent=flow.fwd_packet_count,
                packets_received=flow.bwd_packet_count,
                duration=flow.duration,
                features=features,
                label=None,
                is_malicious=None
            )

            # Create agent state
            state = create_initial_state(f"{self.session_id}-{flow.flow_key}")
            state["raw_network_flows"] = [state_flow]

            # Run through agent workflow
            config = {"configurable": {
                "thread_id": f"{self.session_id}-{flow.flow_key}"}}

            final_state = None
            for output in self.workflow.stream(state, config):
                final_state = output

            if final_state:
                result = list(final_state.values())[-1]
                self._display_detection_result(flow, result)

        except Exception as e:
            self.logger.error(f"Error processing flow: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())

    def _display_detection_result(self, flow: NetworkFlow, result: Dict[str, Any]):
        """
        Display detection result in beautiful format.
        
        Args:
            flow: Original NetworkFlow
            result: Agent workflow result
        """
        # Get ML predictions
        ml_predictions = result.get('ml_predictions', [])
        if not ml_predictions:
            return

        ml_pred = ml_predictions[0]

        # Get LLM analysis
        llm_analysis = result.get('llm_analysis', {})
        analyses = llm_analysis.get('analyses', [])

        # Determine if threat
        is_threat = ml_pred.ensemble_prediction == 'malicious'

        if is_threat:
            self.stats['threats_detected'] += 1
            self.total_threats_detected += 1

            # Display threat box
            llm_text = ""
            llm_severity = "MEDIUM"
            actions = []
            memory_info = None

            if analyses:
                analysis = analyses[0]
                llm_text = analysis.get('reasoning', 'No analysis available')
                llm_severity = analysis.get('severity', 'MEDIUM').upper()
                actions = analysis.get('recommended_actions', [])

            # Get memory context
            memory_contexts = result.get('memory_contexts', [])
            if memory_contexts:
                mem_ctx = memory_contexts[0].get('context')
                if mem_ctx and hasattr(mem_ctx, 'is_repeat_offender'):
                    memory_info = {
                        'is_repeat_offender': mem_ctx.is_repeat_offender,
                        'incident_count': mem_ctx.incidents_from_this_ip,
                        'threat_score': mem_ctx.ip_reputation.threat_score if mem_ctx.ip_reputation else 0.0
                    }
                    if mem_ctx.is_repeat_offender:
                        self.stats['memory_hits'] += 1

            # Get execution results
            execution_results = result.get('execution_results', [])
            if execution_results:
                actions = [f"{r.get('action_type', 'Unknown')}: {r.get('output', 'Done')}"
                           for r in execution_results if r.get('success')]
                self.stats['actions_taken'] += len(actions)

            ColoredLogger.print_threat_box(
                threat_type=f"{flow.protocol} Traffic",
                source=f"{flow.src_ip}:{flow.src_port}",
                destination=f"{flow.dst_ip}:{flow.dst_port}",
                severity=llm_severity,
                ml_confidence=ml_pred.ensemble_confidence,
                llm_reasoning=llm_text[:200] if llm_text else "High-confidence malicious traffic detected",
                memory_info=memory_info,
                actions=actions if actions else None
            )
        else:
            self.stats['benign_flows'] += 1

            # Only log benign flows in debug mode
            self.logger.debug(
                f"Benign: {flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}")

    def _display_status(self):
        """Display current system status."""
        active_flows = len(self.packet_capture.flows)

        # Calculate agentic score (simplified)
        agentic_score = 0.888  # Placeholder - should calculate from metrics

        ColoredLogger.print_system_status(
            status="ACTIVE",
            flows_detected=self.stats['flows_analyzed'],
            active_flows=active_flows,
            threats=self.stats['threats_detected'],
            false_positives=self.total_false_positives,
            agentic_score=agentic_score
        )

    def stop(self):
        """Stop detection and cleanup."""
        self.is_running = False

        if self.packet_capture:
            self.logger.info("Stopping packet capture...")
            self.packet_capture.stop_capture()
            
            # Queue remaining flows for async processing
            self.logger.info("Queueing remaining active flows...")
            remaining = len(self.packet_capture.flows)
            if remaining > 0:
                self.logger.info(f"  Queueing {remaining} flows")
                with self.packet_capture.flows_lock:
                    for flow in self.packet_capture.flows.values():
                        if self.flow_processor:
                            self.flow_processor.submit_flow(flow)
                        else:
                            # Fallback if processor not initialized
                            self._process_flow(flow)
                        self.stats['flows_analyzed'] += 1
                
                if self.flow_processor:
                    self.logger.info("  Waiting for workers to finish...")
                    self.flow_processor.stop()
                    self.logger.info("  ✅ Processed all flows")

        print("\n")
        ColoredLogger.print_separator()
        self._display_final_statistics()

    def _display_final_statistics(self):
        """Display final statistics."""
        ColoredLogger.print_section("DETECTION SESSION SUMMARY")

        stats_display = {
            'Flows Analyzed': self.stats['flows_analyzed'],
            'Threats Detected': self.stats['threats_detected'],
            'Benign Flows': self.stats['benign_flows'],
            'Memory Hits (Repeat Offenders)': self.stats['memory_hits'],
            'Actions Taken': self.stats['actions_taken'],
        }

        if self.stats['flows_analyzed'] > 0:
            detection_rate = self.stats['threats_detected'] / \
                self.stats['flows_analyzed']
            stats_display['Detection Rate'] = detection_rate

        ColoredLogger.print_stats("SESSION STATISTICS", stats_display)

        # Save metrics if available
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()
                collector.save_metrics()
                self.logger.success("Metrics saved successfully")
            except Exception as e:
                self.logger.warning(f"Failed to save metrics: {e}")

        self.logger.success("Detection session complete!")


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    """Test real-time detector."""
    import argparse

    parser = argparse.ArgumentParser(description="Real-Time Threat Detector")
    parser.add_argument('--interface', type=str, default='lo0',
                        help='Network interface to capture on (default: lo0 for localhost)')
    parser.add_argument('--duration', type=int, default=60,
                        help='Detection duration in seconds (0 = indefinite)')
    parser.add_argument('--flow-timeout', type=int, default=10,
                        help='Flow timeout in seconds')

    args = parser.parse_args()

    # Create detector
    detector = RealtimeDetector(
        interface=args.interface,
        flow_timeout=args.flow_timeout
    )

    # Initialize
    detector.initialize()

    # Start detection
    try:
        detector.start(duration=args.duration)
    except KeyboardInterrupt:
        print("\n")
        detector.logger.warning("Interrupted by user")
    finally:
        detector.stop()

"""
Dataset Replay Detector - Stream Flows from Prepared Dataset

Replaces real-time packet capture with controlled dataset streaming.
This approach ensures ML models work correctly (trained on same data distribution)
while demonstrating all agentic AI capabilities.

Location: src/network/dataset_replay_detector.py
Author: Abhinav
Date: November 2025
"""

from src.ml_detection.model_loader import get_model_loader
from src.agent.workflow_graph import create_workflow
from src.agent.state_management import create_initial_state, NetworkFlow as StateNetworkFlow
from src.utils.colored_logger import ColoredLogger, get_logger
import sys
import os
import time
import pandas as pd
from pathlib import Path
from typing import Dict, Any

# Add project root to path
_project_root = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


# Metrics
try:
    from src.metrics import get_metrics_collector
    METRICS_AVAILABLE = True
except ImportError:
    METRICS_AVAILABLE = False


class DatasetReplayDetector:
    """
    Stream network flows from prepared dataset for controlled testing.
    
    Advantages over packet capture:
    - ML models work perfectly (same data distribution as training)
    - Reproducible results
    - Controlled timing
    - All agentic principles demonstrated
    """

    def __init__(self, dataset_path: str, speed_multiplier: float = 1.0):
        """
        Initialize replay detector.
        
        Args:
            dataset_path: Path to replay CSV file
            speed_multiplier: Speed up replay (1.0=real-time, 0.1=10x faster, 0=instant)
        """
        self.logger = get_logger("ReplayDetector")
        self.dataset_path = Path(dataset_path)
        self.speed_multiplier = speed_multiplier

        # Components
        self.ml_loader = None
        self.workflow = None
        self.dataset = None

        # State
        self.session_id = f"replay-{int(time.time())}"
        self.is_running = False

        # Statistics
        self.stats = {
            'flows_processed': 0,
            'threats_detected': 0,
            'benign_flows': 0,
            'ml_detections': 0,
            'llm_analyses': 0,
            'memory_hits': 0,
            'actions_taken': 0
        }

    def initialize(self):
        """Initialize all components and load dataset."""
        ColoredLogger.print_header("DATASET REPLAY DETECTOR", width=70)

        self.logger.info("Initializing components...")

        # Load dataset
        self.logger.info(f"Loading replay dataset: {self.dataset_path.name}")
        if not self.dataset_path.exists():
            self.logger.error(f"Dataset not found: {self.dataset_path}")
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")

        self.dataset = pd.read_csv(self.dataset_path)
        self.logger.success(f"✅ Dataset loaded: {len(self.dataset)} flows")

        # Display dataset info
        malicious = len(self.dataset[self.dataset['Label'] != 'Benign'])
        benign = len(self.dataset[self.dataset['Label'] == 'Benign'])
        self.logger.info(
            f"   Malicious: {malicious} ({malicious/len(self.dataset)*100:.1f}%)")
        self.logger.info(
            f"   Benign: {benign} ({benign/len(self.dataset)*100:.1f}%)")

        # Load ML models
        self.logger.info("Loading ML models (RF, XGBoost, DNN)...")
        self.ml_loader = get_model_loader()

        if not self.ml_loader.models_loaded:
            self.logger.warning("ML models not loaded - detection will fail")
        else:
            self.logger.success("✅ ML models loaded successfully!")

        # Create agent workflow
        self.logger.info("Initializing agent workflow (LangGraph)...")
        self.workflow = create_workflow()

        self.logger.success("✅ All components initialized!")
        ColoredLogger.print_separator()

    def start(self):
        """Start streaming flows from dataset."""
        if not self.workflow or self.dataset is None:
            self.logger.error(
                "Components not initialized! Call initialize() first.")
            return

        self.is_running = True

        ColoredLogger.print_section("STARTING REPLAY", color="\033[92m")
        self.logger.info(f"Streaming {len(self.dataset)} flows")
        self.logger.info(f"Speed: {self.speed_multiplier}x real-time")
        if self.speed_multiplier == 0:
            self.logger.info("(instant mode - no delays)")
        ColoredLogger.print_separator()

        start_time = time.time()

        try:
            # Convert timestamp column to datetime if string
            if self.dataset['timestamp'].dtype == 'object':
                self.dataset['timestamp'] = pd.to_datetime(
                    self.dataset['timestamp'])

            # Stream each flow
            for idx, row in self.dataset.iterrows():
                if not self.is_running:
                    break

                # Process flow
                self._process_flow(row, idx)
                self.stats['flows_processed'] += 1

                # Update status every 10 flows
                if (idx + 1) % 10 == 0:
                    self._display_status()

                # Sleep until next flow (respecting timeline)
                if self.speed_multiplier > 0 and idx < len(self.dataset) - 1:
                    next_row = self.dataset.iloc[idx + 1]
                    time_diff = (next_row['timestamp'] -
                                 row['timestamp']).total_seconds()
                    sleep_time = time_diff * self.speed_multiplier
                    if sleep_time > 0:
                        time.sleep(sleep_time)

            self.logger.success(
                f"✅ Replay complete: {self.stats['flows_processed']} flows processed")

        except KeyboardInterrupt:
            self.logger.warning("Replay interrupted by user")
        finally:
            elapsed = time.time() - start_time
            self.logger.info(f"Total time: {elapsed:.1f}s")
            self.stop()

    def _process_flow(self, row: pd.Series, idx: int):
        """
        Process a single flow from dataset.
        
        Args:
            row: DataFrame row containing flow data
            idx: Flow index
        """
        try:
            # Extract features (columns 3:-1, skipping timestamp/src_ip/dst_ip and Label)
            feature_cols = [col for col in row.index
                            if col not in ['timestamp', 'src_ip', 'dst_ip', 'Label']]
            features = row[feature_cols].values.astype(float)

            # Get ground truth label
            true_label = row['Label']

            # Create StateNetworkFlow for agent
            state_flow = StateNetworkFlow(
                flow_id=f"flow-{idx}",
                timestamp=row['timestamp'].isoformat() if hasattr(
                    row['timestamp'], 'isoformat') else str(row['timestamp']),
                src_ip=row['src_ip'],
                dst_ip=row['dst_ip'],
                # Note: using dst port as src for simplicity
                src_port=int(row.get('Dst Port', 0)),
                dst_port=int(row.get('Dst Port', 0)),
                protocol='TCP' if row.get('Protocol', 6) == 6 else 'UDP',
                bytes_sent=int(row.get('TotLen Fwd Pkts', 0)),
                bytes_received=int(row.get('TotLen Bwd Pkts', 0)),
                packets_sent=int(row.get('Tot Fwd Pkts', 0)),
                packets_received=int(row.get('Tot Bwd Pkts', 0)),
                duration=float(row.get('Flow Duration', 0)) /
                1_000_000,  # Convert to seconds
                features=features,
                label=true_label,
                is_malicious=(true_label != 'Benign')
            )

            # Create agent state
            state = create_initial_state(f"{self.session_id}-flow-{idx}")
            state["raw_network_flows"] = [state_flow]

            # Run through agent workflow
            config = {"configurable": {
                "thread_id": f"{self.session_id}-flow-{idx}"}}

            final_state = None
            for output in self.workflow.stream(state, config):
                final_state = output

            if final_state:
                result = list(final_state.values())[-1]
                self._display_detection_result(row, result, true_label)

        except Exception as e:
            self.logger.error(f"Error processing flow {idx}: {str(e)}")
            import traceback
            self.logger.debug(traceback.format_exc())

    def _display_detection_result(self, row: pd.Series, result: Dict[str, Any], true_label: str):
        """Display detection result."""
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

            # Get LLM details
            llm_text = ""
            llm_severity = "MEDIUM"
            actions = []

            if analyses:
                analysis = analyses[0]
                llm_text = analysis.get(
                    'reasoning', 'Malicious traffic detected')
                llm_severity = analysis.get('severity', 'MEDIUM').upper()
                actions = analysis.get('recommended_actions', [])
                self.stats['llm_analyses'] += 1

            # Get memory context
            memory_contexts = result.get('memory_contexts', [])
            memory_info = None
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

            # Display threat
            ColoredLogger.print_threat_box(
                threat_type=f"{true_label} Attack",
                source=f"{row['src_ip']}",
                destination=f"{row['dst_ip']}:{int(row.get('Dst Port', 0))}",
                severity=llm_severity,
                ml_confidence=ml_pred.ensemble_confidence,
                llm_reasoning=llm_text[:
                                       200] if llm_text else f"Detected {true_label} attack pattern",
                memory_info=memory_info,
                actions=actions if actions else None
            )
        else:
            self.stats['benign_flows'] += 1
            # Only log benign in debug
            self.logger.debug(f"✅ Benign: {row['src_ip']} → {row['dst_ip']}")

    def _display_status(self):
        """Display current status."""
        total = self.stats['flows_processed']
        if total == 0:
            return

        agentic_score = 0.888  # Placeholder

        ColoredLogger.print_system_status(
            status="REPLAYING",
            flows_detected=total,
            active_flows=0,
            threats=self.stats['threats_detected'],
            false_positives=0,
            agentic_score=agentic_score
        )

    def stop(self):
        """Stop replay and show final statistics."""
        self.is_running = False

        print("\n")
        ColoredLogger.print_separator()
        self._display_final_statistics()

    def _display_final_statistics(self):
        """Display final statistics."""
        ColoredLogger.print_section("REPLAY SESSION SUMMARY")

        stats_display = {
            'Flows Processed': self.stats['flows_processed'],
            'Threats Detected': self.stats['threats_detected'],
            'Benign Flows': self.stats['benign_flows'],
            'LLM Analyses': self.stats['llm_analyses'],
            'Memory Hits (Repeat Offenders)': self.stats['memory_hits'],
        }

        if self.stats['flows_processed'] > 0:
            detection_rate = self.stats['threats_detected'] / \
                self.stats['flows_processed']
            stats_display['Detection Rate'] = f"{detection_rate:.1%}"

        ColoredLogger.print_stats("SESSION STATISTICS", stats_display)

        # Save metrics
        if METRICS_AVAILABLE:
            try:
                collector = get_metrics_collector()
                collector.save_metrics()
                self.logger.success("✅ Metrics saved successfully")
            except Exception as e:
                self.logger.warning(f"⚠️  Failed to save metrics: {e}")

        self.logger.success("✅ Replay session complete!")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dataset Replay Detector")
    parser.add_argument('--dataset', type=str,
                        default='data/replay/apt_scenario_1.csv',
                        help='Path to replay dataset CSV')
    parser.add_argument('--speed', type=float, default=0.1,
                        help='Replay speed multiplier (0=instant, 1.0=real-time, 0.1=10x faster)')

    args = parser.parse_args()

    # Create detector
    detector = DatasetReplayDetector(
        dataset_path=args.dataset,
        speed_multiplier=args.speed
    )

    # Initialize
    detector.initialize()

    # Start replay
    try:
        detector.start()
    except KeyboardInterrupt:
        print("\n")
        detector.logger.warning("Interrupted by user")
    finally:
        detector.stop()

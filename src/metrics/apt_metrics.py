"""
APT Detection Metrics and Validation Framework

Provides comprehensive metrics for evaluating APT detection effectiveness:
- Detection stage tracking
- Time-to-detect metrics
- Detection accuracy
- Response effectiveness

Author: Abhinav
Date: December 2025
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import json
from pathlib import Path

from ..network.apt_test_framework import (
    APTStage, APTTestResult
)


class DetectionQuality(Enum):
    """
    Quality of detection based on stage.
    
    IMPORTANT: For APTs, later-stage detections are MORE realistic and credible.
    Real APTs are designed to evade detection at early stages (Reconnaissance, Initial Access).
    Detection at later stages (Lateral Movement, Exfiltration, C2) is expected and realistic.
    """
    EXCELLENT = "excellent"  # Detected at Lateral Movement, Exfiltration, or C2 (realistic for APTs)
    GOOD = "good"  # Detected at Credential Access, Collection, or Discovery
    ACCEPTABLE = "acceptable"  # Detected at Execution, Persistence, or Privilege Escalation
    POOR = "poor"  # Detected at Initial Access (unrealistic - APTs evade this stage)
    VERY_POOR = "very_poor"  # Detected at Reconnaissance (highly unrealistic)
    FAILED = "failed"  # Not detected at all (also realistic - some APTs evade detection)


@dataclass
class APTMetrics:
    """Comprehensive metrics for APT detection evaluation"""
    
    # Test metadata
    test_id: str
    scenario_name: str
    test_timestamp: datetime
    
    # Attack details
    total_stages: int
    stages_executed: List[str]
    
    # Detection metrics
    detected: bool
    detection_stage: Optional[str] = None
    detection_stage_number: Optional[int] = None
    time_to_detect_seconds: Optional[float] = None
    detection_method: Optional[str] = None  # "ML", "LLM", "Context", "Memory"
    detection_quality: Optional[str] = None
    
    # Detection accuracy
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0
    
    # Stage-by-stage detection
    stage_detections: Dict[int, bool] = field(default_factory=dict)  # stage_num -> detected
    
    # Response metrics
    response_time_seconds: Optional[float] = None
    actions_taken: int = 0
    successful_actions: int = 0
    response_types: List[str] = field(default_factory=list)
    
    # Severity assessment
    max_severity: str = "UNKNOWN"
    avg_confidence: float = 0.0
    
    # Detailed events
    detection_events: List[Dict[str, Any]] = field(default_factory=list)
    response_events: List[Dict[str, Any]] = field(default_factory=list)
    
    def calculate_metrics(self, test_result: APTTestResult):
        """Calculate all metrics from test result"""
        self.detected = test_result.detected
        self.detection_stage = test_result.detection_stage.value if test_result.detection_stage else None
        
        if test_result.first_detection:
            det = test_result.first_detection
            self.detection_stage_number = det.detected_at_stage.value
            self.time_to_detect_seconds = test_result.time_to_detect_seconds
            self.detection_method = det.detection_method
            self.max_severity = det.severity.upper()
            self.avg_confidence = det.confidence
            
            # Determine detection quality
            stage_order = [
                APTStage.RECONNAISSANCE,
                APTStage.INITIAL_ACCESS,
                APTStage.EXECUTION,
                APTStage.PERSISTENCE,
                APTStage.PRIVILEGE_ESCALATION,
                APTStage.DEFENSE_EVASION,
                APTStage.CREDENTIAL_ACCESS,
                APTStage.DISCOVERY,
                APTStage.LATERAL_MOVEMENT,
                APTStage.COLLECTION,
                APTStage.COMMAND_AND_CONTROL,
                APTStage.EXFILTRATION,
                APTStage.IMPACT
            ]
            
            detected_idx = stage_order.index(det.detected_at_stage) if det.detected_at_stage in stage_order else len(stage_order)
            
            # REVERSED LOGIC: For APTs, later-stage detections are MORE realistic and credible
            # Early stages (Recon, Initial Access) are unrealistic - APTs evade detection there
            if detected_idx <= 0:  # Reconnaissance - highly unrealistic
                self.detection_quality = DetectionQuality.VERY_POOR.value
            elif detected_idx <= 1:  # Initial Access - unrealistic (APTs evade this)
                self.detection_quality = DetectionQuality.POOR.value
            elif detected_idx <= 5:  # Execution, Persistence, Privilege Escalation, Defense Evasion - acceptable
                self.detection_quality = DetectionQuality.ACCEPTABLE.value
            elif detected_idx <= 9:  # Credential Access, Discovery, Lateral Movement, Collection - good
                self.detection_quality = DetectionQuality.GOOD.value
            elif detected_idx <= 11:  # Command and Control, Exfiltration - excellent (realistic for APTs)
                self.detection_quality = DetectionQuality.EXCELLENT.value
            else:  # Impact or unknown
                self.detection_quality = DetectionQuality.ACCEPTABLE.value
        
        # Stage-by-stage detection
        for stage_def in test_result.stages_executed:
            stage_num = stage_def.stage_number
            # Check if any detection happened at or before this stage
            detected_at_stage = False
            if test_result.first_detection:
                detected_stage_num = None
                for s in test_result.stages_executed:
                    if s.stage == test_result.first_detection.detected_at_stage:
                        detected_stage_num = s.stage_number
                        break
                if detected_stage_num and detected_stage_num <= stage_num:
                    detected_at_stage = True
            self.stage_detections[stage_num] = detected_at_stage
        
        # Response metrics
        self.actions_taken = len(test_result.responses)
        self.successful_actions = sum(1 for r in test_result.responses if r.success)
        self.response_types = list(set(r.action_type for r in test_result.responses))
        
        if test_result.responses:
            first_response = test_result.responses[0]
            if test_result.first_detection:
                response_time = (first_response.timestamp - test_result.first_detection.detection_timestamp).total_seconds()
                self.response_time_seconds = response_time
        
        # Detection events
        for det in test_result.all_detections:
            self.detection_events.append({
                'stage': det.detected_at_stage.value,
                'timestamp': det.detection_timestamp.isoformat(),
                'method': det.detection_method,
                'confidence': det.confidence,
                'severity': det.severity,
                'flow_id': det.flow_id
            })
        
        # Response events
        for resp in test_result.responses:
            self.response_events.append({
                'action_type': resp.action_type,
                'target': resp.target,
                'timestamp': resp.timestamp.isoformat(),
                'success': resp.success,
                'execution_time_ms': resp.execution_time_ms
            })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'test_id': self.test_id,
            'scenario_name': self.scenario_name,
            'test_timestamp': self.test_timestamp.isoformat(),
            'total_stages': self.total_stages,
            'stages_executed': self.stages_executed,
            'detected': self.detected,
            'detection_stage': self.detection_stage,
            'detection_stage_number': self.detection_stage_number,
            'time_to_detect_seconds': self.time_to_detect_seconds,
            'detection_method': self.detection_method,
            'detection_quality': self.detection_quality,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'true_negatives': self.true_negatives,
            'stage_detections': self.stage_detections,
            'response_time_seconds': self.response_time_seconds,
            'actions_taken': self.actions_taken,
            'successful_actions': self.successful_actions,
            'response_types': self.response_types,
            'max_severity': self.max_severity,
            'avg_confidence': self.avg_confidence,
            'detection_events': self.detection_events,
            'response_events': self.response_events
        }
    
    def save_to_file(self, output_path: Path):
        """Save metrics to JSON file"""
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load_from_file(cls, file_path: Path) -> 'APTMetrics':
        """Load metrics from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        metrics = cls(
            test_id=data['test_id'],
            scenario_name=data['scenario_name'],
            test_timestamp=datetime.fromisoformat(data['test_timestamp']),
            total_stages=data['total_stages'],
            stages_executed=data['stages_executed'],
            detected=data['detected'],
            detection_stage=data.get('detection_stage'),
            detection_stage_number=data.get('detection_stage_number'),
            time_to_detect_seconds=data.get('time_to_detect_seconds'),
            detection_method=data.get('detection_method'),
            detection_quality=data.get('detection_quality')
        )
        
        metrics.true_positives = data.get('true_positives', 0)
        metrics.false_positives = data.get('false_positives', 0)
        metrics.false_negatives = data.get('false_negatives', 0)
        metrics.true_negatives = data.get('true_negatives', 0)
        metrics.stage_detections = data.get('stage_detections', {})
        metrics.response_time_seconds = data.get('response_time_seconds')
        metrics.actions_taken = data.get('actions_taken', 0)
        metrics.successful_actions = data.get('successful_actions', 0)
        metrics.response_types = data.get('response_types', [])
        metrics.max_severity = data.get('max_severity', 'UNKNOWN')
        metrics.avg_confidence = data.get('avg_confidence', 0.0)
        metrics.detection_events = data.get('detection_events', [])
        metrics.response_events = data.get('response_events', [])
        
        return metrics


class APTMetricsAggregator:
    """Aggregates metrics across multiple APT tests"""
    
    def __init__(self):
        self.metrics_list: List[APTMetrics] = []
    
    def add_metrics(self, metrics: APTMetrics):
        """Add metrics from a test"""
        self.metrics_list.append(metrics)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get aggregated summary statistics"""
        if not self.metrics_list:
            return {}
        
        total_tests = len(self.metrics_list)
        detected_count = sum(1 for m in self.metrics_list if m.detected)
        detection_rate = detected_count / total_tests if total_tests > 0 else 0.0
        
        # Average time to detect
        times_to_detect = [m.time_to_detect_seconds for m in self.metrics_list if m.time_to_detect_seconds]
        avg_time_to_detect = sum(times_to_detect) / len(times_to_detect) if times_to_detect else None
        
        # Detection quality distribution
        quality_dist = {}
        for m in self.metrics_list:
            if m.detection_quality:
                quality_dist[m.detection_quality] = quality_dist.get(m.detection_quality, 0) + 1
        
        # Detection stage distribution
        stage_dist = {}
        for m in self.metrics_list:
            if m.detection_stage:
                stage_dist[m.detection_stage] = stage_dist.get(m.detection_stage, 0) + 1
        
        # Detection method distribution
        method_dist = {}
        for m in self.metrics_list:
            if m.detection_method:
                method_dist[m.detection_method] = method_dist.get(m.detection_method, 0) + 1
        
        # Average response time
        response_times = [m.response_time_seconds for m in self.metrics_list if m.response_time_seconds]
        avg_response_time = sum(response_times) / len(response_times) if response_times else None
        
        return {
            'total_tests': total_tests,
            'detection_rate': detection_rate,
            'detected_count': detected_count,
            'avg_time_to_detect_seconds': avg_time_to_detect,
            'detection_quality_distribution': quality_dist,
            'detection_stage_distribution': stage_dist,
            'detection_method_distribution': method_dist,
            'avg_response_time_seconds': avg_response_time
        }
    
    def save_aggregated_report(self, output_path: Path):
        """Save aggregated report to file"""
        summary = self.get_summary()
        all_metrics = [m.to_dict() for m in self.metrics_list]
        
        report = {
            'summary': summary,
            'individual_tests': all_metrics,
            'generated_at': datetime.utcnow().isoformat()
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)


__all__ = ['APTMetrics', 'APTMetricsAggregator', 'DetectionQuality']


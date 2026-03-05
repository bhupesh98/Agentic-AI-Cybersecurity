"""
Simplified Feature Extractor for Real-Time Detection

Converts NetworkFlow objects from packet capture into the 78 CIC-IDS features
required by the trained ML models (RF, XGBoost, DNN).

Approach: Extract ~30 core features accurately, impute rest with smart defaults.

Location: src/network/feature_extractor.py
Author: Abhinav
Date: November 2025
"""

import numpy as np
from typing import List, Dict, Any
from dataclasses import dataclass


# CIC-IDS Feature Names (78 total, in exact order from dataset)
FEATURE_NAMES = [
    'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
    'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
    'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt',
    'Down/Up Ratio', 'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg',
    'Fwd Byts/b Avg', 'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg',
    'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg',
    'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 'Subflow Bwd Byts',
    'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts',
    'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]


class FeatureExtractor:
    """
    Extracts 78 CIC-IDS features from NetworkFlow objects.
    
    Strategy:
    - Compute 30+ core features accurately from flow statistics
    - Impute remaining features with smart defaults (zeros or averages)
    - Maintain exact feature order for ML model compatibility
    """

    def __init__(self):
        """Initialize feature extractor."""
        self.protocol_map = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'OTHER': 0
        }

    def extract_features(self, flow) -> List[float]:
        """
        Extract 78 features from a NetworkFlow object.
        
        Args:
            flow: NetworkFlow object from packet_capture.py
            
        Returns:
            List of 78 floats (features in correct order)
        """
        features = []

        # Get flow statistics
        duration = flow.duration if flow.duration > 0 else 0.001  # Avoid division by zero
        total_packets = flow.packet_count
        total_bytes = flow.total_bytes
        fwd_packets = flow.fwd_packet_count
        bwd_packets = flow.bwd_packet_count
        fwd_bytes = flow.fwd_bytes
        bwd_bytes = flow.bwd_bytes

        # ==================== FEATURE 0: Dst Port ====================
        features.append(float(flow.dst_port))

        # ==================== FEATURE 1: Protocol ====================
        protocol_num = self.protocol_map.get(flow.protocol, 0)
        features.append(float(protocol_num))

        # ==================== FEATURE 2: Flow Duration ====================
        features.append(float(duration))

        # ==================== FEATURES 3-4: Packet Counts ====================
        features.append(float(fwd_packets))
        features.append(float(bwd_packets))

        # ==================== FEATURES 5-6: Total Lengths ====================
        features.append(float(fwd_bytes))
        features.append(float(bwd_bytes))

        # ==================== FEATURES 7-14: Packet Length Statistics ====================
        # Forward packet lengths (max, min, mean, std)
        if fwd_packets > 0:
            fwd_pkt_len_mean = fwd_bytes / fwd_packets
            fwd_pkt_len_max = fwd_pkt_len_mean * 1.5  # Approximation
            fwd_pkt_len_min = fwd_pkt_len_mean * 0.5  # Approximation
            fwd_pkt_len_std = fwd_pkt_len_mean * 0.2  # Approximation
        else:
            fwd_pkt_len_mean = fwd_pkt_len_max = fwd_pkt_len_min = fwd_pkt_len_std = 0

        features.extend([
            float(fwd_pkt_len_max),
            float(fwd_pkt_len_min),
            float(fwd_pkt_len_mean),
            float(fwd_pkt_len_std)
        ])

        # Backward packet lengths (max, min, mean, std)
        if bwd_packets > 0:
            bwd_pkt_len_mean = bwd_bytes / bwd_packets
            bwd_pkt_len_max = bwd_pkt_len_mean * 1.5
            bwd_pkt_len_min = bwd_pkt_len_mean * 0.5
            bwd_pkt_len_std = bwd_pkt_len_mean * 0.2
        else:
            bwd_pkt_len_mean = bwd_pkt_len_max = bwd_pkt_len_min = bwd_pkt_len_std = 0

        features.extend([
            float(bwd_pkt_len_max),
            float(bwd_pkt_len_min),
            float(bwd_pkt_len_mean),
            float(bwd_pkt_len_std)
        ])

        # ==================== FEATURES 15-16: Flow Rates ====================
        flow_byts_s = total_bytes / duration
        flow_pkts_s = total_packets / duration
        features.append(float(flow_byts_s))
        features.append(float(flow_pkts_s))

        # ==================== FEATURES 17-21: Flow IAT (Inter-Arrival Time) ====================
        # Approximation: Assume uniform packet distribution
        if total_packets > 1:
            flow_iat_mean = duration / (total_packets - 1)
            flow_iat_std = flow_iat_mean * 0.3  # Approximation
            flow_iat_max = flow_iat_mean * 2.0
            flow_iat_min = flow_iat_mean * 0.5
        else:
            flow_iat_mean = flow_iat_std = flow_iat_max = flow_iat_min = 0

        features.extend([
            float(flow_iat_mean),
            float(flow_iat_std),
            float(flow_iat_max),
            float(flow_iat_min)
        ])

        # ==================== FEATURES 22-26: Forward IAT ====================
        fwd_iat_tot = duration if fwd_packets > 0 else 0
        if fwd_packets > 1:
            fwd_iat_mean = fwd_iat_tot / (fwd_packets - 1)
            fwd_iat_std = fwd_iat_mean * 0.3
            fwd_iat_max = fwd_iat_mean * 2.0
            fwd_iat_min = fwd_iat_mean * 0.5
        else:
            fwd_iat_mean = fwd_iat_std = fwd_iat_max = fwd_iat_min = 0

        features.extend([
            float(fwd_iat_tot),
            float(fwd_iat_mean),
            float(fwd_iat_std),
            float(fwd_iat_max),
            float(fwd_iat_min)
        ])

        # ==================== FEATURES 27-31: Backward IAT ====================
        bwd_iat_tot = duration if bwd_packets > 0 else 0
        if bwd_packets > 1:
            bwd_iat_mean = bwd_iat_tot / (bwd_packets - 1)
            bwd_iat_std = bwd_iat_mean * 0.3
            bwd_iat_max = bwd_iat_mean * 2.0
            bwd_iat_min = bwd_iat_mean * 0.5
        else:
            bwd_iat_mean = bwd_iat_std = bwd_iat_max = bwd_iat_min = 0

        features.extend([
            float(bwd_iat_tot),
            float(bwd_iat_mean),
            float(bwd_iat_std),
            float(bwd_iat_max),
            float(bwd_iat_min)
        ])

        # ==================== FEATURES 32-35: PSH and URG Flags ====================
        # These are available from NetworkFlow
        features.extend([
            float(flow.psh_count),  # Fwd PSH (approximation - using total)
            0.0,  # Bwd PSH (not tracked separately)
            float(flow.urg_count),  # Fwd URG
            0.0   # Bwd URG
        ])

        # ==================== FEATURES 36-37: Header Lengths ====================
        # Estimate: TCP header ~20-60 bytes, use 40 as default
        header_estimate = 40.0
        features.extend([
            float(fwd_packets * header_estimate),  # Fwd Header Len
            float(bwd_packets * header_estimate)   # Bwd Header Len
        ])

        # ==================== FEATURES 38-39: Forward/Backward Packets/s ====================
        fwd_pkts_s = fwd_packets / duration
        bwd_pkts_s = bwd_packets / duration
        features.append(float(fwd_pkts_s))
        features.append(float(bwd_pkts_s))

        # ==================== FEATURES 40-44: Packet Length Stats ====================
        if total_packets > 0:
            pkt_len_mean = total_bytes / total_packets
            pkt_len_min = pkt_len_mean * 0.5
            pkt_len_max = pkt_len_mean * 1.5
            pkt_len_std = pkt_len_mean * 0.2
            pkt_len_var = pkt_len_std ** 2
        else:
            pkt_len_mean = pkt_len_min = pkt_len_max = pkt_len_std = pkt_len_var = 0

        features.extend([
            float(pkt_len_min),
            float(pkt_len_max),
            float(pkt_len_mean),
            float(pkt_len_std),
            float(pkt_len_var)
        ])

        # ==================== FEATURES 45-51: TCP Flag Counts ====================
        features.extend([
            float(flow.fin_count),
            float(flow.syn_count),
            float(flow.rst_count),
            float(flow.psh_count),
            float(flow.ack_count),
            float(flow.urg_count),
            0.0  # CWE Flag Count (not available)
        ])

        # ==================== FEATURE 52: ECE Flag ====================
        features.append(0.0)  # ECE flag (not tracked)

        # ==================== FEATURE 53: Down/Up Ratio ====================
        if fwd_bytes > 0:
            down_up_ratio = bwd_bytes / fwd_bytes
        else:
            down_up_ratio = 0.0
        features.append(float(down_up_ratio))

        # ==================== FEATURES 54-56: Average Sizes ====================
        pkt_size_avg = pkt_len_mean
        fwd_seg_size_avg = fwd_pkt_len_mean
        bwd_seg_size_avg = bwd_pkt_len_mean
        features.extend([
            float(pkt_size_avg),
            float(fwd_seg_size_avg),
            float(bwd_seg_size_avg)
        ])

        # ==================== FEATURES 57-62: Bulk Rate Averages ====================
        # These require complex bulk detection - impute with zeros
        features.extend([0.0] * 6)

        # ==================== FEATURES 63-66: Subflow Statistics ====================
        # Treat entire flow as single subflow
        features.extend([
            float(fwd_packets),
            float(fwd_bytes),
            float(bwd_packets),
            float(bwd_bytes)
        ])

        # ==================== FEATURES 67-68: Initial Window Bytes ====================
        # Estimate based on typical TCP window sizes
        features.extend([
            65535.0,  # Init Fwd Win Byts (typical max)
            65535.0   # Init Bwd Win Byts
        ])

        # ==================== FEATURE 69: Forward Active Data Packets ====================
        # Estimate: packets with PSH flag likely carry data
        fwd_act_data_pkts = flow.psh_count if flow.psh_count > 0 else fwd_packets
        features.append(float(fwd_act_data_pkts))

        # ==================== FEATURE 70: Forward Segment Size Min ====================
        features.append(float(fwd_pkt_len_min))

        # ==================== FEATURES 71-77: Active/Idle Times ====================
        # These require flow state machine - impute with reasonable defaults
        # Active time = time with traffic, Idle = gaps
        if duration > 0:
            # Average time per packet
            active_mean = duration / max(1, total_packets)
            active_std = active_mean * 0.3
            active_max = active_mean * 2.0
            active_min = active_mean * 0.5

            # Idle times (gaps between bursts)
            idle_mean = active_mean * 0.5
            idle_std = idle_mean * 0.3
            idle_max = idle_mean * 2.0
            idle_min = 0.0
        else:
            active_mean = active_std = active_max = active_min = 0.0
            idle_mean = idle_std = idle_max = idle_min = 0.0

        features.extend([
            float(active_mean),
            float(active_std),
            float(active_max),
            float(active_min),
            float(idle_mean),
            float(idle_std),
            float(idle_max),
            float(idle_min)
        ])

        # ==================== VALIDATION ====================
        assert len(
            features) == 78, f"Expected 78 features, got {len(features)}"

        # Replace any NaN or Inf with 0
        features = [0.0 if (np.isnan(f) or np.isinf(f))
                    else f for f in features]

        return features

    def extract_features_batch(self, flows: List) -> List[List[float]]:
        """
        Extract features from multiple flows.
        
        Args:
            flows: List of NetworkFlow objects
            
        Returns:
            List of feature vectors (each is 78 floats)
        """
        return [self.extract_features(flow) for flow in flows]

    def get_feature_names(self) -> List[str]:
        """Get the list of feature names in order."""
        return FEATURE_NAMES.copy()

    def validate_features(self, features: List[float]) -> Dict[str, Any]:
        """
        Validate extracted features.
        
        Args:
            features: List of 78 features
            
        Returns:
            Dictionary with validation results
        """
        if len(features) != 78:
            return {
                'valid': False,
                'error': f'Expected 78 features, got {len(features)}'
            }

        # Check for NaN or Inf
        invalid_count = sum(1 for f in features if np.isnan(f) or np.isinf(f))
        if invalid_count > 0:
            return {
                'valid': False,
                'error': f'Found {invalid_count} invalid values (NaN/Inf)'
            }

        # Check for reasonable ranges
        warnings = []
        if features[0] > 65535:  # Port number
            warnings.append('Dst Port out of range')
        if features[2] < 0:  # Duration
            warnings.append('Negative duration')

        return {
            'valid': True,
            'warnings': warnings,
            'feature_count': len(features),
            'non_zero_count': sum(1 for f in features if f != 0),
            'feature_summary': {
                'dst_port': features[0],
                'protocol': features[1],
                'duration': features[2],
                'total_fwd_pkts': features[3],
                'total_bwd_pkts': features[4],
                'syn_count': features[46],
                'fin_count': features[45]
            }
        }


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    from packet_capture import NetworkFlow
    import time

    print("=" * 70)
    print("FEATURE EXTRACTOR TEST")
    print("=" * 70)

    # Create extractor
    extractor = FeatureExtractor()

    # Test with a synthetic flow
    print("\n🧪 Creating test NetworkFlow...")
    test_flow = NetworkFlow(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.50",
        src_port=54321,
        dst_port=80,
        protocol="TCP",
        start_time=time.time(),
        end_time=time.time() + 5.0,
        packet_count=50,
        total_bytes=5000,
        fwd_packet_count=30,
        bwd_packet_count=20,
        fwd_bytes=3000,
        bwd_bytes=2000,
        syn_count=2,
        fin_count=2,
        rst_count=0,
        psh_count=10,
        ack_count=45,
        urg_count=0
    )
    test_flow.last_packet_time = test_flow.start_time + 5.0
    test_flow.first_packet_time = test_flow.start_time

    print("✅ Test flow created:")
    print(f"   Duration: {test_flow.duration:.2f}s")
    print(f"   Packets: {test_flow.packet_count}")
    print(f"   Bytes: {test_flow.total_bytes}")

    # Extract features
    print("\n⚙️  Extracting 78 features...")
    features = extractor.extract_features(test_flow)

    print(f"✅ Extracted {len(features)} features")

    # Validate
    print("\n🔍 Validating features...")
    validation = extractor.validate_features(features)

    if validation['valid']:
        print("✅ Features are VALID!")
        print(f"   Non-zero features: {validation['non_zero_count']}/78")
        print("\n📊 Feature Summary:")
        for key, value in validation['feature_summary'].items():
            print(f"   {key}: {value}")

        if validation['warnings']:
            print("\n⚠️  Warnings:")
            for warning in validation['warnings']:
                print(f"   • {warning}")
    else:
        print(f"❌ Validation failed: {validation['error']}")

    # Show first 10 features with names
    print("\n📝 First 10 Features:")
    for i in range(10):
        print(f"   {i:2d}. {FEATURE_NAMES[i]:20s} = {features[i]:.2f}")

    print("\n" + "=" * 70)
    print("✅ FEATURE EXTRACTOR TEST COMPLETE")
    print("=" * 70)
    print("\n💡 Next: Integrate with packet_capture.py and test with real packets!")

"""
ML Model Loader for Agentic Cybersecurity System.

This module loads the trained ensemble models (RF, XGB) and provides
prediction capabilities for network flow analysis.

Models loaded from /models/:
    - rf_model_binary.pkl (Random Forest)
    - xgb_model_binary.pkl (XGBoost)
    - scaler_binary.pkl (StandardScaler)
    - label_encoder_binary.pkl (LabelEncoder)
"""

import joblib
import numpy as np
from pathlib import Path
from typing import List, Dict, Any
import logging


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MLModelLoader:
    """
    Loads and manages the trained ML ensemble models (RF + XGBoost).
    Provides a unified interface for making ensemble predictions.
    """

    def __init__(self, models_dir: str = None):
        """
        Initialize the model loader.
        
        Args:
            models_dir: Path to models directory. If None, uses default location.
        """
        if models_dir is None:
            # Default to project root /models/ directory
            project_root = Path(__file__).parent.parent.parent
            models_dir = project_root / "models"

        self.models_dir = Path(models_dir)

        # Model containers
        self.rf_model = None
        self.xgb_model = None
        self.scaler = None
        self.label_encoder = None

        # Model availability flags
        self.models_loaded = False

        logger.info(f"Initializing ML Model Loader from: {self.models_dir}")

    def load_models(self) -> bool:
        """
        Load all trained models from disk.
        
        Returns:
            True if models loaded successfully, False otherwise
        """
        try:
            logger.info("Loading trained ML models...")

            # Load Random Forest
            rf_path = self.models_dir / "rf_model_binary.pkl"
            if rf_path.exists():
                self.rf_model = joblib.load(rf_path)
                self._patch_sklearn_compat(self.rf_model)
                logger.info("✅ Random Forest model loaded")
            else:
                logger.warning(
                    f"⚠️  Random Forest model not found at: {rf_path}")

            # Load XGBoost
            xgb_path = self.models_dir / "xgb_model_binary.pkl"
            if xgb_path.exists():
                self.xgb_model = joblib.load(xgb_path)
                logger.info("✅ XGBoost model loaded")
            else:
                logger.warning(f"⚠️  XGBoost model not found at: {xgb_path}")

            # Load Scaler
            scaler_path = self.models_dir / "scaler_binary.pkl"
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info("✅ Scaler loaded")
            else:
                logger.warning(f"⚠️  Scaler not found at: {scaler_path}")

            # Load Label Encoder
            encoder_path = self.models_dir / "label_encoder_binary.pkl"
            if encoder_path.exists():
                self.label_encoder = joblib.load(encoder_path)
                logger.info("✅ Label Encoder loaded")
            else:
                logger.warning(
                    f"⚠️  Label Encoder not found at: {encoder_path}")

            # Check if at least one model is loaded
            self.models_loaded = (
                self.rf_model is not None or
                self.xgb_model is not None
            )

            if self.models_loaded:
                logger.info("🎉 Models loaded successfully!")
                return True
            else:
                logger.error("❌ No models could be loaded")
                return False

        except Exception as e:
            logger.error(f"❌ Error loading models: {str(e)}")
            self.models_loaded = False
            return False

    def _patch_sklearn_compat(self, forest_model) -> None:
        """
        Patch sklearn 1.3.x pickled RandomForest models to work with sklearn >=1.4.
        sklearn 1.4 added `monotonic_cst` to DecisionTreeClassifier; models trained
        with 1.3 don't have this attribute, causing AttributeError on predict().
        """
        if forest_model is None or not hasattr(forest_model, "estimators_"):
            return
        for tree in forest_model.estimators_:
            if not hasattr(tree, "monotonic_cst"):
                tree.monotonic_cst = None

    def predict_single(self, features) -> Dict[str, Any]:
        """
        Make prediction on a single network flow.
        
        Args:
            features: Feature vector (78 features) - can be list or numpy array
            
        Returns:
            Dictionary containing predictions from all models
        """
        if not self.models_loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")

        # Convert to numpy array if it's a list
        if isinstance(features, list):
            features = np.array(features)

        # Ensure features are 2D array
        if features.ndim == 1:
            features = features.reshape(1, -1)

        # Scale features
        if self.scaler is not None:
            features_scaled = self.scaler.transform(features)
        else:
            features_scaled = features

        predictions = {}

        # Random Forest prediction
        if self.rf_model is not None:
            rf_pred = self.rf_model.predict(features_scaled)[0]
            rf_proba = np.clip(self.rf_model.predict_proba(features_scaled)[0], 0.0, 1.0)
            predictions['rf'] = {
                'prediction': self._decode_label(rf_pred),
                'confidence': float(np.max(rf_proba)),
                'probabilities': rf_proba.tolist()
            }

        # XGBoost prediction
        if self.xgb_model is not None:
            xgb_pred = self.xgb_model.predict(features_scaled)[0]
            # Clip to [0, 1]: older pickled XGBoost models may return raw logits
            # on extreme feature values due to version mismatch
            xgb_proba = np.clip(self.xgb_model.predict_proba(features_scaled)[0], 0.0, 1.0)
            predictions['xgb'] = {
                'prediction': self._decode_label(xgb_pred),
                'confidence': float(np.max(xgb_proba)),
                'probabilities': xgb_proba.tolist()
            }

        # Ensemble prediction (majority vote)
        if predictions:
            predictions['ensemble'] = self._ensemble_vote(predictions)

        return predictions

    def predict_batch(self, features_batch) -> List[Dict[str, Any]]:
        """
        Make predictions on multiple network flows.
        
        Args:
            features_batch: Array or list of feature vectors (N x 78)
            
        Returns:
            List of prediction dictionaries
        """
        if not self.models_loaded:
            raise RuntimeError("Models not loaded. Call load_models() first.")

        # Convert to numpy array if it's a list
        if isinstance(features_batch, list):
            features_batch = np.array(features_batch)

        results = []
        for features in features_batch:
            pred = self.predict_single(features)
            results.append(pred)

        return results

    def _decode_label(self, label_encoded: int) -> str:
        """
        Decode numerical label to string.
        
        Args:
            label_encoded: Encoded label (0 or 1)
            
        Returns:
            String label ('benign' or 'malicious')
        """
        if self.label_encoder is not None:
            label_str = self.label_encoder.inverse_transform([label_encoded])[
                0]
            # Map to simplified labels
            if label_str.lower() == 'benign':
                return 'benign'
            else:
                return 'malicious'
        else:
            # Fallback if label encoder not available
            return 'benign' if label_encoded == 0 else 'malicious'

    def _ensemble_vote(self, predictions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform ensemble voting across all models.
        
        Args:
            predictions: Dictionary of individual model predictions
            
        Returns:
            Ensemble prediction with confidence
        """
        votes = []
        confidences = []

        for model_name in ['rf', 'xgb']:
            if model_name in predictions:
                pred = predictions[model_name]['prediction']
                conf = predictions[model_name]['confidence']
                votes.append(1 if pred == 'malicious' else 0)
                confidences.append(conf)

        if not votes:
            return {'prediction': 'unknown', 'confidence': 0.0, 'agreement': 0.0}

        # Majority vote
        malicious_votes = sum(votes)
        total_votes = len(votes)

        ensemble_pred = 'malicious' if malicious_votes > total_votes / 2 else 'benign'

        # Agreement score (how many models agree)
        agreement = max(malicious_votes, total_votes -
                        malicious_votes) / total_votes

        # Average confidence
        avg_confidence = np.mean(confidences)

        return {
            'prediction': ensemble_pred,
            'confidence': float(avg_confidence),
            'agreement': float(agreement),
            'votes': {'malicious': malicious_votes, 'benign': total_votes - malicious_votes}
        }

    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about loaded models.
        
        Returns:
            Dictionary with model status and metadata
        """
        return {
            'models_loaded': self.models_loaded,
            'rf_available': self.rf_model is not None,
            'xgb_available': self.xgb_model is not None,
            'scaler_available': self.scaler is not None,
            'label_encoder_available': self.label_encoder is not None,
            'models_dir': str(self.models_dir)
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

# Global model loader instance
_global_loader = None


def get_model_loader(force_reload: bool = False) -> MLModelLoader:
    """
    Get or create the global model loader instance.
    
    Args:
        force_reload: If True, reload models even if already loaded
        
    Returns:
        MLModelLoader instance
    """
    global _global_loader

    if _global_loader is None or force_reload:
        _global_loader = MLModelLoader()
        _global_loader.load_models()

    return _global_loader


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    """
    Test the model loader.
    """
    print("=" * 60)
    print("Testing ML Model Loader")
    print("=" * 60)

    # Initialize loader
    loader = MLModelLoader()

    # Load models
    success = loader.load_models()

    if success:
        print("\n✅ Models loaded successfully!")

        # Print model info
        info = loader.get_model_info()
        print("\n📊 Model Information:")
        for key, value in info.items():
            print(f"  • {key}: {value}")

        # Test with dummy features (78 features)
        print("\n🧪 Testing with dummy features...")
        dummy_features = np.random.randn(78)

        try:
            prediction = loader.predict_single(dummy_features)

            print("\n📈 Prediction Results:")
            for model, result in prediction.items():
                print(f"\n  {model.upper()}:")
                for key, value in result.items():
                    print(f"    • {key}: {value}")
        except Exception as e:
            print(f"❌ Prediction failed: {str(e)}")
    else:
        print("\n❌ Failed to load models")

    print("\n" + "=" * 60)
    print("Model loader test complete!")
    print("=" * 60)

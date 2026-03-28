# ML Anomaly Detector
# Phase 12e: Advanced Threat Intelligence & Automation

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

import redis.asyncio as redis


@dataclass
class AnomalyResult:
    """Result of anomaly detection."""

    fingerprint_id: str
    anomaly_score: float
    is_anomaly: bool
    confidence: float
    features_used: List[str]
    model_version: str


class FeatureExtractor:
    """Extract features from JA4 fingerprints for ML models."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def extract(self, fingerprint: Dict[str, Any]) -> List[float]:
        """Convert JA4 fingerprint into numerical features for ML model."""
        features = []

        # Basic features
        features.append(float(fingerprint.get("score", 0.0)))
        features.append(len(fingerprint.get("extensions", [])))
        features.append(len(fingerprint.get("ciphers", [])))

        # JA4 string analysis
        ja4 = fingerprint.get("ja4", "")
        features.append(len(ja4))
        features.append(ja4.count("_"))
        features.append(ja4.count("h"))
        features.append(ja4.count("d"))

        # Timing features (if available)
        if "timestamp" in fingerprint:
            features.append(float(fingerprint["timestamp"]) % 1000)  # Seconds component
        else:
            features.append(0.0)

        # Network features
        features.append(1.0 if "src_ip" in fingerprint else 0.0)
        features.append(1.0 if "dest_ip" in fingerprint else 0.0)

        # Protocol features
        features.append(1.0 if "alpn" in fingerprint else 0.0)
        features.append(len(fingerprint.get("alpn", "")))

        # Pad to minimum feature count
        while len(features) < 20:
            features.append(0.0)

        return features[:20]  # Return exactly 20 features


class MLDetector:
    """Machine learning-based anomaly detection for JA4 fingerprints."""

    def __init__(self, redis_conn: redis.Redis, config: Dict[str, Any]):
        self.redis = redis_conn
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.extractor = FeatureExtractor(config.get("feature_config", {}))
        self.model: Any = None
        self.model_version = self._extract_model_version(config)
        self.model_key = config.get("ml_model_path", "analytics:ml:model:v1")

        # Load model on initialization
        self._load_model()

    def _extract_model_version(self, config: Dict[str, Any]) -> str:
        """Extract model version from config path."""
        path = config.get("ml_model_path", "")
        if "v" in path:
            # Extract version number after 'v'
            parts = path.split("v")
            if len(parts) > 1 and parts[-1]:
                return parts[-1]
        return "1"  # Default version

    def update_model_version(self, version: str):
        """Update to new model version."""
        self.model_version = version
        self.model_key = f"analytics:ml:model:v{version}"
        self.config["ml_model_path"] = self.model_key
        self._load_model()

    def _load_model(self):
        """Load ML model from Redis or initialize default."""
        try:
            # In production, this would load a real ML model
            # For Phase 12e initial implementation, we use a simple threshold model
            self.model = self._create_default_model()
            self.logger.info("Loaded ML model version %s", self.model_version)
        except (ValueError, AttributeError) as e:
            self.logger.error("Failed to load ML model: %s", e)
            self.model = self._create_default_model()

    def _create_default_model(self):
        """Create default threshold-based model for initial implementation."""

        # Simple model that flags scores above threshold as anomalies
        class ThresholdModel:
            def predict(self, features_list: List[List[float]]) -> List[float]:
                """Predict anomaly scores using threshold."""
                scores = []
                for features in features_list:
                    # Use score (first feature) as primary indicator
                    score = features[0]
                    # Add small random variation for realism
                    variation = (hash(str(features)) % 100) / 1000.0
                    anomaly_score = min(1.0, max(0.0, score / 100.0 + variation))
                    scores.append(anomaly_score)
                return scores

        return ThresholdModel()

    async def save_model(self, model_data: bytes):
        """Save ML model to Redis."""
        try:
            await self.redis.set(self.model_key, model_data)
            await self.redis.expire(self.model_key, 86400)  # 24 hour TTL
            self.logger.info("Saved ML model to %s", self.model_key)
        except redis.RedisError as e:
            self.logger.error("Failed to save model: %s", e)
            raise

    async def detect(self, fingerprints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in JA4 fingerprints using ML model."""
        if not self.model:
            self._load_model()

        # Extract features
        features_list = [self.extractor.extract(fp) for fp in fingerprints]

        # Get predictions
        anomaly_scores = self.model.predict(features_list)

        # Format results
        results = []
        for i, (fingerprint, score) in enumerate(zip(fingerprints, anomaly_scores)):
            result = AnomalyResult(
                fingerprint_id=str(i),
                anomaly_score=score,
                is_anomaly=score > 0.7,  # Threshold for anomaly
                confidence=0.9 if score > 0.9 else 0.7 if score > 0.7 else 0.5,
                features_used=[f"feature_{j}" for j in range(len(features_list[i]))],
                model_version=self.model_version,
            )
            results.append(
                {
                    "fingerprint_id": result.fingerprint_id,
                    "anomaly_score": result.anomaly_score,
                    "is_anomaly": result.is_anomaly,
                    "confidence": result.confidence,
                    "model_version": result.model_version,
                }
            )

        return results

    async def get_model_info(self) -> Dict[str, Any]:
        """Get information about current ML model."""
        return {
            "version": self.model_version,
            "type": "threshold",  # Will be 'ml' when real model is implemented
            "features": 20,
            "status": "active",
        }


class MLModelManager:
    """Manage ML model lifecycle and versioning."""

    def __init__(self, redis_conn: redis.Redis):
        self.redis = redis_conn
        self.logger = logging.getLogger(__name__)

    async def list_models(self) -> List[Dict[str, Any]]:
        """List available ML models."""
        try:
            keys = await self.redis.keys("analytics:ml:model:*")
            return [
                {
                    "key": key.decode() if isinstance(key, bytes) else key,
                    "version": (
                        key.decode().split(":")[-1]
                        if isinstance(key, bytes)
                        else key.split(":")[-1]
                    ),
                }
                for key in keys
            ]
        except redis.RedisError as e:
            self.logger.error("Failed to list models: %s", e)
            return []

    async def delete_model(self, version: str):
        """Delete a model version."""
        key = f"analytics:ml:model:v{version}"
        await self.redis.delete(key)


# Integration with Monitoring System
class MLMonitoringIntegration:
    """Integrate ML detector with monitoring system."""

    def __init__(self, monitoring_system):
        self.monitoring = monitoring_system

    async def detect_anomalies(
        self, fingerprints: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Delegate to monitoring system's ML detector."""
        if hasattr(self.monitoring, "ml_detector"):
            return await self.monitoring.ml_detector.detect(fingerprints)
        return []

    async def get_model_metrics(self) -> Dict[str, Any]:
        """Get ML model metrics."""
        if hasattr(self.monitoring, "ml_detector"):
            return await self.monitoring.ml_detector.get_model_info()
        return {"status": "unavailable"}

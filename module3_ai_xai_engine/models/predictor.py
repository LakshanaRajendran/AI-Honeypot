"""
Predictor module for the AI Decision & XAI Engine.

Provides the AnomalyPredictor class to execute inference using trained
Isolation Forest models on Module 2 26-feature session vectors, generating
anomaly scores, transparent feature-deviation explanations, and explicit limitations.
"""

import pathlib
from typing import Any, Dict, List, Optional, Union
import numpy as np
from sklearn.ensemble import IsolationForest

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from models.model_loader import load_anomaly_model
from preprocessing.validator import Module2InputValidator
from schemas.feature_object import Module2SessionPayload
from schemas.prediction_schema import AnomalyPredictionResult, FeatureDeviationExplanation


class AnomalyPredictor:
    """Inference engine for session-level anomaly detection.

    Consumes pre-normalized 26-dimensional session vectors from Module 2,
    evaluates them against an Isolation Forest model, and provides transparent
    feature deviation reports and technical limitations.
    """

    def __init__(
        self,
        model: Optional[IsolationForest] = None,
        metadata: Optional[Dict[str, Any]] = None,
        model_dir: Optional[Union[pathlib.Path, str]] = None,
    ):
        """Initialize the predictor with an in-memory model or from disk.

        Parameters
        ----------
        model : IsolationForest, optional
            Fitted IsolationForest instance.
        metadata : dict, optional
            Model metadata containing feature specifications and limitations.
        model_dir : Path | str, optional
            Path to directory containing saved model and metadata.
        """
        if model is not None and metadata is not None:
            self.model = model
            self.metadata = metadata
        elif model_dir is not None:
            self.model, self.metadata = load_anomaly_model(model_dir)
        else:
            raise ValueError("Must provide either (model, metadata) or model_dir.")

        self.validator = Module2InputValidator()
        self._verify_metadata()

    def _verify_metadata(self) -> None:
        """Verify that loaded model metadata matches canonical Module 2 specification."""
        if self.metadata.get("feature_count") != MODULE2_FEATURE_COUNT:
            raise ValueError(
                f"Incompatible model: feature_count {self.metadata.get('feature_count')} "
                f"!= expected {MODULE2_FEATURE_COUNT}."
            )
        if self.metadata.get("feature_names") != list(MODULE2_CANONICAL_FEATURE_NAMES):
            raise ValueError("Incompatible model: feature_names do not match Module 2 canonical sequence.")

    def predict_session(
        self,
        payload: Union[Module2SessionPayload, Dict[str, Any]],
    ) -> AnomalyPredictionResult:
        """Perform anomaly inference on a single session vector.

        Parameters
        ----------
        payload : Module2SessionPayload | dict
            Validated or raw Module 2 session payload.

        Returns
        -------
        AnomalyPredictionResult
            Inference result containing anomaly score, is_anomaly flag,
            transparent feature explanations, and operational limitations.

        Raises
        ------
        ValueError or ValidationError
            If the incoming payload violates schema, feature count, or contains NaNs/Infs.
        """
        # 1. Strictly validate incoming payload schema
        validated_payload = self.validator.validate(payload)

        # 2. Extract feature vector as 2D numpy array
        feature_vector = np.array(validated_payload.feature_vector, dtype=float).reshape(1, -1)

        # 3. Compute Isolation Forest score and prediction
        # decision_function yields > 0 for inliers, < 0 for outliers.
        # We define anomaly_score = -decision_function such that HIGHER indicates GREATER anomalousness.
        decision_val = float(self.model.decision_function(feature_vector)[0])
        anomaly_score = float(-decision_val)

        # sklearn predict returns -1 for anomaly/outlier, +1 for normal inlier
        is_anomaly = bool(self.model.predict(feature_vector)[0] == -1)

        # 4. Generate transparent feature-deviation explanations
        explanations = self._generate_explanations(validated_payload)

        # 5. Compile explicit limitations and operational disclosures
        limitations = self._compile_limitations()

        return AnomalyPredictionResult(
            session_id=validated_payload.session_id,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly,
            model_version=self.metadata.get("model_version", "1.0.0-unspecified"),
            explanations=explanations,
            limitations=limitations,
        )

    def _generate_explanations(
        self,
        payload: Module2SessionPayload,
    ) -> List[FeatureDeviationExplanation]:
        """Compute feature deviations against genuine reference baseline if available.

        Safeguard: If no genuine reference statistics exist, no misleading baseline
        statistics are computed; an informative note is attached instead.
        """
        explanations: List[FeatureDeviationExplanation] = []
        ref_stats = self.metadata.get("reference_statistics")
        is_genuine = self.metadata.get("is_production_validated", False)

        if not is_genuine or not ref_stats:
            # No genuine reference dataset exists to compare against
            explanations.append(
                FeatureDeviationExplanation(
                    feature_name="ALL_FEATURES",
                    observed_value=0.0,
                    reference_mean=None,
                    reference_std=None,
                    deviation_score=None,
                    description=(
                        "Baseline reference statistics are unavailable because genuine training vectors "
                        "have not been established. Feature deviation metrics are suppressed to avoid misleading comparisons."
                    ),
                )
            )
            return explanations

        # If genuine reference statistics exist
        ref_means = ref_stats.get("means", {})
        ref_stds = ref_stats.get("stds", {})

        for name, value in zip(MODULE2_CANONICAL_FEATURE_NAMES, payload.feature_vector):
            mean = ref_means.get(name)
            std = ref_stds.get(name)

            if mean is not None and std is not None and std > 0:
                z_dev = abs(value - mean) / std
                # Highlight features with significant standardized deviation (|z| > 2.0)
                if z_dev >= 2.0:
                    explanations.append(
                        FeatureDeviationExplanation(
                            feature_name=name,
                            observed_value=float(value),
                            reference_mean=float(mean),
                            reference_std=float(std),
                            deviation_score=float(z_dev),
                            description=(
                                f"Feature '{name}' observed at {value:.3f}, deviating by {z_dev:.2f} "
                                f"standard deviations from verified baseline (mean: {mean:.3f}, std: {std:.3f})."
                            ),
                        )
                    )

        return explanations

    def _compile_limitations(self) -> List[str]:
        """Compile explicit technical and domain limitations for this prediction."""
        limitations = [
            (
                "Anomaly detection identifies statistical outliers relative to model training data. "
                "Anomalousness does NOT establish confirmed maliciousness, attacker identity, or sophistication."
            ),
            (
                "Score Semantics: anomaly_score is the negative Isolation Forest decision function. "
                "Higher values indicate greater isolation. It is an uncalibrated geometric distance, NOT a probability."
            ),
            f"Scaler Assumption: {self.metadata.get('scaler_assumptions', 'Unspecified upstream scaling')}",
            f"Training Data Provenance: {self.metadata.get('training_data_source', 'Unknown')}",
        ]

        if not self.metadata.get("is_production_validated", False):
            limitations.append(
                "CRITICAL LIMITATION: Model is NOT production-validated. The upstream Module 2 scaler was "
                "fitted on dummy data and genuine 26-feature training vectors are pending from the upstream pipeline."
            )

        return limitations

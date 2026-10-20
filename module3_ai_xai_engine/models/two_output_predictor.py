"""
Two-Output Predictor Engine for Module 3 (AI Decision & XAI Engine).

Integrates:
- Output A: Binary classification (is_weaponized_intrusion) with calibrated confidence.
- Output B: Multi-label attacker intent prediction across supported categories
  (['reconnaissance', 'execution', 'persistence', 'defense_evasion']).
  Explicitly flags 'credential_access' as unsupported by ML.
- Auxiliary: Optional Isolation Forest anomaly detection signal.
- Transparent feature-deviation explanations and operational disclosures.
"""

import json
import pathlib
from typing import Any, Dict, List, Optional, Union
import joblib
import numpy as np

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from explainability.shap_explainer import ShapExplainer
from models.predictor import AnomalyPredictor
from preprocessing.validator import Module2InputValidator
from schemas.feature_object import Module2SessionPayload
from schemas.prediction_schema import (
    AuxiliaryAnomalyOutput,
    BinaryClassificationOutput,
    FeatureDeviationExplanation,
    MultiLabelIntentOutput,
    ShapExplanation,
    UnifiedModule3Result,
)


class TwoOutputPredictor:
    """Unified inference engine for Module 3 producing Output A, Output B, and auxiliary signals."""

    def __init__(
        self,
        model_dir: Union[pathlib.Path, str] = "experiments/two_output_model_v1",
        anomaly_predictor: Optional[AnomalyPredictor] = None,
    ):
        """Load trained two-output models, scaler, and metadata.

        Parameters
        ----------
        model_dir : Path | str
            Directory containing binary model, intent model, scaler, and metadata.
        anomaly_predictor : AnomalyPredictor, optional
            Optional auxiliary anomaly detector.
        """
        self.model_dir = pathlib.Path(model_dir)
        self.validator = Module2InputValidator()
        self.anomaly_predictor = anomaly_predictor

        # Load artifacts
        binary_path = self.model_dir / "binary_weaponization_model.joblib"
        intent_path = self.model_dir / "multilabel_intent_model.joblib"
        scaler_path = self.model_dir / "cowrie_adapter_scaler.joblib"
        meta_path = self.model_dir / "model_metadata.json"

        if not binary_path.is_file():
            raise FileNotFoundError(f"Binary model artifact not found: {binary_path.resolve()}")
        if not intent_path.is_file():
            raise FileNotFoundError(f"Multi-label intent model artifact not found: {intent_path.resolve()}")
        if not scaler_path.is_file():
            raise FileNotFoundError(f"Scaler artifact not found: {scaler_path.resolve()}")
        if not meta_path.is_file():
            raise FileNotFoundError(f"Model metadata not found: {meta_path.resolve()}")

        self.binary_model = joblib.load(binary_path)
        self.intent_model = joblib.load(intent_path)
        self.scaler = joblib.load(scaler_path)

        with open(meta_path, "r", encoding="utf-8") as f:
            self.metadata = json.load(f)

        self.supported_intents = self.metadata["models"]["intent_model"]["supported_targets"]
        self.unsupported_intents = self.metadata["models"]["intent_model"]["unsupported_targets"]

        # SHAP is optional: an explainer initialization failure must not
        # prevent the existing classifier and intent model from running.
        self.shap_explainer = None
        self.shap_initialization_error = None
        try:
            self.shap_explainer = ShapExplainer(self.binary_model)
        except Exception as exc:
            self.shap_initialization_error = (
                f"{type(exc).__name__}: {exc}"
            )

    def predict_session(
        self,
        payload: Union[Module2SessionPayload, Dict[str, Any]],
    ) -> UnifiedModule3Result:
        """Run full two-output inference on a Module 2 session payload.

        Parameters
        ----------
        payload : Module2SessionPayload | dict
            Incoming session data conforming to Module 2 26-feature specification.

        Returns
        -------
        UnifiedModule3Result
            Structured response containing binary classification, multi-label intent,
            optional anomaly signal, feature explanations, and operational limitations.
        """
        # 1. Strictly validate incoming payload schema
        validated_payload = self.validator.validate(payload)

        # 2. Extract feature vector
        # If unscaled raw_features are present, scale with frozen training scaler;
        # otherwise, assume incoming vector is already appropriately normalized.
        if validated_payload.raw_features and all(k in validated_payload.raw_features for k in MODULE2_CANONICAL_FEATURE_NAMES):
            raw_row = [float(validated_payload.raw_features[k]) for k in MODULE2_CANONICAL_FEATURE_NAMES]
            X_scaled = self.scaler.transform(np.array([raw_row], dtype=float))
        else:
            X_scaled = np.array(validated_payload.feature_vector, dtype=float).reshape(1, -1)

        # 3. Output A: Binary Classification
        pred_class_int = int(self.binary_model.predict(X_scaled)[0])
        prob_weaponized = float(self.binary_model.predict_proba(X_scaled)[0][1])
        label_str = "weaponized_intrusion" if pred_class_int == 1 else "low_interaction_probe"

        binary_output = BinaryClassificationOutput(
            predicted_class=pred_class_int,
            predicted_label=label_str,
            confidence=prob_weaponized if pred_class_int == 1 else float(1.0 - prob_weaponized),
            classification_basis="supervised_random_forest_on_provisional_targets",
        )

        # 4. Output B: Multi-Label Attacker Intent
        pred_intents_raw = self.intent_model.predict(X_scaled)[0]
        detected_intents: List[str] = []
        intent_scores: Dict[str, float] = {}

        for idx, intent_name in enumerate(self.supported_intents):
            is_active = bool(pred_intents_raw[idx] == 1)
            if is_active:
                detected_intents.append(intent_name)

            # Extract calibrated probability from sub-estimator
            estimator = self.intent_model.estimators_[idx]
            if hasattr(estimator, "predict_proba"):
                probs = estimator.predict_proba(X_scaled)[0]
                # If binary estimator has both classes
                if len(probs) == 2:
                    intent_scores[intent_name] = float(probs[1])
                else:
                    intent_scores[intent_name] = float(probs[0])
            else:
                intent_scores[intent_name] = 1.0 if is_active else 0.0

        intent_output = MultiLabelIntentOutput(
            detected_intents=detected_intents,
            intent_scores=intent_scores,
            unsupported_intents=list(self.unsupported_intents),
            intent_basis="multi_output_random_forest_on_provisional_targets",
        )

        # 5. Optional Auxiliary Anomaly Signal
        aux_anomaly: Optional[AuxiliaryAnomalyOutput] = None
        if self.anomaly_predictor is not None:
            anom_res = self.anomaly_predictor.predict_session(validated_payload)
            aux_anomaly = AuxiliaryAnomalyOutput(
                anomaly_score=anom_res.anomaly_score,
                is_anomaly=anom_res.is_anomaly,
                detector_version=anom_res.model_version,
            )

        # 6. Transparent Feature Explanations
        explanations = self._generate_feature_explanations(validated_payload, X_scaled[0])

        # 7. Disclosures & Operational Limitations
        limitations = [
            "PROVISIONAL TARGET LABELS: Targets were derived via deterministic rule patterns and do not represent verified external ground truth.",
            "BOTNET REPETITION OVERLAP: Predictions are evaluated on known honeypot botnet archetypes; high confidence indicates recognition of learned script archetypes rather than novel attack generalization.",
            "FEATURE-LABEL CIRCULARITY: The 26 canonical features include heuristic risk/MITRE scores that partly share keywords with the labeling rules.",
            "UNSUPPORTED INTENT: 'credential_access' has only 3 positive cases across 1,000 sessions (0.3% support) and is excluded from supervised ML prediction to prevent unreliable outputs.",
        ]

        # 8. SHAP explanation of the binary model prediction.
        shap_explanation = None
        if self.shap_explainer is not None:
            try:
                shap_data = self.shap_explainer.explain(
                    feature_vector=X_scaled[0],
                    feature_names=MODULE2_CANONICAL_FEATURE_NAMES,
                    top_k=5,
                )
                shap_explanation = ShapExplanation(**shap_data)
            except Exception as exc:
                limitations.append(
                    "SHAP explanation unavailable for this prediction: "
                    f"{type(exc).__name__}: {exc}"
                )
        else:
            limitations.append(
                "SHAP explainer could not be initialized: "
                f"{self.shap_initialization_error or 'unknown initialization error'}"
            )

        return UnifiedModule3Result(
            session_id=validated_payload.session_id,
            classification=binary_output,
            intent=intent_output,
            anomaly=aux_anomaly,
            explanations=explanations,
            shap_explanation=shap_explanation,
            label_provenance="provisional_rule_derived_behavioral_targets",
            limitations=limitations,
        )

    def _generate_feature_explanations(
        self,
        payload: Module2SessionPayload,
        scaled_vector: np.ndarray,
    ) -> List[FeatureDeviationExplanation]:
        """Generate transparent feature deviation explanations based on training scaler baseline."""
        explanations: List[FeatureDeviationExplanation] = []
        means = self.scaler.mean_
        stds = self.scaler.scale_

        for idx, (name, val_scaled) in enumerate(zip(MODULE2_CANONICAL_FEATURE_NAMES, scaled_vector)):
            # If standardized feature value has large deviation (|z| >= 2.0)
            if abs(val_scaled) >= 2.0:
                obs_val = float(payload.raw_features[name]) if payload.raw_features else float(val_scaled)
                explanations.append(
                    FeatureDeviationExplanation(
                        feature_name=name,
                        observed_value=obs_val,
                        reference_mean=float(means[idx]),
                        reference_std=float(stds[idx]),
                        deviation_score=float(abs(val_scaled)),
                        description=(
                            f"Feature '{name}' deviates by {abs(val_scaled):.2f} standard deviations "
                            f"from training baseline (mean: {means[idx]:.2f}, std: {stds[idx]:.2f})."
                        ),
                    )
                )

        return explanations


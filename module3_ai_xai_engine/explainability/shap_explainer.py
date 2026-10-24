"""Inference-time SHAP explanations for Module 3's binary Random Forest."""

from typing import Any, Dict, List, Sequence

import numpy as np
import shap


class ShapExplainer:
    """Explain the binary model's weaponized-intrusion prediction."""

    def __init__(self, model: Any):
        self.model = model
        self._explainer = shap.TreeExplainer(model)

    @staticmethod
    def _positive_class_values(shap_result: Any) -> np.ndarray:
        """Normalize SHAP output across common SHAP versions."""
        values = getattr(shap_result, "values", shap_result)

        if isinstance(values, list):
            values = values[1] if len(values) > 1 else values[0]

        values = np.asarray(values)

        # Recent SHAP versions may return:
        # (samples, features, classes)
        if values.ndim == 3:
            values = values[:, :, 1] if values.shape[-1] > 1 else values[:, :, 0]

        if values.ndim == 2:
            values = values[0]
        elif values.ndim != 1:
            raise ValueError(f"Unexpected SHAP value shape: {values.shape}")

        return values.astype(float)

    def explain(
        self,
        feature_vector: Sequence[float],
        feature_names: Sequence[str],
        top_k: int = 5,
    ) -> Dict[str, Any]:
        """Return the largest signed contributions to class 1."""
        row = np.asarray(feature_vector, dtype=float).reshape(1, -1)

        if row.shape[1] != len(feature_names):
            raise ValueError(
                f"Feature count mismatch: {row.shape[1]} values but "
                f"{len(feature_names)} feature names."
            )

        result = self._explainer(row)
        values = self._positive_class_values(result)

        if len(values) != len(feature_names):
            raise ValueError(
                f"SHAP returned {len(values)} values for "
                f"{len(feature_names)} features."
            )

        order = np.argsort(np.abs(values))[::-1][:max(1, int(top_k))]
        features: List[Dict[str, Any]] = []

        for idx in order:
            value = float(values[idx])

            if value > 0:
                direction = "supports_weaponized_intrusion"
            elif value < 0:
                direction = "opposes_weaponized_intrusion"
            else:
                direction = "neutral"

            features.append({
                "feature_name": str(feature_names[idx]),
                "shap_value": round(value, 6),
                "direction": direction,
            })

        return {
            "model_explained": "weaponized_intrusion_probability",
            "explainer": "SHAP TreeExplainer",
            "top_features": features,
            "interpretation_note": (
                "Positive SHAP values push the model toward class 1 "
                "(weaponized_intrusion); negative values push it away. "
                "These are model contributions, not proof of malicious intent."
            ),
        }

"""
Feature Combiner module for the AI Decision & XAI Engine.

Transforms structured Module3Input payloads into a single
canonical numerical feature vector ready for ML models.
"""

from config import ENGINEERED_FEATURE_ORDER
from schemas.input_schema import Module3Input


class FeatureCombiner:
    """Combines engineered features and behavior embeddings into a
    single canonical feature vector.

    The output vector has the engineered features first (in the order
    defined by ``ENGINEERED_FEATURE_ORDER``), followed immediately by
    the complete behavior embedding.
    """

    def combine(self, module_input: Module3Input) -> list[float]:
        """Convert a Module3Input into a flat numerical feature vector.

        Parameters
        ----------
        module_input : Module3Input
            The validated input payload.

        Returns
        -------
        list[float]
            Feature vector containing engineered features (in canonical
            order) followed by the behavior embedding.
        """
        vector: list[float] = []

        # Append engineered features in canonical order
        features = module_input.engineered_features
        for name in ENGINEERED_FEATURE_ORDER:
            vector.append(float(getattr(features, name)))

        # Append the complete behavior embedding unchanged
        vector.extend(module_input.behavior_embedding)

        return vector


"""
Prediction schema module for the AI Decision & XAI Engine.

Defines strongly-typed Pydantic schemas for Module 3 anomaly detection
inference results, transparent feature-deviation explanations, and operational limitations.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class FeatureDeviationExplanation(BaseModel):
    """Transparent explanation of an unusual feature observation.

    Highlights significant deviation of a feature value without asserting
    or implying confirmed malicious intent or threat sophistication.
    """

    feature_name: str = Field(..., description="Canonical name of the 26-feature specification.")
    observed_value: float = Field(..., description="Observed numeric value in the incoming session vector.")
    reference_mean: Optional[float] = Field(
        default=None,
        description="Mean value in the verified reference dataset, if available."
    )
    reference_std: Optional[float] = Field(
        default=None,
        description="Standard deviation in the verified reference dataset, if available."
    )
    deviation_score: Optional[float] = Field(
        default=None,
        description="Normalized deviation score (e.g., |z-score|) relative to genuine reference statistics."
    )
    description: str = Field(
        ...,
        description="Factual description of the deviation without attributing malicious intent."
    )


class AnomalyPredictionResult(BaseModel):
    """Standardized output of the Module 3 Anomaly Detection Engine.

    Adheres strictly to the integration contract:
    - anomaly_score: Float where higher values indicate greater anomalousness (NOT a probability).
    - is_anomaly: Boolean flag indicating if the session is an outlier.
    - model_version: Identifier of the active model and schema version.
    - explanations: List of transparent feature-level deviations.
    - limitations: Disclosures regarding training data, scaling dependencies, and intent boundaries.
    """

    session_id: str = Field(..., description="Unique session identifier matching input payload.")
    anomaly_score: float = Field(
        ...,
        description=(
            "Anomaly score computed from Isolation Forest decision function, "
            "inverted such that HIGHER values indicate GREATER anomalousness. "
            "Note: This is an uncalibrated geometric outlier score, NOT a calibrated probability."
        )
    )
    is_anomaly: bool = Field(
        ...,
        description="Binary outlier flag based on the Isolation Forest decision boundary (contamination threshold)."
    )
    model_version: str = Field(..., description="Model artifact version and specification string.")
    explanations: List[FeatureDeviationExplanation] = Field(
        default_factory=list,
        description="List of feature deviation explanations identifying unusual attributes."
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit technical disclosures, scaler assumptions, and analytical boundaries."
    )


class BinaryClassificationOutput(BaseModel):
    """Output A: Binary classification between active weaponization and low-interaction probing."""

    predicted_class: int = Field(..., description="0 = low-interaction probe, 1 = weaponized intrusion.")
    predicted_label: str = Field(..., description="'low_interaction_probe' or 'weaponized_intrusion'.")
    confidence: Optional[float] = Field(
        default=None,
        description="Estimated probability P(weaponized_intrusion | X) in [0.0, 1.0]."
    )
    classification_basis: str = Field(
        default="supervised_random_forest_on_provisional_targets",
        description="Source and methodology used to derive this prediction."
    )


class MultiLabelIntentOutput(BaseModel):
    """Output B: Multi-label attacker intent prediction across supported tactical categories."""

    detected_intents: List[str] = Field(
        default_factory=list,
        description="List of attacker tactical intents detected above classification threshold."
    )
    intent_scores: Dict[str, float] = Field(
        default_factory=dict,
        description="Model confidence probabilities for supported intent categories."
    )
    unsupported_intents: List[str] = Field(
        default_factory=lambda: ["credential_access"],
        description="Intents excluded from supervised prediction due to insufficient sample support."
    )
    intent_basis: str = Field(
        default="multi_output_random_forest_on_provisional_targets",
        description="Methodology used to derive multi-label intent scores."
    )


class AuxiliaryAnomalyOutput(BaseModel):
    """Optional auxiliary anomaly detection signal from Isolation Forest."""

    anomaly_score: Optional[float] = Field(
        default=None,
        description="Negative decision function value where higher indicates greater geometric isolation."
    )
    is_anomaly: Optional[bool] = Field(
        default=None,
        description="True if flagged as an outlier by Isolation Forest boundary."
    )
    detector_version: Optional[str] = Field(
        default=None,
        description="Version string of the auxiliary anomaly detector."
    )


class ShapFeatureContribution(BaseModel):
    """A signed SHAP contribution for one input feature."""

    feature_name: str
    shap_value: float
    direction: str


class ShapExplanation(BaseModel):
    """SHAP explanation for the binary weaponized-intrusion model."""

    model_explained: str
    explainer: str
    top_features: List[ShapFeatureContribution] = Field(default_factory=list)
    interpretation_note: str


class UnifiedModule3Result(BaseModel):
    """Unified structured response conforming to Module 3 specification for Module 4 handoff."""

    session_id: str = Field(..., description="Unique session identifier matching input payload.")
    classification: BinaryClassificationOutput = Field(..., description="Output A: Binary classification.")
    intent: MultiLabelIntentOutput = Field(..., description="Output B: Multi-label attacker intent.")
    anomaly: Optional[AuxiliaryAnomalyOutput] = Field(
        default=None,
        description="Optional auxiliary anomaly signal."
    )
    explanations: List[FeatureDeviationExplanation] = Field(
        default_factory=list,
        description="Transparent feature deviations identifying unusual attributes."
    )
    shap_explanation: Optional[ShapExplanation] = Field(
        default=None,
        description="Optional SHAP explanation of the binary classifier prediction."
    )
    label_provenance: str = Field(
        default="provisional_rule_derived_behavioral_targets",
        description="Clarification that training targets are rule-derived, NOT external ground truth."
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Technical disclosures regarding botnet repetition, heuristic circularity, and data scarcity."
    )

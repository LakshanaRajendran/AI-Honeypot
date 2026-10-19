"""
Module 2 Feature Object Schema.

Defines the Pydantic data model for ingesting normalized 26-dimensional
session feature vectors produced by Module 2.
"""

import math
from typing import Any, Optional

import numpy as np
from pydantic import BaseModel, Field, field_validator, model_validator

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT


class Module2SessionPayload(BaseModel):
    """Represents a validated session feature vector from Module 2.

    Attributes
    ----------
    session_id : str
        Unique session identifier (non-empty).
    feature_count : int
        Must be strictly equal to 26.
    feature_names : list[str]
        Must match MODULE2_CANONICAL_FEATURE_NAMES exactly in count and order.
    feature_vector : list[float]
        Pre-scaled, normalized 26-dimensional float vector.
    schema_version : Optional[str]
        Schema version string, default "1.0".
    sequence : Optional[list[str]]
        Ordered list of observed command/event tokens in the session.
    raw_features : Optional[dict[str, Any]]
        Optional unscaled feature values before Module 2 normalization.
    """

    session_id: str
    feature_count: int = Field(default=MODULE2_FEATURE_COUNT)
    feature_names: list[str] = Field(default_factory=lambda: list(MODULE2_CANONICAL_FEATURE_NAMES))
    feature_vector: list[float]
    schema_version: Optional[str] = "1.0"
    sequence: Optional[list[str]] = None
    raw_features: Optional[dict[str, Any]] = None

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, v: str) -> str:
        """Ensure session_id is a non-empty, non-whitespace string."""
        if not isinstance(v, str):
            raise ValueError("session_id must be a string.")
        if not v.strip():
            raise ValueError("session_id cannot be empty or contain only whitespace.")
        return v

    @field_validator("feature_count")
    @classmethod
    def validate_feature_count(cls, v: int) -> int:
        """Ensure feature_count is exactly 26."""
        if v != MODULE2_FEATURE_COUNT:
            raise ValueError(
                f"feature_count must be exactly {MODULE2_FEATURE_COUNT}, got {v}."
            )
        return v

    @field_validator("feature_names")
    @classmethod
    def validate_feature_names(cls, v: list[str]) -> list[str]:
        """Ensure feature_names matches canonical 26-feature sequence."""
        if not isinstance(v, (list, tuple)):
            raise ValueError("feature_names must be a list of strings.")
        if len(v) != MODULE2_FEATURE_COUNT:
            raise ValueError(
                f"feature_names must contain exactly {MODULE2_FEATURE_COUNT} names, got {len(v)}."
            )
        if list(v) != MODULE2_CANONICAL_FEATURE_NAMES:
            raise ValueError(
                "feature_names does not match the canonical 26-feature ordering from feature_schema.json."
            )
        return list(v)

    @field_validator("feature_vector", mode="before")
    @classmethod
    def validate_vector_values(cls, v: Any) -> list[float]:
        """Strictly validate numeric values in feature_vector.

        Rejects booleans, non-numeric types, nulls, NaNs, and infinities.
        """
        if not isinstance(v, (list, tuple)):
            raise ValueError("feature_vector must be a list or tuple of numeric floats.")

        validated: list[float] = []
        for idx, item in enumerate(v):
            if isinstance(item, bool):
                raise ValueError(
                    f"feature_vector[{idx}] cannot be a boolean (found: {item!r})."
                )
            if item is None:
                raise ValueError(f"feature_vector[{idx}] cannot be None/null.")
            if not isinstance(item, (int, float)):
                raise ValueError(
                    f"feature_vector[{idx}] must be numeric, got {type(item).__name__}."
                )
            f_val = float(item)
            if math.isnan(f_val) or math.isinf(f_val):
                raise ValueError(
                    f"feature_vector[{idx}] must be finite (cannot be NaN or Inf, found: {f_val})."
                )
            validated.append(f_val)
        return validated

    @field_validator("feature_vector")
    @classmethod
    def validate_vector_length(cls, v: list[float]) -> list[float]:
        """Ensure feature_vector has exactly 26 values."""
        if len(v) != MODULE2_FEATURE_COUNT:
            raise ValueError(
                f"feature_vector must contain exactly {MODULE2_FEATURE_COUNT} values, got {len(v)}."
            )
        return v

    @model_validator(mode="after")
    def validate_cross_field_consistency(self) -> "Module2SessionPayload":
        """Verify cross-field alignment between count and vector length."""
        if len(self.feature_vector) != self.feature_count:
            raise ValueError(
                f"Length of feature_vector ({len(self.feature_vector)}) "
                f"does not match feature_count ({self.feature_count})."
            )
        return self

    def to_numpy(self) -> np.ndarray:
        """Convert feature_vector directly to a 1D float64 numpy array."""
        return np.array(self.feature_vector, dtype=np.float64)

    def to_feature_dict(self) -> dict[str, float]:
        """Convert vector to a dict mapping canonical feature names to values."""
        return dict(zip(self.feature_names, self.feature_vector))


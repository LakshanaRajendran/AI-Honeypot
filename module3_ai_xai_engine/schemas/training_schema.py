"""
Training schema module for the AI Decision & XAI Engine.

This module defines the Pydantic model for labeled training data
used during model training.
"""

from pydantic import BaseModel

from schemas.input_schema import EngineeredFeatures


class TrainingSample(BaseModel):
    """A single labeled training sample representing one attacker session.

    Each training sample contains a session identifier, engineered features,
    an optional behavior embedding vector, and a ground-truth label
    indicating the attack stage (e.g., Reconnaissance, Exploitation, etc.).

    Attributes
    ----------
    session_id : str
        Unique identifier for the attacker session.
    engineered_features : EngineeredFeatures
        Aggregated feature values derived from the session.
    behavior_embedding : list[float]
        Optional embedding vector for deep learning models.
    label : str
        Ground-truth attack stage label.
    """

    session_id: str
    engineered_features: EngineeredFeatures
    behavior_embedding: list[float]
    label: str


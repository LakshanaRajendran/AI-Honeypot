"""
Input schema module for the AI Decision & XAI Engine.

This module defines the Pydantic models for input data
fed into the engine for classification and prediction.
"""

from pydantic import BaseModel


class EngineeredFeatures(BaseModel):
    """Aggregated feature values derived from raw honeypot session data.

    These features capture behavioral patterns observed during a session,
    such as authentication attempts, command usage, network connections,
    data transfer volumes, file system interactions, and session duration.
    """

    failed_logins: int
    successful_logins: int
    command_count: int
    unique_commands: int
    ssh_connections: int
    https_connections: int
    bytes_sent: float
    bytes_received: float
    file_reads: int
    file_writes: int
    sensitive_file_access: int
    session_duration: float


class Module3Input(BaseModel):
    """Top-level input payload for the AI Decision & XAI Engine.

    Represents a single session or event to be classified/predicted
    by the engine. Contains the session identifier, engineered features,
    and an optional behavior embedding vector for deep learning models.
    """

    session_id: str
    engineered_features: EngineeredFeatures
    behavior_embedding: list[float]


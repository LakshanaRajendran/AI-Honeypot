"""
Configuration module for the AI Decision & XAI Engine.

This module contains configuration settings, paths, hyperparameters,
and canonical constants used across the engine.
"""

# ---------------------------------------------------------------------------
# Engineered Feature Order (Canonical)
# ---------------------------------------------------------------------------
# This list defines the exact order in which engineered features are
# stored, combined, and passed to the ML model.  Every component that
# works with feature vectors must import and use this constant to
# guarantee consistency between training and inference.
#
# Reused by:
#   - Feature Combiner  (preprocessing/combiner.py)
#   - Dataset Loader    (training/dataset_loader.py)
#   - Model Trainer     (training/train_model.py)
#   - Predictor         (models/predictor.py)
# ---------------------------------------------------------------------------

ENGINEERED_FEATURE_ORDER = [
    "failed_logins",
    "successful_logins",
    "command_count",
    "unique_commands",
    "ssh_connections",
    "https_connections",
    "bytes_sent",
    "bytes_received",
    "file_reads",
    "file_writes",
    "sensitive_file_access",
    "session_duration",
]

# ---------------------------------------------------------------------------
# Module 2 Canonical 26-Feature Schema Specification
# ---------------------------------------------------------------------------
# Official feature ordering as verified against feature_schema.json.
# Every Module 2 session feature vector must match this exact sequence.
MODULE2_FEATURE_COUNT = 26

MODULE2_CANONICAL_FEATURE_NAMES = [
    "total_events",
    "command_count",
    "unique_commands",
    "unique_processes",
    "unique_mitre_tactics",
    "unique_mitre_techniques",
    "session_duration_seconds",
    "mean_inter_event_seconds",
    "std_inter_event_seconds",
    "min_inter_event_seconds",
    "max_inter_event_seconds",
    "commands_per_minute",
    "network_utility_ratio",
    "file_inspection_ratio",
    "identity_command_ratio",
    "credential_keyword_ratio",
    "download_utility_ratio",
    "mean_risk_score",
    "max_risk_score",
    "risk_score_std",
    "high_or_critical_ratio",
    "path_command_ratio",
    "pipe_ratio",
    "redirect_ratio",
    "mean_command_length",
    "mean_argument_count",
]

# ---------------------------------------------------------------------------
# General Engine Configuration
# ---------------------------------------------------------------------------

CONFIG = {
    "model": {
        "model_path": "saved_models/",
        "random_state": 42,
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    },
}


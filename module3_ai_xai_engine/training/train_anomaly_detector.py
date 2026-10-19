"""
Training module for the Module 3 Isolation Forest Anomaly Detection Engine.

Provides functionality to fit, evaluate, and serialize an Isolation Forest
anomaly detector on canonical 26-feature session vectors adhering to Module 2's specification.
"""

import pathlib
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from sklearn.ensemble import IsolationForest

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from models.model_loader import save_anomaly_model
from preprocessing.validator import Module2InputValidator
from schemas.feature_object import Module2SessionPayload
from training.dataset_loader import DatasetLoader


def train_isolation_forest(
    sessions: List[Module2SessionPayload],
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42,
    data_source_description: str = "unspecified",
    is_production_validated: bool = False,
    scaler_assumptions: Optional[str] = None,
) -> Tuple[IsolationForest, Dict[str, Any]]:
    """Train an Isolation Forest model on validated 26-feature session payloads.

    Parameters
    ----------
    sessions : list[Module2SessionPayload]
        List of validated session payloads. Must contain at least one session.
    contamination : float, default 0.05
        Expected proportion of outliers in the training dataset.
    n_estimators : int, default 100
        Number of isolation trees in the ensemble.
    random_state : int, default 42
        Seed for reproducibility.
    data_source_description : str
        Description of the dataset used for training.
    is_production_validated : bool, default False
        Flag indicating if the training data represents verified, genuine honeypot sessions.
    scaler_assumptions : str, optional
        Custom description of scaling contract and scaler provenance.

    Returns
    -------
    tuple[IsolationForest, dict]
        Fitted model and associated metadata.
    """
    if not sessions:
        raise ValueError("Cannot train IsolationForest: sessions list is empty.")

    validator = Module2InputValidator()
    # Validate each session
    validated_sessions = validator.validate_batch(sessions)

    # Convert to 2D numpy array [n_samples, 26]
    X = np.array([s.feature_vector for s in validated_sessions], dtype=float)

    if X.shape[1] != MODULE2_FEATURE_COUNT:
        raise ValueError(
            f"Expected {MODULE2_FEATURE_COUNT} features per session, got shape {X.shape}."
        )

    # Check for NaN / Inf
    if not np.all(np.isfinite(X)):
        raise ValueError("Feature matrix contains non-finite values (NaN or Inf).")

    # Fit Isolation Forest
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)

    # Compute reference statistics only if genuine production data is used
    ref_stats: Optional[Dict[str, Dict[str, float]]] = None
    if is_production_validated and len(validated_sessions) >= 2:
        means = np.mean(X, axis=0)
        stds = np.std(X, axis=0)
        ref_stats = {
            "means": {name: float(m) for name, m in zip(MODULE2_CANONICAL_FEATURE_NAMES, means)},
            "stds": {name: float(s) for name, s in zip(MODULE2_CANONICAL_FEATURE_NAMES, stds)},
        }

    default_scaler_assump = (
        "pre_standardized_z_scores_by_upstream_module2; "
        "UNVERIFIED dependency (upstream scaler was fitted on 2 dummy sessions); "
        "no secondary scaling applied."
    )

    metadata = {
        "model_version": "1.0.0-anomaly-iforest",
        "model_type": "IsolationForest",
        "feature_count": MODULE2_FEATURE_COUNT,
        "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
        "hyperparameters": {
            "n_estimators": n_estimators,
            "contamination": contamination,
            "random_state": random_state,
        },
        "sample_count": len(validated_sessions),
        "training_data_source": data_source_description,
        "is_production_validated": is_production_validated,
        "scaler_assumptions": scaler_assumptions or default_scaler_assump,
        "score_semantics": (
            "anomaly_score = -decision_function(X). Higher values indicate greater anomalousness "
            "(decision boundary at 0.0). Uncalibrated geometric outlier score, NOT a probability."
        ),
        "reference_statistics": ref_stats,
    }

    return model, metadata


def train_from_adapter_payloads(
    payloads: List[Module2SessionPayload],
    scaler_metadata: Optional[Dict[str, Any]] = None,
    contamination: float = 0.05,
    n_estimators: int = 100,
    random_state: int = 42,
    data_source_description: str = "cowrie_adapter_streamed_sessions",
    is_production_validated: bool = False,
) -> Tuple[IsolationForest, Dict[str, Any]]:
    """Train Isolation Forest on payloads produced by CowrieSessionAdapter."""
    if scaler_metadata:
        scaler_assump = (
            f"standardized_by_module3_cowrie_adapter; "
            f"scaler_version={scaler_metadata.get('scaler_version', '1.0.0')}; "
            f"sample_count={scaler_metadata.get('sample_count', len(payloads))}; "
            f"no secondary scaling applied."
        )
    else:
        scaler_assump = None

    return train_isolation_forest(
        sessions=payloads,
        contamination=contamination,
        n_estimators=n_estimators,
        random_state=random_state,
        data_source_description=data_source_description,
        is_production_validated=is_production_validated,
        scaler_assumptions=scaler_assump,
    )


def train_and_save_from_file(
    dataset_file: Union[pathlib.Path, str],
    target_dir: Union[pathlib.Path, str],
    is_production_validated: bool = False,
    contamination: float = 0.05,
    random_state: int = 42,
) -> Tuple[pathlib.Path, pathlib.Path]:
    """Load session vectors from a JSON file, train an Isolation Forest, and save artifacts.

    Parameters
    ----------
    dataset_file : Path | str
        Path to JSON file containing Module 2 session vectors.
    target_dir : Path | str
        Destination directory to save model and metadata.
    is_production_validated : bool, default False
        Must be True only if training on verified production honeypot data.
    contamination : float, default 0.05
        Contamination rate.
    random_state : int, default 42
        Random state seed.

    Returns
    -------
    tuple[Path, Path]
        Paths to the saved model and metadata files.
    """
    loader = DatasetLoader()
    sessions = loader.load_module2_session_vectors(dataset_file)

    model, metadata = train_isolation_forest(
        sessions=sessions,
        contamination=contamination,
        random_state=random_state,
        data_source_description=str(dataset_file),
        is_production_validated=is_production_validated,
    )

    return save_anomaly_model(model, metadata, target_dir)


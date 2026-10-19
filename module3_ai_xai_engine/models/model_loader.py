"""
Model loader module for the AI Decision & XAI Engine.

Handles serialization, deserialization, and integrity validation for
trained anomaly detection models (Isolation Forest) and their associated metadata.
"""

import json
import pathlib
from typing import Any, Dict, Tuple
import joblib
from sklearn.ensemble import IsolationForest

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT


def save_anomaly_model(
    model: IsolationForest,
    metadata: Dict[str, Any],
    target_dir: pathlib.Path | str,
    model_filename: str = "anomaly_detector.joblib",
    metadata_filename: str = "anomaly_detector_metadata.json",
) -> Tuple[pathlib.Path, pathlib.Path]:
    """Serialize an Isolation Forest model and its metadata to disk.

    Parameters
    ----------
    model : IsolationForest
        Fitted scikit-learn IsolationForest instance.
    metadata : dict
        Metadata dictionary detailing model configuration, feature order,
        training data provenance, scaler assumptions, and validation status.
    target_dir : pathlib.Path | str
        Destination directory.
    model_filename : str, default "anomaly_detector.joblib"
        Filename for the serialized model artifact.
    metadata_filename : str, default "anomaly_detector_metadata.json"
        Filename for the metadata JSON file.

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path]
        Paths to the saved model file and metadata file.
    """
    dest_path = pathlib.Path(target_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    # Validate feature metadata before saving
    if metadata.get("feature_count") != MODULE2_FEATURE_COUNT:
        raise ValueError(
            f"Metadata feature_count must be {MODULE2_FEATURE_COUNT}, "
            f"got {metadata.get('feature_count')}."
        )

    if metadata.get("feature_names") != list(MODULE2_CANONICAL_FEATURE_NAMES):
        raise ValueError("Metadata feature_names do not match canonical Module 2 feature ordering.")

    model_path = dest_path / model_filename
    metadata_path = dest_path / metadata_filename

    # Save binary artifact
    joblib.dump(model, model_path)

    # Save JSON metadata
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return model_path, metadata_path


def load_anomaly_model(
    target_dir: pathlib.Path | str,
    model_filename: str = "anomaly_detector.joblib",
    metadata_filename: str = "anomaly_detector_metadata.json",
) -> Tuple[IsolationForest, Dict[str, Any]]:
    """Load and validate an Isolation Forest model and its metadata from disk.

    Parameters
    ----------
    target_dir : pathlib.Path | str
        Directory containing the model and metadata artifacts.
    model_filename : str, default "anomaly_detector.joblib"
        Filename of the serialized model.
    metadata_filename : str, default "anomaly_detector_metadata.json"
        Filename of the metadata JSON file.

    Returns
    -------
    tuple[IsolationForest, dict]
        The loaded IsolationForest model and validated metadata dictionary.

    Raises
    ------
    FileNotFoundError
        If either the model file or the metadata file does not exist.
    ValueError
        If the metadata is corrupted or indicates incompatible feature order/count.
    """
    src_path = pathlib.Path(target_dir)
    model_path = src_path / model_filename
    metadata_path = src_path / metadata_filename

    if not model_path.is_file():
        raise FileNotFoundError(f"Anomaly model artifact not found at: {model_path.resolve()}")

    if not metadata_path.is_file():
        raise FileNotFoundError(f"Anomaly model metadata not found at: {metadata_path.resolve()}")

    # Load and validate metadata
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception as exc:
        raise ValueError(f"Failed to parse anomaly model metadata JSON: {exc}") from exc

    # Integrity verification
    if metadata.get("feature_count") != MODULE2_FEATURE_COUNT:
        raise ValueError(
            f"Incompatible model: feature_count {metadata.get('feature_count')} != {MODULE2_FEATURE_COUNT}"
        )

    if metadata.get("feature_names") != list(MODULE2_CANONICAL_FEATURE_NAMES):
        raise ValueError("Incompatible model: feature_names do not match Module 2 canonical sequence.")

    # Load model artifact
    try:
        model = joblib.load(model_path)
    except Exception as exc:
        raise ValueError(f"Failed to deserialize model artifact with joblib: {exc}") from exc

    if not isinstance(model, IsolationForest):
        raise ValueError(f"Expected IsolationForest model artifact, got {type(model).__name__}")

    return model, metadata

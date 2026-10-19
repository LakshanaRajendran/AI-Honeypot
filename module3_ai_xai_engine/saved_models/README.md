# Saved Models Directory

This directory stores trained model artifacts and associated metadata for Module 3 (AI Decision & XAI Engine).

## Anomaly Detection Model Specification (Module 2 Integration)

When trained on verified production data, the Isolation Forest anomaly detector generates two companion artifacts:

1. `anomaly_detector.joblib`: Serialized `sklearn.ensemble.IsolationForest` estimator trained on the canonical 26-feature session vectors.
2. `anomaly_detector_metadata.json`: Specification document detailing:
   * `model_version`: Model version identifier (e.g. `1.0.0-anomaly-iforest`).
   * `model_type`: Algorithm name (`IsolationForest`).
   * `feature_count`: Strictly 26.
   * `feature_names`: Exact sequence matching `MODULE2_CANONICAL_FEATURE_NAMES`.
   * `scaler_assumptions`: Upstream standardized z-scores; no secondary scaling.
   * `training_data_source`: Provenance of training sessions.
   * `is_production_validated`: Boolean flag indicating if verified honeypot sessions were used.
   * `score_semantics`: `anomaly_score = -decision_function(X)`. Higher values indicate greater isolation. Boundary at `0.0`. Not a probability.
   * `reference_statistics`: Baseline means and standard deviations for transparent deviation explanations (populated only when genuine data exists).

## Current Status

> **NOTE:** Genuine 26-feature training vectors from Module 2's full Cowrie run are currently pending upstream generation. In accordance with project integrity constraints, no dummy or synthetic model artifact is saved here as a production model.

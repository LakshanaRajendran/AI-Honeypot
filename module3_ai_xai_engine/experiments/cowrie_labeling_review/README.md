# Cowrie Labeling Review Dataset

Generated on: 2026-10-19
Location: `experiments/cowrie_labeling_review/`

## Overview
This dataset contains 1000 unique command-bearing Cowrie honeypot sessions extracted incrementally from `data/raw/logs/` and featurized into Module 2's canonical 26-feature specification.

## Provenance and Safeguards
- **NOT Production-Validated:** These labels are rule-derived provisional heuristics for research review.
- **Strict Canonical Interface:** The 26 numerical features adhere to `MODULE2_CANONICAL_FEATURE_NAMES` in exact sequence.
- **Scaler Isolation:** The `StandardScaler` was fitted strictly on the 80% training split (797 sessions); the held-out test split (200 sessions) was transformed without data leakage.
- **Label Separation:** Targets (`is_weaponized_intrusion`, multi-label intents) are strictly segregated from the 26 numeric features.

## Files
- `dataset_labeled_full.csv`: Full 1000 extracted sessions with 26 unscaled features and provisional labels.
- `train_sessions.json`: 797 training sessions formatted as `Module2SessionPayload` with z-score standardized vectors.
- `test_sessions.json`: 200 test sessions formatted as `Module2SessionPayload`.
- `label_evidence.json`: Command matches and rule audit log for every session.
- `cowrie_adapter_scaler.joblib`: Serialized `StandardScaler` fitted on training split only.
- `cowrie_adapter_scaler_metadata.json`: Means, scales, and constant feature records.
- `extraction_summary.json`: Detailed numeric counts and distributions.

# Module 3 Two-Output Model (v1)

Generated on: 2026-10-19  
Artifact Directory: `experiments/two_output_model_v1/`

## Engine Specification
Provides both required outputs for Module 3:
1. **Output A: Binary Classification (`is_weaponized_intrusion`)**
   - High-threat / active weaponization vs. low-interaction probing.
   - Evaluated with precision, recall, F1, and PR-AUC.
2. **Output B: Multi-Label Attacker Intent (`reconnaissance`, `execution`, `persistence`, `defense_evasion`)**
   - Predicts multiple concurrent tactical attacker behaviors.
   - **`credential_access` is marked UNSUPPORTED** due to extreme scarcity ($N=3$).

## Artifacts
- `binary_weaponization_model.joblib`: Trained binary Random Forest classifier.
- `multilabel_intent_model.joblib`: Trained multi-output Random Forest classifier.
- `cowrie_adapter_scaler.joblib`: Frozen training-split `StandardScaler`.
- `model_metadata.json`: Complete specification, feature order, hyperparameters, and disclosures.
- `evaluation_report.json`: Metrics breakdown.

## Honest Disclosures
- **Not Ground Truth:** Labels are rule-derived behavioral targets.
- **Archetype Repetition:** High test scores are influenced by identical bot scripts across sessions.

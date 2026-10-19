# Module 3: AI Decision & Explainability (XAI) Engine

## 1. Overview and Role
Module 3 serves as the **AI Decision and Explainability Engine** for the honeypot pipeline. It ingests session feature vectors from Module 2, evaluates threat characteristics using trained machine learning models, produces structured decision outputs (binary threat classification and multi-label attacker intent), provides transparent feature-deviation explanations, and exposes an optional auxiliary anomaly signal for downstream consumption by Module 4.

---

## 2. Directory Structure
The directory structure corresponds to the actual implementation in `module3_ai_xai_engine`:

```
module3_ai_xai_engine/
├── config.py                               # Engine configuration & canonical 26-feature constants
├── main.py                                 # Pipeline entry point
├── README.md                               # Handover documentation
├── requirements.txt                        # Pinned runtime dependencies
├── TODO.md                                 # Implementation tracking notes
├── .gitignore                              # Git exclusion rules
├── data/
│   └── processed/
│       ├── test_dataset.csv                # Processed test split (embeddings + session features)
│       └── training_dataset.csv            # Processed training split (embeddings + session features)
├── experiments/
│   ├── cowrie_labeling_review/             # Training datasets, scalers & provisional labeling audit
│   │   ├── AUDIT_AND_TRAINING_DECISION.md  # Training decisions & data provenance report
│   │   ├── cowrie_adapter_scaler.joblib    # StandardScaler fitted strictly on training partition
│   │   ├── cowrie_adapter_scaler_metadata.json
│   │   ├── dataset_labeled_full.csv        # Full labeled session dataset (1,000 sessions)
│   │   ├── extraction_summary.json
│   │   ├── label_evidence.json             # Rule matches per session
│   │   ├── README.md
│   │   ├── test_dataset.csv                # 200-session test partition
│   │   ├── test_sessions.json              # Canonical 26-feature test payload fixtures
│   │   ├── train_dataset.csv               # 800-session train partition
│   │   └── train_sessions.json             # Canonical 26-feature train payload fixtures
│   ├── final_module3_audit/
│   │   ├── FINAL_MODULE3_REPORT.md         # Comprehensive audit & validation findings
│   │   ├── run_validation_audit.py         # Leakage benchmark & holdout validation script
│   │   └── validation_audit_results.json   # Machine-readable audit results
│   └── two_output_model_v1/                # Active inference artifacts
│       ├── binary_weaponization_model.joblib # Supervised Random Forest for Output A
│       ├── cowrie_adapter_scaler.joblib    # Training-set scaler for inference
│       ├── evaluation_report.json          # Metrics on test partition
│       ├── model_metadata.json             # Artifact provenance & supported intents metadata
│       ├── multilabel_intent_model.joblib  # MultiOutput Random Forest for Output B
│       └── README.md
├── explainability/
│   ├── __init__.py
│   ├── explanation_formatter.py            # Formatter for human-readable disclosures
│   ├── shap_explainer.py                   # TreeExplainer helper
│   └── visualization.py                    # Visualization utility functions
├── inference/
│   └── __init__.py
├── models/
│   ├── __init__.py
│   ├── attack_detector.pkl                 # Legacy attack classification model
│   ├── classifier.py                       # Base classifier interface
│   ├── model_loader.py                     # Serializer and validator for Isolation Forest models
│   ├── predictor.py                        # AnomalyPredictor (Isolation Forest outlier detection)
│   └── two_output_predictor.py             # TwoOutputPredictor (Output A, Output B & disclosures)
├── preprocessing/
│   ├── __init__.py
│   ├── combiner.py                         # Vector concatenation utility
│   ├── scaler.py                           # Scaler utility
│   └── validator.py                        # Module2InputValidator (strict 26-feature validation)
├── saved_models/
│   └── README.md                           # Model storage conventions
├── schemas/
│   ├── __init__.py
│   ├── decision_object.py                  # Legacy decision schema
│   ├── explanation_schema.py               # Feature explanation schema
│   ├── feature_object.py                   # Module2SessionPayload Pydantic schema
│   ├── input_schema.py                     # Legacy 12-feature input schema
│   ├── prediction_schema.py                # UnifiedModule3Result and output sub-models
│   └── training_schema.py                  # Training data container schema
├── tests/
│   ├── __init__.py
│   ├── test_anomaly_detector.py            # 12 tests for Isolation Forest engine
│   ├── test_cowrie_adapter.py              # 6 tests for telemetry adapter & scaler
│   ├── test_module2_input.py               # 13 tests for 26-feature input validation
│   └── test_two_output_engine.py           # 6 tests for two-output inference engine
├── training/
│   ├── __init__.py
│   ├── behavior_embedding.py               # Command token Word2Vec embedding builder
│   ├── build_training_dataset.py           # Training dataset assembler
│   ├── cowrie_adapter.py                   # Incremental JSONL telemetry streamer & extractor
│   ├── dataset_loader.py                   # Pass-through loader for Module 2 JSON files
│   ├── evaluate_model.py                   # Evaluation utility
│   ├── extract_provisional_dataset.py      # Session extraction from Cowrie logs
│   ├── feature_extractor.py                # Feature extraction utility
│   ├── parse_cowrie.py                     # Telemetry parsing helpers
│   ├── provisional_labeler.py              # Rule-based behavioral labeling engine
│   ├── session_builder.py                  # Session aggregation utility
│   ├── shap_explainer.py                   # Interactive SHAP explanation script
│   ├── train_anomaly_detector.py           # Isolation Forest training script
│   ├── train_model.py                      # Model training entry point
│   └── train_two_output_models.py          # Two-output Random Forest training script
└── utils/
    ├── __init__.py
    ├── helpers.py                          # General utilities
    └── logger.py                           # Engine logging configuration
```

---

## 3. Module 2 Input Contract
Module 3 ingests session payloads generated by Module 2 conforming to `feature_schema.json` and serialized as `feature_vector.json`.

### Canonical 26-Feature Specification
Input ingestion is enforced by `Module2SessionPayload` (`schemas/feature_object.py`) and `Module2InputValidator` (`preprocessing/validator.py`). Features must appear in the exact sequence specified by `MODULE2_CANONICAL_FEATURE_NAMES`:

1. `total_events`
2. `command_count`
3. `unique_commands`
4. `unique_processes`
5. `unique_mitre_tactics`
6. `unique_mitre_techniques`
7. `session_duration_seconds`
8. `mean_inter_event_seconds`
9. `std_inter_event_seconds`
10. `min_inter_event_seconds`
11. `max_inter_event_seconds`
12. `commands_per_minute`
13. `network_utility_ratio`
14. `file_inspection_ratio`
15. `identity_command_ratio`
16. `credential_keyword_ratio`
17. `download_utility_ratio`
18. `mean_risk_score`
19. `max_risk_score`
20. `risk_score_std`
21. `high_or_critical_ratio`
22. `path_command_ratio`
23. `pipe_ratio`
24. `redirect_ratio`
25. `mean_command_length`
26. `mean_argument_count`

### Ingestion and Validation Behavior
- **Pass-Through Guarantee:** Normalized vectors in `feature_vector` pass through directly without secondary re-scaling. If unscaled `raw_features` are supplied, they are scaled using the frozen training scaler (`experiments/two_output_model_v1/cowrie_adapter_scaler.joblib`).
- **Strict Validation:** Rejects non-numeric types, booleans, strings, nulls, `NaN`, `Inf`, empty or whitespace session IDs, or feature counts $\ne 26$.

---

## 4. Prediction Outputs and Explanation Capabilities
The primary inference engine is `TwoOutputPredictor` (`models/two_output_predictor.py`), which loads artifacts from `experiments/two_output_model_v1` and outputs `UnifiedModule3Result` (`schemas/prediction_schema.py`):

### Output A: Binary Threat Classification
- `predicted_class`: `0` (`low_interaction_probe`) or `1` (`weaponized_intrusion`).
- `predicted_label`: Categorical label string.
- `confidence`: Estimated probability in `[0.0, 1.0]`.
- `classification_basis`: `"supervised_random_forest_on_provisional_targets"`.

### Output B: Multi-Label Attacker Intent
- `detected_intents`: Attacker tactical intents detected above classification threshold.
- `intent_scores`: Per-category confidence scores for supported categories:
  - `reconnaissance`
  - `execution`
  - `persistence`
  - `defense_evasion`
- `unsupported_intents`: `["credential_access"]` (explicitly excluded from ML scoring due to insufficient positive sample support).

### Auxiliary Signal: Anomaly Detection (Optional)
- `anomaly_score`: Inverted Isolation Forest decision function score (higher indicates greater geometric isolation).
- `is_anomaly`: Boolean outlier flag.

### Transparent Feature-Deviation Explanations
- Explanations identify individual features whose standardized values deviate significantly ($|z| \ge 2.0$) from the training set baseline mean and standard deviation.
- Reports `feature_name`, `observed_value`, `reference_mean`, `reference_std`, `deviation_score`, and a neutral description without attributing unverified intent.

---

## 5. Setup and Execution Instructions (Windows PowerShell)

### Step 1: Set Working Directory to Module 3
Execute all commands from `module3_ai_xai_engine` to ensure relative artifact paths resolve properly:
```powershell
cd D:\MINIPROJECT\AI-Honeypot\module3_ai_xai_engine
```

### Step 2: Create and Activate Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Run Tests
```powershell
python -m unittest discover tests
```

---

## 6. Verified Test Status
In the isolated handover environment, **37 tests passed (100%)**:

- `tests/test_module2_input.py`: **13 tests passed** &mdash; 26-feature validation, ordering, pass-through loader, rejection of malformed types, NaNs, and Infs.
- `tests/test_anomaly_detector.py`: **12 tests passed** &mdash; Isolation Forest training, metadata serialization, decision boundary scoring, and fixture isolation.
- `tests/test_cowrie_adapter.py`: **6 tests passed** &mdash; Streaming JSONL telemetry ingestion, command filtering, tokenization, and scaler consistency.
- `tests/test_two_output_engine.py`: **6 tests passed** &mdash; Output A binary prediction, Output B multi-label prediction, `credential_access` unsupported check, invalid payload rejection, and determinism.

> [!NOTE]
> Passing all 37 tests confirms that the implemented software pipeline, schema validators, artifact loaders, and inference paths function as designed. Test success does not establish generalization across unobserved attack traffic or readiness for production deployment.

---

## 7. Known Limitations and Technical Boundaries

1. **Provisional Behavioral Target Labels:**
   Output A classifies sessions between low-interaction probing (`uname -a`, discovery) and active weaponization (dropper downloads, persistence commands) based on deterministic rule heuristics. It is not an absolute "malicious vs. benign" verdict, as all public honeypot traffic is unauthorized.
2. **Excluded Intent Category (`credential_access`):**
   Across the 1,000-session honeypot dataset, `credential_access` appeared in only 3 sessions (0.3% support). Supervised learning cannot reliably model this category; it is explicitly declared in `unsupported_intents` and omitted from ML scores.
3. **Feature-Label Circularity:**
   The canonical 26 features include 6 heuristic risk and MITRE score aggregates (`mean_risk_score`, `high_or_critical_ratio`, etc.) that partly rely on keyword matching, which overlaps with the provisional labeling rules.
4. **Generalization to Unseen Attack Archetypes:**
   High performance on random 80/20 train/test splits reflects identical botnet scripts repeating across partitions. In a dedicated audit experiment where specific command archetypes were held out entirely from training (e.g., Mirai droppers using `/bin/busybox cat /proc/self/exe`), the model predicted probing for all 54 held-out sessions (0% accuracy under those specific audit conditions). The models recognize learned campaign archetypes rather than generalizing universally to novel exploit structures.

---

## 8. Intended Module 4 Handover Interface
Module 4 (Response & Mitigation Engine) will consume `UnifiedModule3Result` produced by `TwoOutputPredictor`. **Module 4 integration is not yet complete**, as Module 4 ingestion code has not yet been implemented in the repository.

### Illustrative Integration Example
The following snippet illustrates how Module 4 is intended to interface with Module 3:

```python
from models.two_output_predictor import TwoOutputPredictor
from schemas.feature_object import Module2SessionPayload

# 1. Initialize predictor
predictor = TwoOutputPredictor(model_dir="experiments/two_output_model_v1")

# 2. Ingest valid Module 2 payload (illustrative fixture)
payload = Module2SessionPayload(
    session_id="session_sample_01",
    feature_count=26,
    feature_vector=[0.1] * 26,
)

# 3. Execute inference
result = predictor.predict_session(payload)

# 4. Access structured outputs
print("Session:", result.session_id)
print("Classification:", result.classification.predicted_label)
print("Confidence:", result.classification.confidence)
print("Detected Intents:", result.intent.detected_intents)
print("Intent Scores:", result.intent.intent_scores)
```

### Illustrative Output Payload (`UnifiedModule3Result`)
*(Note: Values below are synthetic illustrative placeholders representing schema structure, not live inference results.)*

```json
{
  "session_id": "session_sample_01",
  "classification": {
    "predicted_class": 1,
    "predicted_label": "weaponized_intrusion",
    "confidence": 0.985,
    "classification_basis": "supervised_random_forest_on_provisional_targets"
  },
  "intent": {
    "detected_intents": ["execution", "persistence"],
    "intent_scores": {
      "reconnaissance": 0.05,
      "execution": 0.94,
      "persistence": 0.88,
      "defense_evasion": 0.12
    },
    "unsupported_intents": ["credential_access"],
    "intent_basis": "multi_output_random_forest_on_provisional_targets"
  },
  "anomaly": null,
  "explanations": [
    {
      "feature_name": "download_utility_ratio",
      "observed_value": 0.5,
      "reference_mean": 0.02,
      "reference_std": 0.11,
      "deviation_score": 4.36,
      "description": "Feature 'download_utility_ratio' deviates by 4.36 standard deviations from training baseline."
    }
  ],
  "label_provenance": "provisional_rule_derived_behavioral_targets",
  "limitations": [
    "PROVISIONAL TARGET LABELS: Targets were derived via deterministic rule patterns...",
    "BOTNET REPETITION OVERLAP: Predictions are evaluated on known honeypot botnet archetypes...",
    "UNSUPPORTED INTENT: 'credential_access' has only 3 positive cases across 1,000 sessions..."
  ]
}
```

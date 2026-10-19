"""
Experimental Training Pipeline for Module 3 Two-Output Engine.

Trains:
1. Output A: Supervised Binary Classifier (`is_weaponized_intrusion`).
2. Output B: Supervised Multi-Label Intent Predictor for supported intents:
   ['reconnaissance', 'execution', 'persistence', 'defense_evasion'].
   Note: 'credential_access' is explicitly excluded from supervised training due to
   insufficient support (3 positive examples in 1,000 sessions).

Enforces:
- Exact 26-feature canonical sequence.
- Consistent application of the training-only scaler.
- Honest, leakage-aware evaluation reporting per-class metrics, confusion matrix, and PR-AUC.
- Complete artifact isolation under `experiments/two_output_model_v1/`.
"""

import json
import os
import pathlib
import sys

_project_root = pathlib.Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from typing import Any, Dict, List, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.multioutput import MultiOutputClassifier
from sklearn.preprocessing import StandardScaler

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from training.cowrie_adapter import load_adapter_scaler

SUPPORTED_INTENTS = ["reconnaissance", "execution", "persistence", "defense_evasion"]
UNSUPPORTED_INTENTS = ["credential_access"]


def train_and_evaluate_two_output_engine(
    review_dir: pathlib.Path,
    output_dir: pathlib.Path,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train experimental models, evaluate with honest metrics, and persist artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load Datasets and Training Scaler
    train_df = pd.read_csv(review_dir / "train_dataset.csv")
    test_df = pd.read_csv(review_dir / "test_dataset.csv")
    scaler, scaler_meta = load_adapter_scaler(review_dir)

    print(f"Loaded {len(train_df)} training sessions and {len(test_df)} test sessions.")

    # 2. Extract Features (Unscaled) and Scale with Frozen Training Scaler
    X_train_raw = train_df[list(MODULE2_CANONICAL_FEATURE_NAMES)].values.astype(float)
    X_test_raw = test_df[list(MODULE2_CANONICAL_FEATURE_NAMES)].values.astype(float)

    X_train = scaler.transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

    # 3. Model A: Binary Classifier (is_weaponized_intrusion)
    y_train_binary = train_df["is_weaponized_intrusion"].values.astype(int)
    y_test_binary = test_df["is_weaponized_intrusion"].values.astype(int)

    clf_binary = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    clf_binary.fit(X_train, y_train_binary)

    # Evaluate Binary Classifier
    y_pred_binary = clf_binary.predict(X_test)
    y_prob_binary = clf_binary.predict_proba(X_test)[:, 1]

    cm_binary = confusion_matrix(y_test_binary, y_pred_binary).tolist()
    binary_metrics = {
        "confusion_matrix": {
            "tn": cm_binary[0][0],
            "fp": cm_binary[0][1],
            "fn": cm_binary[1][0],
            "tp": cm_binary[1][1],
        },
        "class_0_probing": {
            "precision": float(precision_score(y_test_binary, y_pred_binary, pos_label=0)),
            "recall": float(recall_score(y_test_binary, y_pred_binary, pos_label=0)),
            "f1": float(f1_score(y_test_binary, y_pred_binary, pos_label=0)),
            "support": int(np.sum(y_test_binary == 0)),
        },
        "class_1_weaponized": {
            "precision": float(precision_score(y_test_binary, y_pred_binary, pos_label=1)),
            "recall": float(recall_score(y_test_binary, y_pred_binary, pos_label=1)),
            "f1": float(f1_score(y_test_binary, y_pred_binary, pos_label=1)),
            "support": int(np.sum(y_test_binary == 1)),
        },
        "macro_f1": float(f1_score(y_test_binary, y_pred_binary, average="macro")),
        "pr_auc": float(average_precision_score(y_test_binary, y_prob_binary)),
        "roc_auc": float(roc_auc_score(y_test_binary, y_prob_binary)),
        "brier_score": float(brier_score_loss(y_test_binary, y_prob_binary)),
    }

    print("Binary Classification Results:")
    print(f"  Macro F1: {binary_metrics['macro_f1']:.4f}")
    print(f"  Weaponized Recall: {binary_metrics['class_1_weaponized']['recall']:.4f}")
    print(f"  PR-AUC: {binary_metrics['pr_auc']:.4f}")

    # 4. Model B: Multi-Label Intent Predictor (Supported Intents Only)
    Y_train_intents = train_df[SUPPORTED_INTENTS].values.astype(int)
    Y_test_intents = test_df[SUPPORTED_INTENTS].values.astype(int)

    base_intent_rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    clf_intent = MultiOutputClassifier(base_intent_rf, n_jobs=-1)
    clf_intent.fit(X_train, Y_train_intents)

    # Evaluate Intent Predictor
    Y_pred_intents = clf_intent.predict(X_test)

    intent_metrics = {}
    f1_list = []
    for idx, intent_name in enumerate(SUPPORTED_INTENTS):
        y_true_col = Y_test_intents[:, idx]
        y_pred_col = Y_pred_intents[:, idx]
        pos_cnt = int(np.sum(y_true_col == 1))

        prec = float(precision_score(y_true_col, y_pred_col, zero_division=0))
        rec = float(recall_score(y_true_col, y_pred_col, zero_division=0))
        f1 = float(f1_score(y_true_col, y_pred_col, zero_division=0))
        f1_list.append(f1)

        intent_metrics[intent_name] = {
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "support": pos_cnt,
            "status": "SUPPORTED_TRAINED",
        }

    intent_summary = {
        "supported_intents": intent_metrics,
        "unsupported_intents": {
            name: {
                "status": "UNSUPPORTED_INSUFFICIENT_DATA",
                "reason": "Only 3 positive instances out of 1,000 sessions (0.3% support). Cannot reliably train or evaluate.",
            }
            for name in UNSUPPORTED_INTENTS
        },
        "macro_f1_supported": float(np.mean(f1_list)),
    }

    print("Multi-Label Intent Results:")
    print(f"  Macro F1 (Supported): {intent_summary['macro_f1_supported']:.4f}")
    for name, m in intent_metrics.items():
        print(f"  - {name}: F1={m['f1']:.4f}, Recall={m['recall']:.4f}, Support={m['support']}")

    # 5. Persist Model Artifacts and Scaler in experiments/two_output_model_v1/
    joblib.dump(clf_binary, output_dir / "binary_weaponization_model.joblib")
    joblib.dump(clf_intent, output_dir / "multilabel_intent_model.joblib")
    joblib.dump(scaler, output_dir / "cowrie_adapter_scaler.joblib")

    # Metadata
    metadata = {
        "model_version": "1.0.0-two-output-v1",
        "timestamp": "2026-10-19",
        "provenance": "experimental_provisional_label_pipeline",
        "is_production_validated": False,
        "feature_count": MODULE2_FEATURE_COUNT,
        "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
        "random_state": random_state,
        "models": {
            "binary_model": {
                "algorithm": "RandomForestClassifier",
                "hyperparameters": {"n_estimators": 100, "max_depth": 6, "class_weight": "balanced"},
                "target": "is_weaponized_intrusion",
                "metrics": binary_metrics,
            },
            "intent_model": {
                "algorithm": "MultiOutputClassifier(RandomForestClassifier)",
                "hyperparameters": {"n_estimators": 100, "max_depth": 6, "class_weight": "balanced"},
                "supported_targets": SUPPORTED_INTENTS,
                "unsupported_targets": UNSUPPORTED_INTENTS,
                "metrics": intent_summary,
            },
        },
        "scaler_assumptions": (
            "pre_standardized_by_training_split_of_cowrie_labeling_review; "
            "fitted_strictly_on_train_set; no double scaling."
        ),
        "disclosures_and_limitations": [
            "PROVISIONAL TARGET LABELS: Labels were assigned via deterministic rule patterns and do not represent verified external ground truth.",
            "BOTNET REPETITION OVERLAP: 100% of test command sequences overlap with training command archetypes; metrics reflect recognition within known campaigns rather than out-of-distribution generalization.",
            "FEATURE-LABEL CIRCULARITY: The 26 canonical features include heuristic risk/MITRE scores that partly share keywords with the labeling rules.",
            "UNSUPPORTED INTENT: 'credential_access' has only 3 positive cases and is omitted from the ML model.",
        ],
    }

    with open(output_dir / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    with open(output_dir / "evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump({"binary": binary_metrics, "intent": intent_summary}, f, indent=2)

    readme_content = f"""# Module 3 Two-Output Model (v1)

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
"""
    with open(output_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)

    print(f"Artifacts successfully saved to: {output_dir}")
    return metadata


if __name__ == "__main__":
    review_dir = pathlib.Path("experiments/cowrie_labeling_review")
    output_dir = pathlib.Path("experiments/two_output_model_v1")
    train_and_evaluate_two_output_engine(review_dir, output_dir)


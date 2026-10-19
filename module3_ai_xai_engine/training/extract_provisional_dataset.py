"""
Dataset Extraction and Provisional Labeling Pipeline for Module 3.

Executes:
1. Streaming extraction of up to 1,000 unique command-bearing Cowrie honeypot sessions.
2. Canonical 26-feature computation via CowrieSessionAdapter.
3. Auditable provisional labeling (binary weaponized vs probing, and multi-label intent).
4. Data-quality validation (constant features, extremes, label distributions).
5. Train/test partition split (80/20) and StandardScaler fitting on train set only.
6. Artifact persistence under `experiments/cowrie_labeling_review/`.
"""

import hashlib
import json
import os
import pathlib
import sys

_project_root = pathlib.Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from typing import Any, Dict, List, Set, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from preprocessing.validator import Module2InputValidator
from schemas.feature_object import Module2SessionPayload
from training.cowrie_adapter import (
    CowrieSessionAdapter,
    parse_iso_timestamp,
    save_adapter_scaler,
)
from training.provisional_labeler import ProvisionalLabeler


def extract_and_build_dataset(
    raw_data_dir: pathlib.Path,
    output_dir: pathlib.Path,
    max_sessions: int = 1000,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Run full bounded extraction, labeling, validation, and splitting."""
    output_dir.mkdir(parents=True, exist_ok=True)
    adapter = CowrieSessionAdapter(enable_heuristic_enrichment=True)
    labeler = ProvisionalLabeler()
    validator = Module2InputValidator()

    # 1. Discover all Cowrie JSON files
    candidate_files = sorted(list(raw_data_dir.rglob("cowrie.json*")))
    json_files = [f for f in candidate_files if not f.name.endswith(".log") and not f.name.endswith(".zip")]

    # Statistics tracking
    stats = {
        "files_inspected": len(json_files),
        "source_files": [str(f.relative_to(raw_data_dir.parent)) for f in json_files[:15]],
        "total_lines_read": 0,
        "malformed_lines": 0,
        "skipped_records_no_session": 0,
        "duplicate_session_fragments_merged": 0,
    }

    command_sessions_dict: Dict[str, Dict[str, Any]] = {}
    seen_session_files: Dict[str, Set[str]] = {}

    print(f"Streaming up to {max_sessions} unique command-bearing sessions across {len(json_files)} files...")

    for file_path in json_files:
        if len(command_sessions_dict) >= max_sessions:
            break

        file_has_sessions = False
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                stats["total_lines_read"] += 1
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed_lines"] += 1
                    continue

                if not isinstance(record, dict):
                    continue

                sess_id = record.get("session")
                if not sess_id or not isinstance(sess_id, str) or not sess_id.strip():
                    stats["skipped_records_no_session"] += 1
                    continue

                event_id = record.get("eventid", "")
                is_cmd_event = event_id in ("cowrie.command.input", "cowrie.command.failed") or "input" in record
                cmd_input = record.get("input") if is_cmd_event else None

                # Only initialize or update session if it is already known or if it has a command
                if sess_id not in command_sessions_dict:
                    if not (is_cmd_event and isinstance(cmd_input, str)):
                        continue
                    if len(command_sessions_dict) >= max_sessions:
                        break
                    command_sessions_dict[sess_id] = {
                        "session_id": sess_id,
                        "commands": [],
                        "timestamps": [],
                        "event_count": 0,
                    }
                    seen_session_files[sess_id] = set()
                else:
                    if str(file_path) not in seen_session_files[sess_id]:
                        stats["duplicate_session_fragments_merged"] += 1

                seen_session_files[sess_id].add(str(file_path))
                sess_info = command_sessions_dict[sess_id]
                sess_info["event_count"] += 1

                ts = parse_iso_timestamp(record.get("timestamp"))
                if ts:
                    sess_info["timestamps"].append(ts)

                if is_cmd_event and isinstance(cmd_input, str):
                    sess_info["commands"].append(cmd_input)

    # Filter to only command-bearing sessions and cap strictly at max_sessions
    command_sessions = [s for s in command_sessions_dict.values() if len(s["commands"]) >= 1][:max_sessions]

    print(f"Extracted {len(command_sessions)} unique command-bearing sessions.")

    # 2. Featurize and Label each session
    extracted_records = []
    evidence_records = {}
    unscaled_feature_matrix = []

    for sess in command_sessions:
        # Canonical 26 features
        features, provenance = adapter.compute_session_features(sess)
        row_features = [features[name] for name in MODULE2_CANONICAL_FEATURE_NAMES]
        unscaled_feature_matrix.append(row_features)

        # Provisional Labels
        label_res = labeler.label_session(sess["commands"])
        sess_id = sess["session_id"]

        # Anonymize session identifier for external view while keeping auditability
        anonymized_id = f"sess_{hashlib.sha256(sess_id.encode()).hexdigest()[:12]}"

        record_entry = {
            "session_id": sess_id,
            "session_hash": anonymized_id,
            "command_count": len(sess["commands"]),
            "is_weaponized_intrusion": label_res["is_weaponized_intrusion"],
            "reconnaissance": label_res["intents"]["reconnaissance"],
            "credential_access": label_res["intents"]["credential_access"],
            "persistence": label_res["intents"]["persistence"],
            "defense_evasion": label_res["intents"]["defense_evasion"],
            "execution": label_res["intents"]["execution"],
            "commands": sess["commands"],
        }
        # Append canonical features to entry
        for name in MODULE2_CANONICAL_FEATURE_NAMES:
            record_entry[name] = features[name]

        extracted_records.append(record_entry)
        evidence_records[sess_id] = {
            "binary_evidence": label_res["binary_evidence"],
            "intent_evidence": label_res["intent_evidence"],
            "commands": sess["commands"],
        }

    # 3. Create DataFrame and Validate
    df_full = pd.DataFrame(extracted_records)

    # Feature validation
    X_unscaled = np.array(unscaled_feature_matrix, dtype=float)
    assert X_unscaled.shape[1] == MODULE2_FEATURE_COUNT, f"Expected {MODULE2_FEATURE_COUNT} features, got {X_unscaled.shape[1]}"
    assert np.all(np.isfinite(X_unscaled)), "Non-finite values found in feature matrix!"

    # Identify constant features
    feature_stds = np.std(X_unscaled, axis=0)
    constant_features = [
        MODULE2_CANONICAL_FEATURE_NAMES[i]
        for i, std_val in enumerate(feature_stds)
        if std_val == 0.0
    ]

    # Label statistics
    binary_counts = df_full["is_weaponized_intrusion"].value_counts().to_dict()
    resolved_mask = df_full["is_weaponized_intrusion"].isin([0, 1])
    df_resolved = df_full[resolved_mask].copy()
    df_resolved["is_weaponized_intrusion"] = df_resolved["is_weaponized_intrusion"].astype(int)

    intent_counts = {
        col: {
            "positive (1)": int((df_full[col] == 1).sum()),
            "negative / unobserved (0)": int((df_full[col] == 0).sum()),
        }
        for col in ["reconnaissance", "credential_access", "persistence", "defense_evasion", "execution"]
    }

    # 4. Partition Split (80% Train, 20% Test) on Resolved Sessions
    # Stratified by binary label
    train_df, test_df = train_test_split(
        df_resolved,
        test_size=0.20,
        random_state=random_state,
        stratify=df_resolved["is_weaponized_intrusion"],
    )

    # 5. Fit Scaler ONLY on Training Split
    X_train_unscaled = train_df[list(MODULE2_CANONICAL_FEATURE_NAMES)].values.astype(float)
    X_test_unscaled = test_df[list(MODULE2_CANONICAL_FEATURE_NAMES)].values.astype(float)

    scaler = StandardScaler(copy=True, with_mean=True, with_std=True)
    scaler.fit(X_train_unscaled)
    # Zero variance handling: set scale to 1.0
    scaler.scale_ = np.where(scaler.scale_ == 0.0, 1.0, scaler.scale_)

    X_train_scaled = scaler.transform(X_train_unscaled)
    X_test_scaled = scaler.transform(X_test_unscaled)

    # 6. Build Module2SessionPayload instances for train and test splits
    def _build_payloads(sub_df: pd.DataFrame, X_scaled: np.ndarray) -> List[Dict[str, Any]]:
        payload_list = []
        for idx, (_, row) in enumerate(sub_df.iterrows()):
            vector = [float(v) for v in X_scaled[idx]]
            raw_feats = {name: float(row[name]) for name in MODULE2_CANONICAL_FEATURE_NAMES}
            payload = Module2SessionPayload(
                session_id=str(row["session_id"]),
                feature_count=MODULE2_FEATURE_COUNT,
                feature_names=list(MODULE2_CANONICAL_FEATURE_NAMES),
                feature_vector=vector,
                schema_version="1.0",
                sequence=[f"cmd:{c}" for c in row["commands"]],
                raw_features=raw_feats,
            )
            # Strict validator pass
            validator.validate(payload)
            payload_dict = payload.model_dump()
            payload_dict["target_is_weaponized"] = int(row["is_weaponized_intrusion"])
            payload_dict["target_intents"] = {
                "reconnaissance": int(row["reconnaissance"]),
                "credential_access": int(row["credential_access"]),
                "persistence": int(row["persistence"]),
                "defense_evasion": int(row["defense_evasion"]),
                "execution": int(row["execution"]),
            }
            payload_list.append(payload_dict)
        return payload_list

    train_payloads = _build_payloads(train_df, X_train_scaled)
    test_payloads = _build_payloads(test_df, X_test_scaled)

    # 7. Persist Artifacts
    # CSVs
    df_full.to_csv(output_dir / "dataset_labeled_full.csv", index=False)
    train_df.to_csv(output_dir / "train_dataset.csv", index=False)
    test_df.to_csv(output_dir / "test_dataset.csv", index=False)

    # JSON Payloads
    with open(output_dir / "train_sessions.json", "w", encoding="utf-8") as f:
        json.dump(train_payloads, f, indent=2)

    with open(output_dir / "test_sessions.json", "w", encoding="utf-8") as f:
        json.dump(test_payloads, f, indent=2)

    # Label Evidence
    with open(output_dir / "label_evidence.json", "w", encoding="utf-8") as f:
        json.dump(evidence_records, f, indent=2)

    # Scaler Artifacts
    scaler_meta = {
        "scaler_version": "1.0.0-cowrie-provisional-review",
        "provenance": "fitted_strictly_on_train_split_of_cowrie_labeling_review",
        "sample_count_train": len(train_df),
        "sample_count_test": len(test_df),
        "feature_count": MODULE2_FEATURE_COUNT,
        "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
        "constant_features": constant_features,
        "means": {name: float(m) for name, m in zip(MODULE2_CANONICAL_FEATURE_NAMES, scaler.mean_)},
        "scales": {name: float(s) for name, s in zip(MODULE2_CANONICAL_FEATURE_NAMES, scaler.scale_)},
    }
    save_adapter_scaler(scaler, scaler_meta, output_dir)

    # Extraction Summary
    summary = {
        "extraction_stats": stats,
        "total_command_sessions_extracted": len(command_sessions),
        "constant_features": constant_features,
        "binary_label_distribution": {str(k): int(v) for k, v in binary_counts.items()},
        "resolved_sessions_count": len(df_resolved),
        "unresolved_sessions_count": len(df_full) - len(df_resolved),
        "train_set_size": len(train_df),
        "test_set_size": len(test_df),
        "intent_distribution": intent_counts,
        "feature_ordering_verified": list(MODULE2_CANONICAL_FEATURE_NAMES),
    }

    with open(output_dir / "extraction_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # README
    readme_content = f"""# Cowrie Labeling Review Dataset

Generated on: 2026-10-19
Location: `experiments/cowrie_labeling_review/`

## Overview
This dataset contains {len(command_sessions)} unique command-bearing Cowrie honeypot sessions extracted incrementally from `data/raw/logs/` and featurized into Module 2's canonical 26-feature specification.

## Provenance and Safeguards
- **NOT Production-Validated:** These labels are rule-derived provisional heuristics for research review.
- **Strict Canonical Interface:** The 26 numerical features adhere to `MODULE2_CANONICAL_FEATURE_NAMES` in exact sequence.
- **Scaler Isolation:** The `StandardScaler` was fitted strictly on the 80% training split ({len(train_df)} sessions); the held-out test split ({len(test_df)} sessions) was transformed without data leakage.
- **Label Separation:** Targets (`is_weaponized_intrusion`, multi-label intents) are strictly segregated from the 26 numeric features.

## Files
- `dataset_labeled_full.csv`: Full {len(df_full)} extracted sessions with 26 unscaled features and provisional labels.
- `train_sessions.json`: {len(train_df)} training sessions formatted as `Module2SessionPayload` with z-score standardized vectors.
- `test_sessions.json`: {len(test_df)} test sessions formatted as `Module2SessionPayload`.
- `label_evidence.json`: Command matches and rule audit log for every session.
- `cowrie_adapter_scaler.joblib`: Serialized `StandardScaler` fitted on training split only.
- `cowrie_adapter_scaler_metadata.json`: Means, scales, and constant feature records.
- `extraction_summary.json`: Detailed numeric counts and distributions.
"""
    with open(output_dir / "README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)

    print(f"Dataset review artifacts successfully saved to: {output_dir}")
    return summary


if __name__ == "__main__":
    raw_dir = pathlib.Path("data/raw")
    exp_dir = pathlib.Path("experiments/cowrie_labeling_review")
    summary = extract_and_build_dataset(raw_dir, exp_dir, max_sessions=1000)
    print("Execution complete. Summary:")
    print(json.dumps(summary, indent=2))

# Module 2: Telemetry Feature Engineering Engine (TFEE)

Module 2 is responsible for transforming raw honeypot telemetry into a deterministic, numerically stable feature vector suitable for downstream ML and XAI workflows. It does not perform attack classification.

## What Module 2 does

- Reads telemetry from JSON or JSONL input
- Validates required and optional fields
- Cleans malformed records without inventing data
- Groups events by session
- Extracts behavioral features from session activity, commands, processes, risk metadata, and network/file indicators
- Builds a chronological command sequence for later sequence-based modeling
- Encodes features in a fixed order
- Scales features using a saved scaler
- Writes machine-readable feature outputs for Module 3

## What Module 2 does not do

- It does not predict attack labels such as Reconnaissance, Malware, or Brute Force.
- It does not train or classify telemetry into attack categories.
- It does not create synthetic attack labels.

## Input schema

Each telemetry record may include required fields such as:

- timestamp
- session
- source_ip
- command
- process
- risk
- score
- mitre

Optional fields may also appear, including network, file activity, process activity, and authentication telemetry. Missing optional fields are accepted as long as required fields remain valid.

## Processing pipeline

1. Reader
2. Schema validation
3. Cleaning
4. DataFrame construction
5. Feature extraction
6. Session aggregation
7. Behavioral sequence construction
8. Feature encoding
9. Normalization
10. Output writing

## Feature categories

The feature vector focuses on behavior rather than raw text labels:

- Session and activity features
- Command features
- Process features
- Network indicators when present
- File-access indicators when present
- Authentication indicators when present
- Risk and MITRE-derived telemetry features

## Output format

Module 2 writes a feature vector per session in JSON output. The primary output is:

- output/feature_vector.json
- output/feature_schema.json
- output/feature_scaler.joblib

The feature vector is a list of numeric values in a fixed feature order. The schema maps each index to a named feature.

## Scaling policy

The scaler is trained explicitly on development data and saved to disk. Production/inference mode does not silently refit the scaler. Use:

- python -m src.pipeline
- python -m src.pipeline --fit-scaler

## How to run

From the Module2 directory:

python -m src.pipeline

For explicit scaler fitting:

python -m src.pipeline --fit-scaler

## How to test

python -m pytest -q

## Module 2 → Module 3 Interface

Module 2 provides the following artifacts to Module 3:

1. feature_vector.json
   - The normalized numerical feature vector for each session.
   - This is the numeric representation Module 3 consumes.

2. feature_schema.json
   - The mapping between each vector index and the semantic feature name.
   - This defines the feature ordering that Module 3 must preserve.

3. feature_scaler.joblib
   - The fitted scaler created during Module 2 preprocessing.
   - Module 3 must not refit this scaler when consuming inference data.

The intended flow is:

Module 1
→ telemetry.json
→ Module 2
→ feature_vector.json + feature_schema.json + feature_scaler.joblib
→ Module 3

Module 2 never emits attack labels. It only emits behavioral numerical features to be consumed by the classifier.

## Current output contract

The current pipeline writes session-level records to feature_vector.json. Each record contains:

- schema_version
- session_id
- feature_count
- feature_names
- feature_vector
- sequence
- raw_features

The primary numerical artifact for Module 3 is feature_vector. The feature ordering is defined by feature_schema.json and is preserved across training and inference.

## Notes

This pipeline is deterministic, reproducible, and designed to preserve explainable feature names for later SHAP and auditing workflows.



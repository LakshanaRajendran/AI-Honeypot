# Module 2 → Module 3 Handoff

This folder contains the artifacts produced by Module 2 for Module 3 consumption.

## Input

Module 1 emits telemetry JSON records into Module 2. The telemetry contract is the raw telemetry stream and is not passed directly to Module 3.

## Output

Module 2 produces a fixed-length numeric representation for each session:

- feature_vector.json
- feature_schema.json
- feature_scaler.joblib

## Semantics

### feature_vector.json

This file contains the normalized numerical feature vector for each session. It is the artifact Module 3 should consume for inference.

### feature_schema.json

This file maps each vector index to the semantic feature name and description. The ordering in the schema must match the ordering in the vector.

### feature_scaler.joblib

This is the fitted preprocessing artifact created by Module 2. Module 3 must not refit it during inference. Module 3 should load the existing scaler only if it needs to reverse or inspect scaling behavior; it should not retrain or replace it.

## Contract

Module 3 receives:

- a fixed-length numerical vector
- a schema describing index-to-feature mapping
- the saved scaler used by Module 2 preprocessing

Module 3 must preserve feature order exactly as defined by feature_schema.json and must not invent attack labels inside Module 2.

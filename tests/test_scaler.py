import json
import math
from pathlib import Path

import pytest

from src.pipeline import run_pipeline


SCALER_PATH = Path("output/feature_scaler.joblib")


def ensure_scaler_exists():
    if not SCALER_PATH.exists():
        run_pipeline(input_file="data/raw/telemetry.json", mode="fit-scaler")


def test_fit_scaler_saves_file():
    if SCALER_PATH.exists():
        SCALER_PATH.unlink()
    records = run_pipeline(input_file="data/raw/telemetry.json", mode="fit-scaler")
    assert SCALER_PATH.exists(), "Scaler file should be created in fit-scaler mode"
    assert Path("output/feature_vector.json").exists()
    assert isinstance(records, list)
    assert len(records) > 0


def test_inference_requires_scaler():
    ensure_scaler_exists()
    assert SCALER_PATH.exists(), "Precondition: scaler must exist for inference test"
    records = run_pipeline(input_file="data/raw/telemetry.json", mode="inference")
    assert Path("output/feature_vector.json").exists()
    assert len(records) > 0


def test_inference_fails_without_scaler():
    if SCALER_PATH.exists():
        SCALER_PATH.unlink()
    with pytest.raises(RuntimeError):
        run_pipeline(input_file="data/raw/telemetry.json", mode="inference")


def test_feature_vector_matches_schema_contract():
    ensure_scaler_exists()
    schema = json.loads(Path("output/feature_schema.json").read_text(encoding="utf-8"))
    records = json.loads(Path("output/feature_vector.json").read_text(encoding="utf-8"))
    assert isinstance(records, list)
    assert len(records) > 0

    schema_features = schema["features"]
    assert [item["index"] for item in schema_features] == list(range(len(schema_features)))
    assert len({item["name"] for item in schema_features}) == len(schema_features)

    for record in records:
        vector = record["feature_vector"]
        names = record["feature_names"]
        assert len(vector) == len(names)
        assert len(vector) == len(schema_features)
        assert len(set(names)) == len(names)
        assert all(isinstance(value, (int, float)) for value in vector)
        assert all(not math.isnan(float(value)) for value in vector)
        assert all(value is not None for value in vector)


def test_inference_mode_does_not_refit_scaler():
    ensure_scaler_exists()

    before = json.loads(Path("output/feature_vector.json").read_text(encoding="utf-8"))
    run_pipeline(input_file="data/raw/telemetry.json", mode="inference")
    after = json.loads(Path("output/feature_vector.json").read_text(encoding="utf-8"))
    assert len(before) == len(after)
    assert len(before[0]["feature_vector"]) == len(after[0]["feature_vector"])

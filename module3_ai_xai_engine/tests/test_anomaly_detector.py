"""
Unit and integration tests for Module 3 Isolation Forest Anomaly Detection Engine.

Tests cover:
- Training Isolation Forest on 26-feature session vectors.
- Model serialization, deserialization, and metadata integrity checks.
- Inference pipeline, anomaly score calculation, and boundary behavior.
- Transparent feature-deviation explanations and explicit limitations.
- Strict rejection of invalid schemas, malformed features, and non-finite values.
- Isolated smoke-test path guaranteeing temporary fixtures never overwrite production paths.
"""

import json
import math
import pathlib
import tempfile
import unittest
import numpy as np
from pydantic import ValidationError
from sklearn.ensemble import IsolationForest

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from models.model_loader import load_anomaly_model, save_anomaly_model
from models.predictor import AnomalyPredictor
from schemas.feature_object import Module2SessionPayload
from schemas.prediction_schema import AnomalyPredictionResult
from training.train_anomaly_detector import train_and_save_from_file, train_isolation_forest


class TestAnomalyDetectionEngine(unittest.TestCase):
    """Test suite for Module 3 Isolation Forest training, persistence, and inference."""

    def setUp(self):
        """Build standard valid 26-feature test fixtures."""
        # 5 synthetic sessions for testing pipeline plumbing
        self.fixtures = []
        for i in range(5):
            vec = [float(j * 0.1 + i * 0.05) for j in range(MODULE2_FEATURE_COUNT)]
            self.fixtures.append(
                Module2SessionPayload(
                    session_id=f"TEST_SESS_{i:03d}",
                    feature_count=MODULE2_FEATURE_COUNT,
                    feature_names=list(MODULE2_CANONICAL_FEATURE_NAMES),
                    feature_vector=vec,
                    schema_version="1.0",
                )
            )

    # -----------------------------------------------------------------------
    # 1. Training & Schema Validation Tests
    # -----------------------------------------------------------------------

    def test_train_isolation_forest_valid(self):
        """Verify training succeeds on valid 26-feature payloads."""
        model, metadata = train_isolation_forest(
            sessions=self.fixtures,
            contamination=0.1,
            n_estimators=20,
            data_source_description="unit_test_fixtures",
            is_production_validated=False,
        )

        self.assertIsInstance(model, IsolationForest)
        self.assertEqual(metadata["feature_count"], MODULE2_FEATURE_COUNT)
        self.assertEqual(metadata["feature_names"], list(MODULE2_CANONICAL_FEATURE_NAMES))
        self.assertFalse(metadata["is_production_validated"])
        self.assertIn("UNVERIFIED dependency", metadata["scaler_assumptions"])
        self.assertIn("score_semantics", metadata)

    def test_train_empty_sessions_raises(self):
        """Verify training raises ValueError on empty session list."""
        with self.assertRaises(ValueError) as ctx:
            train_isolation_forest(sessions=[])
        self.assertIn("sessions list is empty", str(ctx.exception))

    def test_train_rejects_non_finite_values(self):
        """Verify training rejects NaN and Infinity."""
        bad_fixture = Module2SessionPayload(
            session_id="BAD_SESS",
            feature_count=MODULE2_FEATURE_COUNT,
            feature_names=list(MODULE2_CANONICAL_FEATURE_NAMES),
            feature_vector=[0.0] * 25 + [1.0],
        )
        # Manually alter feature vector to test matrix validation check
        bad_fixture.feature_vector[5] = float("nan")

        with self.assertRaises(Exception):
            train_isolation_forest(sessions=[bad_fixture])

    # -----------------------------------------------------------------------
    # 2. Model Persistence & Metadata Integrity Tests
    # -----------------------------------------------------------------------

    def test_model_save_and_load_roundtrip(self):
        """Verify model and metadata save and load correctly in a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model, metadata = train_isolation_forest(
                sessions=self.fixtures,
                n_estimators=10,
                data_source_description="temp_test",
                is_production_validated=False,
            )

            model_path, meta_path = save_anomaly_model(model, metadata, tmpdir)
            self.assertTrue(model_path.is_file())
            self.assertTrue(meta_path.is_file())

            loaded_model, loaded_meta = load_anomaly_model(tmpdir)
            self.assertEqual(loaded_meta["feature_count"], MODULE2_FEATURE_COUNT)
            self.assertEqual(loaded_meta["feature_names"], list(MODULE2_CANONICAL_FEATURE_NAMES))

            # Test predictions are identical before and after loading
            sample_vec = np.array([self.fixtures[0].feature_vector])
            pred_orig = model.decision_function(sample_vec)
            pred_loaded = loaded_model.decision_function(sample_vec)
            np.testing.assert_array_almost_equal(pred_orig, pred_loaded)

    def test_load_rejects_corrupted_metadata_feature_count(self):
        """Verify loading fails if metadata feature_count doesn't match 26."""
        with tempfile.TemporaryDirectory() as tmpdir:
            model, metadata = train_isolation_forest(sessions=self.fixtures, n_estimators=5)
            model_path, meta_path = save_anomaly_model(model, metadata, tmpdir)

            # Corrupt the metadata file on disk
            with open(meta_path, "r", encoding="utf-8") as f:
                saved_meta = json.load(f)
            saved_meta["feature_count"] = 25
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(saved_meta, f)

            with self.assertRaises(ValueError) as ctx:
                load_anomaly_model(tmpdir)
            self.assertIn("Incompatible model", str(ctx.exception))

    def test_load_nonexistent_directory_raises(self):
        """Verify loading from nonexistent directory raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            load_anomaly_model("D:/nonexistent_directory_12345")

    # -----------------------------------------------------------------------
    # 3. Inference Engine & Prediction Schema Tests
    # -----------------------------------------------------------------------

    def test_inference_valid_session(self):
        """Verify AnomalyPredictor generates valid AnomalyPredictionResult."""
        model, metadata = train_isolation_forest(
            sessions=self.fixtures,
            n_estimators=20,
            is_production_validated=False,
        )
        predictor = AnomalyPredictor(model=model, metadata=metadata)

        result = predictor.predict_session(self.fixtures[0])

        self.assertIsInstance(result, AnomalyPredictionResult)
        self.assertEqual(result.session_id, "TEST_SESS_000")
        self.assertIsInstance(result.anomaly_score, float)
        self.assertIsInstance(result.is_anomaly, bool)
        self.assertIsInstance(result.model_version, str)
        self.assertIsInstance(result.explanations, list)
        self.assertIsInstance(result.limitations, list)

        # Confirm limitation disclosure is present
        limitations_text = " ".join(result.limitations)
        self.assertIn("NOT production-validated", limitations_text)
        self.assertIn("does NOT establish confirmed maliciousness", limitations_text)

    def test_inference_rejects_invalid_feature_count(self):
        """Verify predictor rejects payload with wrong feature length."""
        model, metadata = train_isolation_forest(sessions=self.fixtures, n_estimators=10)
        predictor = AnomalyPredictor(model=model, metadata=metadata)

        bad_dict = {
            "session_id": "BAD_SESSION",
            "feature_count": 25,
            "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES[:25]),
            "feature_vector": [0.1] * 25,
        }

        with self.assertRaises(Exception):
            predictor.predict_session(bad_dict)

    def test_inference_rejects_non_numeric_values(self):
        """Verify predictor rejects payload with string or boolean values."""
        model, metadata = train_isolation_forest(sessions=self.fixtures, n_estimators=10)
        predictor = AnomalyPredictor(model=model, metadata=metadata)

        bad_vec = list(self.fixtures[0].feature_vector)
        bad_vec[0] = "string_value"  # type: ignore

        bad_dict = {
            "session_id": "BAD_SESSION",
            "feature_count": MODULE2_FEATURE_COUNT,
            "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
            "feature_vector": bad_vec,
        }

        with self.assertRaises(Exception):
            predictor.predict_session(bad_dict)

    # -----------------------------------------------------------------------
    # 4. Transparent Feature-Deviation Explanation Tests
    # -----------------------------------------------------------------------

    def test_unvalidated_model_suppresses_misleading_baseline_stats(self):
        """Verify unvalidated models do not invent misleading reference statistics."""
        model, metadata = train_isolation_forest(
            sessions=self.fixtures,
            is_production_validated=False,
        )
        predictor = AnomalyPredictor(model=model, metadata=metadata)

        result = predictor.predict_session(self.fixtures[0])
        self.assertEqual(len(result.explanations), 1)
        self.assertIn("Baseline reference statistics are unavailable", result.explanations[0].description)
        self.assertIsNone(result.explanations[0].reference_mean)

    def test_genuine_reference_computes_transparent_deviations(self):
        """Verify verified models compute transparent deviation scores for extreme features."""
        # Train with is_production_validated=True
        model, metadata = train_isolation_forest(
            sessions=self.fixtures,
            is_production_validated=True,
            data_source_description="verified_test_dataset",
        )
        predictor = AnomalyPredictor(model=model, metadata=metadata)

        # Create an outlier session vector where 'mean_risk_score' is 10 standard deviations away
        outlier_vec = list(self.fixtures[0].feature_vector)
        risk_idx = MODULE2_CANONICAL_FEATURE_NAMES.index("mean_risk_score")
        outlier_vec[risk_idx] = 100.0  # Massive spike

        outlier_payload = Module2SessionPayload(
            session_id="OUTLIER_SESS",
            feature_count=MODULE2_FEATURE_COUNT,
            feature_names=list(MODULE2_CANONICAL_FEATURE_NAMES),
            feature_vector=outlier_vec,
        )

        result = predictor.predict_session(outlier_payload)
        risk_explanations = [
            e for e in result.explanations if e.feature_name == "mean_risk_score"
        ]
        self.assertEqual(len(risk_explanations), 1)
        self.assertGreater(risk_explanations[0].deviation_score, 2.0)
        self.assertIn("standard deviations from verified baseline", risk_explanations[0].description)
        # Ensure description does not assert malicious intent
        self.assertNotIn("malicious", risk_explanations[0].description.lower())
        self.assertNotIn("attacker", risk_explanations[0].description.lower())

    # -----------------------------------------------------------------------
    # 5. Isolated Smoke-Test Path (No Production Artifact Overwriting)
    # -----------------------------------------------------------------------

    def test_isolated_smoke_test_path(self):
        """Verify smoke-test path works end-to-end without touching saved_models/."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = pathlib.Path(tmpdir)
            json_file = tmp_path / "smoke_sessions.json"

            # Write fixture to temporary JSON
            fixtures_dict = [s.model_dump() for s in self.fixtures]
            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(fixtures_dict, f)

            # Run training pipeline into temporary directory
            model_file, meta_file = train_and_save_from_file(
                dataset_file=json_file,
                target_dir=tmp_path / "artifacts",
                is_production_validated=False,
            )

            self.assertTrue(model_file.exists())
            self.assertTrue(meta_file.exists())

            # Load into predictor from temporary directory
            predictor = AnomalyPredictor(model_dir=tmp_path / "artifacts")
            result = predictor.predict_session(self.fixtures[0])
            self.assertIsInstance(result, AnomalyPredictionResult)

            # Verify saved_models/ has not been touched
            prod_model = pathlib.Path("saved_models/anomaly_detector.joblib")
            self.assertFalse(prod_model.exists())


if __name__ == "__main__":
    unittest.main()

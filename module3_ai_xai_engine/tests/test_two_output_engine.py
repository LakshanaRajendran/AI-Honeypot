"""
Unit tests for Module 3 Two-Output Prediction Engine.

Verifies:
- Production of UnifiedModule3Result with Output A and Output B.
- Calibrated confidence ranges [0.0, 1.0].
- Multi-label intent prediction across supported categories.
- Explicit exclusion and documentation of 'credential_access' as unsupported by ML.
- Optional integration of auxiliary anomaly detection signal.
- Strict schema validation and rejection of invalid payloads.
"""

import json
import pathlib
import unittest
import numpy as np

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from models.predictor import AnomalyPredictor
from models.two_output_predictor import TwoOutputPredictor
from schemas.feature_object import Module2SessionPayload
from schemas.prediction_schema import UnifiedModule3Result
from training.train_anomaly_detector import train_isolation_forest


class TestTwoOutputEngine(unittest.TestCase):
    """Test suite for TwoOutputPredictor and UnifiedModule3Result."""

    @classmethod
    def setUpClass(cls):
        """Initialize TwoOutputPredictor from experiments/two_output_model_v1."""
        model_dir = pathlib.Path("experiments/two_output_model_v1")
        if not model_dir.exists():
            raise unittest.SkipTest("experiments/two_output_model_v1 directory does not exist.")

        # Train a lightweight Isolation Forest to test auxiliary anomaly integration
        dummy_fixtures = [
            Module2SessionPayload(
                session_id=f"DUMMY_SESS_{i}",
                feature_count=MODULE2_FEATURE_COUNT,
                feature_names=list(MODULE2_CANONICAL_FEATURE_NAMES),
                feature_vector=[0.0] * MODULE2_FEATURE_COUNT,
            )
            for i in range(5)
        ]
        anom_model, anom_meta = train_isolation_forest(
            sessions=dummy_fixtures, n_estimators=10, is_production_validated=False
        )
        cls.aux_anomaly_predictor = AnomalyPredictor(model=anom_model, metadata=anom_meta)

        # Initialize TwoOutputPredictor with auxiliary anomaly detector
        cls.predictor = TwoOutputPredictor(
            model_dir=model_dir,
            anomaly_predictor=cls.aux_anomaly_predictor,
        )

        # Also initialize a predictor without auxiliary anomaly detector
        cls.predictor_no_anomaly = TwoOutputPredictor(
            model_dir=model_dir,
            anomaly_predictor=None,
        )

    def setUp(self):
        """Prepare sample valid payload."""
        self.valid_payload = Module2SessionPayload(
            session_id="SESS_TEST_99",
            feature_count=MODULE2_FEATURE_COUNT,
            feature_names=list(MODULE2_CANONICAL_FEATURE_NAMES),
            feature_vector=[0.1] * MODULE2_FEATURE_COUNT,
            raw_features={name: 1.0 for name in MODULE2_CANONICAL_FEATURE_NAMES},
            sequence=["cmd:uname -a"],
        )

    def test_predict_session_unified_structure(self):
        """Verify full inference produces valid UnifiedModule3Result with all sections."""
        res = self.predictor.predict_session(self.valid_payload)

        self.assertIsInstance(res, UnifiedModule3Result)
        self.assertEqual(res.session_id, "SESS_TEST_99")

        # Output A: Classification
        self.assertIn(res.classification.predicted_class, [0, 1])
        self.assertIn(res.classification.predicted_label, ["low_interaction_probe", "weaponized_intrusion"])
        self.assertGreaterEqual(res.classification.confidence, 0.0)
        self.assertLessEqual(res.classification.confidence, 1.0)

        # Output B: Intent
        self.assertIsInstance(res.intent.detected_intents, list)
        self.assertIn("reconnaissance", res.intent.intent_scores)
        self.assertIn("execution", res.intent.intent_scores)
        self.assertIn("persistence", res.intent.intent_scores)
        self.assertIn("defense_evasion", res.intent.intent_scores)

        # Verify credential_access is explicitly unsupported and not fabricated in scores
        self.assertIn("credential_access", res.intent.unsupported_intents)
        self.assertNotIn("credential_access", res.intent.intent_scores)

        # Auxiliary Anomaly
        self.assertIsNotNone(res.anomaly)
        self.assertIsInstance(res.anomaly.anomaly_score, float)
        self.assertIsInstance(res.anomaly.is_anomaly, bool)

        # Limitations & Provenance
        self.assertEqual(res.label_provenance, "provisional_rule_derived_behavioral_targets")
        self.assertTrue(len(res.limitations) >= 3)

    def test_predict_session_without_anomaly(self):
        """Verify inference gracefully handles absence of auxiliary anomaly detector."""
        res = self.predictor_no_anomaly.predict_session(self.valid_payload)
        self.assertIsInstance(res, UnifiedModule3Result)
        self.assertIsNone(res.anomaly)

    def test_predict_rejects_invalid_features(self):
        """Verify predictor rejects payload with wrong feature length or invalid fields."""
        bad_dict = {
            "session_id": "BAD_SESS",
            "feature_count": 25,
            "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES[:25]),
            "feature_vector": [0.1] * 25,
        }
        with self.assertRaises(Exception):
            self.predictor.predict_session(bad_dict)

    def test_predict_rejects_non_finite_values(self):
        """Verify predictor rejects payloads containing NaN or Inf."""
        bad_vec = [0.1] * MODULE2_FEATURE_COUNT
        bad_vec[5] = float("nan")
        bad_dict = {
            "session_id": "NAN_SESS",
            "feature_count": MODULE2_FEATURE_COUNT,
            "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
            "feature_vector": bad_vec,
        }
        with self.assertRaises(Exception):
            self.predictor.predict_session(bad_dict)

    def test_missing_model_artifacts_raises(self):
        """Verify loading predictor from nonexistent directory raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            TwoOutputPredictor(model_dir="nonexistent_two_output_dir_9999")

    def test_deterministic_behavior(self):
        """Verify predictor returns identical deterministic predictions on identical input."""
        res1 = self.predictor.predict_session(self.valid_payload)
        res2 = self.predictor.predict_session(self.valid_payload)
        self.assertEqual(res1.classification.predicted_class, res2.classification.predicted_class)
        self.assertEqual(res1.classification.confidence, res2.classification.confidence)
        self.assertEqual(res1.intent.detected_intents, res2.intent.detected_intents)
        self.assertEqual(res1.intent.intent_scores, res2.intent.intent_scores)


if __name__ == "__main__":
    unittest.main()


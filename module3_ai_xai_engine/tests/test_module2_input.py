"""
Unit tests for Module 2 26-feature input schema, validation, and loader.

Built with standard library `unittest` (no pytest dependency required).

Verifies:
- Ingestion of canonical Module 2 feature_vector.json payloads.
- Strict rejection of booleans, strings, nulls, NaNs, infinities, and invalid lengths.
- Pass-through guarantee: pre-normalized vectors are never modified or re-scaled.
- Backward compatibility: legacy 12-feature pipeline and classes remain intact.
"""

import json
import math
import pathlib
import unittest
from pydantic import ValidationError

from config import (
    ENGINEERED_FEATURE_ORDER,
    MODULE2_CANONICAL_FEATURE_NAMES,
    MODULE2_FEATURE_COUNT,
)
from preprocessing.combiner import FeatureCombiner
from preprocessing.validator import InputValidator, Module2InputValidator
from schemas.feature_object import Module2SessionPayload
from schemas.input_schema import EngineeredFeatures, Module3Input
from schemas.training_schema import TrainingSample
from training.dataset_loader import DatasetLoader


class TestModule2InputCompatibility(unittest.TestCase):
    """Test suite for Module 2 26-feature input schema, validation, and loader."""

    def setUp(self):
        """Set up standard 26-feature vector and payload dict for testing."""
        self.valid_26_vector = [float(i * 0.1 - 1.0) for i in range(MODULE2_FEATURE_COUNT)]
        self.valid_payload_dict = {
            "schema_version": "1.0",
            "session_id": "TEST_SESSION_001",
            "feature_count": MODULE2_FEATURE_COUNT,
            "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
            "feature_vector": list(self.valid_26_vector),
            "sequence": ["cmd:whoami", "cmd:id"],
            "raw_features": {name: 1.0 for name in MODULE2_CANONICAL_FEATURE_NAMES},
        }

    # -----------------------------------------------------------------------
    # 1. Real File Ingestion Tests
    # -----------------------------------------------------------------------

    def test_load_actual_feature_vector_file(self):
        """Verify loading from the real Module 2 feature_vector.json file."""
        candidates = [
            pathlib.Path("D:/MINIPROJECT/feature_vector.json"),
            pathlib.Path(__file__).resolve().parent.parent.parent / "feature_vector.json",
        ]
        file_path = next((p for p in candidates if p.is_file()), None)

        if file_path is None:
            self.skipTest("feature_vector.json not found in test environment.")

        loader = DatasetLoader()
        sessions = loader.load_module2_session_vectors(file_path)

        # Dynamic count check (do not hardcode an assumption of exact count)
        self.assertGreaterEqual(len(sessions), 1, "Expected at least one session in feature_vector.json")

        for session in sessions:
            self.assertIsInstance(session, Module2SessionPayload)
            self.assertIsInstance(session.session_id, str)
            self.assertTrue(session.session_id.strip() != "")
            self.assertEqual(session.feature_count, MODULE2_FEATURE_COUNT)
            self.assertEqual(len(session.feature_vector), MODULE2_FEATURE_COUNT)
            self.assertEqual(session.feature_names, MODULE2_CANONICAL_FEATURE_NAMES)

            # Verify numpy conversion and dict mapping
            arr = session.to_numpy()
            self.assertEqual(arr.shape, (26,))
            self.assertEqual(arr.dtype.name, "float64")

            f_dict = session.to_feature_dict()
            self.assertEqual(len(f_dict), 26)
            self.assertEqual(list(f_dict.keys()), MODULE2_CANONICAL_FEATURE_NAMES)

    def test_feature_vector_pass_through_no_scaler(self):
        """Verify that feature vectors pass through exactly as normalized, without refitting."""
        candidates = [
            pathlib.Path("D:/MINIPROJECT/feature_vector.json"),
            pathlib.Path(__file__).resolve().parent.parent.parent / "feature_vector.json",
        ]
        file_path = next((p for p in candidates if p.is_file()), None)

        if file_path is None:
            self.skipTest("feature_vector.json not found in test environment.")

        with file_path.open("r", encoding="utf-8") as f:
            raw_json_data = json.load(f)

        loader = DatasetLoader()
        sessions = loader.load_module2_session_vectors(file_path)

        raw_list = raw_json_data if isinstance(raw_json_data, list) else [raw_json_data]
        self.assertEqual(len(sessions), len(raw_list))

        for parsed_session, original_raw in zip(sessions, raw_list):
            # Bit-for-bit equivalence with incoming pre-normalized values
            self.assertEqual(parsed_session.feature_vector, original_raw["feature_vector"])

    # -----------------------------------------------------------------------
    # 2. Strict Type & Numeric Rejection Tests
    # -----------------------------------------------------------------------

    def test_reject_booleans_in_feature_vector(self):
        """Pydantic must not coerce boolean True/False into 1.0/0.0."""
        payload = dict(self.valid_payload_dict)
        payload["feature_vector"] = list(payload["feature_vector"])
        payload["feature_vector"][0] = True

        with self.assertRaises((ValueError, ValidationError)) as ctx:
            Module2SessionPayload(**payload)
        self.assertIn("boolean", str(ctx.exception).lower())

    def test_reject_strings_in_feature_vector(self):
        """String representations of numbers must be rejected."""
        payload = dict(self.valid_payload_dict)
        payload["feature_vector"] = list(payload["feature_vector"])
        payload["feature_vector"][5] = "0.75"

        with self.assertRaises((ValueError, ValidationError)):
            Module2SessionPayload(**payload)

    def test_reject_nulls_in_feature_vector(self):
        """None/null values in feature_vector must be rejected."""
        payload = dict(self.valid_payload_dict)
        payload["feature_vector"] = list(payload["feature_vector"])
        payload["feature_vector"][10] = None

        with self.assertRaises((ValueError, ValidationError)):
            Module2SessionPayload(**payload)

    def test_reject_nan_in_feature_vector(self):
        """NaN values must be rejected."""
        payload = dict(self.valid_payload_dict)
        payload["feature_vector"] = list(payload["feature_vector"])
        payload["feature_vector"][3] = float("nan")

        with self.assertRaises((ValueError, ValidationError)) as ctx:
            Module2SessionPayload(**payload)
        self.assertTrue("nan" in str(ctx.exception).lower() or "finite" in str(ctx.exception).lower())

    def test_reject_infinity_in_feature_vector(self):
        """Positive and negative infinity must be rejected."""
        for inf_val in (float("inf"), float("-inf")):
            payload = dict(self.valid_payload_dict)
            payload["feature_vector"] = list(payload["feature_vector"])
            payload["feature_vector"][7] = inf_val

            with self.assertRaises((ValueError, ValidationError)):
                Module2SessionPayload(**payload)

    # -----------------------------------------------------------------------
    # 3. Schema Structure & Cardinality Tests
    # -----------------------------------------------------------------------

    def test_reject_feature_count_mismatch(self):
        """feature_count not equal to 26 must be rejected."""
        payload = dict(self.valid_payload_dict)
        payload["feature_count"] = 25

        with self.assertRaises((ValueError, ValidationError)):
            Module2SessionPayload(**payload)

    def test_reject_vector_length_mismatch(self):
        """feature_vector with fewer or more than 26 elements must be rejected."""
        payload = dict(self.valid_payload_dict)
        payload["feature_vector"] = payload["feature_vector"][:25]  # 25 items

        with self.assertRaises((ValueError, ValidationError)):
            Module2SessionPayload(**payload)

    def test_reject_feature_names_order_mismatch(self):
        """feature_names with swapped or altered order must be rejected."""
        payload = dict(self.valid_payload_dict)
        names = list(payload["feature_names"])
        names[0], names[1] = names[1], names[0]  # Swap first two
        payload["feature_names"] = names

        with self.assertRaises((ValueError, ValidationError)):
            Module2SessionPayload(**payload)

    def test_reject_empty_or_whitespace_session_id(self):
        """session_id cannot be empty or whitespace."""
        for bad_id in ("", "   ", "\t\n"):
            payload = dict(self.valid_payload_dict)
            payload["session_id"] = bad_id
            with self.assertRaises((ValueError, ValidationError)):
                Module2SessionPayload(**payload)

    # -----------------------------------------------------------------------
    # 4. Validator Class Tests
    # -----------------------------------------------------------------------

    def test_module2_input_validator(self):
        """Module2InputValidator properly validates dicts and payload instances."""
        validator = Module2InputValidator()

        # Valid dict
        res = validator.validate(self.valid_payload_dict)
        self.assertIsInstance(res, Module2SessionPayload)

        # Valid batch
        batch_res = validator.validate_batch([self.valid_payload_dict, self.valid_payload_dict])
        self.assertEqual(len(batch_res), 2)
        self.assertTrue(all(isinstance(r, Module2SessionPayload) for r in batch_res))

        # Invalid input type
        with self.assertRaises(ValueError):
            validator.validate("not_a_dict_or_payload")

    # -----------------------------------------------------------------------
    # 5. Legacy Backward Compatibility Tests
    # -----------------------------------------------------------------------

    def test_legacy_pipeline_backward_compatibility(self):
        """Ensure legacy 12-feature schema and components remain completely operational."""
        # 1. Legacy feature order is 12 features
        self.assertEqual(len(ENGINEERED_FEATURE_ORDER), 12)
        self.assertIn("failed_logins", ENGINEERED_FEATURE_ORDER)
        self.assertIn("session_duration", ENGINEERED_FEATURE_ORDER)

        # 2. Legacy schemas instantiate normally
        eng_features = EngineeredFeatures(
            failed_logins=2,
            successful_logins=1,
            command_count=5,
            unique_commands=4,
            ssh_connections=1,
            https_connections=0,
            bytes_sent=1024.0,
            bytes_received=2048.0,
            file_reads=3,
            file_writes=1,
            sensitive_file_access=0,
            session_duration=45.0,
        )

        module3_input = Module3Input(
            session_id="LEGACY_SESSION",
            engineered_features=eng_features,
            behavior_embedding=[0.1] * 50,
        )

        # 3. Legacy InputValidator works
        legacy_validator = InputValidator()
        validated = legacy_validator.validate(module3_input)
        self.assertEqual(validated.session_id, "LEGACY_SESSION")

        # 4. Legacy FeatureCombiner works (12 + 50 = 62)
        combiner = FeatureCombiner()
        vector = combiner.combine(module3_input)
        self.assertEqual(len(vector), 62)
        self.assertEqual(vector[:12], [2.0, 1.0, 5.0, 4.0, 1.0, 0.0, 1024.0, 2048.0, 3.0, 1.0, 0.0, 45.0])

        # 5. Legacy TrainingSample works
        sample = TrainingSample(
            session_id="LEGACY_SAMPLE",
            engineered_features=eng_features,
            behavior_embedding=[0.2] * 50,
            label="malicious",
        )
        self.assertEqual(sample.label, "malicious")


if __name__ == "__main__":
    unittest.main()


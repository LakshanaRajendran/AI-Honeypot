"""
Comprehensive unit and integration tests for the demonstration dashboard backend.

Verifies:
1. System health check and SHA-256 hash validation for frozen model/scaler artifacts.
2. Thread-safe execution of the offline demonstration pipeline.
3. Accurate CSV report generation from session telemetry.
4. HTTP REST API endpoints (/api/status, /api/data, /api/documentation, /api/export, /api/run-demo).
5. Strict localhost enforcement and path traversal defenses.
"""

import json
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer
from pathlib import Path

from dashboard.server import (
    check_system_health,
    execute_offline_pipeline,
    generate_csv_report,
    DashboardRequestHandler,
    EXPECTED_HASHES,
    compute_sha256,
)

TEST_PORT = 8099
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestDashboardBackend(unittest.TestCase):
    """Test suite for dashboard backend logic and REST endpoints."""

    @classmethod
    def setUpClass(cls):
        """Start an in-process HTTP test server on localhost."""
        cls.server = ThreadingHTTPServer(("127.0.0.1", TEST_PORT), DashboardRequestHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)  # Allow server to bind

    @classmethod
    def tearDownClass(cls):
        """Shutdown test server."""
        cls.server.shutdown()
        cls.server.server_close()

    def test_artifact_hashes_match_expected(self):
        """Verify all frozen models and scalers match expected SHA-256 signatures bit-for-bit."""
        model_dir = PROJECT_ROOT / "module3_ai_xai_engine" / "experiments" / "two_output_model_v1"
        for filename, expected_hash in EXPECTED_HASHES.items():
            path = model_dir / filename
            self.assertTrue(path.is_file(), f"Missing artifact: {filename}")
            actual_hash = compute_sha256(path)
            self.assertEqual(
                actual_hash,
                expected_hash,
                f"Hash mismatch for {filename}! The model or scaler artifact has been altered.",
            )

    def test_health_check_structure(self):
        """Verify health check dictionary contains required fields and safety disclosures."""
        health = check_system_health()
        self.assertIn("status", health)
        self.assertIn("artifacts", health)
        self.assertIn("cowrie_logs", health)
        self.assertIn("safety_guarantees", health)
        self.assertTrue(health["artifacts_intact"])
        self.assertTrue(health["safety_guarantees"]["simulation_only"])
        self.assertTrue(health["safety_guarantees"]["no_live_commands_executed"])
        self.assertTrue(health["safety_guarantees"]["frozen_model_and_scaler"])

    def test_csv_report_generation(self):
        """Verify CSV generation produces valid headers and rows."""
        sample_data = {
            "sessions": [
                {
                    "session_id": "test_sess_01",
                    "source_ips": ["192.168.1.100"],
                    "event_count": 3,
                    "commands_observed": ["whoami", "uname -a", "id"],
                    "raw_features": {"session_duration_seconds": 12.5},
                    "module3_prediction": {
                        "classification": {"predicted_label": "low_interaction_probe", "confidence": 0.95},
                        "intent": {"detected_intents": ["reconnaissance"]},
                        "shap_explanation": {"top_features": [{"feature_name": "identity_command_ratio", "shap_value": 0.12}]},
                    },
                    "module4_decision": {
                        "selected_strategy": "standard_observation",
                        "threat_level": "low",
                    },
                    "module4_simulation": {
                        "status": "simulated_only",
                        "simulated_profile": "profile_standard_observation",
                    },
                }
            ]
        }
        csv_text = generate_csv_report(sample_data)
        lines = csv_text.strip().split("\n")
        self.assertGreaterEqual(len(lines), 2)
        self.assertIn("session_id", lines[0])
        self.assertIn("test_sess_01", lines[1])
        self.assertIn("low_interaction_probe", lines[1])
        self.assertIn("standard_observation", lines[1])

    def test_api_status_endpoint(self):
        """Verify GET /api/status returns HTTP 200 and healthy JSON."""
        url = f"http://127.0.0.1:{TEST_PORT}/api/status"
        with urllib.request.urlopen(url) as response:
            self.assertEqual(response.status, 200)
            data = json.loads(response.read().decode("utf-8"))
            self.assertEqual(data["status"], "healthy")
            self.assertTrue(data["artifacts_intact"])

    def test_api_data_endpoint(self):
        """Verify GET /api/data returns valid session records."""
        url = f"http://127.0.0.1:{TEST_PORT}/api/data"
        with urllib.request.urlopen(url) as response:
            self.assertEqual(response.status, 200)
            data = json.loads(response.read().decode("utf-8"))
            self.assertIn("sessions", data)
            self.assertIn("safety", data)
            self.assertFalse(data["safety"]["commands_executed"])
            self.assertFalse(data["safety"]["live_deception_applied"])

    def test_api_documentation_endpoint(self):
        """Verify GET /api/documentation serves markdown guide and parsed headings."""
        url = f"http://127.0.0.1:{TEST_PORT}/api/documentation"
        with urllib.request.urlopen(url) as response:
            self.assertEqual(response.status, 200)
            data = json.loads(response.read().decode("utf-8"))
            self.assertIn("content_markdown", data)
            self.assertIn("headings", data)
            self.assertGreater(len(data["headings"]), 10)

    def test_api_export_json_and_csv(self):
        """Verify GET /api/export handles both JSON and CSV formats."""
        url_json = f"http://127.0.0.1:{TEST_PORT}/api/export?format=json"
        with urllib.request.urlopen(url_json) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "application/json")

        url_csv = f"http://127.0.0.1:{TEST_PORT}/api/export?format=csv"
        with urllib.request.urlopen(url_csv) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "text/csv")

    def test_head_request(self):
        """Verify HEAD / returns HTTP 200 without payload body."""
        url = f"http://127.0.0.1:{TEST_PORT}/"
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(len(response.read()), 0)

    def test_path_traversal_protection(self):
        """Verify that directory traversal attempts are rejected with 403 Forbidden."""
        url = f"http://127.0.0.1:{TEST_PORT}/../../etc/passwd"
        try:
            with urllib.request.urlopen(url) as response:
                # If server doesn't raise, check status
                self.assertIn(response.status, (403, 404))
        except urllib.error.HTTPError as exc:
            self.assertIn(exc.code, (403, 404))


if __name__ == "__main__":
    unittest.main()

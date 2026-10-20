import unittest

from module4_decision_engine.execution_adapter import simulate_decision


def make_decision(
    strategy="controlled_execution_deception",
    confidence=0.95,
    status="pending",
    requires_execution_layer=True,
):
    """Build a representative Module 4 decision."""

    return {
        "schema_version": "1.0",
        "engine_version": "1.0.0",
        "session_id": "TEST-001",
        "threat_level": "high",
        "source_classification_confidence": confidence,
        "detected_intent_used": "execution",
        "selected_strategy": strategy,
        "decision_basis": ["Unit test decision"],
        "requires_execution_layer": requires_execution_layer,
        "execution_status": status,
        "execution_note": "Unit test only",
    }


class TestExecutionAdapter(unittest.TestCase):

    def test_valid_decision_is_simulated(self):
        result = simulate_decision(make_decision())

        self.assertEqual(result["status"], "simulated_only")
        self.assertEqual(
            result["simulated_profile"],
            "profile_simulated_execution_deception",
        )

    def test_safe_fallback_accepts_missing_confidence(self):
        decision = make_decision(
            strategy="safe_observation_fallback",
            confidence=None,
        )

        result = simulate_decision(decision)

        self.assertEqual(result["status"], "simulated_only")
        self.assertEqual(
            result["simulated_profile"],
            "profile_safe_observation",
        )

    def test_safe_fallback_accepts_low_confidence(self):
        decision = make_decision(
            strategy="safe_observation_fallback",
            confidence=0.40,
        )

        result = simulate_decision(decision)

        self.assertEqual(result["status"], "simulated_only")

    def test_regular_strategy_rejects_missing_confidence(self):
        decision = make_decision(confidence=None)

        result = simulate_decision(decision)

        self.assertEqual(result["status"], "rejected")
        self.assertIn("confidence", result["reason"].lower())

    def test_regular_strategy_rejects_out_of_range_confidence(self):
        for confidence in (-0.1, 1.1):
            with self.subTest(confidence=confidence):
                result = simulate_decision(
                    make_decision(confidence=confidence)
                )
                self.assertEqual(result["status"], "rejected")

    def test_boolean_confidence_is_rejected(self):
        result = simulate_decision(make_decision(confidence=True))

        self.assertEqual(result["status"], "rejected")

    def test_unknown_strategy_is_rejected(self):
        result = simulate_decision(
            make_decision(strategy="unknown_strategy")
        )

        self.assertEqual(result["status"], "rejected")
        self.assertIsNone(result["simulated_profile"])

    def test_missing_session_id_is_rejected(self):
        decision = make_decision()
        decision["session_id"] = ""

        result = simulate_decision(decision)

        self.assertEqual(result["status"], "rejected")

    def test_non_pending_decision_is_rejected(self):
        result = simulate_decision(
            make_decision(status="simulated_only")
        )

        self.assertEqual(result["status"], "rejected")

    def test_execution_layer_must_be_requested(self):
        result = simulate_decision(
            make_decision(requires_execution_layer=False)
        )

        self.assertEqual(result["status"], "rejected")

    def test_simulation_never_claims_live_execution(self):
        result = simulate_decision(make_decision())

        self.assertEqual(result["execution_mode"], "simulation_only")
        self.assertFalse(result["applied_to_cowrie"])
        self.assertFalse(result["commands_executed"])


if __name__ == "__main__":
    unittest.main()

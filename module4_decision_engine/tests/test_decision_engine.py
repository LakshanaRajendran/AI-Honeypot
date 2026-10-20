import unittest

from module4_decision_engine.decision_engine import decide


def prediction(label, confidence=0.95, intents=None):
    return {
        "session_id": "TEST-001",
        "classification": {
            "predicted_label": label,
            "confidence": confidence,
        },
        "intent": {
            "detected_intents": intents or [],
            "intent_scores": {},
        },
        "shap_explanation": {
            "top_features": [
                {"feature_name": "unique_commands", "shap_value": 0.2}
            ]
        },
    }


class TestModule4DecisionEngine(unittest.TestCase):

    def test_execution_intent(self):
        result = decide(
            prediction("weaponized_intrusion", intents=["execution"])
        )
        self.assertEqual(
            result["selected_strategy"],
            "controlled_execution_deception",
        )
        self.assertEqual(result["execution_status"], "pending")

    def test_persistence_has_priority(self):
        result = decide(
            prediction(
                "weaponized_intrusion",
                intents=["execution", "persistence"],
            )
        )
        self.assertEqual(
            result["selected_strategy"],
            "simulated_persistence_artifacts",
        )

    def test_probe_uses_standard_observation(self):
        result = decide(prediction("low_interaction_probe"))
        self.assertEqual(
            result["selected_strategy"],
            "standard_observation",
        )

    def test_low_confidence_uses_fallback(self):
        result = decide(
            prediction("weaponized_intrusion", confidence=0.40, intents=["execution"])
        )
        self.assertEqual(
            result["selected_strategy"],
            "safe_observation_fallback",
        )

    def test_unsupported_or_missing_intent_uses_fallback(self):
        result = decide(
            prediction("weaponized_intrusion", intents=["credential_access"])
        )
        self.assertEqual(
            result["selected_strategy"],
            "safe_observation_fallback",
        )

    def test_unknown_label_uses_fallback(self):
        result = decide(prediction("unknown_label"))
        self.assertEqual(
            result["selected_strategy"],
            "safe_observation_fallback",
        )

    def test_invalid_input_is_rejected(self):
        with self.assertRaises(ValueError):
            decide({"session_id": "TEST-001"})

    def test_shap_is_context_not_the_decision_rule(self):
        first = prediction("weaponized_intrusion", intents=["execution"])
        second = prediction("weaponized_intrusion", intents=["execution"])
        second["shap_explanation"]["top_features"] = [
            {"feature_name": "download_utility_ratio", "shap_value": -0.8}
        ]

        first_result = decide(first)
        second_result = decide(second)

        self.assertEqual(
            first_result["selected_strategy"],
            second_result["selected_strategy"],
        )
        self.assertNotEqual(
            first_result["decision_basis"],
            second_result["decision_basis"],
        )


if __name__ == "__main__":
    unittest.main()

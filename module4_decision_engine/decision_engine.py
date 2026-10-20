"""Module 4: Rule-based decision engine for adaptive honeypot deception.

This module selects a strategy but does not execute deception actions.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ENGINE_VERSION = "1.0.0"
MIN_CONFIDENCE = 0.65

STRATEGIES = {
    "reconnaissance": "reconnaissance_decoy_profile",
    "execution": "controlled_execution_deception",
    "persistence": "simulated_persistence_artifacts",
    "defense_evasion": "monitoring_evasion_observation_profile",
}

SUPPORTED_INTENTS = set(STRATEGIES)


def decide(module3: dict[str, Any]) -> dict[str, Any]:
    """Convert a Module 3 prediction into a proposed deception decision."""

    if not isinstance(module3, dict):
        raise ValueError("Module 3 input must be a JSON object.")

    session_id = module3.get("session_id")
    classification = module3.get("classification")

    if not session_id or not isinstance(classification, dict):
        raise ValueError(
            "Input must contain session_id and classification fields."
        )

    label = classification.get("predicted_label")
    confidence = classification.get("confidence")

    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not 0 <= confidence <= 1
    ):
        return _fallback(session_id, "Missing or invalid classification confidence.")

    if label not in {"weaponized_intrusion", "low_interaction_probe"}:
        return _fallback(session_id, "Unknown classification label.")

    if confidence < MIN_CONFIDENCE:
        return _fallback(
            session_id,
            f"Confidence {confidence:.2f} is below the "
            f"configured threshold {MIN_CONFIDENCE:.2f}.",
        )

    if label == "low_interaction_probe":
        return _result(
            session_id=session_id,
            threat_level="low",
            strategy="standard_observation",
            rationale=[
                "Module 3 classified the session as low_interaction_probe.",
                "The prediction met the configured confidence threshold.",
                "Use the standard observation profile; no escalation is proposed.",
            ],
            confidence=float(confidence),
            intent=None,
        )

    intent_data = module3.get("intent", {})
    detected_intents = (
        intent_data.get("detected_intents", [])
        if isinstance(intent_data, dict)
        else []
    )

    if not isinstance(detected_intents, list):
        detected_intents = []

    # Deterministic priority: persistence > defense evasion > execution > recon.
    intent_priority = [
        "persistence",
        "defense_evasion",
        "execution",
        "reconnaissance",
    ]

    selected_intent = next(
        (intent for intent in intent_priority if intent in detected_intents),
        None,
    )

    if selected_intent is None:
        return _fallback(
            session_id,
            "Weaponized intrusion was predicted, but no supported intent "
            "was detected. Manual review or a conservative profile is required.",
            confidence=float(confidence),
        )

    shap_data = module3.get("shap_explanation")
    shap_features = []

    if isinstance(shap_data, dict):
        top_features = shap_data.get("top_features", [])
        if isinstance(top_features, list):
            for item in top_features[:3]:
                if isinstance(item, dict) and item.get("feature_name"):
                    shap_features.append(item["feature_name"])

    rationale = [
        "Module 3 classified the session as weaponized_intrusion.",
        f"Classification confidence: {confidence:.2f}.",
        f"Detected supported intent: {selected_intent}.",
        "The strategy was selected using predefined Module 4 rules.",
    ]

    if shap_features:
        rationale.append(
            "SHAP context (model explanation only): "
            + ", ".join(shap_features)
            + "."
        )

    rationale.append(
        "SHAP contributions inform the explanation but do not independently "
        "determine the strategy."
    )

    return _result(
        session_id=session_id,
        threat_level="high",
        strategy=STRATEGIES[selected_intent],
        rationale=rationale,
        confidence=float(confidence),
        intent=selected_intent,
    )


def _fallback(
    session_id: str,
    reason: str,
    confidence: float | None = None,
) -> dict[str, Any]:
    """Return a conservative decision without activating a response."""

    return _result(
        session_id=session_id,
        threat_level="undetermined",
        strategy="safe_observation_fallback",
        rationale=[reason, "No adaptive deception action has been executed."],
        confidence=confidence,
        intent=None,
    )


def _result(
    session_id: str,
    threat_level: str,
    strategy: str,
    rationale: list[str],
    confidence: float | None,
    intent: str | None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "engine_version": ENGINE_VERSION,
        "session_id": session_id,
        "threat_level": threat_level,
        "source_classification_confidence": confidence,
        "detected_intent_used": intent,
        "selected_strategy": strategy,
        "decision_basis": rationale,
        "requires_execution_layer": True,
        "execution_status": "pending",
        "execution_note": (
            "Decision only. A separate execution layer must validate and "
            "apply the strategy, then report its actual status."
        ),
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "Usage: python -m module4_decision_engine.decision_engine "
            "<module3_input.json> <module4_output.json>",
            file=sys.stderr,
        )
        return 2

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    try:
        with input_path.open(encoding="utf-8") as file:
            module3_data = json.load(file)

        decision = decide(module3_data)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(decision, file, indent=2)
            file.write("\n")

        print(json.dumps(decision, indent=2))
        print(f"\nDecision saved to: {output_path}")
        return 0

    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Module 4 error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

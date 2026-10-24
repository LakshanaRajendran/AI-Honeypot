"""
Simulation-only execution adapter for Module 4.

Validates Module 4 decisions and simulates deception profile selection.
Does NOT execute shell commands, modify Cowrie, or apply live deception.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


ENGINE_VERSION = "1.0.0-simulation"

# Allowlisted profiles for simulation only.
# These profiles do not activate services or change Cowrie behavior.
ALLOWED_PROFILES = {
    "standard_observation": "profile_standard_observation",
    "safe_observation_fallback": "profile_safe_observation",
    "reconnaissance_decoy_profile": "profile_simulated_recon_decoy",
    "controlled_execution_deception": "profile_simulated_execution_deception",
    "simulated_persistence_artifacts": "profile_simulated_persistence",
    "monitoring_evasion_observation_profile": (
        "profile_simulated_evasion_observation"
    ),
}


def simulate_decision(decision: dict) -> dict:
    """Validate one Module 4 decision and simulate profile selection."""

    session_id = decision.get("session_id")

    result = {
        "session_id": session_id,
        "adapter_version": ENGINE_VERSION,
        "execution_mode": "simulation_only",
        "applied_to_cowrie": False,
        "commands_executed": False,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # 1. Validate the session identifier.
    if not isinstance(session_id, str) or not session_id.strip():
        result.update({
            "status": "rejected",
            "reason": "Missing or invalid session_id.",
            "simulated_profile": None,
        })
        return result

    strategy = decision.get("selected_strategy")
    result["requested_strategy"] = strategy

    # 2. Require an explicit request for the execution layer.
    if decision.get("requires_execution_layer") is not True:
        result.update({
            "status": "rejected",
            "reason": "Decision does not request the execution layer.",
            "simulated_profile": None,
        })
        return result

    # 3. Only process decisions that have not already been processed.
    if decision.get("execution_status") != "pending":
        result.update({
            "status": "rejected",
            "reason": (
                "Expected an unexecuted Module 4 decision "
                "with status pending."
            ),
            "simulated_profile": None,
        })
        return result

    # 4. Validate classification confidence.
    confidence = decision.get("source_classification_confidence")

    if strategy == "safe_observation_fallback":
        # A fallback is intended for uncertain predictions.
        # Module 4 may deliberately set confidence to None.
        if confidence is not None and (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= confidence <= 1.0
        ):
            result.update({
                "status": "rejected",
                "reason": (
                    "Fallback confidence, when provided, "
                    "must be within [0, 1]."
                ),
                "simulated_profile": None,
            })
            return result

    else:
        # All other strategies require a valid numeric confidence.
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0.0 <= confidence <= 1.0
        ):
            result.update({
                "status": "rejected",
                "reason": (
                    "Classification confidence is missing "
                    "or outside [0, 1]."
                ),
                "simulated_profile": None,
            })
            return result

    # 5. Only allow predefined strategies.
    profile = ALLOWED_PROFILES.get(strategy)

    if profile is None:
        result.update({
            "status": "rejected",
            "reason": "Strategy is not in the adapter allowlist.",
            "simulated_profile": None,
        })
        return result

    # 6. Record simulated selection, not actual execution.
    result.update({
        "status": "simulated_only",
        "reason": (
            "Decision validated; profile selection simulated. "
            "No changes were applied to Cowrie."
        ),
        "simulated_profile": profile,
    })

    return result


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Simulate Module 4 strategy selection "
            "without modifying Cowrie."
        )
    )

    parser.add_argument(
        "input_report",
        help="Path to the existing Cowrie integration report JSON",
    )

    parser.add_argument(
        "output_report",
        help="Path for the separate simulation report JSON",
    )

    args = parser.parse_args()

    input_path = Path(args.input_report).expanduser()
    output_path = Path(args.output_report).expanduser()

    if not input_path.is_file():
        raise SystemExit(f"Input report not found: {input_path}")

    try:
        report = json.loads(input_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"Could not read input report: {exc}") from exc

    if not isinstance(report, dict):
        raise SystemExit("Input report must contain a JSON object.")

    sessions = report.get("sessions")

    if not isinstance(sessions, list):
        raise SystemExit("Input report does not contain a sessions list.")

    results = []

    for session in sessions:
        if not isinstance(session, dict):
            results.append({
                "status": "rejected",
                "execution_mode": "simulation_only",
                "applied_to_cowrie": False,
                "commands_executed": False,
                "simulated_profile": None,
                "reason": "Session entry is not a JSON object.",
            })
            continue

        decision = session.get("module4_decision")

        if not isinstance(decision, dict):
            results.append({
                "session_id": session.get("session_id"),
                "status": "rejected",
                "execution_mode": "simulation_only",
                "applied_to_cowrie": False,
                "commands_executed": False,
                "simulated_profile": None,
                "reason": "Module 4 decision is missing or invalid.",
            })
            continue

        results.append(simulate_decision(decision))

    output = {
        "report_version": "1.0",
        "mode": "simulation_only",
        "source_report": str(input_path.resolve()),
        "sessions_processed": len(results),
        "safety": {
            "simulation_only": True,
            "cowrie_modified": False,
            "commands_executed": False,
            "live_deception_applied": False,
        },
        "results": results,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(output, indent=2) + "\n",
        encoding="utf-8",
    )

    simulated_count = sum(
        item.get("status") == "simulated_only"
        for item in results
    )

    rejected_count = sum(
        item.get("status") == "rejected"
        for item in results
    )

    print("Simulation report:", output_path.resolve())
    print("Sessions processed:", len(results))
    print("Decisions simulated:", simulated_count)
    print("Decisions rejected:", rejected_count)
    print("Cowrie modified: False")
    print("Commands executed: False")
    print("Live deception applied: False")


if __name__ == "__main__":
    main()

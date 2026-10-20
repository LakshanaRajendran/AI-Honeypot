#!/usr/bin/env python3
"""
Offline integration demo:
Cowrie logs -> 26 raw features -> Module 3 -> Module 4.

Safety:
- Reads existing Cowrie JSON logs only.
- Never executes captured commands.
- Never starts or changes Cowrie.
- Never applies a deception strategy.
- Marks heuristic risk scores and model limitations explicitly.
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE3_ROOT = PROJECT_ROOT / "module3_ai_xai_engine"
COWRIE_LOG_DIR = Path.home() / "cowrie" / "var" / "log" / "cowrie"

OUTPUT_PATH = PROJECT_ROOT / "output" / "cowrie_integration_demo.json"

# Make Module 3's local imports (config, models, schemas, etc.) resolve
# to the Module 3 implementation, not another module's similarly named files.
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(MODULE3_ROOT))

from config import MODULE2_CANONICAL_FEATURE_NAMES  # noqa: E402
from models.two_output_predictor import TwoOutputPredictor  # noqa: E402
from module4_decision_engine.decision_engine import decide  # noqa: E402
from src.feature_extractor import extract_features  # noqa: E402


HIGH_RISK_PATTERNS = [
    r"\b(nc|netcat|nmap|wget|curl|scp|socat)\b",
    r"\b(chmod|chown|sudo)\b",
    r"/etc/(shadow|sudoers)\b",
    r"\b(id_rsa|authorized_keys)\b",
    r"\bbash\s+-c\b",
]

DISCOVERY_PATTERNS = [
    r"\b(whoami|id|hostname|uname|pwd|ls|find|ps|env|ifconfig|ip)\b",
    r"\b(cat|less|more|head|tail|grep)\b",
]


def classify_heuristic_risk(command: str) -> tuple[str, float]:
    """Assign a transparent demo heuristic, not a verified attack label."""
    text = command.strip().lower()

    if any(re.search(pattern, text) for pattern in HIGH_RISK_PATTERNS):
        return "HIGH", 8.0

    if any(re.search(pattern, text) for pattern in DISCOVERY_PATTERNS):
        return "MEDIUM", 4.0

    return "LOW", 1.0


def read_cowrie_commands() -> tuple[list[dict], list[str]]:
    """Read command.input events from existing Cowrie JSON logs."""
    if not COWRIE_LOG_DIR.is_dir():
        raise FileNotFoundError(
            f"Cowrie log directory not found: {COWRIE_LOG_DIR}"
        )

    log_files = sorted(
        p for p in COWRIE_LOG_DIR.glob("cowrie.json*") if p.is_file()
    )
    if not log_files:
        raise FileNotFoundError(
            f"No cowrie.json log files found in {COWRIE_LOG_DIR}"
        )

    events = []
    malformed_lines = 0

    for path in log_files:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    malformed_lines += 1
                    continue

                if not isinstance(event, dict):
                    continue
                if event.get("eventid") != "cowrie.command.input":
                    continue

                session_id = event.get("session")
                timestamp = event.get("timestamp")
                command = event.get("input")

                if not isinstance(session_id, str) or not session_id.strip():
                    continue
                if not isinstance(timestamp, str) or not timestamp.strip():
                    continue
                if not isinstance(command, str) or not command.strip():
                    continue

                risk, score = classify_heuristic_risk(command)

                events.append({
                    "timestamp": timestamp,
                    "session": session_id,
                    "source_ip": event.get("src_ip", "unknown"),
                    "command": command.strip(),
                    "process": command.strip().split()[0].lower(),
                    "risk": risk,
                    "score": score,
                    # The current Cowrie command events do not supply
                    # verified MITRE labels, so leave them absent.
                })

    print(f"Cowrie log files examined: {len(log_files)}")
    print(f"Malformed JSON lines skipped: {malformed_lines}")
    print(f"Command events selected: {len(events)}")

    return events, [p.name for p in log_files]


def main() -> int:
    events, source_files = read_cowrie_commands()

    if not events:
        print("No usable Cowrie command-input events were found.")
        return 1

    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df = df.dropna(subset=["timestamp", "session", "command"])
    df = df.sort_values(["session", "timestamp"], kind="mergesort")

    if df.empty:
        print("No valid timestamped command events remain after parsing.")
        return 1

    # Predictor loads its own saved Module 3 models and scaler.
    model_dir = MODULE3_ROOT / "experiments" / "two_output_model_v1"
    predictor = TwoOutputPredictor(model_dir=model_dir)

    reports = []
    sessions = list(df.groupby("session", sort=True))

    print(f"Usable sessions: {len(sessions)}")

    for session_id, session_df in sessions:
        session_df = session_df.copy().reset_index(drop=True)

        # The existing feature extractor consumes the 26-feature contract.
        raw = extract_features(session_df)

        # Ensure all canonical features exist and are ordinary finite numbers.
        raw_features = {}
        for name in MODULE2_CANONICAL_FEATURE_NAMES:
            value = raw.get(name, 0.0)
            number = float(value)
            if not pd.notna(number) or number in (float("inf"), float("-inf")):
                number = 0.0
            raw_features[name] = number

        commands = session_df["command"].astype(str).tolist()
        sequence = [
            f"cmd:{command.split()[0]}"
            for command in commands
            if command.strip()
        ]

        # Module 3 uses raw_features to apply its own frozen scaler.
        payload = {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "feature_count": len(MODULE2_CANONICAL_FEATURE_NAMES),
            "feature_names": list(MODULE2_CANONICAL_FEATURE_NAMES),
            "feature_vector": [
                raw_features[name]
                for name in MODULE2_CANONICAL_FEATURE_NAMES
            ],
            "raw_features": raw_features,
            "sequence": sequence,
        }

        prediction = predictor.predict_session(payload).model_dump(mode="json")

        # Module 4 is decision-only. This function does not execute anything.
        decision = decide(prediction)

        reports.append({
            "session_id": str(session_id),
            "source_ips": sorted({
                str(ip) for ip in session_df["source_ip"].dropna().tolist()
            }),
            "event_count": int(len(session_df)),
            "commands_observed": commands,
            "risk_scoring_method": (
                "Local transparent keyword heuristic; not verified ground truth."
            ),
            "raw_features": raw_features,
            "module3_prediction": prediction,
            "module4_decision": decision,
        })

        print(
            f"Session {session_id}: "
            f"classification={prediction['classification']['predicted_label']}, "
            f"confidence={prediction['classification']['confidence']}, "
            f"intents={prediction['intent']['detected_intents']}, "
            f"strategy={decision['selected_strategy']}, "
            f"execution={decision['execution_status']}"
        )

    result = {
        "report_version": "1.0",
        "mode": "offline_historical_log_demo",
        "source_log_directory": str(COWRIE_LOG_DIR),
        "source_log_files": source_files,
        "command_events_processed": int(len(df)),
        "sessions_processed": len(reports),
        "safety": {
            "commands_executed": False,
            "cowrie_configuration_changed": False,
            "deception_response_executed": False,
            "module4_execution_status": "pending",
        },
        "limitations": [
            "Historical Cowrie logs are used; this is not live monitoring.",
            "Local source IPs such as 127.0.0.1 indicate local test activity.",
            "Risk scores are heuristic demo features, not ground-truth labels.",
            "Module 3 model metadata states that the model is not production validated.",
            "SHAP is an explanation of model behavior, not proof of malicious intent.",
            "Only Cowrie command-input events are aggregated in this adapter.",
            "Kernel process telemetry is not session-correlated in this demo.",
        ],
        "sessions": reports,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"\nIntegration report saved to: {OUTPUT_PATH}")
    print("Safety check: no deception response was executed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"INTEGRATION ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise

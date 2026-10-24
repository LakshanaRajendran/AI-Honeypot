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

import argparse
import json
import math
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE3_ROOT = PROJECT_ROOT / "module3_ai_xai_engine"
DEFAULT_COWRIE_LOG_DIR = Path.home() / "cowrie" / "var" / "log" / "cowrie"
SAMPLE_COWRIE_LOG_DIR = PROJECT_ROOT / "data" / "sample_cowrie_logs"

OUTPUT_PATH = PROJECT_ROOT / "output" / "cowrie_integration_demo.json"


def resolve_cowrie_log_dir(custom_path: str | Path | None = None) -> Path:
    """Resolve Cowrie log directory with portable fallback for teammate laptops."""
    if custom_path:
        p = Path(custom_path).expanduser().resolve()
        if p.is_dir():
            return p
    env_dir = os.environ.get("COWRIE_LOG_DIR")
    if env_dir:
        p = Path(env_dir).expanduser().resolve()
        if p.is_dir():
            return p
    if DEFAULT_COWRIE_LOG_DIR.is_dir() and any(DEFAULT_COWRIE_LOG_DIR.glob("cowrie.json*")):
        return DEFAULT_COWRIE_LOG_DIR
    if SAMPLE_COWRIE_LOG_DIR.is_dir() and any(SAMPLE_COWRIE_LOG_DIR.glob("cowrie.json*")):
        return SAMPLE_COWRIE_LOG_DIR
    return DEFAULT_COWRIE_LOG_DIR


# Make Module 3's local imports (config, models, schemas, etc.) resolve
# to the Module 3 implementation, not another module's similarly named files.
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(MODULE3_ROOT))

from config import MODULE2_CANONICAL_FEATURE_NAMES  # noqa: E402
from models.two_output_predictor import TwoOutputPredictor  # noqa: E402
from module4_decision_engine.decision_engine import decide  # noqa: E402
from module4_decision_engine.execution_adapter import simulate_decision  # noqa: E402
from training.cowrie_adapter import CowrieSessionAdapter, parse_iso_timestamp  # noqa: E402


def read_cowrie_commands(log_dir: Path | None = None) -> tuple[list[dict], list[str]]:
    """Read command.input events from existing Cowrie JSON logs."""
    target_dir = log_dir or resolve_cowrie_log_dir()
    if not target_dir.is_dir():
        raise FileNotFoundError(
            f"Cowrie log directory not found: {target_dir}. "
            "Please ensure ~/cowrie or data/sample_cowrie_logs exists."
        )

    log_files = sorted(
        p for p in target_dir.glob("cowrie.json*") if p.is_file()
    )
    if not log_files:
        raise FileNotFoundError(
            f"No cowrie.json log files found in {target_dir}"
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
                if not isinstance(command, str) or not command.strip():
                    continue

                events.append({
                    "timestamp": timestamp if isinstance(timestamp, str) else "",
                    "session": session_id.strip(),
                    "source_ip": event.get("src_ip", "unknown"),
                    "command": command.strip(),
                })

    print(f"Cowrie log files examined: {len(log_files)}")
    print(f"Malformed JSON lines skipped: {malformed_lines}")
    print(f"Command events selected: {len(events)}")

    return events, [p.name for p in log_files]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cowrie Honeypot to Module 4 Pipeline Demo")
    parser.add_argument("--log-dir", help="Path to Cowrie log directory or sample directory", default=None)
    args = parser.parse_args(argv)

    log_dir = resolve_cowrie_log_dir(args.log_dir)
    print(f"Cowrie log source directory: {log_dir}")
    events, source_files = read_cowrie_commands(log_dir)

    if not events:
        print("No usable Cowrie command-input events were found.")
        return 1

    # Group commands and timestamps by session
    sessions_data: dict[str, dict] = defaultdict(lambda: {
        "session_id": "",
        "source_ips": set(),
        "commands": [],
        "timestamps": [],
    })

    for ev in events:
        sid = ev["session"]
        sess = sessions_data[sid]
        sess["session_id"] = sid
        if ev.get("source_ip"):
            sess["source_ips"].add(str(ev["source_ip"]))
        sess["commands"].append(ev["command"])
        ts_obj = parse_iso_timestamp(ev.get("timestamp"))
        if ts_obj is not None:
            sess["timestamps"].append(ts_obj)

    # Filter sessions with at least one command
    usable_sessions = [
        s for s in sessions_data.values() if len(s["commands"]) >= 1
    ]
    usable_sessions.sort(key=lambda s: s["session_id"])

    if not usable_sessions:
        print("No valid command sessions remain after aggregation.")
        return 1

    # Initialize Module 3 canonical Cowrie adapter with deterministic heuristic enrichment
    adapter = CowrieSessionAdapter(enable_heuristic_enrichment=True)

    # Predictor loads its own saved Module 3 models and scaler.
    model_dir = MODULE3_ROOT / "experiments" / "two_output_model_v1"
    predictor = TwoOutputPredictor(model_dir=model_dir)

    reports = []
    print(f"Usable sessions: {len(usable_sessions)}")

    for sess_info in usable_sessions:
        session_id = sess_info["session_id"]
        commands = sess_info["commands"]
        timestamps = sorted(sess_info["timestamps"])
        source_ips = sorted(sess_info["source_ips"])

        # Construct session dictionary conforming to CowrieSessionAdapter schema
        session_dict = {
            "session_id": session_id,
            "commands": commands,
            "timestamps": timestamps,
            "src_ip": source_ips[0] if source_ips else "unknown",
        }

        # Canonical 26-feature extraction and provenance tracking
        raw, provenance = adapter.compute_session_features(session_dict)

        # Ensure all canonical features exist and are ordinary finite numbers.
        raw_features = {}
        for name in MODULE2_CANONICAL_FEATURE_NAMES:
            value = raw.get(name, 0.0)
            number = float(value)
            if not math.isfinite(number):
                number = 0.0
            raw_features[name] = number

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

        # Module 4 rule-based decision engine
        decision = decide(prediction)

        # Module 4 simulation-only execution adapter
        simulation = simulate_decision(decision)

        reports.append({
            "session_id": str(session_id),
            "source_ips": source_ips,
            "event_count": int(len(commands)),
            "commands_observed": commands,
            "feature_provenance": provenance,
            "raw_features": raw_features,
            "module3_prediction": prediction,
            "module4_decision": decision,
            "module4_simulation": simulation,
        })

        conf = prediction["classification"]["confidence"]
        conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else "N/A"
        print(
            f"Session {session_id}: "
            f"classification={prediction['classification']['predicted_label']}, "
            f"confidence={conf_str}, "
            f"intents={prediction['intent']['detected_intents']}, "
            f"strategy={decision['selected_strategy']}, "
            f"simulation={simulation['status']} ({simulation.get('simulated_profile')})"
        )

    result = {
        "report_version": "1.0",
        "mode": "offline_historical_log_demo",
        "source_log_directory": str(log_dir),
        "source_log_files": source_files,
        "command_events_processed": int(len(events)),
        "sessions_processed": len(reports),
        "safety": {
            "commands_executed": False,
            "cowrie_configuration_changed": False,
            "deception_response_executed": False,
            "module4_execution_status": "simulated_only",
            "live_deception_applied": False,
        },
        "limitations": [
            "Historical Cowrie logs are used; this is not live monitoring.",
            "Local source IPs such as 127.0.0.1 indicate local test activity.",
            "MITRE and risk scores are deterministic heuristic enrichments, not ground-truth labels.",
            "Module 3 model metadata states that the model is not production validated.",
            "SHAP is an explanation of model behavior, not proof of malicious intent.",
            "Only Cowrie command-input events are aggregated in this adapter.",
            "Kernel process telemetry is not session-correlated in this demo.",
            "Module 4 execution adapter operates in simulation-only mode; no live deception profiles are applied.",
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

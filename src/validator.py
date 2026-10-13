from datetime import datetime
from typing import Any, Dict, List, Tuple

REQUIRED_FIELDS = [
    "timestamp",
    "session",
    "source_ip",
    "command",
    "process",
    "risk",
    "score",
    "mitre",
]

OPTIONAL_FIELDS = [
    "network",
    "file_activity",
    "process_activity",
    "auth",
    "parent_process",
    "process_tree",
    "destination_ip",
    "destination_port",
    "bytes_sent",
    "bytes_received",
]

ALLOWED_RISKS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _is_valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return False
    try:
        datetime.fromisoformat(candidate.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _is_valid_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def validate_event(event: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(event, dict):
        return ["Event is not a JSON object"]

    for field in REQUIRED_FIELDS:
        if field not in event or event.get(field) is None:
            errors.append(f"Missing required field: {field}")

    if "session" in event and event.get("session") is not None:
        if not isinstance(event["session"], str) or not event["session"].strip():
            errors.append("Session must be a non-empty string")

    if "timestamp" in event and event.get("timestamp") is not None:
        if not _is_valid_timestamp(event["timestamp"]):
            errors.append("Invalid timestamp format")

    if "source_ip" in event and event.get("source_ip") is not None:
        if not _is_valid_ip(event["source_ip"]):
            errors.append("Invalid source_ip")

    if "command" in event and event.get("command") is not None:
        command = event["command"]
        if not isinstance(command, str) or not command.strip():
            errors.append("Command must be a non-empty string when present")

    if "process" in event and event.get("process") is not None:
        process = event["process"]
        if not isinstance(process, str) or not process.strip():
            errors.append("Process must be a non-empty string when present")

    if "risk" in event and event.get("risk") is not None:
        risk = str(event["risk"]).strip().upper()
        if risk not in ALLOWED_RISKS:
            errors.append("Risk not in allowed set")

    if "score" in event and event.get("score") is not None:
        try:
            float(event["score"])
        except (TypeError, ValueError):
            errors.append("Score is not numeric")

    if "mitre" in event and event.get("mitre") is not None:
        mitre = event["mitre"]
        if not isinstance(mitre, dict):
            errors.append("Mitre field must be an object")
        else:
            if "tactic" in mitre and mitre["tactic"] is not None and not isinstance(mitre["tactic"], str):
                errors.append("MITRE tactic must be a string when present")
            if "technique" in mitre and mitre["technique"] is not None and not isinstance(mitre["technique"], str):
                errors.append("MITRE technique must be a string when present")

    return errors


def validate_events(events: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    valid_events: List[Dict[str, Any]] = []
    invalid_events: List[Dict[str, Any]] = []
    for event in events:
        errors = validate_event(event)
        if errors:
            invalid_events.append({"event": event, "errors": errors})
        else:
            valid_events.append(event)
    return valid_events, invalid_events


if __name__ == "__main__":
    import json

    events = []
    try:
        with open("../data/raw/telemetry.json", "r", encoding="utf-8") as handle:
            events = json.load(handle)
    except Exception:
        pass
    valid, invalid = validate_events(events)
    print("Valid:", len(valid))
    print("Invalid:", len(invalid))

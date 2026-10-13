import json
import warnings
from pathlib import Path
from typing import Any, Dict, List


def load_telemetry(file_path: str) -> List[Dict[str, Any]]:
    """Load telemetry events from a JSON array or JSONL file.

    Returns a list of Python dictionaries. Malformed JSON lines are ignored only
    after being reported via a warning so the caller is not silently losing data.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Telemetry file not found: {path}")

    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return []

    try:
        data = json.loads(text)
        if isinstance(data, list):
            valid = [item for item in data if isinstance(item, dict)]
            if len(valid) != len(data):
                warnings.warn(f"Skipped {len(data) - len(valid)} non-object entries while reading JSON array", RuntimeWarning)
            return valid
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    events: List[Dict[str, Any]] = []
    malformed_lines: List[int] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                malformed_lines.append(line_number)
                continue

            if isinstance(record, dict):
                events.append(record)
            else:
                malformed_lines.append(line_number)

    if malformed_lines:
        warnings.warn(
            f"Skipped malformed telemetry entries on lines: {malformed_lines}. "
            "Valid events were preserved and returned.",
            RuntimeWarning,
        )
    return events


if __name__ == "__main__":
    events = load_telemetry("../data/raw/telemetry.json")
    print("Events loaded:", len(events))
    if events:
        print("First event:", events[0])

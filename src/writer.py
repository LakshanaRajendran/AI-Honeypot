import json
from pathlib import Path
from typing import Any


def save_json(data: Any, output_file: str):
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


if __name__ == "__main__":
    sample = [{"session": "S1", "features": {"a": 1}}]
    save_json(sample, "../output/features/session_features.json")
    print("Wrote sample output")

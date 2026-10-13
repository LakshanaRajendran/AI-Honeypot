import json
from pathlib import Path

from src.reader import load_telemetry


def test_reader_json_array(tmp_path):
    events = [
        {
            "timestamp": "2026-08-01T14:00:01Z",
            "session": "A",
            "source_ip": "10.0.0.1",
            "command": "whoami",
            "process": "whoami",
            "risk": "LOW",
            "score": 1,
            "mitre": {"tactic": "Discovery", "technique": "T1033"},
        }
    ]
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps(events), encoding="utf-8")
    assert load_telemetry(str(path)) == events


def test_reader_jsonl(tmp_path):
    path = tmp_path / "telemetry.jsonl"
    payload = """{"timestamp":"2026-08-01T14:00:01Z","session":"A","source_ip":"10.0.0.1","command":"whoami","process":"whoami","risk":"LOW","score":1,"mitre":{"tactic":"Discovery","technique":"T1033"}}\n{"timestamp":"2026-08-01T14:00:02Z","session":"A","source_ip":"10.0.0.1","command":"ls","process":"ls","risk":"LOW","score":1,"mitre":{"tactic":"Discovery","technique":"T1083"}}\n"""
    path.write_text(payload, encoding="utf-8")
    events = load_telemetry(str(path))
    assert len(events) == 2
    assert events[0]["command"] == "whoami"


def test_reader_reports_malformed_json(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"timestamp": "bad"}\n{broken}\n', encoding="utf-8")
    events = load_telemetry(str(path))
    assert len(events) == 1
    assert events[0]["timestamp"] == "bad"

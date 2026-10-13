import json
from pathlib import Path

from src.feature_extractor import extract_features
from src.sequence_builder import build_sequence
from src.session_builder import group_by_session
from src.cleaner import clean_events_to_df


def test_feature_extraction_uses_session_behavior():
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
        },
        {
            "timestamp": "2026-08-01T14:00:03Z",
            "session": "A",
            "source_ip": "10.0.0.1",
            "command": "ls -la",
            "process": "ls",
            "risk": "LOW",
            "score": 1,
            "mitre": {"tactic": "Discovery", "technique": "T1083"},
        },
        {
            "timestamp": "2026-08-01T14:00:05Z",
            "session": "A",
            "source_ip": "10.0.0.1",
            "command": "curl http://example.com",
            "process": "curl",
            "risk": "HIGH",
            "score": 8,
            "mitre": {"tactic": "Command and Control", "technique": "T1105"},
        },
    ]
    df = clean_events_to_df(events)
    features = extract_features(df)
    assert features["total_events"] == 3
    assert features["command_count"] == 3
    assert features["unique_processes"] >= 2
    assert features["network_utility_ratio"] > 0
    assert features["mean_risk_score"] > 0


def test_session_builder_groups_by_session_and_keeps_order():
    events = [
        {"timestamp": "2026-08-01T14:00:02Z", "session": "B", "source_ip": "10.0.0.2", "command": "ls", "process": "ls", "risk": "LOW", "score": 1, "mitre": {"tactic": "Discovery", "technique": "T1083"}},
        {"timestamp": "2026-08-01T14:00:01Z", "session": "B", "source_ip": "10.0.0.2", "command": "pwd", "process": "pwd", "risk": "LOW", "score": 1, "mitre": {"tactic": "Discovery", "technique": "T1033"}},
        {"timestamp": "2026-08-01T14:00:03Z", "session": "A", "source_ip": "10.0.0.1", "command": "whoami", "process": "whoami", "risk": "LOW", "score": 1, "mitre": {"tactic": "Discovery", "technique": "T1033"}},
    ]
    df = clean_events_to_df(events)
    grouped = group_by_session(df)
    assert set(grouped) == {"A", "B"}
    assert grouped["B"]["command"].tolist() == ["pwd", "ls"]


def test_sequence_is_chronological_and_deterministic():
    events = [
        {"timestamp": "2026-08-01T14:00:03Z", "session": "S", "source_ip": "10.0.0.1", "command": "curl https://example.com", "process": "curl", "risk": "HIGH", "score": 8, "mitre": {"tactic": "Command and Control", "technique": "T1105"}},
        {"timestamp": "2026-08-01T14:00:01Z", "session": "S", "source_ip": "10.0.0.1", "command": "whoami", "process": "whoami", "risk": "LOW", "score": 1, "mitre": {"tactic": "Discovery", "technique": "T1033"}},
        {"timestamp": "2026-08-01T14:00:02Z", "session": "S", "source_ip": "10.0.0.1", "command": "ls -la", "process": "ls", "risk": "LOW", "score": 1, "mitre": {"tactic": "Discovery", "technique": "T1083"}},
    ]
    df = clean_events_to_df(events)
    seq = build_sequence(df)
    assert seq == ["cmd:whoami", "cmd:ls", "cmd:curl"]


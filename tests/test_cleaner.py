import pandas as pd

from src.cleaner import clean_event_dict, clean_events_to_df


def test_clean_event_dict_normalizes_fields():
    event = {
        "timestamp": " 2026-08-01T14:00:01Z ",
        "session": "  A  ",
        "source_ip": " 10.0.0.1 ",
        "command": "  whoami  ",
        "process": " WHOAMI ",
        "risk": " low ",
        "score": "1",
        "mitre": {"tactic": "Discovery", "technique": "T1033"},
    }
    cleaned = clean_event_dict(event)
    assert cleaned["timestamp"] == "2026-08-01T14:00:01Z"
    assert cleaned["session"] == "A"
    assert cleaned["source_ip"] == "10.0.0.1"
    assert cleaned["command"] == "whoami"
    assert cleaned["process"] == "whoami"
    assert cleaned["risk"] == "LOW"
    assert cleaned["score"] == 1.0


def test_clean_events_to_df_removes_duplicates_and_invalid_rows():
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
            "timestamp": "bad",
            "session": "A",
            "source_ip": "10.0.0.1",
            "command": "ls",
            "process": "ls",
            "risk": "MEDIUM",
            "score": "x",
            "mitre": {"tactic": "Discovery"},
        },
    ]
    df = clean_events_to_df(events)
    assert len(df) == 1
    assert df["session"].tolist() == ["A"]
    assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])

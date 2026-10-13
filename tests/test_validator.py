from src.validator import validate_event, validate_events


def test_required_fields_are_enforced():
    event = {
        "timestamp": "2026-08-01T14:00:01Z",
        "session": "A",
        "source_ip": "10.0.0.1",
        "command": "whoami",
        "process": "whoami",
        "risk": "LOW",
        "score": 1,
        "mitre": {"tactic": "Discovery", "technique": "T1033"},
    }
    assert validate_event(event) == []


def test_missing_required_field_is_rejected():
    event = {
        "timestamp": "2026-08-01T14:00:01Z",
        "session": "A",
        "source_ip": "10.0.0.1",
        "command": "whoami",
        "process": "whoami",
        "score": 1,
        "mitre": {"tactic": "Discovery", "technique": "T1033"},
    }
    errors = validate_event(event)
    assert any("Missing required field: risk" in e for e in errors)


def test_optional_fields_do_not_block_valid_events():
    event = {
        "timestamp": "2026-08-01T14:00:01Z",
        "session": "A",
        "source_ip": "10.0.0.1",
        "command": "whoami",
        "process": "whoami",
        "risk": "MEDIUM",
        "score": 5,
        "mitre": {"tactic": "Discovery"},
    }
    errors = validate_event(event)
    assert not errors


def test_invalid_mitre_structure_is_rejected():
    event = {
        "timestamp": "2026-08-01T14:00:01Z",
        "session": "A",
        "source_ip": "10.0.0.1",
        "command": "whoami",
        "process": "whoami",
        "risk": "LOW",
        "score": 1,
        "mitre": "Discovery",
    }
    errors = validate_event(event)
    assert any("Mitre" in e for e in errors)


def test_validate_events_partitions_invalid_records():
    valid, invalid = validate_events([
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
            "session": "",
            "source_ip": "bad",
            "command": "",
            "process": "",
            "risk": "UNKNOWN",
            "score": "abc",
            "mitre": {"tactic": 10},
        },
    ])
    assert len(valid) == 1
    assert len(invalid) == 1

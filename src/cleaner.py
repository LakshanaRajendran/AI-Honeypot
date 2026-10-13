import json
from typing import Any, Dict, List

import pandas as pd


def _normalize_whitespace(value: Any) -> Any:
    if isinstance(value, str):
        return " ".join(value.strip().split())
    return value


def _normalize_mitre(mitre: Any) -> Any:
    if not isinstance(mitre, dict):
        return {}
    normalized = {}
    for key in ("tactic", "technique", "subtechnique"):
        value = mitre.get(key)
        if isinstance(value, str):
            normalized[key] = value.strip()
    return normalized


def clean_event_dict(event: Dict[str, Any]) -> Dict[str, Any]:
    cleaned = dict(event)

    for field in ("timestamp", "session", "source_ip", "command", "process", "risk"):
        value = cleaned.get(field)
        if isinstance(value, str):
            cleaned[field] = _normalize_whitespace(value)

    if isinstance(cleaned.get("session"), str):
        cleaned["session"] = cleaned["session"].strip()
    if isinstance(cleaned.get("source_ip"), str):
        cleaned["source_ip"] = cleaned["source_ip"].strip()
    if isinstance(cleaned.get("command"), str):
        cleaned["command"] = cleaned["command"].strip()
    if isinstance(cleaned.get("process"), str):
        cleaned["process"] = cleaned["process"].strip().lower()
    if isinstance(cleaned.get("risk"), str):
        cleaned["risk"] = cleaned["risk"].strip().upper()
    if isinstance(cleaned.get("timestamp"), str):
        cleaned["timestamp"] = cleaned["timestamp"].strip()
    if isinstance(cleaned.get("mitre"), dict):
        cleaned["mitre"] = _normalize_mitre(cleaned["mitre"])

    if cleaned.get("score") is not None:
        try:
            cleaned["score"] = float(cleaned["score"])
        except (TypeError, ValueError):
            cleaned["score"] = None

    return cleaned


def clean_events_to_df(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Return a cleaned, deduplicated DataFrame ready for feature extraction."""
    cleaned_events = [clean_event_dict(event) for event in events if isinstance(event, dict)]
    if not cleaned_events:
        return pd.DataFrame()

    df = pd.DataFrame(cleaned_events)

    required_columns = ["timestamp", "session", "source_ip", "command", "process", "risk", "score", "mitre"]
    for column in required_columns:
        if column not in df.columns:
            df[column] = None

    if "mitre" in df.columns:
        df["__mitre_signature__"] = df["mitre"].apply(lambda value: json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value))
        duplicate_subset = [column for column in df.columns if column != "mitre" and column != "__mitre_signature__"]
        df = df.drop_duplicates(subset=duplicate_subset + ["__mitre_signature__"], ignore_index=True)
        df = df.drop(columns=["__mitre_signature__"])
    else:
        df = df.drop_duplicates(ignore_index=True)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    if "session" in df.columns:
        df["session"] = df["session"].astype(str).str.strip()
    if "source_ip" in df.columns:
        df["source_ip"] = df["source_ip"].astype(str).str.strip()
    if "command" in df.columns:
        df["command"] = df["command"].apply(lambda value: " ".join(str(value).strip().split()) if isinstance(value, str) else None)
    if "process" in df.columns:
        df["process"] = df["process"].apply(lambda value: str(value).strip().lower() if isinstance(value, str) else None)
    if "risk" in df.columns:
        df["risk"] = df["risk"].apply(lambda value: str(value).strip().upper() if isinstance(value, str) else None)
    if "score" in df.columns:
        df["score"] = pd.to_numeric(df["score"], errors="coerce")

    if "mitre" in df.columns:
        df["mitre_tactic"] = df["mitre"].apply(lambda value: value.get("tactic") if isinstance(value, dict) else None)
        df["mitre_technique"] = df["mitre"].apply(lambda value: value.get("technique") if isinstance(value, dict) else None)

    df = df.dropna(subset=["timestamp", "session", "command", "process", "risk", "score"])
    if "source_ip" in df.columns:
        df = df[df["source_ip"].astype(str).str.len() > 0]

    df = df.sort_values(["session", "timestamp"], kind="mergesort").reset_index(drop=True)
    return df


if __name__ == "__main__":
    sample = [
        {
            "timestamp": " 2026-08-01T14:00:01Z ",
            "session": "  A  ",
            "source_ip": " 10.0.0.1 ",
            "command": " whoami ",
            "process": " WHOAMI ",
            "risk": " low ",
            "score": "1",
            "mitre": {"tactic": "Discovery", "technique": "T1033"},
        }
    ]
    df = clean_events_to_df(sample)
    print(df)


import re
from typing import Dict

import numpy as np
import pandas as pd


NETWORK_PATTERNS = [
    "curl",
    "wget",
    "nc",
    "netcat",
    "ssh",
    "scp",
    "ftp",
    "telnet",
    "nmap",
    "ping",
]
FILE_PATTERNS = ["cat", "less", "more", "head", "tail", "grep", "find", "sed", "awk"]
IDENTITY_PATTERNS = ["whoami", "id", "hostname", "uname", "who"]
CREDENTIAL_PATTERNS = ["passwd", "shadow", "id_rsa", "authorized_keys", "credential", "sudoers"]
DOWNLOAD_PATTERNS = ["curl", "wget", "scp", "ftp", "tftp"]


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator / denominator)


def _normalize_command(value: str) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def extract_features(session_df) -> Dict:
    """Compute behavior-oriented telemetry features for a single session."""
    if session_df is None or session_df.empty:
        return {}

    session_df = session_df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    total_events = len(session_df)
    commands = session_df["command"].fillna("").astype(str)
    commands_lower = commands.map(_normalize_command)
    processes = session_df["process"].fillna("").astype(str)

    features: Dict = {}
    features["total_events"] = int(total_events)
    features["command_count"] = int(total_events)
    features["unique_commands"] = int(commands.nunique(dropna=True))
    features["unique_processes"] = int(processes.nunique(dropna=True))
    features["unique_mitre_tactics"] = int(session_df["mitre_tactic"].nunique(dropna=True)) if "mitre_tactic" in session_df.columns else 0
    features["unique_mitre_techniques"] = int(session_df["mitre_technique"].nunique(dropna=True)) if "mitre_technique" in session_df.columns else 0

    timestamps = pd.to_datetime(session_df["timestamp"], errors="coerce") if "timestamp" in session_df.columns else pd.Series([pd.NaT] * total_events)
    if total_events > 0:
        start = timestamps.min()
        end = timestamps.max()
        session_duration = (end - start).total_seconds() if pd.notna(start) and pd.notna(end) else 0.0
    else:
        session_duration = 0.0
    features["session_duration_seconds"] = float(session_duration)

    if total_events > 1:
        intervals = timestamps.dropna().diff().dt.total_seconds().dropna()
        if not intervals.empty:
            features["mean_inter_event_seconds"] = float(intervals.mean())
            features["std_inter_event_seconds"] = float(intervals.std(ddof=0)) if not intervals.empty else 0.0
            features["min_inter_event_seconds"] = float(intervals.min())
            features["max_inter_event_seconds"] = float(intervals.max())
        else:
            features["mean_inter_event_seconds"] = 0.0
            features["std_inter_event_seconds"] = 0.0
            features["min_inter_event_seconds"] = 0.0
            features["max_inter_event_seconds"] = 0.0
    else:
        features["mean_inter_event_seconds"] = 0.0
        features["std_inter_event_seconds"] = 0.0
        features["min_inter_event_seconds"] = 0.0
        features["max_inter_event_seconds"] = 0.0

    features["commands_per_minute"] = float(total_events / (session_duration / 60.0)) if session_duration > 0 else 0.0

    if total_events > 0:
        features["path_command_ratio"] = _safe_ratio(int(commands_lower.str.contains("/", regex=False).sum()), total_events)
        features["pipe_ratio"] = _safe_ratio(int(commands_lower.str.contains("|", regex=False).sum()), total_events)
        features["redirect_ratio"] = _safe_ratio(int(commands_lower.str.contains(r">|>>|2>", regex=True).sum()), total_events)
        features["mean_command_length"] = float(commands.str.len().fillna(0).mean())
        features["mean_argument_count"] = float(commands.map(lambda value: len(str(value).split()) - 1 if str(value).strip() else 0).mean())
    else:
        features["path_command_ratio"] = 0.0
        features["pipe_ratio"] = 0.0
        features["redirect_ratio"] = 0.0
        features["mean_command_length"] = 0.0
        features["mean_argument_count"] = 0.0

    def _ratio_for_patterns(patterns):
        matches = 0
        for pattern in patterns:
            matches += int(commands_lower.str.contains(re.escape(pattern), regex=True).sum())
        return _safe_ratio(matches, total_events)

    features["network_utility_ratio"] = _ratio_for_patterns(NETWORK_PATTERNS)
    features["file_inspection_ratio"] = _ratio_for_patterns(FILE_PATTERNS)
    features["identity_command_ratio"] = _ratio_for_patterns(IDENTITY_PATTERNS)
    features["credential_keyword_ratio"] = _ratio_for_patterns(CREDENTIAL_PATTERNS)
    features["download_utility_ratio"] = _ratio_for_patterns(DOWNLOAD_PATTERNS)

    if "score" in session_df.columns:
        scores = pd.to_numeric(session_df["score"], errors="coerce").dropna()
        features["mean_risk_score"] = float(scores.mean()) if not scores.empty else 0.0
        features["max_risk_score"] = float(scores.max()) if not scores.empty else 0.0
        features["risk_score_std"] = float(scores.std(ddof=0)) if not scores.empty else 0.0
    else:
        features["mean_risk_score"] = 0.0
        features["max_risk_score"] = 0.0
        features["risk_score_std"] = 0.0

    if "risk" in session_df.columns:
        risk_values = session_df["risk"].fillna("").astype(str).str.upper()
        high_count = int(risk_values.isin(["HIGH", "CRITICAL"]).sum())
        features["high_or_critical_ratio"] = _safe_ratio(high_count, total_events)
    else:
        features["high_or_critical_ratio"] = 0.0

    return features


if __name__ == "__main__":
    import json
    from pathlib import Path

    data = json.loads(Path("../data/raw/telemetry.json").read_text(encoding="utf-8"))
    import pandas as pd

    df = pd.DataFrame(data)
    if not df.empty:
        print(extract_features(df))

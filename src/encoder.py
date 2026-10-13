import json
from pathlib import Path
from typing import Dict, List

FEATURE_ORDER: List[str] = [
    "total_events",
    "command_count",
    "unique_commands",
    "unique_processes",
    "unique_mitre_tactics",
    "unique_mitre_techniques",
    "session_duration_seconds",
    "mean_inter_event_seconds",
    "std_inter_event_seconds",
    "min_inter_event_seconds",
    "max_inter_event_seconds",
    "commands_per_minute",
    "network_utility_ratio",
    "file_inspection_ratio",
    "identity_command_ratio",
    "credential_keyword_ratio",
    "download_utility_ratio",
    "mean_risk_score",
    "max_risk_score",
    "risk_score_std",
    "high_or_critical_ratio",
    "path_command_ratio",
    "pipe_ratio",
    "redirect_ratio",
    "mean_command_length",
    "mean_argument_count",
]

FEATURE_DESCRIPTIONS = {
    "total_events": "Total telemetry events in the session.",
    "command_count": "Number of commands observed in the session.",
    "unique_commands": "Distinct command strings seen in the session.",
    "unique_processes": "Distinct process names observed in the session.",
    "unique_mitre_tactics": "Distinct MITRE tactic labels seen in the session.",
    "unique_mitre_techniques": "Distinct MITRE technique labels seen in the session.",
    "session_duration_seconds": "Elapsed time from first to last event in seconds.",
    "mean_inter_event_seconds": "Average delay between telemetry events.",
    "std_inter_event_seconds": "Standard deviation of inter-event timing.",
    "min_inter_event_seconds": "Minimum inter-event delay in seconds.",
    "max_inter_event_seconds": "Maximum inter-event delay in seconds.",
    "commands_per_minute": "Command rate normalized per minute.",
    "network_utility_ratio": "Fraction of commands using network-related utilities.",
    "file_inspection_ratio": "Fraction of commands using file inspection utilities.",
    "identity_command_ratio": "Fraction of commands exposing local identity or host information.",
    "credential_keyword_ratio": "Fraction of commands containing credential-related keywords.",
    "download_utility_ratio": "Fraction of commands using file download utilities.",
    "mean_risk_score": "Average telemetry risk score for the session.",
    "max_risk_score": "Highest risk score observed in the session.",
    "risk_score_std": "Standard deviation of risk scores in the session.",
    "high_or_critical_ratio": "Fraction of events at HIGH or CRITICAL risk level.",
    "path_command_ratio": "Fraction of commands using explicit paths.",
    "pipe_ratio": "Fraction of commands using shell pipes.",
    "redirect_ratio": "Fraction of commands redirecting output.",
    "mean_command_length": "Average command length in characters.",
    "mean_argument_count": "Average argument count per command.",
}


def encode_feature_vector(raw_features: Dict) -> List[float]:
    vector: List[float] = []
    for name in FEATURE_ORDER:
        value = raw_features.get(name)
        if value is None:
            vector.append(0.0)
            continue
        try:
            vector.append(float(value))
        except (TypeError, ValueError):
            vector.append(0.0)
    return vector


def save_feature_schema(output_path: str):
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    features = [
        {
            "index": index,
            "name": name,
            "type": "numeric",
            "description": FEATURE_DESCRIPTIONS.get(name, "Telemetry-derived behavioral feature."),
            "source": "session_aggregation",
        }
        for index, name in enumerate(FEATURE_ORDER)
    ]
    schema = {"schema_version": "1.0", "features": features, "feature_names": FEATURE_ORDER}
    path.write_text(json.dumps(schema, indent=2), encoding="utf-8")


if __name__ == "__main__":
    save_feature_schema("../output/feature_schema.json")
    print("Saved feature schema with", len(FEATURE_ORDER), "features")

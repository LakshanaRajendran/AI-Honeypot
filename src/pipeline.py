"""TFEE pipeline entrypoint.

Run with: python -m src.pipeline
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

from src.cleaner import clean_events_to_df
from src.encoder import FEATURE_ORDER, encode_feature_vector, save_feature_schema
from src.feature_extractor import extract_features
from src.normalizer import fit_and_save_scaler, load_scaler, transform_with_scaler
from src.reader import load_telemetry
from src.sequence_builder import build_sequence
from src.session_builder import group_by_session
from src.validator import validate_events
from src.writer import save_json


def run_pipeline(input_file: str = "data/raw/telemetry.json", mode: str = "dev"):
    """Run the telemetry feature engineering pipeline.

    mode options:
    - dev: fits a scaler if one is missing; useful during local development
    - fit-scaler: explicitly fits and saves the scaler
    - inference: requires an existing scaler and does not silently refit it
    """
    events = load_telemetry(input_file)
    input_count = len(events)
    print("Raw events:", input_count)

    valid_events, invalid_events = validate_events(events)
    print("Valid events:", len(valid_events))
    print("Invalid events:", len(invalid_events))

    df_clean = clean_events_to_df(valid_events)
    cleaned_count = len(df_clean)
    duplicates_removed = max(len(valid_events) - cleaned_count, 0)
    print("Cleaned rows:", cleaned_count)

    Path("data/processed").mkdir(parents=True, exist_ok=True)
    df_clean.to_json("data/processed/cleaned_events.json", orient="records", indent=2, date_format="iso")

    sessions = group_by_session(df_clean)
    print("Sessions:", len(sessions))

    raw_feature_rows = []
    session_ids = []
    sequences = []
    out_records = []
    for session_id, session_df in sorted(sessions.items()):
        raw = extract_features(session_df)
        seq = build_sequence(session_df)
        session_ids.append(session_id)
        sequences.append(seq)
        raw_feature_rows.append([raw.get(name, 0.0) for name in FEATURE_ORDER])

    if raw_feature_rows:
        df_features = pd.DataFrame(raw_feature_rows, columns=FEATURE_ORDER)
    else:
        df_features = pd.DataFrame(columns=FEATURE_ORDER)

    save_feature_schema("output/feature_schema.json")

    scaler = load_scaler("output/feature_scaler.joblib")
    if mode == "fit-scaler":
        if df_features.empty:
            raise RuntimeError("No features to fit scaler on")
        scaler = fit_and_save_scaler(df_features, "output/feature_scaler.joblib")
        print("Fitted scaler and saved to output/feature_scaler.joblib")
        scaled = transform_with_scaler(df_features, scaler)
    elif mode == "inference":
        if scaler is None:
            raise RuntimeError("Scaler not found for inference mode. Run with --mode fit-scaler first.")
        scaled = transform_with_scaler(df_features, scaler) if not df_features.empty else []
    elif mode == "dev":
        if scaler is None and not df_features.empty:
            scaler = fit_and_save_scaler(df_features, "output/feature_scaler.joblib")
            print("Fitted scaler (dev) and saved to output/feature_scaler.joblib")
        scaled = transform_with_scaler(df_features, scaler) if scaler is not None and not df_features.empty else []
    else:
        raise ValueError(f"Unknown mode: {mode}")

    for index, session_id in enumerate(session_ids):
        raw = extract_features(sessions[session_id])
        sequence = sequences[index]
        feature_vector = encode_feature_vector(raw)
        if isinstance(scaled, list):
            if index < len(scaled):
                feature_vector = [float(value) for value in scaled[index]]
        elif hasattr(scaled, "__len__") and len(scaled) > index:
            feature_vector = [float(value) for value in scaled[index]]

        out = {
            "schema_version": "1.0",
            "session_id": session_id,
            "feature_count": len(FEATURE_ORDER),
            "feature_names": FEATURE_ORDER,
            "feature_vector": feature_vector,
            "sequence": sequence,
            "raw_features": raw,
        }
        out_records.append(out)

    Path("output").mkdir(parents=True, exist_ok=True)
    save_json(out_records, "output/feature_vector.json")
    print("Wrote output/feature_vector.json")

    report = {
        "input_events": input_count,
        "valid_events": len(valid_events),
        "rejected_events": len(invalid_events),
        "sessions": len(sessions),
        "feature_count": len(FEATURE_ORDER),
        "missing_values": int(df_features.isna().sum().sum()) if not df_features.empty else 0,
        "duplicate_events_removed": int(duplicates_removed),
        "schema_version": "1.0",
    }
    save_json(report, "output/feature_quality_report.json")
    print("Wrote output/feature_quality_report.json")
    return out_records


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the TFEE feature-engineering pipeline")
    parser.add_argument("--mode", choices=["fit-scaler", "inference", "dev"], default="dev", help="Pipeline execution mode")
    parser.add_argument("--fit-scaler", dest="fit_scaler", action="store_true", help="Explicitly fit and save the scaler before inference")
    parser.add_argument("--input", default="data/raw/telemetry.json", help="Input telemetry file")
    args = parser.parse_args(argv)

    mode = args.mode
    if args.fit_scaler:
        mode = "fit-scaler"

    try:
        run_pipeline(input_file=args.input, mode=mode)
    except Exception as exc:  # pragma: no cover
        print("ERROR:", exc, file=sys.stderr)
        raise


if __name__ == "__main__":
    main()

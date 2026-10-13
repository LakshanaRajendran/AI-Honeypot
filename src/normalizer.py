from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

SCALER_FILENAME = "output/feature_scaler.joblib"


def normalize_events(events):
    df = pd.DataFrame(events)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values(["session", "timestamp"], kind="mergesort").reset_index(drop=True)
    return df


def fit_and_save_scaler(df_features: pd.DataFrame, scaler_path: Optional[str] = None) -> StandardScaler:
    if df_features.empty:
        raise ValueError("Cannot fit a scaler without feature rows")
    scaler = StandardScaler()
    scaler.fit(df_features.values)
    path = scaler_path or SCALER_FILENAME
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, path)
    return scaler


def load_scaler(scaler_path: Optional[str] = None) -> Optional[StandardScaler]:
    path = scaler_path or SCALER_FILENAME
    p = Path(path)
    if not p.exists():
        return None
    return joblib.load(p)


def transform_with_scaler(df_features: pd.DataFrame, scaler: StandardScaler) -> np.ndarray:
    return scaler.transform(df_features.values)


if __name__ == "__main__":
    import json

    p = Path("../data/raw/telemetry.json")
    if p.exists():
        events = json.loads(p.read_text(encoding="utf-8"))
    else:
        events = []
    df = normalize_events(events)
    print("DataFrame created:", df.shape)

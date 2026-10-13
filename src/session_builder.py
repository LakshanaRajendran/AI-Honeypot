from typing import Dict

import pandas as pd


def group_by_session(df: pd.DataFrame) -> Dict[str, pd.DataFrame]:
    """Group a cleaned DataFrame by session and preserve chronological order."""
    sessions: Dict[str, pd.DataFrame] = {}
    if df is None or df.empty:
        return sessions
    for session_id, session_df in df.groupby("session", sort=True):
        sessions[session_id] = session_df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    return sessions


if __name__ == "__main__":
    print("session_builder module")

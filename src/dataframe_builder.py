from typing import Any, Dict, List

import pandas as pd

from src.cleaner import clean_events_to_df


def build_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """Build the canonical cleaned DataFrame for feature engineering."""
    return clean_events_to_df(events)


__all__ = ["build_dataframe"]

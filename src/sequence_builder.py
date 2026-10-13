from typing import List


def build_sequence(session_df) -> List[str]:
    """Build a chronological, deterministic command sequence for a session."""
    sequence: List[str] = []
    if session_df is None or session_df.empty:
        return sequence

    ordered = session_df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    for _, row in ordered.iterrows():
        command = row.get("command")
        if not isinstance(command, str):
            continue
        command = command.strip()
        if not command:
            continue
        name = command.split()[0]
        sequence.append(f"cmd:{name}")
    return sequence


if __name__ == "__main__":
    print(build_sequence([]))

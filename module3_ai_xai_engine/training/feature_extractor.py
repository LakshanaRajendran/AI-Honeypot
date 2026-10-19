"""
Feature Extractor module for the AI Decision & XAI Engine.

Provides the FeatureExtractor class that converts grouped attacker
sessions into numerical feature dictionaries for machine learning.
"""

from datetime import datetime
from typing import Any


class FeatureExtractor:
    """Extracts numerical features from grouped attacker sessions.

    Each session is analysed for authentication attempts, command
    usage, file activity, and basic session metadata.  The result
    is a flat dictionary of numeric values per session.
    """

    # ISO-8601 timestamp format used by Cowrie logs (without trailing Z).
    _TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

    def extract_features(self, sessions: list[dict]) -> list[dict[str, Any]]:
        """Extract numerical features from a list of attacker sessions.

        Parameters
        ----------
        sessions : list[dict]
            Session list produced by SessionBuilder.  Each item must
            contain ``session_id`` and ``events`` keys.

        Returns
        -------
        list[dict[str, Any]]
            Feature dictionaries with the following keys:

            - session_id
            - session_duration
            - total_events
            - failed_login_count
            - successful_login_count
            - command_count
            - unique_command_count
            - download_count
            - unique_event_types
        """
        features: list[dict[str, Any]] = []

        for session in sessions:
            session_id = session.get("session_id", "unknown")
            events = session.get("events", [])

            feature = self._extract_session(session_id, events)
            features.append(feature)

        return features

    # ------------------------------------------------------------------
    # Per-session extraction
    # ------------------------------------------------------------------

    def _extract_session(
        self,
        session_id: str,
        events: list[dict],
    ) -> dict[str, Any]:
        """Compute all features for a single session.

        Parameters
        ----------
        session_id : str
            The session identifier.
        events : list[dict]
            All events belonging to this session.

        Returns
        -------
        dict[str, Any]
            Feature dictionary for the session.
        """
        return {
            "session_id": session_id,
            "session_duration": self._compute_duration(events),
            "total_events": len(events),
            "failed_login_count": self._count_by_eventid(events, "login.failed"),
            "successful_login_count": self._count_by_eventid(events, "login.success"),
            "command_count": self._count_by_eventid(events, "command.input"),
            "unique_command_count": self._count_unique_commands(events),
            "download_count": self._count_by_eventid(events, "download"),
            "unique_event_types": self._count_unique_event_types(events),
        }

    # ------------------------------------------------------------------
    # Individual feature helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_duration(events: list[dict]) -> float:
        """Calculate session duration from event timestamps.

        Uses the first and last available timestamp in the event list.
        Falls back to 0 if no timestamps can be parsed.

        Parameters
        ----------
        events : list[dict]
            Session events.

        Returns
        -------
        float
            Duration in seconds, or 0.0 on failure.
        """
        timestamps: list[float] = []

        for event in events:
            ts_str = event.get("timestamp")
            if ts_str and isinstance(ts_str, str):
                try:
                    # Remove trailing 'Z' before parsing
                    cleaned = ts_str.rstrip("Z")
                    dt = datetime.strptime(cleaned, FeatureExtractor._TIMESTAMP_FORMAT)
                    timestamps.append(dt.timestamp())
                except (ValueError, TypeError):
                    continue

        if len(timestamps) < 2:
            return 0.0

        return max(timestamps) - min(timestamps)

    @staticmethod
    def _count_by_eventid(events: list[dict], substring: str) -> int:
        """Count events whose ``eventid`` field contains *substring*.

        Parameters
        ----------
        events : list[dict]
            Session events.
        substring : str
            Substring to look for in the eventid.

        Returns
        -------
        int
            Number of matching events.
        """
        count = 0
        for event in events:
            eid = event.get("eventid", "")
            if isinstance(eid, str) and substring in eid:
                count += 1
        return count

    @staticmethod
    def _count_unique_commands(events: list[dict]) -> int:
        """Count the number of distinct ``input`` command strings.

        Only considers events whose ``eventid`` contains
        ``"command.input"`` and whose ``input`` field is a
        non-empty string.

        Parameters
        ----------
        events : list[dict]
            Session events.

        Returns
        -------
        int
            Number of unique command strings.
        """
        commands: set[str] = set()

        for event in events:
            eid = event.get("eventid", "")
            if isinstance(eid, str) and "command.input" in eid:
                cmd = event.get("input")
                if isinstance(cmd, str) and cmd.strip():
                    commands.add(cmd.strip())

        return len(commands)

    @staticmethod
    def _count_unique_event_types(events: list[dict]) -> int:
        """Count the number of distinct ``eventid`` values.

        Parameters
        ----------
        events : list[dict]
            Session events.

        Returns
        -------
        int
            Number of different event types.
        """
        types: set[str] = set()

        for event in events:
            eid = event.get("eventid")
            if isinstance(eid, str) and eid.strip():
                types.add(eid.strip())

        return len(types)


if __name__ == "__main__":
    from parse_cowrie import CowrieParser
    from session_builder import SessionBuilder

    parser = CowrieParser()
    events = parser.parse_directory(
        r"D:\MINIPROJECT\module3_ai_xai_engine\data\raw",
        max_files=2,
    )

    builder = SessionBuilder()
    sessions = builder.build_sessions(events)

    extractor = FeatureExtractor()
    features = extractor.extract_features(sessions)

    print(features[0])


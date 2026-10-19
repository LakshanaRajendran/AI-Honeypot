"""
Session Builder module for the AI Decision & XAI Engine.

Provides the SessionBuilder class that groups a flat list of Cowrie
event dictionaries into per-session event lists, preserving the
original event order within each session.
"""

from typing import Any


class SessionBuilder:
    """Groups raw Cowrie events into attacker sessions.

    Each session is identified by a Cowrie session ID extracted from
    the event dictionary.  Events that lack a session identifier are
    skipped and counted.
    """

    # Ordered list of possible keys that may hold the session identifier.
    _SESSION_KEYS = ["session", "session_id"]

    def build_sessions(self, events: list[dict]) -> list[dict[str, Any]]:
        """Group events by their Cowrie session identifier.

        Parameters
        ----------
        events : list[dict]
            Flat list of Cowrie event dictionaries from CowrieParser.

        Returns
        -------
        list[dict[str, Any]]
            A list of session dictionaries, each containing:
            - ``session_id`` : str
            - ``events``     : list[dict]  (in original order)
        """
        total_input = len(events)
        sessions: dict[str, list[dict]] = {}
        skipped = 0

        for event in events:
            session_id = self._extract_session_id(event)

            if session_id is None:
                skipped += 1
                continue

            # Preserve original insertion order (Python 3.7+).
            if session_id not in sessions:
                sessions[session_id] = []
            sessions[session_id].append(event)

        # Build the output list in insertion order
        result = [
            {"session_id": sid, "events": evts}
            for sid, evts in sessions.items()
        ]

        total_sessions = len(result)

        print(f"Total input events: {total_input}")
        print(f"Events without session ID skipped: {skipped}")
        print(f"Total sessions created: {total_sessions}")

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @classmethod
    def _extract_session_id(cls, event: dict) -> str | None:
        """Extract the session identifier from an event dictionary.

        Checks possible keys in order of preference:

        #. ``"session"``
        #. ``"session_id"``

        Parameters
        ----------
        event : dict
            A single Cowrie event.

        Returns
        -------
        str or None
            The session ID if found, otherwise ``None``.
        """
        for key in cls._SESSION_KEYS:
            value = event.get(key)
            if value is not None and isinstance(value, str) and value.strip():
                return value
        return None


if __name__ == "__main__":
    from parse_cowrie import CowrieParser

    parser = CowrieParser()
    events = parser.parse_directory(
        r"D:\MINIPROJECT\module3_ai_xai_engine\data\raw",
        max_files=2,
    )

    builder = SessionBuilder()
    sessions = builder.build_sessions(events)

    print(sessions[0])


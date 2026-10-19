"""
Cowrie log parser for the AI Decision & XAI Engine.

Provides the CowrieParser class that reads all Cowrie JSON log
files from a directory tree and returns a single combined list
of parsed event dictionaries.
"""

import json
import pathlib
from typing import Optional


class CowrieParser:
    """Parses Cowrie honeypot JSON log files into a combined event list.

    Recursively scans a directory for files whose name starts with
    ``cowrie.json``, reads each file line-by-line, and parses every
    line as a separate JSON object.
    """

    def parse_directory(
        self,
        directory_path: str,
        max_files: Optional[int] = None,
    ) -> list[dict]:
        """Parse all Cowrie JSON files under *directory_path*.

        Parameters
        ----------
        directory_path : str
            Root directory to search recursively for Cowrie JSON files.
        max_files : int or None, optional
            Maximum number of files to process.  ``None`` means no limit.

        Returns
        -------
        list[dict]
            A single list containing every parsed Cowrie event.
        """
        root = pathlib.Path(directory_path).resolve()

        if not root.is_dir():
            raise NotADirectoryError(
                f"Directory does not exist: {root}"
            )

        # 1. Discover matching files
        cowrie_files = self._discover_files(root, max_files)

        # 2. Process each file
        all_events: list[dict] = []
        total_skipped = 0

        for file_path in cowrie_files:
            events, skipped = self._parse_file(file_path)
            all_events.extend(events)
            total_skipped += skipped

        # 3. Print summary
        print(f"Total files processed: {len(cowrie_files)}")
        print(f"Total events parsed: {len(all_events)}")
        print(f"Total malformed lines skipped: {total_skipped}")

        return all_events

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _discover_files(
        root: pathlib.Path,
        max_files: Optional[int],
    ) -> list[pathlib.Path]:
        """Recursively find files whose name starts with ``cowrie.json``.

        Parameters
        ----------
        root : pathlib.Path
            The directory to search.
        max_files : int or None
            Maximum number of files to return (``None`` = no limit).

        Returns
        -------
        list[pathlib.Path]
            Sorted list of matching file paths.
        """
        matches = sorted(root.rglob("cowrie.json*"))

        if max_files is not None:
            matches = matches[:max_files]

        return matches

    @staticmethod
    def _parse_file(file_path: pathlib.Path) -> tuple[list[dict], int]:
        """Read a single Cowrie JSON file and parse its lines.

        Parameters
        ----------
        file_path : pathlib.Path
            Path to the file to parse.

        Returns
        -------
        tuple[list[dict], int]
            (parsed_events, malformed_lines_skipped).
        """
        events: list[dict] = []
        skipped = 0

        try:
            with file_path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        event = json.loads(stripped)
                        if isinstance(event, dict):
                            events.append(event)
                        else:
                            skipped += 1
                    except json.JSONDecodeError:
                        skipped += 1
        except (OSError, PermissionError) as exc:
            print(f"Warning: could not read {file_path.name}: {exc}")

        return events, skipped


if __name__ == "__main__":
    parser = CowrieParser()
    events = parser.parse_directory(
        r"D:\MINIPROJECT\module3_ai_xai_engine\data\raw",
        max_files=2,
    )
    print(events[:5])


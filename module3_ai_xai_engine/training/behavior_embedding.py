"""
Behavioural Embedding Generator for the AI Decision & XAI Engine.

Provides the BehaviourEmbeddingGenerator class that converts grouped
attacker sessions into fixed-size behavioural embeddings using a
Word2Vec-style approach trained on Cowrie event sequences.

This module is intended ONLY for offline training data preparation
and will NOT be part of the final runtime pipeline.  During
integration, Module 2 will supply the required behaviour
representation directly.
"""

import json
from typing import Any

import numpy as np
from gensim.models import Word2Vec


class BehaviorEmbeddingGenerator:
    """Generate session-level behavioural embeddings from attacker events.

    The generator:

    1. Extracts event type sequences from each session (using the
       ``eventid`` field as the behaviour token).
    2. Trains a Word2Vec model on all extracted sequences to learn
       distributed representations of each event type.
    3. For each session, averages the vectors of all its event types
       to produce a single fixed-size behavioural embedding.

    Parameters
    ----------
    embedding_dim : int, optional
        Dimensionality of the Word2Vec embedding vectors (default 50).
    window : int, optional
        Maximum distance between the current and predicted word within
        a sequence (default 5).
    min_count : int, optional
        Ignores all words with total frequency lower than this
        (default 1 — no filtering).
    workers : int, optional
        Number of worker threads for Word2Vec training (default 1 for
        deterministic behaviour).
    seed : int, optional
        Random seed for reproducible Word2Vec training (default 42).
    """

    def __init__(
        self,
        embedding_dim: int = 50,
        window: int = 5,
        min_count: int = 1,
        workers: int = 1,
        seed: int = 42,
    ) -> None:
        self.embedding_dim = embedding_dim
        self.window = window
        self.min_count = min_count
        self.workers = workers
        self.seed = seed

        # Internal model — populated during generate_embeddings()
        self._model: Word2Vec | None = None
        # Internal vocabulary mapping event_type -> embedding vector
        self._embeddings: dict[str, np.ndarray] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_embeddings(self, sessions: list[dict]) -> list[dict[str, Any]]:
        """Generate session-level behavioural embeddings from attacker sessions.

        The method:

        - Collects all unique event types across sessions.
        - Trains a Word2Vec model on session event sequences.
        - Averages per-event embeddings to produce one vector per session.

        Parameters
        ----------
        sessions : list[dict]
            Session list produced by :class:`SessionBuilder`.  Each item
            must contain ``session_id`` (str) and ``events`` (list[dict]).

        Returns
        -------
        list[dict[str, Any]]
            A list of dictionaries, each containing:

            - ``session_id`` (str) — the original session identifier.
            - ``behavior_embedding`` (list[float]) — the averaged
              embedding vector (length = ``embedding_dim``).

            Sessions with no usable events will receive a zero-vector
            embedding.
        """
        # 1. Convert sessions to event-type sequences
        sequences = self._build_sequences(sessions)

        # 2. Train Word2Vec model on the sequences
        self._train_word2vec(sequences)

        # 3. Generate session-level embeddings
        results: list[dict[str, Any]] = []
        for session, seq in zip(sessions, sequences):
            session_id = session.get("session_id", "unknown")
            session_embedding = self._average_embedding(seq)
            results.append(
                {
                    "session_id": session_id,
                    "behavior_embedding": session_embedding.tolist(),
                }
            )

        return results

    def save_embeddings(self, data: list[dict], output_path: str) -> None:
        """Save behavioural embeddings to a JSON file.

        Each record in the output file contains:

        - ``session_id`` — the session identifier.
        - ``behavior_embedding`` — the averaged embedding vector.

        Parameters
        ----------
        data : list[dict]
            The list of embedding records returned by
            :meth:`generate_embeddings`.
        output_path : str
            Path to the output JSON file.

        Raises
        ------
        IOError
            If the file cannot be written.
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # ------------------------------------------------------------------
    # Sequence extraction helpers
    # ------------------------------------------------------------------

    def _build_sequences(self, sessions: list[dict]) -> list[list[str]]:
        """Convert sessions into lists of event-type tokens.

        For each session, extracts the ``eventid`` from every event.
        Events without a valid ``eventid`` string are silently skipped.

        Parameters
        ----------
        sessions : list[dict]
            Session list from :class:`SessionBuilder`.

        Returns
        -------
        list[list[str]]
            A list of token sequences, one per session, preserving the
            original event order.
        """
        sequences: list[list[str]] = []
        for session in sessions:
            events = session.get("events", [])
            seq = self._extract_event_types(events)
            sequences.append(seq)
        return sequences

    @staticmethod
    def _extract_event_types(events: list[dict]) -> list[str]:
        """Safely extract ``eventid`` tokens from a list of events.

        Parameters
        ----------
        events : list[dict]
            A list of event dictionaries.

        Returns
        -------
        list[str]
            The sequence of valid ``eventid`` strings, preserving order.
            Empty or invalid event IDs are omitted.
        """
        tokens: list[str] = []
        for event in events:
            eid = event.get("eventid")
            if isinstance(eid, str) and eid.strip():
                tokens.append(eid.strip())
        return tokens

    # ------------------------------------------------------------------
    # Word2Vec training helper
    # ------------------------------------------------------------------

    def _train_word2vec(self, sequences: list[list[str]]) -> None:
        """Train a Word2Vec model on the provided event-type sequences.

        After training, stores the learned vectors in
        ``self._embeddings`` for fast lookup.

        Parameters
        ----------
        sequences : list[list[str]]
            Tokenised event sequences, one per session.
        """
        if not sequences or all(len(seq) == 0 for seq in sequences):
            # No data — store empty embedding dict
            self._model = None
            self._embeddings = {}
            return

        model = Word2Vec(
            sentences=sequences,
            vector_size=self.embedding_dim,
            window=self.window,
            min_count=self.min_count,
            workers=self.workers,
            seed=self.seed,
            sg=1,  # Skip-gram (1) works better for infrequent tokens
        )

        self._model = model

        # Extract learned vectors for every token in the vocabulary
        self._embeddings = {
            token: model.wv[token] for token in model.wv.index_to_key
        }

    # ------------------------------------------------------------------
    # Embedding averaging helper
    # ------------------------------------------------------------------

    def _average_embedding(self, event_types: list[str]) -> np.ndarray:
        """Average the embeddings of a sequence of event types.

        Parameters
        ----------
        event_types : list[str]
            A sequence of event-type tokens.

        Returns
        -------
        np.ndarray
            The averaged embedding vector (length = ``embedding_dim``).
            Returns a zero vector if the sequence is empty or none of
            its tokens are in the vocabulary.
        """
        if not event_types or not self._embeddings:
            return np.zeros(self.embedding_dim, dtype=np.float32)

        vectors: list[np.ndarray] = []
        for token in event_types:
            vec = self._embeddings.get(token)
            if vec is not None:
                vectors.append(vec)

        if not vectors:
            return np.zeros(self.embedding_dim, dtype=np.float32)

        return np.mean(vectors, axis=0).astype(np.float32)


if __name__ == "__main__":
    import sys
    import pathlib

    # Ensure the project root is on sys.path so that sibling modules
    # (parse_cowrie, session_builder) can be imported directly.
    project_root = pathlib.Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from parse_cowrie import CowrieParser
    from session_builder import SessionBuilder

    parser = CowrieParser()

    events = parser.parse_directory(
        r"D:\MINIPROJECT\module3_ai_xai_engine\data\raw",
        max_files=2,
    )

    sessions = SessionBuilder().build_sessions(events)

    generator = BehaviorEmbeddingGenerator()

    embeddings = generator.generate_embeddings(sessions)

    print(embeddings[0])


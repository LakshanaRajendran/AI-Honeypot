"""
Training Dataset Builder for the AI Decision & XAI Engine.

Provides the TrainingDatasetBuilder class that combines numerical
behavioural features from FeatureExtractor with behavioural embeddings
from BehaviorEmbeddingGenerator into one final ML training dataset.

This is Step 5 of the training pipeline:

    Cowrie Logs
         ↓
    Parser
         ↓
    Session Builder
         ↓
    Feature Extraction + Behaviour Embedding
         ↓
    Final ML Training Dataset    <-- YOU ARE HERE
"""

import os
from typing import Any

import pandas as pd


class TrainingDatasetBuilder:
    """Combine numerical features and behavioural embeddings into a
    single training-ready dataset.

    Each row in the output dataset corresponds to one attacker session,
    identified by ``session_id``.  Feature columns preserve all values
    from the feature extractor, while the behaviour embedding list is
    expanded into separate columns (``embedding_1`` … ``embedding_N``).
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def combine_features_and_embeddings(
        self,
        features: list[dict[str, Any]],
        embeddings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Merge numerical features and behavioural embeddings by session_id.

        Parameters
        ----------
        features : list[dict]
            Feature dictionaries produced by :class:`FeatureExtractor`.
            Each dict must contain at least ``session_id``.
        embeddings : list[dict]
            Embedding dictionaries produced by
            :class:`BehaviorEmbeddingGenerator`.  Each dict must contain
            ``session_id`` and ``behavior_embedding`` (list[float]).

        Returns
        -------
        list[dict]
            Merged dataset.  Each record contains:

            - ``session_id`` (str)
            - All numerical feature columns from the feature extractor.
            - ``embedding_1`` … ``embedding_N`` (float or None).

        Notes
        -----
        - Sessions present in **both** lists are merged normally.
        - Sessions present **only** in *features* are included with
          ``None`` for all embedding columns (sessions without
          embeddings).
        - Sessions present **only** in *embeddings* are **skipped**
          with a warning because they lack the feature columns required
          for ML training.
        - Original input dictionaries are **never** modified; new output
          dictionaries are created.
        """
        # 1. Build lookup dictionaries (first occurrence wins on duplicates)
        features_by_id: dict[str, dict] = {}
        for f in features:
            sid = f.get("session_id")
            if sid and sid not in features_by_id:
                features_by_id[sid] = f

        embeddings_by_id: dict[str, dict] = {}
        for e in embeddings:
            sid = e.get("session_id")
            if sid and sid not in embeddings_by_id:
                embeddings_by_id[sid] = e

        # 2. Determine embedding dimension from actual data
        embedding_dim = self._resolve_embedding_dim(embeddings)

        # 3. Determine feature column order from the first feature dict
        feature_columns: list[str] = []
        if features:
            feature_columns = [
                k for k in features[0] if k != "session_id"
            ]

        # 4. Merge over the union of all session IDs
        all_session_ids: set[str] = (
            set(features_by_id.keys()) | set(embeddings_by_id.keys())
        )

        merged: list[dict[str, Any]] = []
        sessions_with_embeddings = 0
        sessions_without_embeddings = 0

        for sid in sorted(all_session_ids):
            feat = features_by_id.get(sid)
            emb = embeddings_by_id.get(sid)

            # Skip sessions that only have an embedding (not a valid ML sample)
            if feat is None and emb is not None:
                print(
                    f"Warning: session '{sid}' has an embedding but no "
                    f"features. Skipping (not a valid training sample)."
                )
                continue

            # Build a new output dictionary (never mutate inputs)
            record: dict[str, Any] = {"session_id": sid}

            # -- Feature columns --
            if feat is not None:
                for col in feature_columns:
                    record[col] = feat.get(col)
            else:
                # Session in neither list (shouldn't happen), but handle safely
                for col in feature_columns:
                    record[col] = None

            # -- Embedding columns --
            if emb is not None:
                emb_list = emb.get("behavior_embedding", [])
                for i in range(embedding_dim):
                    if i < len(emb_list):
                        record[f"embedding_{i + 1}"] = emb_list[i]
                    else:
                        record[f"embedding_{i + 1}"] = None
                sessions_with_embeddings += 1
            else:
                for i in range(embedding_dim):
                    record[f"embedding_{i + 1}"] = None
                sessions_without_embeddings += 1

            merged.append(record)

        # 5. Print dataset statistics
        total_samples = len(merged)
        total_feature_cols = len(feature_columns)

        print(f"\n{'=' * 50}")
        print("Training Dataset Statistics")
        print(f"{'=' * 50}")
        print(f"  Total training samples:      {total_samples}")
        print(f"  Total feature columns:       {total_feature_cols}")
        print(f"  Sessions with embeddings:    {sessions_with_embeddings}")
        print(f"  Sessions without embeddings: {sessions_without_embeddings}")
        print(f"{'=' * 50}\n")

        return merged

    # ------------------------------------------------------------------
    # Save helper
    # ------------------------------------------------------------------

    def save_dataset(
        self,
        dataset: list[dict[str, Any]],
        output_path: str,
    ) -> None:
        """Save the merged training dataset to a CSV file.

        The CSV will have a deterministic column order:

        1. ``session_id``
        2. All numerical feature columns (in the order they appeared in
           the feature extractor output).
        3. ``embedding_1`` … ``embedding_N``

        Parameters
        ----------
        dataset : list[dict]
            The merged dataset returned by
            :meth:`combine_features_and_embeddings`.
        output_path : str
            Path to the output CSV file.  Intermediate directories are
            created automatically if they do not exist.

        Raises
        ------
        OSError
            If the file cannot be written.
        """
        # Build a DataFrame from the merged dataset
        df = pd.DataFrame(dataset)

        # Organise columns in deterministic order
        ordered_columns = self._order_columns(df)

        # Reorder (only the columns that actually exist)
        existing_ordered = [c for c in ordered_columns if c in df.columns]
        df = df[existing_ordered]

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Write CSV
        df.to_csv(output_path, index=False)
        print(f"Training dataset saved to: {output_path}")
        print(f"  Shape: {df.shape[0]} rows × {df.shape[1]} columns")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_embedding_dim(
        embeddings: list[dict[str, Any]],
    ) -> int:
        """Determine the embedding dimension from the first non-empty record.

        Falls back to ``50`` if no embeddings are available (the default
        used by :class:`BehaviorEmbeddingGenerator`).

        Parameters
        ----------
        embeddings : list[dict]
            Embedding records from :class:`BehaviorEmbeddingGenerator`.

        Returns
        -------
        int
            The length of the ``behavior_embedding`` list, or 50.
        """
        for emb in embeddings:
            emb_list = emb.get("behavior_embedding", [])
            if emb_list:
                return len(emb_list)
        return 50

    @staticmethod
    def _order_columns(df: pd.DataFrame) -> list[str]:
        """Produce a deterministic column ordering.

        Columns are ordered as:

        1. ``session_id`` (if present)
        2. All columns that are **not** embedding columns and not
           ``session_id`` (feature columns) — preserving original order.
        3. ``embedding_1`` … ``embedding_N`` (sorted numerically).

        Parameters
        ----------
        df : pd.DataFrame
            The merged dataset as a DataFrame.

        Returns
        -------
        list[str]
            Ordered column names.
        """
        session_col = "session_id"
        embedding_cols = sorted(
            [c for c in df.columns if c.startswith("embedding_")],
            key=lambda x: int(x.split("_")[1]),
        )
        feature_cols = [
            c for c in df.columns
            if c != session_col and not c.startswith("embedding_")
        ]

        ordered: list[str] = []
        if session_col in df.columns:
            ordered.append(session_col)
        ordered.extend(feature_cols)
        ordered.extend(embedding_cols)

        return ordered


# ======================================================================
# Test / demo block
# ======================================================================

if __name__ == "__main__":
    from parse_cowrie import CowrieParser
    from session_builder import SessionBuilder
    from feature_extractor import FeatureExtractor
    from behavior_embedding import BehaviorEmbeddingGenerator

    parser = CowrieParser()

    events = parser.parse_directory(
        r"D:\MINIPROJECT\module3_ai_xai_engine\data\raw",
        max_files=2,
    )

    sessions = SessionBuilder().build_sessions(events)

    features = FeatureExtractor().extract_features(sessions)

    embeddings = BehaviorEmbeddingGenerator().generate_embeddings(sessions)

    builder = TrainingDatasetBuilder()

    dataset = builder.combine_features_and_embeddings(
        features,
        embeddings,
    )

    builder.save_dataset(
        dataset,
        "data/processed/training_dataset.csv",
    )


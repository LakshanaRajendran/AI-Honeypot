"""
Training pipeline module for the AI Decision & XAI Engine.

Provides:
  - TrainingPipeline   — converts labeled TrainingSample objects into
                         train/test splits (Module 2 integration).
  - AttackDetectionTrainer — labels behavioural data and trains a
                         Random Forest classifier for attack detection
                         (Step 6 of the training pipeline).
"""

import os
import sys
import pathlib
from dataclasses import dataclass, field
from typing import Any

# Ensure the project root is on sys.path so that sibling modules
# (preprocessing.combiner, schemas.training_schema, etc.) can be
# imported when this file is run directly.
_project_root = pathlib.Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from preprocessing.combiner import FeatureCombiner
from schemas.training_schema import TrainingSample


@dataclass
class PreparedData:
    """Container for the output of the data preparation pipeline.

    Attributes
    ----------
    X_train : np.ndarray
        Training feature matrix of shape (n_train_samples, n_features).
    X_test : np.ndarray
        Test feature matrix of shape (n_test_samples, n_features).
    y_train : np.ndarray
        Training labels as integer class IDs of shape (n_train_samples,).
    y_test : np.ndarray
        Test labels as integer class IDs of shape (n_test_samples,).
    label_encoder : LabelEncoder
        Fitted label encoder mapping original string labels to integers.
    """

    X_train: np.ndarray = field(default_factory=lambda: np.empty(0))
    X_test: np.ndarray = field(default_factory=lambda: np.empty(0))
    y_train: np.ndarray = field(default_factory=lambda: np.empty(0))
    y_test: np.ndarray = field(default_factory=lambda: np.empty(0))
    label_encoder: LabelEncoder = field(default_factory=LabelEncoder)


class TrainingPipeline:
    """Prepares labeled training data for consumption by ML classifiers.

    The pipeline converts a list of TrainingSample objects into a
    feature matrix, encodes string labels as integers, and splits
    the data into training and test sets.
    """

    def __init__(self) -> None:
        self._combiner = FeatureCombiner()

    def prepare_training_data(
        self, samples: list[TrainingSample]
    ) -> PreparedData:
        """Convert labeled samples into train/test splits.

        Steps performed:
          1. Generate feature vectors via FeatureCombiner.
          2. Extract string labels.
          3. Encode labels with sklearn LabelEncoder.
          4. Stratified train/test split (test_size=0.2, random_state=42).

        Parameters
        ----------
        samples : list[TrainingSample]
            Labeled training samples to prepare.

        Returns
        -------
        PreparedData
            Dataclass containing X_train, X_test, y_train, y_test,
            and the fitted LabelEncoder.
        """
        # 1 + 2. Generate feature matrix and label vector
        X, y = self._build_feature_matrix_and_labels(samples)

        # 3. Encode string labels to integers
        X, y, label_encoder = self._encode_labels(X, y)

        # 4. Stratified train/test split
        X_train, X_test, y_train, y_test = self._split(X, y)

        return PreparedData(
            X_train=X_train,
            X_test=X_test,
            y_train=y_train,
            y_test=y_test,
            label_encoder=label_encoder,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_feature_matrix_and_labels(
        self, samples: list[TrainingSample]
    ) -> tuple[list[list[float]], list[str]]:
        """Convert samples into a feature matrix and label list.

        Parameters
        ----------
        samples : list[TrainingSample]
            Labeled training samples.

        Returns
        -------
        tuple[list[list[float]], list[str]]
            Tuple of (feature_matrix, label_vector).
        """
        X: list[list[float]] = []
        y: list[str] = []

        for sample in samples:
            X.append(self._combiner.combine(sample))
            y.append(sample.label)

        return X, y

    @staticmethod
    def _encode_labels(
        X: list[list[float]], y: list[str]
    ) -> tuple[np.ndarray, np.ndarray, LabelEncoder]:
        """Encode string labels into integer class IDs.

        Parameters
        ----------
        X : list[list[float]]
            Feature matrix as a list of lists.
        y : list[str]
            String labels.

        Returns
        -------
        tuple[np.ndarray, np.ndarray, LabelEncoder]
            Tuple of (X as ndarray, y as encoded ndarray, fitted encoder).
        """
        encoder = LabelEncoder()
        y_encoded = encoder.fit_transform(y)
        return np.array(X, dtype=np.float64), y_encoded, encoder

    @staticmethod
    def _split(
        X: np.ndarray, y: np.ndarray
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Perform a stratified train/test split.

        Parameters
        ----------
        X : np.ndarray
            Full feature matrix.
        y : np.ndarray
            Encoded labels.

        Returns
        -------
        tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]
            X_train, X_test, y_train, y_test.
        """
        return train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y,
        )


# ======================================================================
# AttackDetectionTrainer — Step 6 of the Module 3 training pipeline
# ======================================================================


class AttackDetectionTrainer:
    """Create binary labels for behavioural data and train a Random
    Forest classifier for attack detection.

    This class operates on the merged behavioural dataset produced by
    :class:`TrainingDatasetBuilder` (Step 5).

    Pipeline::

        CSV dataset  ──►  create_labels()  ──►  train_model()  ──►  save_model()
    """

    # ------------------------------------------------------------------
    # Label creation
    # ------------------------------------------------------------------

    LABEL_FEATURES = (
        "successful_login_count",
        "download_count",
        "command_count",
        "failed_login_count",
    )

    def create_labels(self, dataset: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Generate binary labels for each session based on behavioural rules.

        A session is labelled **malicious (1)** if *any* of the following
        conditions is true:

        - ``successful_login_count > 0``
        - ``download_count > 0``
        - ``command_count >= 10``
        - ``failed_login_count >= 5``

        Otherwise the session is labelled **normal (0)**.

        Parameters
        ----------
        dataset : list[dict]
            The merged dataset from :class:`TrainingDatasetBuilder`.

        Returns
        -------
        list[dict]
            The same records with an additional ``label`` key (int).
        """
        labeled: list[dict[str, Any]] = []
        malicious_count = 0
        normal_count = 0

        for record in dataset:
            # Create a new dict (never mutate the original)
            labeled_record = dict(record)

            # Apply behavioural rules
            successful_login = record.get("successful_login_count", 0) or 0
            download = record.get("download_count", 0) or 0
            command = record.get("command_count", 0) or 0
            failed_login = record.get("failed_login_count", 0) or 0

            if (
                successful_login > 0
                or download > 0
                or command >= 10
                or failed_login >= 5
            ):
                labeled_record["label"] = 1
                malicious_count += 1
            else:
                labeled_record["label"] = 0
                normal_count += 1

            labeled.append(labeled_record)

        # Print label statistics
        total = len(labeled)
        print(f"\n{'=' * 45}")
        print("Label Distribution Statistics")
        print(f"{'=' * 45}")
        print(f"  Total samples:     {total}")
        print(f"  Malicious samples: {malicious_count}")
        print(f"  Normal samples:    {normal_count}")
        print(f"{'=' * 45}\n")

        return labeled

    # ------------------------------------------------------------------
    # Model training
    # ------------------------------------------------------------------

    def train_model(self, dataset: list[dict[str, Any]]) -> RandomForestClassifier:
        """Train a Random Forest classifier on the labeled dataset.

        Steps:
        1. Separate features (X) and labels (y).
        2. Remove non-feature columns (``session_id``, ``label``).
        3. Stratified 80/20 train-test split.
        4. Train :class:`~sklearn.ensemble.RandomForestClassifier`.
        5. Evaluate and print metrics on the held-out test set.

        Parameters
        ----------
        dataset : list[dict]
            Labeled records returned by :meth:`create_labels`.

        Returns
        -------
        RandomForestClassifier
            The trained classifier, fitted on the full training split.
        """
        # 1. Convert to DataFrame for easy column manipulation
        df = pd.DataFrame(dataset)

        # 2. Separate features and labels
        y = df["label"].values

        feature_columns = [c for c in df.columns if c not in ("session_id", "label")]
        X = df[feature_columns].values

        # 3. Stratified train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y,
        )

        # ---- Save the held-out test dataset for later SHAP inference ----
        # Reproduce the same stratified split on the DataFrame index to
        # recover the original row indices of the test set.
        _, df_test_idx, _, _ = train_test_split(
            df.index.values,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y,
        )
        test_df = df.iloc[df_test_idx].copy()
        test_df.to_csv("data/processed/test_dataset.csv", index=False)
        print(f"Test dataset saved to: data/processed/test_dataset.csv")
        print(f"  Shape: {test_df.shape[0]} rows x {test_df.shape[1]} columns")
        # -----------------------------------------------------------------

        # 4. Train Random Forest
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        # 5. Evaluate on the test set
        y_pred = model.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        print(f"\n{'=' * 45}")
        print("Model Evaluation (Test Set)")
        print(f"{'=' * 45}")
        print(f"  Accuracy:           {accuracy:.4f}")
        print(f"  Precision:          {precision:.4f}")
        print(f"  Recall:             {recall:.4f}")
        print(f"  F1-score:           {f1:.4f}")
        print(f"\n  Confusion Matrix:")
        print(f"  {cm}")
        print(f"{'=' * 45}\n")

        return model

    # ------------------------------------------------------------------
    # Model persistence
    # ------------------------------------------------------------------

    @staticmethod
    def save_model(model: RandomForestClassifier, output_path: str) -> None:
        """Save a trained model to disk using joblib.

        Parameters
        ----------
        model : RandomForestClassifier
            The trained classifier.
        output_path : str
            Destination file path.  Intermediate directories are
            created automatically if they do not exist.

        Raises
        ------
        OSError
            If the file cannot be written.
        """
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        joblib.dump(model, output_path)
        print(f"Trained model saved to: {output_path}")


# ======================================================================
# Test / demo block
# ======================================================================

if __name__ == "__main__":
    trainer = AttackDetectionTrainer()

    dataset = pd.read_csv("data/processed/training_dataset.csv")
    dataset = dataset.to_dict("records")

    labeled_data = trainer.create_labels(dataset)

    model = trainer.train_model(labeled_data)

    trainer.save_model(model, "models/attack_detector.pkl")


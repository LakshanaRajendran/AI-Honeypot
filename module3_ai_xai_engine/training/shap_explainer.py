"""
SHAP Explainer module for the AI Decision & XAI Engine.

Provides the ShapExplainer class that uses SHAP (SHapley Additive
exPlanations) to explain predictions made by the trained Random Forest
attack detection model.

This is Step 7 of the Module 3 training pipeline:

    Cowrie Logs
         ↓
    Parser
         ↓
    Session Builder
         ↓
    Feature Extraction + Behaviour Embedding
         ↓
    Final ML Training Dataset
         ↓
    Attack Detection Trainer (Step 6)
         ↓
    SHAP Explainability (Step 7)     <-- YOU ARE HERE
"""

import os
import sys
import warnings
from typing import Any, Optional

import joblib
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier

# Use a non-interactive backend so plots can be saved without a display
matplotlib.use("Agg")

warnings.filterwarnings("ignore", category=UserWarning, module="shap")


class ShapExplainer:
    """Generate SHAP-based explanations for Random Forest predictions.

    The explainer computes SHAP values using :class:`shap.TreeExplainer`,
    which is optimised for tree-based models such as
    :class:`~sklearn.ensemble.RandomForestClassifier`.

    Typical usage::

        explainer = ShapExplainer()

        model = explainer.load_model("models/attack_detector.pkl")
        X, y = explainer.load_dataset("data/processed/training_dataset.csv")

        explainer.create_explainer(model)

        result = explainer.explain_sample(model, X, sample_index=0)
        explainer.plot_summary(model, X)
        explainer.plot_waterfall(model, X, sample_index=0)
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        self._explainer: Optional[shap.TreeExplainer] = None

    # -- Model loading -------------------------------------------------

    @staticmethod
    def load_model(model_path: str) -> RandomForestClassifier:
        """Load a trained Random Forest model from disk.

        Parameters
        ----------
        model_path : str
            Path to the serialised model file (``.pkl``).

        Returns
        -------
        RandomForestClassifier
            The deserialised model.

        Raises
        ------
        FileNotFoundError
            If the model file does not exist.
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        model: RandomForestClassifier = joblib.load(model_path)
        print(f"Model loaded from: {model_path}")
        print(f"  Type: {type(model).__name__}")
        if hasattr(model, "n_features_in_"):
            print(f"  Expected features: {model.n_features_in_}")
        return model

    # -- Dataset loading -----------------------------------------------

    @staticmethod
    def load_dataset(
        csv_path: str,
    ) -> tuple[pd.DataFrame, Optional[pd.Series]]:
        """Load the processed training dataset from a CSV file.

        The ``session_id`` column is always removed.  If a ``label``
        column is present it is separated and returned as a separate
        Series; otherwise ``None`` is returned for the labels.

        Parameters
        ----------
        csv_path : str
            Path to the processed CSV dataset.

        Returns
        -------
        tuple[pd.DataFrame, Optional[pd.Series]]
            ``(X, y)`` where:

            - ``X`` – feature matrix with ``session_id`` (and optionally
              ``label``) removed.
            - ``y`` – label series if the column existed, else ``None``.

        Raises
        ------
        FileNotFoundError
            If the CSV file does not exist.
        """
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Dataset file not found: {csv_path}")

        df = pd.read_csv(csv_path)
        print(f"Dataset loaded from: {csv_path}")
        print(f"  Shape: {df.shape[0]} rows × {df.shape[1]} columns")

        # Work on a copy to avoid mutating the original DataFrame
        X = df.copy()

        # Remove session_id (always present)
        if "session_id" in X.columns:
            X.drop(columns=["session_id"], inplace=True)
            print("  Removed column: session_id")

        # Separate label if it exists
        y: Optional[pd.Series] = None
        if "label" in X.columns:
            y = X["label"].copy()
            X.drop(columns=["label"], inplace=True)
            print("  Removed column: label (separated as target)")
            print(f"  Label distribution:\\n    {y.value_counts().to_string().replace(chr(10), chr(10) + '    ')}")

        print(f"  Feature matrix shape: {X.shape}")
        return X, y

    # -- Explainer creation -------------------------------------------

    def create_explainer(self, model: RandomForestClassifier) -> shap.TreeExplainer:
        """Create a SHAP ``TreeExplainer`` for the provided model.

        Parameters
        ----------
        model : RandomForestClassifier
            A trained Random Forest classifier.

        Returns
        -------
        shap.TreeExplainer
            The initialised explainer instance (also stored internally).
        """
        self._explainer = shap.TreeExplainer(model)
        print(f"SHAP TreeExplainer created for model type: {type(model).__name__}")
        return self._explainer

    # -- Single-sample explanation -------------------------------------

    def explain_sample(
        self,
        model: RandomForestClassifier,
        X: pd.DataFrame,
        sample_index: int = 0,
    ) -> dict[str, Any]:
        """Generate SHAP values for a single sample and print a summary.

        Parameters
        ----------
        model : RandomForestClassifier
            The trained classifier.
        X : pd.DataFrame
            Feature matrix.
        sample_index : int
            Row index of the sample to explain (default ``0``).

        Returns
        -------
        dict
            Structured explanation result::

                {
                    "prediction": int,
                    "probability": float,
                    "top_features": [
                        {"feature": str, "shap_value": float},
                        ...
                    ],
                    "sample_index": int
                }
        """
        if self._explainer is None:
            raise RuntimeError(
                "Explainer not initialised. Call create_explainer() first."
            )

        # Select the single sample
        sample = X.iloc[[sample_index]]
        sample_series = X.iloc[sample_index]

        # Generate SHAP values for the sample
        shap_values = self._explainer.shap_values(sample)

        # -- Handle binary classification output --
        # Output shape depends on SHAP + sklearn version:
        #   - Older: list of two arrays [neg_class, pos_class]
        #   - Newer (3D): (n_samples, n_features, n_classes)
        # We always take the positive (malicious) class values.
        if isinstance(shap_values, list):
            # Legacy list format: [neg_class_array, pos_class_array]
            sample_shap = (
                shap_values[1].flatten()
                if len(shap_values) == 2
                else shap_values[0].flatten()
            )
        elif shap_values.ndim == 3:
            # Newer 3D format: (n_samples, n_features, n_classes)
            sample_shap = shap_values[0, :, 1].flatten()
        else:
            sample_shap = shap_values.flatten()

        # Get prediction and probability
        pred_class = int(model.predict(sample)[0])
        proba = model.predict_proba(sample)[0]

        # For binary classification, get probability of the predicted class
        if len(proba) == 2:
            pred_probability = float(proba[pred_class])
        else:
            pred_probability = float(proba[pred_class])

        # Map class index to label name
        class_label = "malicious" if pred_class == 1 else "normal"

        # Build feature importance list
        feature_names = list(X.columns)
        feature_shap_values = list(zip(feature_names, sample_shap))
        feature_shap_values.sort(key=lambda x: abs(x[1]), reverse=True)

        top_features = [
            {"feature": feat, "shap_value": round(float(val), 6)}
            for feat, val in feature_shap_values[:10]
        ]

        # -- Print explanation --
        separator = "=" * 58
        print(f"\n{separator}")
        print("SHAP Sample Explanation")
        print(separator)
        print(f"  Sample index:      {sample_index}")
        print(f"  Predicted class:   {pred_class} ({class_label})")
        print(f"  Prediction prob.:  {pred_probability:.6f}")
        print(f"\n  Top 10 Most Influential Features:")
        print(f"  {'#' :<4} {'Feature':<30} {'SHAP Value':<15}")
        print(f"  {'-' :<4} {'-' * 29:<30} {'-' * 14:<15}")
        for rank, feat_info in enumerate(top_features, start=1):
            print(
                f"  {rank:<4} {feat_info['feature']:<30} {feat_info['shap_value']:<15.6f}"
            )
        print(separator)

        # -- Return structured result --
        return {
            "prediction": pred_class,
            "probability": pred_probability,
            "top_features": top_features,
            "sample_index": sample_index,
        }

    # -- Summary plot --------------------------------------------------

    def plot_summary(
        self,
        model: RandomForestClassifier,
        X: pd.DataFrame,
    ) -> str:
        """Generate and save a SHAP summary plot showing global feature importance.

        The plot is saved to ``outputs/shap/summary_plot.png``.

        Parameters
        ----------
        model : RandomForestClassifier
            The trained classifier.
        X : pd.DataFrame
            Feature matrix (used as background for SHAP values).

        Returns
        -------
        str
            Path to the saved plot.
        """
        if self._explainer is None:
            raise RuntimeError(
                "Explainer not initialised. Call create_explainer() first."
            )

        # Compute SHAP values for the whole dataset (use a subset if large)
        n_samples = min(500, len(X))
        X_subset = X.iloc[:n_samples]

        print(f"Computing SHAP values for summary plot ({n_samples} samples)...")
        shap_values = self._explainer.shap_values(X_subset)

        # For binary classification, extract the positive (malicious) class.
        # Output shape depends on SHAP + sklearn version:
        #   - Older: list of two arrays [neg_class, pos_class]
        #   - Newer (3D): (n_samples, n_features, n_classes)
        if isinstance(shap_values, list) and len(shap_values) == 2:
            plot_values = shap_values[1]
        elif hasattr(shap_values, 'ndim') and shap_values.ndim == 3:
            plot_values = shap_values[:, :, 1]
        else:
            plot_values = shap_values

        # Create output directory
        output_dir = "outputs/shap"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "summary_plot.png")

        # Generate and save the summary plot
        plt.figure(figsize=(12, 8))
        shap.summary_plot(
            plot_values,
            X_subset,
            feature_names=list(X_subset.columns),
            show=False,
        )
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()

        print(f"Summary plot saved to: {output_path}")
        return output_path

    # -- Waterfall plot ------------------------------------------------

    def plot_waterfall(
        self,
        model: RandomForestClassifier,
        X: pd.DataFrame,
        sample_index: int = 0,
    ) -> str:
        """Generate and save a SHAP waterfall plot for a single prediction.

        The plot is saved to ``outputs/shap/waterfall_plot_sample{sample_index}.png``.

        Parameters
        ----------
        model : RandomForestClassifier
            The trained classifier.
        X : pd.DataFrame
            Feature matrix.
        sample_index : int
            Row index of the sample to explain (default ``0``).

        Returns
        -------
        str
            Path to the saved plot.
        """
        if self._explainer is None:
            raise RuntimeError(
                "Explainer not initialised. Call create_explainer() first."
            )

        # Select the single sample
        sample = X.iloc[[sample_index]]
        sample_series = X.iloc[sample_index]

        # Compute SHAP values
        shap_values = self._explainer.shap_values(sample)

        # For binary classification, extract the positive (malicious) class.
        # Output shape depends on SHAP + sklearn version:
        #   - Older: list of two arrays [neg_class, pos_class]
        #   - Newer (3D): (n_samples, n_features, n_classes)
        if isinstance(shap_values, list) and len(shap_values) == 2:
            sample_shap = shap_values[1]
        elif hasattr(shap_values, 'ndim') and shap_values.ndim == 3:
            sample_shap = shap_values[0, :, 1]
        else:
            sample_shap = shap_values

        # Create Explanation object for waterfall plot
        base_value = (
            self._explainer.expected_value[1]
            if isinstance(self._explainer.expected_value, (list, np.ndarray))
            and len(self._explainer.expected_value) == 2
            else self._explainer.expected_value
        )

        # If expected_value is an array with a single element, extract the scalar
        if isinstance(base_value, np.ndarray) and base_value.ndim == 0:
            base_value = float(base_value)
        elif isinstance(base_value, np.ndarray) and base_value.shape == (1,):
            base_value = float(base_value[0])
        elif isinstance(base_value, (list, np.ndarray)) and len(base_value) == 1:
            base_value = float(base_value[0])

        # Ensure base_value is a scalar float
        base_value_scalar = float(base_value) if isinstance(base_value, (int, float, np.floating)) else float(np.array(base_value).flatten()[0])

        shap_exp = shap.Explanation(
            values=sample_shap.flatten(),
            base_values=base_value_scalar,
            data=sample_series.values,
            feature_names=list(X.columns),
        )

        # Disable auto-clustering to avoid an internal SHAP v0.49.1
        # indexing bug where ``order[i]`` can exceed the number of
        # features when ``max_display`` is set.
        shap_exp.clustering = None

        # Create output directory
        output_dir = "outputs/shap"
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"waterfall_plot_sample{sample_index}.png")

        # Generate and save the waterfall plot
        #    Use ``shap.plots.waterfall`` (the newer API).  Set
        #    ``show=False`` so we can save the figure ourselves.
        #    We also explicitly pass ``clustering=None`` to work around
        #    a SHAP v0.49.1 indexing bug.
        max_display = min(15, len(X.columns))
        plt.figure(figsize=(12, 8))
        shap.plots.waterfall(
            shap_exp,
            show=False,
            max_display=max_display,
        )
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()

        print(f"Waterfall plot saved to: {output_path}")
        return output_path


# ======================================================================
# Test / demo block — interactive inference on the held-out test set
# ======================================================================

if __name__ == "__main__":
    explainer = ShapExplainer()

    # 1. Load trained model
    model = explainer.load_model("models/attack_detector.pkl")

    # 2. Load the held-out test dataset (with session_id and label columns)
    test_csv_path = "data/processed/test_dataset.csv"
    if not os.path.exists(test_csv_path):
        print(f"ERROR: Test dataset not found at: {test_csv_path}")
        print("Run `python training/train_model.py` first to generate it.")
        sys.exit(1)

    test_df = pd.read_csv(test_csv_path)
    print(f"\nTest dataset loaded from: {test_csv_path}")
    print(f"  Shape: {test_df.shape[0]} rows x {test_df.shape[1]} columns")

    # 3. Display the first 10 available session IDs
    session_ids = test_df["session_id"].tolist()
    print("\nAvailable Test Sessions")
    print("-" * 30)
    for idx, sid in enumerate(session_ids[:10], start=1):
        print(f"  {idx}. {sid}")
    if len(session_ids) > 10:
        print(f"  ... and {len(session_ids) - 10} more")

    # 4. Prompt the user for a session ID
    print()
    target_session_id = input("Enter Session ID: ").strip()

    # 5. Search for the session_id in the test dataset
    if target_session_id not in session_ids:
        print(f"\nERROR: Session ID '{target_session_id}' not found in the test dataset.")
        print("Please check the session ID and try again.")
        sys.exit(1)

    print(f"\nSession '{target_session_id}' found in test dataset. Running inference...")

    # 6. Locate the row
    row = test_df[test_df["session_id"] == target_session_id].iloc[0]

    # 7. Build the feature matrix (drop session_id and label)
    X_row = test_df[test_df["session_id"] == target_session_id].copy()
    X_row.drop(columns=["session_id", "label"], inplace=True)

    # 8. Run prediction and probability
    pred_class = int(model.predict(X_row)[0])
    proba = model.predict_proba(X_row)[0]
    pred_probability = float(proba[pred_class])
    class_label = "malicious" if pred_class == 1 else "normal"

    print(f"\n{'=' * 58}")
    print(f"  Session ID:          {target_session_id}")
    print(f"  Prediction:          {pred_class} ({class_label})")
    print(f"  Prediction Prob.:    {pred_probability:.6f}")
    print(f"{'=' * 58}")

    # 9. Compute SHAP values for the selected session
    explainer.create_explainer(model)

    shap_values = explainer._explainer.shap_values(X_row)

    # Handle binary classification output format
    if isinstance(shap_values, list):
        sample_shap = shap_values[1].flatten() if len(shap_values) == 2 else shap_values[0].flatten()
    elif hasattr(shap_values, 'ndim') and shap_values.ndim == 3:
        sample_shap = shap_values[0, :, 1].flatten()
    else:
        sample_shap = shap_values.flatten()

    feature_names = list(X_row.columns)
    feature_shap_values = list(zip(feature_names, sample_shap))
    feature_shap_values.sort(key=lambda x: abs(x[1]), reverse=True)

    top_features = [
        {"feature": feat, "shap_value": round(float(val), 6)}
        for feat, val in feature_shap_values[:10]
    ]

    # 10. Print top 10 contributing features
    print(f"\n  Top 10 Contributing Features:")
    print(f"  {'Feature':<30} {'SHAP Value':<15}")
    print(f"  {'-' * 29:<30} {'-' * 14:<15}")
    for feat_info in top_features:
        print(f"  {feat_info['feature']:<30} {feat_info['shap_value']:<15.6f}")
    print()

    # 11. Generate and save waterfall plot for the selected session
    explainer.plot_waterfall(model, X_row, sample_index=0)

    # Rename the waterfall file to include the session ID
    default_waterfall = "outputs/shap/waterfall_plot_sample0.png"
    session_waterfall = f"outputs/shap/waterfall_{target_session_id}.png"
    if os.path.exists(default_waterfall):
        os.rename(default_waterfall, session_waterfall)
        print(f"Waterfall plot renamed to: {session_waterfall}")

    # 12. Keep the existing summary plot functionality unchanged
    print("\nGenerating global SHAP summary plot (on first 500 test samples)...")
    X_for_summary = test_df.drop(columns=["session_id", "label"]).copy()
    explainer.plot_summary(model, X_for_summary)

    print("\nDone.")


"""
Classifier module for the AI Decision & XAI Engine.

Provides model trainers for scikit-learn classifiers used
to categorise cybersecurity threats.
"""

from sklearn.ensemble import RandomForestClassifier

from training.train_model import PreparedData


class RandomForestTrainer:
    """Trains a Random Forest classifier on prepared training data."""

    def train(self, prepared_data: PreparedData) -> RandomForestClassifier:
        """Train a Random Forest classifier.

        Parameters
        ----------
        prepared_data : PreparedData
            Container with X_train and y_train arrays obtained from
            the TrainingPipeline.

        Returns
        -------
        RandomForestClassifier
            The fitted classifier ready for evaluation.

        Raises
        ------
        ValueError
            If the training arrays are empty or have no samples.
        """
        if prepared_data.X_train.shape[0] == 0:
            raise ValueError(
                "X_train is empty — provide at least one training sample."
            )

        if prepared_data.y_train.shape[0] == 0:
            raise ValueError(
                "y_train is empty — provide at least one label."
            )

        classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )

        classifier.fit(prepared_data.X_train, prepared_data.y_train)

        return classifier


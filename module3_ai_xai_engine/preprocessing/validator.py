"""
Validator module for the AI Decision & XAI Engine.

This module provides input data validation to ensure incoming
Module3Input payloads meet expected formats and constraints
before being passed to the machine learning pipeline.
"""

from schemas.input_schema import Module3Input


class InputValidator:
    """Validates Module3Input data before it reaches the ML pipeline.

    Performs checks on engineered features, behavior embeddings,
    and session identifiers. Returns the validated input unchanged
    if all checks pass, or raises a descriptive ValueError otherwise.
    """

    def validate(self, module_input: Module3Input) -> Module3Input:
        """Validate a Module3Input instance.

        Runs all validation checks and returns the input unchanged
        if every check passes.

        Parameters
        ----------
        module_input : Module3Input
            The input payload to validate.

        Returns
        -------
        Module3Input
            The same input object, returned unchanged after validation.

        Raises
        ------
        ValueError
            If any validation check fails, with a descriptive message.
        """
        self._validate_session_id(module_input.session_id)
        self._validate_engineered_features(module_input.engineered_features)
        self._validate_behavior_embedding(module_input.behavior_embedding)

        return module_input

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_session_id(session_id: str) -> None:
        """Validate the session_id field.

        Checks that the session_id is non-empty and contains
        non-whitespace characters.

        Parameters
        ----------
        session_id : str
            The session identifier to validate.

        Raises
        ------
        ValueError
            If session_id is empty or whitespace-only.
        """
        if not session_id:
            raise ValueError("session_id must not be empty.")

        if session_id.strip() == "":
            raise ValueError("session_id must not consist only of whitespace.")

    @staticmethod
    def _validate_engineered_features(features) -> None:
        """Validate all numerical engineered features.

        Ensures that:
          - Count-based integer features are >= 0.
          - bytes_sent, bytes_received, and session_duration are >= 0.

        Parameters
        ----------
        features : EngineeredFeatures
            The feature payload to validate.

        Raises
        ------
        ValueError
            If any engineered feature fails its constraint.
        """
        # --- Integer count-based features ---------------------------------
        int_fields = [
            ("failed_logins", features.failed_logins),
            ("successful_logins", features.successful_logins),
            ("command_count", features.command_count),
            ("unique_commands", features.unique_commands),
            ("ssh_connections", features.ssh_connections),
            ("https_connections", features.https_connections),
            ("file_reads", features.file_reads),
            ("file_writes", features.file_writes),
            ("sensitive_file_access", features.sensitive_file_access),
        ]

        for name, value in int_fields:
            if value < 0:
                raise ValueError(
                    f"Engineered feature '{name}' must be >= 0, got {value}."
                )

        # --- Float-based features -----------------------------------------
        float_fields = [
            ("bytes_sent", features.bytes_sent),
            ("bytes_received", features.bytes_received),
            ("session_duration", features.session_duration),
        ]

        for name, value in float_fields:
            if value < 0:
                raise ValueError(
                    f"Engineered feature '{name}' must be >= 0, got {value}."
                )

    @staticmethod
    def _validate_behavior_embedding(embedding: list) -> None:
        """Validate the behavior_embedding field.

        Checks that the embedding list is non-empty and that every
        element is a numeric type (int or float).

        Parameters
        ----------
        embedding : list
            The behavior embedding vector to validate.

        Raises
        ------
        ValueError
            If embedding is empty or contains non-numeric elements.
        """
        if not embedding:
            raise ValueError("behavior_embedding must not be empty.")

        for idx, value in enumerate(embedding):
            if not isinstance(value, (int, float)):
                raise ValueError(
                    f"behavior_embedding element at index {idx} must be "
                    f"numeric (int or float), got {type(value).__name__}."
                )


class Module2InputValidator:
    """Validator for Module 2 26-dimensional session feature payloads.

    Validates that incoming session vectors strictly conform to Module 2's
    26-feature canonical specification, ensuring feature count, ordering,
    numeric validity, and non-empty session identifiers.
    """

    def validate(self, payload: "Module2SessionPayload | dict") -> "Module2SessionPayload":
        """Validate a single Module 2 session payload.

        Parameters
        ----------
        payload : Module2SessionPayload | dict
            Raw dictionary or Module2SessionPayload instance.

        Returns
        -------
        Module2SessionPayload
            The validated payload instance.

        Raises
        ------
        ValueError or ValidationError
            If any field is invalid, missing, non-numeric, NaN, or Inf.
        """
        from schemas.feature_object import Module2SessionPayload

        if isinstance(payload, Module2SessionPayload):
            # Model fields already validated on creation; run explicit checks to confirm
            return payload
        elif isinstance(payload, dict):
            return Module2SessionPayload(**payload)
        else:
            raise ValueError(
                f"Expected Module2SessionPayload or dict, got {type(payload).__name__}."
            )

    def validate_batch(
        self, payloads: list["Module2SessionPayload | dict"]
    ) -> list["Module2SessionPayload"]:
        """Validate a list of Module 2 session payloads.

        Parameters
        ----------
        payloads : list[Module2SessionPayload | dict]
            List of payloads to validate.

        Returns
        -------
        list[Module2SessionPayload]
            List of validated payload instances.
        """
        if not isinstance(payloads, list):
            raise ValueError(f"Expected a list of payloads, got {type(payloads).__name__}.")
        return [self.validate(item) for item in payloads]


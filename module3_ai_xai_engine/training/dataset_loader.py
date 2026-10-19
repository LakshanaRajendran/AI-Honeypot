"""
Dataset Loader module for the AI Decision & XAI Engine.

Provides the DatasetLoader class for reading labeled training data
from JSON files and returning strongly typed TrainingSample objects.
"""

import json
import pathlib
from json import JSONDecodeError
from typing import Union

from schemas.feature_object import Module2SessionPayload
from schemas.training_schema import TrainingSample


class DatasetLoader:
    """Loads training datasets and Module 2 session vectors from JSON files.

    Supports both single JSON objects and JSON arrays of samples/vectors.
    """

    def load_module2_session_vectors(
        self, file_path: Union[str, pathlib.Path]
    ) -> list[Module2SessionPayload]:
        """Load and validate Module 2 session feature vectors from a JSON file.

        Accepts a JSON file containing either a single session object or
        an array of session objects structured according to Module 2's
        canonical 26-feature specification.

        Parameters
        ----------
        file_path : str | pathlib.Path
            Path to the Module 2 JSON file (e.g. feature_vector.json).

        Returns
        -------
        list[Module2SessionPayload]
            A list of validated Module2SessionPayload instances.

        Raises
        ------
        FileNotFoundError
            If the specified file does not exist.
        json.JSONDecodeError
            If the file contains malformed JSON.
        ValueError or ValidationError
            If any session payload violates schema or numeric constraints.
        """
        path = pathlib.Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Module 2 dataset file not found: {path.resolve()}")

        if not path.is_file():
            raise FileNotFoundError(f"Path is not a file: {path.resolve()}")

        raw_data = self._read_file(path)
        samples_data = self._normalize_to_list(raw_data)

        from preprocessing.validator import Module2InputValidator

        validator = Module2InputValidator()
        return validator.validate_batch(samples_data)

    def load_from_json(self, file_path: Union[str, pathlib.Path]) -> list[TrainingSample]:
        """Load a dataset from a JSON file.

        Accepts a JSON file containing either a single training sample
        object or an array of training sample objects.  In both cases
        a list of TrainingSample instances is returned.

        Parameters
        ----------
        file_path : str | pathlib.Path
            Path to the JSON dataset file.

        Returns
        -------
        list[TrainingSample]
            A list of validated training samples.

        Raises
        ------
        FileNotFoundError
            If the specified file does not exist.
        json.JSONDecodeError
            If the file contains malformed JSON.
        pydantic.ValidationError
            If any sample cannot be parsed into a TrainingSample.
        """
        path = pathlib.Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Dataset file not found: {path.resolve()}")

        if not path.is_file():
            raise FileNotFoundError(f"Path is not a file: {path.resolve()}")

        raw_data = self._read_file(path)
        samples_data = self._normalize_to_list(raw_data)
        return self._parse_samples(samples_data)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_file(path: pathlib.Path) -> object:
        """Read and parse the JSON file.

        Parameters
        ----------
        path : pathlib.Path
            Path to the file.

        Returns
        -------
        object
            Decoded JSON content (dict or list).

        Raises
        ------
        json.JSONDecodeError
            If the file content is not valid JSON.
        """
        try:
            with path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except JSONDecodeError as exc:
            raise JSONDecodeError(
                f"Invalid JSON in dataset file '{path.name}': {exc.msg}",
                exc.doc,
                exc.pos,
            )

    @staticmethod
    def _normalize_to_list(data: object) -> list[dict]:
        """Normalise input to a list of dictionaries.

        If the top-level value is a single dict it is wrapped in a list.

        Parameters
        ----------
        data : object
            Decoded JSON data.

        Returns
        -------
        list[dict]
            A list of sample dictionaries.

        Raises
        ------
        ValueError
            If the data is neither a dict nor a list of dicts.
        """
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError(
            f"Expected a JSON object or array, got {type(data).__name__}."
        )

    @staticmethod
    def _parse_samples(samples_data: list[dict]) -> list[TrainingSample]:
        """Parse a list of dictionaries into TrainingSample objects.

        Parameters
        ----------
        samples_data : list[dict]
            Raw sample dictionaries.

        Returns
        -------
        list[TrainingSample]
            Validated training samples.

        Raises
        ------
        pydantic.ValidationError
            Propagated from Pydantic if a sample is malformed.
        """
        return [TrainingSample(**sample) for sample in samples_data]


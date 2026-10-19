"""
Logger Module

TODO: Set up logging configuration for the module.
"""
import logging


def setup_logger(name=__name__, level=logging.INFO):
    """
    TODO: Configure and return a logger instance.

    Args:
        name: Logger name.
        level: Logging level.

    Returns:
        logging.Logger instance.
    """
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


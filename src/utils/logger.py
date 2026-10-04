"""Structured logging configuration."""

import logging
import sys


def setup_logging(
    level: int = logging.INFO, log_file: str | None = None, name: str = "InterVul-Graph"
) -> logging.Logger:
    """Setup structured logger with console and optional file handlers.

    Args:
        level: Logging verbosity level.
        log_file: Optional path to save log output.
        name: Logger hierarchy name.

    Returns:
        Configured logger instance.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "InterVul-Graph") -> logging.Logger:
    """Get or create logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logging(name=name)
    return logger

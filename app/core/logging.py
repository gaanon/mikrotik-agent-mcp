"""
app/core/logging.py

Structured logging configuration for the application.
All tool calls, policy decisions, and MikroTik API calls are logged here.
"""
import logging
import sys
from app.core.config import settings


def setup_logging() -> None:
    """Configure root logger with a structured format and the configured log level."""
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers = []  # Remove any default handlers
    root_logger.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger. Call this in each module instead of logging.getLogger directly."""
    return logging.getLogger(name)

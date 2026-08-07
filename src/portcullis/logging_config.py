"""Logging configuration for Portcullis.

Portcullis logs to **stderr** (never stdout, which is reserved for report
output and machine consumption) and is **silent by default** — a scanner used
in scripts and CI should not chatter unless asked. ``-v``/``--verbose`` raises
verbosity (INFO, then DEBUG); ``--quiet`` suppresses everything below WARNING.

The library never calls ``logging.basicConfig`` at import time; only the CLI
configures handlers, so importing Portcullis as a library leaves the host
application's logging untouched (a standard library-etiquette rule).
"""

from __future__ import annotations

import logging
import sys

LOGGER_NAME = "portcullis"


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    """Return the Portcullis logger (or a child of it)."""
    return logging.getLogger(name)


def configure_logging(verbosity: int = 0, quiet: bool = False) -> None:
    """Configure the ``portcullis`` logger for CLI use.

    verbosity: 0 = WARNING (default), 1 = INFO, 2+ = DEBUG.
    quiet: force ERROR level regardless of verbosity.
    """
    if quiet:
        level = logging.ERROR
    elif verbosity <= 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.DEBUG

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    # Replace handlers so repeated CLI invocations in one process don't stack.
    logger.handlers.clear()
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False

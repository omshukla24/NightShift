"""Library logging — silent by default, opt-in for the CLI.

Library code logs to a logger with a NullHandler so importing NIGHTSHIFT never
spams a host application. `enable()` turns on a simple stderr handler.
"""
from __future__ import annotations

import logging as _logging

_LOGGER = _logging.getLogger("nightshift")
_LOGGER.addHandler(_logging.NullHandler())


def get_logger(name: str | None = None) -> _logging.Logger:
    return _LOGGER if name is None else _LOGGER.getChild(name)


def enable(level: int = _logging.INFO) -> None:
    h = _logging.StreamHandler()
    h.setFormatter(_logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    _LOGGER.addHandler(h)
    _LOGGER.setLevel(level)

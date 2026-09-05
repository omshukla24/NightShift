"""Typed exceptions — so callers can catch what they mean, not bare Exception."""
from __future__ import annotations


class NightshiftError(Exception):
    """Base class for every error NIGHTSHIFT raises deliberately."""


class ValidationError(NightshiftError, ValueError):
    """Bad input: a non-positive amount, an unknown kind, a malformed scenario."""


class ScenarioError(NightshiftError, KeyError):
    """A scenario was requested that does not exist, or a duplicate key was defined."""


class ConfigError(NightshiftError):
    """Invalid configuration."""

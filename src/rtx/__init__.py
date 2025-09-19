"""Real Tracker X package entry."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

__all__ = ["__version__", "get_data_path"]

__version__ = "0.1.0"


def get_data_path(resource: str) -> Path:
    """Return the absolute path to a packaged data file."""
    with resources.as_file(resources.files("rtx.data") / resource) as path:
        return path

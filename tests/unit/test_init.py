from __future__ import annotations

from pathlib import Path

from rtx import get_data_path


def test_get_data_path():
    """Test that get_data_path returns a valid path."""
    path = get_data_path("top_packages.json")
    assert isinstance(path, Path)
    assert path.exists()
    assert path.name == "top_packages.json"

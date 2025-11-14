from __future__ import annotations

import pytest

from rtx.registry import get_scanners
from rtx.scanners import NpmScanner, PyPIScanner


def test_get_scanners() -> None:
    scanners = get_scanners()
    assert len(scanners) == 11

    scanners = get_scanners(["npm", "pip"])
    assert len(scanners) == 2
    assert isinstance(scanners[0], NpmScanner)
    assert isinstance(scanners[1], PyPIScanner)

    with pytest.raises(ValueError):
        get_scanners(["unknown"])
from __future__ import annotations

import pytest

from rtx.registry import get_scanners


def test_get_scanners_deduplicates_casefold() -> None:
    scanners = get_scanners(["NPM", "npm", "PyPI"])
    managers = [scanner.manager for scanner in scanners]
    assert managers == ["npm", "pypi"]


def test_get_scanners_raises_with_preserved_order() -> None:
    with pytest.raises(ValueError) as exc:
        get_scanners(["npm", "unknown", "Mystery", "unknown"])
    assert str(exc.value) == "Unknown package manager(s): unknown, Mystery"

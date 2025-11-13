from __future__ import annotations

import pytest

from rtx.scanners.common import (
    _parse_conda_dependency,
    _parse_requirement_line,
    merge_dependency_version,
)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("", None),
        ("# comment", None),
        ("-r requirements.txt", None),
        ("name==", None),
        ("name == 1.2.3", ("name", "1.2.3")),
        ("name==1.2.3", ("name", "1.2.3")),
        ("name", ("name", "*")),
        ("name==1.2.3 # comment", ("name", "1.2.3")),
        ("name @ https://example.com/pkg.zip", ("name", "@ https://example.com/pkg.zip")),
        ("name>=1.2.3", ("name", ">=1.2.3")),
        ("name<2.0.0,>=1.2.3", ("name", ">=1.2.3,<2.0.0")),
    ],
)
def test_parse_requirement_line(line: str, expected: tuple[str, str] | None) -> None:
    assert _parse_requirement_line(line) == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("", None),
        ("# comment", None),
        ("conda-forge::name", ("name", "*")),
        ("conda-forge::name=1.2.3", ("name", "1.2.3")),
        ("name=1.2.3", ("name", "1.2.3")),
        ("name", ("name", "*")),
        ("name 1.2.3", ("name", "1.2.3")),
    ],
)
def test_parse_conda_dependency(line: str, expected: tuple[str, str] | None) -> None:
    assert _parse_conda_dependency(line) == expected


def test_merge_dependency_version() -> None:
    store: dict[str, str] = {}
    assert merge_dependency_version(store, "name", "1.2.3") is True
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", "1.2.3") is False
    assert merge_dependency_version(store, "name", "*") is False
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", ">=1.2.3") is False
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", "@ https://example.com/pkg.zip") is True
    assert store["name"] == "@ https://example.com/pkg.zip"
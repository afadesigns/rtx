from __future__ import annotations

import pytest

from rtx.advisory import (
    _extract_numeric_score,
    _severity_from_github,
    _severity_from_label,
    _severity_from_osv,
)
from rtx.models import Severity


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"severity": [{"score": "9.0"}]}, Severity.CRITICAL),
        ({"severity": [{"score": "7.0"}]}, Severity.HIGH),
        ({"severity": [{"score": "4.0"}]}, Severity.MEDIUM),
        ({"severity": [{"score": "0.1"}]}, Severity.LOW),
        ({"database_specific": {"severity": "CRITICAL"}}, Severity.CRITICAL),
    ],
)
def test_severity_from_osv(entry: dict, expected: Severity) -> None:
    assert _severity_from_osv(entry) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (1.0, 1.0),
        ("2.0", 2.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.0),
        ("Score: 9.8", 9.8),
        (None, 0.0),
    ],
)
def test_extract_numeric_score(raw: object, expected: float) -> None:
    assert _extract_numeric_score(raw) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("low", Severity.LOW),
        (None, Severity.NONE),
    ],
)
def test_severity_from_label(label: str | None, expected: Severity) -> None:
    assert _severity_from_label(label) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("low", Severity.LOW),
        (None, Severity.LOW),
    ],
)
def test_severity_from_github(label: str | None, expected: Severity) -> None:
    assert _severity_from_github(label) == expected
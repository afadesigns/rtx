from __future__ import annotations

from pathlib import Path

from datetime import datetime
from pathlib import Path

import pytest

from rtx.models import Dependency, PackageFinding, Report
from rtx.sbom import (
    _license_entry,
    _license_key,
    _normalize_licenses,
    _purl,
    _serialize_references,
    generate_sbom,
)


def test_generate_sbom() -> None:
    report = Report(
        path=Path("."),
        findings=[
            PackageFinding(
                dependency=Dependency("pypi", "name", "1.0", True, Path("manifest")),
                advisories=[],
                signals=[],
                score=0,
            )
        ],
        generated_at=datetime.utcnow(),
        managers=[],
    )
    sbom = generate_sbom(report)
    assert sbom["bomFormat"] == "CycloneDX"
    assert len(sbom["components"]) == 1


def test_purl() -> None:
    finding = PackageFinding(
        dependency=Dependency("pypi", "name", "1.0", True, Path("manifest")),
        advisories=[],
        signals=[],
        score=0,
    )
    assert _purl(finding) == "pkg:pypi/name@1.0"

    finding = PackageFinding(
        dependency=Dependency(
            "maven", "group:artifact", "1.0", True, Path("manifest")
        ),
        advisories=[],
        signals=[],
        score=0,
    )
    assert _purl(finding) == "pkg:maven/group/artifact@1.0"


@pytest.mark.parametrize(
    ("metadata", "expected"),
    [
        ({"license": "MIT"}, [{"license": {"id": "MIT"}}]),
        ({"license": ["MIT", "Apache-2.0"]}, [{"license": {"id": "MIT"}}, {"license": {"id": "Apache-2.0"}}]),
        ({"license": {"id": "MIT"}}, [{"license": {"id": "MIT"}}]),
        ({}, [{"license": {"id": "UNKNOWN"}}]),
        ({"license": None}, [{"license": {"id": "UNKNOWN"}}]),
    ],
)
def test_normalize_licenses(metadata: dict, expected: list) -> None:
    assert _normalize_licenses(metadata) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("MIT", {"license": {"id": "MIT"}}),
        ("  ", None),
        ({"id": "MIT"}, {"license": {"id": "MIT"}}),
        ({"name": "MIT"}, {"license": {"id": "MIT"}}),
        ({"license": {"id": "MIT"}}, {"license": {"id": "MIT"}}),
        ({}, {"license": {}}),
        (None, None),
    ],
)
def test_license_entry(value: object, expected: dict | None) -> None:
    assert _license_entry(value) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"license": {"id": "MIT"}}, ("MIT", ())),
        ({"license": {"name": "MIT"}}, ("MIT", ())),
        ({"license": {"foo": "bar"}}, ("dict", (("foo", "bar"),))),
    ],
)
def test_license_key(entry: dict, expected: tuple) -> None:
    assert _license_key(entry) == expected


@pytest.mark.parametrize(
    ("references", "expected"),
    [
        (["http://example.com"], [{"url": "http://example.com"}]),
        (["  http://example.com  "], [{"url": "http://example.com"}]),
        ([""], []),
        ([None], []),
    ],
)
def test_serialize_references(references: list, expected: list) -> None:
    assert _serialize_references(references) == expected

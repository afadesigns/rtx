from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from rtx import __version__
from rtx.models import Dependency, PackageFinding, Report
from rtx.sbom import generate_sbom, write_sbom


def test_generate_sbom_contains_components(tmp_path: Path) -> None:
    dependency = Dependency(
        ecosystem="pypi",
        name="requests",
        version="2.31.0",
        direct=True,
        manifest=tmp_path,
    )
    finding = PackageFinding(dependency=dependency, score=0.0)
    report = Report(
        path=tmp_path,
        managers=["pypi"],
        findings=[finding],
        generated_at=datetime.utcnow(),
    )
    sbom = generate_sbom(report)
    assert sbom["components"][0]["name"] == "requests"
    assert sbom["components"][0]["purl"].startswith("pkg:pypi/requests")
    assert sbom["components"][0]["licenses"] == [{"license": {"id": "UNKNOWN"}}]


def test_generate_sbom_includes_project_version_and_license(tmp_path: Path) -> None:
    dependency = Dependency(
        ecosystem="npm",
        name="left-pad",
        version="1.0.0",
        direct=False,
        manifest=tmp_path,
        metadata={"license": ["MIT", "Apache-2.0"]},
    )
    report = Report(
        path=tmp_path,
        managers=["npm"],
        findings=[PackageFinding(dependency=dependency)],
        generated_at=datetime.utcnow(),
    )
    sbom = generate_sbom(report)
    assert sbom["metadata"]["tools"][0]["version"] == __version__
    licenses = sbom["components"][0]["licenses"]
    assert {entry["license"]["id"] for entry in licenses} == {"MIT", "Apache-2.0"}


def test_write_sbom_creates_parent_directories(tmp_path: Path) -> None:
    dependency = Dependency(
        ecosystem="pypi",
        name="tool",
        version="0.0.1",
        direct=True,
        manifest=tmp_path,
    )
    report = Report(
        path=tmp_path,
        managers=["pypi"],
        findings=[PackageFinding(dependency=dependency)],
        generated_at=datetime.utcnow(),
    )
    destination = tmp_path / "reports" / "sbom.json"
    write_sbom(report, path=destination)
    assert destination.exists()
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["components"][0]["name"] == "tool"

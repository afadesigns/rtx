from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rtx.models import Dependency, PackageFinding, Report
from rtx.sbom import generate_sbom


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

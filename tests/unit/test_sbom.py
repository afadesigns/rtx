from __future__ import annotations

from pathlib import Path

from datetime import datetime
from pathlib import Path

from rtx.models import Dependency, PackageFinding, Report
from rtx.sbom import _purl, generate_sbom


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


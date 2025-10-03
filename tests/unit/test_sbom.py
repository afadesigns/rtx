from __future__ import annotations

import json
from pathlib import Path

from rtx import __version__
from rtx.models import Advisory, Dependency, PackageFinding, Report, Severity
from rtx.sbom import generate_sbom, write_sbom
from rtx.utils import utc_now


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
        generated_at=utc_now(),
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
        metadata={"license": {"MIT", "Apache-2.0"}},
    )
    report = Report(
        path=tmp_path,
        managers=["npm"],
        findings=[PackageFinding(dependency=dependency)],
        generated_at=utc_now(),
    )
    sbom = generate_sbom(report)
    assert sbom["metadata"]["tools"][0]["version"] == __version__
    licenses = sbom["components"][0]["licenses"]
    assert {entry["license"]["id"] for entry in licenses} == {"MIT", "Apache-2.0"}


def test_generate_sbom_merges_duplicate_components(tmp_path: Path) -> None:
    direct_dependency = Dependency(
        ecosystem="pypi",
        name="demo",
        version="1.0.0",
        direct=True,
        manifest=tmp_path / "pyproject.toml",
        metadata={"license": "MIT"},
    )
    indirect_dependency = Dependency(
        ecosystem="pypi",
        name="demo",
        version="1.0.0",
        direct=False,
        manifest=tmp_path / "sub" / "pyproject.toml",
        metadata={"license": {"id": "MIT"}},
    )
    findings = [
        PackageFinding(dependency=direct_dependency),
        PackageFinding(dependency=indirect_dependency),
    ]
    report = Report(
        path=tmp_path,
        managers=["pypi"],
        findings=findings,
        generated_at=utc_now(),
    )
    sbom = generate_sbom(report)
    assert len(sbom["components"]) == 1
    component = sbom["components"][0]
    assert component["scope"] == "required"
    assert component["licenses"] == [{"license": {"id": "MIT"}}]


def test_generate_sbom_merges_vulnerabilities(tmp_path: Path) -> None:
    dependency_a = Dependency(
        ecosystem="pypi",
        name="alpha",
        version="1.0.0",
        direct=True,
        manifest=tmp_path / "alpha",
    )
    dependency_b = Dependency(
        ecosystem="npm",
        name="beta",
        version="2.0.0",
        direct=False,
        manifest=tmp_path / "beta",
    )
    advisory_low = Advisory(
        identifier="OSV-1",
        source="osv.dev",
        severity=Severity.LOW,
        summary="Initial",
        references=[
            " https://example.com/vuln ",
            "https://example.com/vuln",
            "",
            "\t",
        ],
    )
    advisory_high = Advisory(
        identifier="OSV-1",
        source="osv.dev",
        severity=Severity.HIGH,
        summary="Escalated",
        references=["https://example.com/vuln", "https://mirror.example/vuln", None],
    )
    findings = [
        PackageFinding(dependency=dependency_a, advisories=[advisory_low]),
        PackageFinding(dependency=dependency_b, advisories=[advisory_high]),
    ]
    report = Report(
        path=tmp_path,
        managers=["pypi", "npm"],
        findings=findings,
        generated_at=utc_now(),
    )
    sbom = generate_sbom(report)
    vulnerabilities = sbom["vulnerabilities"]
    assert len(vulnerabilities) == 1
    entry = vulnerabilities[0]
    assert entry["ratings"][0]["severity"] == Severity.HIGH.value
    refs = [ref["url"] for ref in entry["references"]]
    assert refs == ["https://example.com/vuln", "https://mirror.example/vuln"]
    affects = [affect["ref"] for affect in entry["affects"]]
    assert affects == sorted(affects)
    assert set(affects) == {
        "pkg:pypi/alpha@1.0.0",
        "pkg:npm/beta@2.0.0",
    }


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
        generated_at=utc_now(),
    )
    destination = tmp_path / "reports" / "sbom.json"
    write_sbom(report, path=destination)
    assert destination.exists()
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["components"][0]["name"] == "tool"


def test_generate_sbom_orders_outputs(tmp_path: Path) -> None:
    dependency_a = Dependency(
        ecosystem="pypi",
        name="zeta",
        version="1.0.0",
        direct=True,
        manifest=tmp_path / "zeta",
    )
    dependency_b = Dependency(
        ecosystem="pypi",
        name="alpha",
        version="1.0.0",
        direct=False,
        manifest=tmp_path / "alpha",
    )
    advisory = Advisory(
        identifier="OSV-ORDER",
        source="osv.dev",
        severity=Severity.MEDIUM,
        summary="Ordering check",
        references=[
            "https://example.com/b",
            "https://example.com/a",
        ],
    )
    findings = [
        PackageFinding(dependency=dependency_a, advisories=[advisory]),
        PackageFinding(dependency=dependency_b, advisories=[advisory]),
    ]
    report = Report(
        path=tmp_path,
        managers=["pypi"],
        findings=findings,
        generated_at=utc_now(),
    )

    sbom = generate_sbom(report)
    component_names = [component["name"] for component in sbom["components"]]
    assert component_names == sorted(component_names)
    vulnerability = sbom["vulnerabilities"][0]
    assert [ref["url"] for ref in vulnerability["references"]] == [
        "https://example.com/a",
        "https://example.com/b",
    ]
    assert [affect["ref"] for affect in vulnerability["affects"]] == sorted(
        affect["ref"] for affect in vulnerability["affects"]
    )

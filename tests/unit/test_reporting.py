from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from rtx.exceptions import ReportRenderingError
from rtx.models import Advisory, Dependency, PackageFinding, Report, Severity, TrustSignal
from rtx.reporting import render, render_json


def _sample_report() -> Report:
    dependency = Dependency(
        ecosystem="pypi",
        name="demo",
        version="1.2.3",
        direct=True,
        manifest=Path("pyproject.toml"),
        metadata={"summary": "Demo package"},
    )
    finding = PackageFinding(
        dependency=dependency,
        advisories=[
            Advisory(
                identifier="OSV-2025-0001",
                source="osv.dev",
                severity=Severity.LOW,
                summary="Example issue",
                references=[],
            )
        ],
        signals=[
            TrustSignal(
                category="maintainer",
                severity=Severity.LOW,
                message="Single maintainer",
                evidence={},
            )
        ],
        score=0.2,
    )
    return Report(
        path=Path("."),
        managers=["pypi"],
        findings=[finding],
        generated_at=datetime.utcnow(),
        stats={"dependency_count": 1},
    )


def test_render_json_roundtrip(tmp_path: Path) -> None:
    report = _sample_report()
    output = tmp_path / "report.json"
    serialized = render_json(report, path=output)
    saved = output.read_text(encoding="utf-8")
    assert saved == serialized
    payload = json.loads(serialized)
    assert payload["summary"]["total"] == 1


def test_render_html_writes_file(tmp_path: Path) -> None:
    report = _sample_report()
    output = tmp_path / "report.html"
    render(report, fmt="html", output=output)
    contents = output.read_text(encoding="utf-8")
    assert "Real Tracker X" in contents
    assert "Demo package" in contents


def test_render_requires_output_for_json(tmp_path: Path) -> None:
    report = _sample_report()
    with pytest.raises(ReportRenderingError):
        render(report, fmt="json")


def test_render_unknown_format(tmp_path: Path) -> None:
    report = _sample_report()
    with pytest.raises(ReportRenderingError):
        render(report, fmt="pdf", output=tmp_path / "out.pdf")

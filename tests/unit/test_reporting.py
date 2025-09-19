from __future__ import annotations

import json
from datetime import datetime
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from rtx.exceptions import ReportRenderingError
from rtx.models import Advisory, Dependency, PackageFinding, Report, Severity, TrustSignal
from rtx.reporting import render, render_json, render_table


def test_render_table_includes_signal_details() -> None:
    dependency = Dependency(
        ecosystem="pypi",
        name="demo",
        version="1.0.0",
        direct=True,
        manifest=Path("pyproject.toml"),
        metadata={},
    )
    signal = TrustSignal(
        category="maintainer",
        severity=Severity.MEDIUM,
        message="No maintainers listed",
        evidence={"maintainers": []},
    )
    finding = PackageFinding(
        dependency=dependency,
        advisories=[],
        signals=[signal],
        score=0.4,
    )
    report = Report(
        path=Path("."),
        managers=["pypi"],
        findings=[finding],
        generated_at=datetime.utcnow(),
        stats={"dependency_count": 1},
    )

    buffer = StringIO()
    console = Console(file=buffer, force_terminal=False, color_system=None, width=120, record=False)
    render_table(report, console=console)
    output = buffer.getvalue()

    assert "maintainer (medium)" in output
    assert "No maintainers listed" in output
    assert "[maintainers=[]]" in output
    assert "Signals: maintainer=1" in output
    assert "Signal severities: medium=1" in output


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
    assert payload["summary"]["signal_counts"]["maintainer"] == 1
    assert payload["summary"]["signal_severity_totals"]["low"] == 1
    assert payload["summary"]["signal_severity_counts"]["maintainer"]["low"] == 1


def test_render_html_writes_file(tmp_path: Path) -> None:
    report = _sample_report()
    output = tmp_path / "report.html"
    render(report, fmt="html", output=output)
    contents = output.read_text(encoding="utf-8")
    assert "Real Tracker X" in contents
    assert "Demo package" in contents
    assert "Signal Breakdown" in contents
    assert "Signal Severities" in contents


def test_render_requires_output_for_json(tmp_path: Path) -> None:
    report = _sample_report()
    with pytest.raises(ReportRenderingError):
        render(report, fmt="json")


def test_render_unknown_format(tmp_path: Path) -> None:
    report = _sample_report()
    with pytest.raises(ReportRenderingError):
        render(report, fmt="pdf", output=tmp_path / "out.pdf")

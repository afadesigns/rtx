from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from rtx.cli import _report_from_payload, main
from rtx.models import Advisory, Dependency, PackageFinding, Report, Severity, TrustSignal
from rtx.system import ToolStatus


def _sample_report(exit_code: int = 0) -> Report:
    dependency = Dependency(
        ecosystem="pypi",
        name="sample",
        version="1.0.0",
        direct=True,
        manifest=Path("pyproject.toml"),
        metadata={},
    )
    severity = Severity.HIGH if exit_code == 2 else Severity.NONE
    finding = PackageFinding(
        dependency=dependency,
        advisories=[
            Advisory(
                identifier="OSV-2024-0001",
                source="osv.dev",
                severity=severity,
                summary="Example advisory",
                references=["https://example.com"],
            )
        ]
        if exit_code
        else [],
        signals=[
            TrustSignal(
                category="maintainer",
                severity=severity,
                message="Single maintainer",
                evidence={"maintainers": ["solo"]},
            )
        ]
        if exit_code
        else [],
        score=1.0 if exit_code else 0.0,
    )
    findings: list[PackageFinding] = [finding] if exit_code else []
    return Report(
        path=Path("."),
        managers=["pypi"],
        findings=findings,
        generated_at=datetime.utcnow(),
        stats={
            "dependency_count": len(findings),
            "direct_dependencies": len([f for f in findings if f.dependency.direct]),
            "indirect_dependencies": len([f for f in findings if not f.dependency.direct]),
            "graph_nodes": len(findings),
            "graph_edges": 0,
            "manager_usage": {"pypi": len(findings)},
        },
    )


@pytest.fixture(autouse=True)
def mock_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("rtx.cli._configure_logging", lambda level: None, raising=False)


def test_scan_invokes_render(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any) -> None:
    report = _sample_report(exit_code=0)
    captured: dict[str, Any] = {}

    monkeypatch.setattr(
        "rtx.api.scan_project",
        lambda path, managers=None: report,
        raising=False,
    )
    monkeypatch.setattr(
        "rtx.reporting.render_table",
        lambda report_obj, console=None: captured.update({"fmt": "table"}),
        raising=False,
    )
    monkeypatch.setattr("rtx.sbom.write_sbom", lambda *_, **__: None, raising=False)

    exit_code = main(["scan", "--path", str(tmp_path)])
    assert exit_code == 0
    assert captured == {"fmt": "table"}
    captured_stdout = capsys.readouterr().out
    assert "table" not in captured_stdout  # ensure our stub handled rendering


def test_scan_rejects_unknown_format(tmp_path: Path, capsys: Any) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", "--path", str(tmp_path), "--format", "pdf"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "invalid choice" in captured.err


def test_scan_unknown_manager(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: Any) -> None:
    def fail(_path: Path, managers=None):
        raise ValueError("Unknown package manager(s): foo")

    monkeypatch.setattr("rtx.api.scan_project", fail, raising=False)
    exit_code = main(["scan", "--path", str(tmp_path), "--manager", "foo"])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Unknown package manager(s): foo" in captured.out


def test_scan_signal_summary_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: Any,
) -> None:
    report = _sample_report(exit_code=2)
    monkeypatch.setattr("rtx.api.scan_project", lambda *_: report, raising=False)
    monkeypatch.setattr("rtx.reporting.render_table", lambda *_, **__: None, raising=False)
    monkeypatch.setattr("rtx.sbom.write_sbom", lambda *_, **__: None, raising=False)

    exit_code = main(
        [
            "scan",
            "--path",
            str(tmp_path),
            "--show-signal-summary",
            "--signal-summary-output",
            str(tmp_path / "summary.json"),
        ]
    )

    assert exit_code == 2
    captured = capsys.readouterr().out
    assert "Signals: maintainer=1" in captured
    summary_path = tmp_path / "summary.json"
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    assert data["counts"]["maintainer"] == 1


def test_report_renders_from_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: Any,
) -> None:
    report = _sample_report(exit_code=2)
    payload = report.to_dict()
    payload["summary"]["generated_at"] = report.generated_at.isoformat()
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(payload), encoding="utf-8")

    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        "rtx.reporting.render",
        lambda report_obj, fmt, output: captured.update(
            {
                "fmt": fmt,
                "output": output,
                "exit": report_obj.exit_code(),
            }
        ),
        raising=False,
    )

    exit_code = main(
        [
            "report",
            str(report_file),
            "--format",
            "json",
            "--output",
            str(tmp_path / "out.json"),
        ]
    )
    assert exit_code == 2
    assert captured["fmt"] == "json"
    assert Path(captured["output"]).name == "out.json"


def test_report_signal_summary_flag(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: Any,
) -> None:
    report = _sample_report(exit_code=2)
    payload = report.to_dict()
    payload["summary"]["generated_at"] = report.generated_at.isoformat()
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(payload), encoding="utf-8")

    monkeypatch.setattr("rtx.reporting.render", lambda *_, **__: None, raising=False)

    exit_code = main(
        [
            "report",
            str(report_file),
            "--format",
            "table",
            "--show-signal-summary",
        ]
    )

    assert exit_code == 2
    captured = capsys.readouterr().out
    assert "Signals: maintainer=1" in captured


def test_report_missing_file(tmp_path: Path, capsys: Any) -> None:
    exit_code = main(["report", str(tmp_path / "missing.json")])
    captured = capsys.readouterr()
    assert exit_code == 4
    assert "Failed to read report file" in captured.out


def test_pre_upgrade_unknown_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: Any,
) -> None:
    def fail(_path: Path, managers=None):
        raise ValueError("Unknown package manager(s): foo")

    monkeypatch.setattr("rtx.api.scan_project", fail, raising=False)
    exit_code = main(
        [
            "pre-upgrade",
            "--path",
            str(tmp_path),
            "--package",
            "requests",
            "--version",
            "2.32.0",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Unknown package manager(s): foo" in captured.out


def test_report_from_payload_roundtrip() -> None:
    report = _sample_report(exit_code=2)
    payload = report.to_dict()
    payload["summary"]["generated_at"] = report.generated_at.isoformat()
    restored = _report_from_payload(payload)
    assert restored.exit_code() == 2


def test_diagnostics_outputs_plain_text(monkeypatch: pytest.MonkeyPatch) -> None:
    statuses = [
        ToolStatus(name="pip", available=True, path="/usr/bin/pip", version="pip 25"),
        ToolStatus(name="npm", available=False),
        ToolStatus(name="uv", available=True, path="/usr/bin/uv", error="timeout"),
    ]

    monkeypatch.setattr(
        "rtx.cli.collect_manager_diagnostics",
        lambda: statuses,
        raising=False,
    )

    lines: list[str] = []

    class DummyConsole:
        def print(self, message: str) -> None:
            lines.append(message)

    monkeypatch.setattr("rtx.cli._get_console", lambda: DummyConsole(), raising=False)

    exit_code = main(["diagnostics"])

    assert exit_code == 1
    assert any("pip" in line and "available" in line for line in lines)
    assert any("npm" in line and "missing" in line for line in lines)
    assert any("uv" in line and "error=timeout" in line for line in lines)


def test_diagnostics_json_output(monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
    statuses = [ToolStatus(name="pip", available=True, path="/usr/bin/pip", version="pip 25")]

    monkeypatch.setattr(
        "rtx.cli.collect_manager_diagnostics",
        lambda: statuses,
        raising=False,
    )

    exit_code = main(["diagnostics", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["pip"]["available"] is True

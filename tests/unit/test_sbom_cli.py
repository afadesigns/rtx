from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

from rtx.models import Report
from rtx.sbom_cli import main as sbom_main


@pytest.mark.parametrize("fmt", ["json", "html"])
def test_sbom_cli_writes_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fmt: str) -> None:
    output_path = tmp_path / ("report." + fmt)

    def fake_scan_project(path: Path, managers: list[str] | None = None):  # type: ignore[unused-argument]
        return Report(
            path=path,
            managers=managers or [],
            findings=[],
            generated_at=datetime.utcnow(),
        )

    monkeypatch.setattr("rtx.sbom_cli.scan_project", fake_scan_project)

    argv = [
        "sbom-cli",
        "--path",
        str(tmp_path),
        "--output",
        str(output_path),
        "--format",
        fmt,
    ]
    monkeypatch.setattr(sys, "argv", argv)

    sbom_main()

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    if fmt == "json":
        assert content.strip().startswith("{")
    else:
        assert "<html" in content.lower()

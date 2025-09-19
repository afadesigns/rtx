from __future__ import annotations

from pathlib import Path

from rtx.scanners.npm import NpmScanner
from rtx.scanners.pypi import PyPIScanner


def test_pypi_scanner_reads_pyproject(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        """[project]\nname='demo'\nversion='0.1.0'\ndependencies=['requests==2.31.0']\n""",
        encoding="utf-8",
    )
    scanner = PyPIScanner()
    packages = scanner.scan(project)
    assert any(dep.name == "requests" for dep in packages)


def test_npm_scanner_reads_package_lock(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "package-lock.json").write_text(
        """{\n  \"packages\": {\n    \"node_modules/lodash\": {\"version\": \"4.17.21\"}\n  }\n}\n""",
        encoding="utf-8",
    )
    scanner = NpmScanner()
    packages = scanner.scan(project)
    assert packages[0].name == "lodash"

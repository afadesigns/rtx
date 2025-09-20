from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from rtx.registry import get_scanners
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


def test_pypi_scanner_prefers_poetry_dep_versions(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        textwrap.dedent(
            """
            [project]
            name = "demo"
            version = "0.1.0"
            dependencies = ["requests"]

            [tool.poetry.dependencies]
            requests = "2.31.0"
            """
        ),
        encoding="utf-8",
    )
    scanner = PyPIScanner()
    packages = scanner.scan(project)

    assert any(dep.name == "requests" and dep.version == "2.31.0" for dep in packages)


def test_npm_scanner_reads_package_lock(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "package-lock.json").write_text(
        textwrap.dedent(
            """
            {
              "packages": {
                "node_modules/lodash": {"version": "4.17.21"}
              }
            }
            """
        ),
        encoding="utf-8",
    )
    scanner = NpmScanner()
    packages = scanner.scan(project)
    assert packages[0].name == "lodash"


def test_npm_scanner_prefers_lockfile_versions(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "package-lock.json").write_text(
        textwrap.dedent(
            """
            {
              "packages": {
                "node_modules/lodash": {"version": "4.17.21"}
              }
            }
            """
        ),
        encoding="utf-8",
    )
    (project / "package.json").write_text(
        """{"dependencies": {"lodash": "^5.0.0"}}""",
        encoding="utf-8",
    )

    scanner = NpmScanner()
    packages = scanner.scan(project)

    assert len(packages) == 1
    dependency = packages[0]
    assert dependency.version == "4.17.21"
    assert dependency.metadata["source"] == "package-lock.json"


def test_get_scanners_unknown() -> None:
    with pytest.raises(ValueError, match="Unknown package manager"):
        get_scanners(["does-not-exist"])


def test_get_scanners_deduplicates_input_order() -> None:
    scanners = get_scanners(["pypi", "npm", "pypi", "npm"])
    names = [type(scanner).__name__ for scanner in scanners]
    assert names == ["PyPIScanner", "NpmScanner"]

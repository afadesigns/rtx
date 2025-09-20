from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from rtx.registry import get_scanners
from rtx.scanners.composer import ComposerScanner
from rtx.scanners.npm import NpmScanner
from rtx.scanners.nuget import NuGetScanner
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


def test_get_scanners_alias_support() -> None:
    scanners = get_scanners(["pip", "node", "gem"])
    names = [type(scanner).__name__ for scanner in scanners]
    assert names == ["PyPIScanner", "NpmScanner", "RubyGemsScanner"]


def test_pypi_scanner_handles_pipfile_tables(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "Pipfile").write_text(
        textwrap.dedent(
            """
            [packages]
            requests = {version = "==2.31.0", extras = ["socks"]}
            local = {path = ".", editable = true}

            [dev-packages]
            rich = "*"
            """
        ),
        encoding="utf-8",
    )
    scanner = PyPIScanner()
    packages = scanner.scan(project)

    versions = {dep.name: dep.version for dep in packages}
    assert versions["requests"] == "2.31.0"
    assert versions["rich"] == "*"
    assert "local" not in versions or versions["local"].startswith("@ ")


def test_composer_scanner_marks_direct_and_dev_dependencies(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "composer.json").write_text(
        textwrap.dedent(
            """
            {
              "require": {
                "vendor/core": "^1.2"
              },
              "require-dev": {
                "vendor/devtool": "^0.3"
              }
            }
            """
        ),
        encoding="utf-8",
    )
    (project / "composer.lock").write_text(
        textwrap.dedent(
            """
            {
              "packages": [
                {"name": "vendor/core", "version": "1.2.1"}
              ],
              "packages-dev": [
                {"name": "vendor/devtool", "version": "0.3.5"},
                {"name": "third/party", "version": "2.0.0"}
              ]
            }
            """
        ),
        encoding="utf-8",
    )

    scanner = ComposerScanner()
    dependencies = {dep.name: dep for dep in scanner.scan(project)}

    core = dependencies["vendor/core"]
    assert core.version == "1.2.1"
    assert core.direct is True
    assert core.metadata["scope"] == "production"
    assert core.metadata["source"] == "composer.lock"

    devtool = dependencies["vendor/devtool"]
    assert devtool.direct is True
    assert devtool.metadata["dev"] is True
    assert devtool.metadata["scope"] == "development"

    transitive = dependencies["third/party"]
    assert transitive.direct is False
    assert transitive.metadata["scope"] == "transitive"


def test_nuget_scanner_parses_project_references(tmp_path: Path) -> None:
    project = tmp_path / "demo"
    project.mkdir()
    (project / "packages.lock.json").write_text("{}", encoding="utf-8")
    (project / "broken.csproj").write_text("<Project>", encoding="utf-8")
    (project / "app.csproj").write_text(
        textwrap.dedent(
            """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                <PackageReference Include="Serilog" >
                  <Version>2.12.0</Version>
                </PackageReference>
              </ItemGroup>
            </Project>
            """
        ),
        encoding="utf-8",
    )

    scanner = NuGetScanner()
    dependencies = {dep.name: dep for dep in scanner.scan(project)}

    assert dependencies["Newtonsoft.Json"].version == "13.0.3"
    assert dependencies["Serilog"].version == "2.12.0"

from __future__ import annotations

from pathlib import Path

import pytest

from rtx.scanners.common import (
    _clean_pnpm_version,
    _parse_conda_dependency,
    _parse_npm_token,
    _parse_pnpm_package_key,
    _parse_requirement_line,
    merge_dependency_version,
    read_brewfile,
    read_cargo_lock,
    read_composer_lock,
    read_dockerfile,
    read_environment_yml,
    read_gemfile_lock,
    read_go_mod,
    read_maven_pom,
    read_packages_lock,
    read_pnpm_lock,
    read_poetry_lock,
    read_requirements,
    read_uv_lock,
)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("", None),
        ("# comment", None),
        ("-r requirements.txt", None),
        ("name==", None),
        ("name == 1.2.3", ("name", "1.2.3")),
        ("name==1.2.3", ("name", "1.2.3")),
        ("name", ("name", "*")),
        ("name==1.2.3 # comment", ("name", "1.2.3")),
        ("name @ https://example.com/pkg.zip", ("name", "@ https://example.com/pkg.zip")),
        ("name>=1.2.3", ("name", ">=1.2.3")),
        ("name<2.0.0,>=1.2.3", ("name", ">=1.2.3,<2.0.0")),
    ],
)
def test_parse_requirement_line(line: str, expected: tuple[str, str] | None) -> None:
    assert _parse_requirement_line(line) == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("", None),
        ("# comment", None),
        ("conda-forge::name", ("name", "*")),
        ("conda-forge::name=1.2.3", ("name", "1.2.3")),
        ("name=1.2.3", ("name", "1.2.3")),
        ("name", ("name", "*")),
        ("name 1.2.3", ("name", "1.2.3")),
    ],
)
def test_parse_conda_dependency(line: str, expected: tuple[str, str] | None) -> None:
    assert _parse_conda_dependency(line) == expected


def test_merge_dependency_version() -> None:
    store: dict[str, str] = {}
    assert merge_dependency_version(store, "name", "1.2.3") is True
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", "1.2.3") is False
    assert merge_dependency_version(store, "name", "*") is False
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", ">=1.2.3") is False
    assert store["name"] == "1.2.3"
    assert merge_dependency_version(store, "name", "@ https://example.com/pkg.zip") is True
    assert store["name"] == "@ https://example.com/pkg.zip"


def test_read_requirements(tmp_path: Path) -> None:
    (tmp_path / "base.txt").write_text("name==1.2.3")
    (tmp_path / "constraints.txt").write_text("name==1.2.3\nother==4.5.6")
    (tmp_path / "requirements.txt").write_text("-r base.txt\n-c constraints.txt")
    requirements = read_requirements(tmp_path / "requirements.txt")
    assert requirements == {"name": "1.2.3", "other": "4.5.6"}


def test_read_dockerfile(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
        FROM python:3.11
        RUN pip install name==1.2.3
        RUN npm install other@4.5.6 && \
            pip install another==7.8.9
        """
    )
    dependencies = read_dockerfile(dockerfile)
    assert dependencies == {
        "pypi:name": "1.2.3",
        "npm:other": "4.5.6",
        "pypi:another": "7.8.9",
    }


def test_read_go_mod(tmp_path: Path) -> None:
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        """
        module example.com/my/module
        go 1.18
        require (
            example.com/other/module v1.2.3
            example.com/another/module v4.5.6
        )
        """
    )
    dependencies = read_go_mod(go_mod)
    assert dependencies == {
        "example.com/other/module": "v1.2.3",
        "example.com/another/module": "v4.5.6",
    }


def test_read_brewfile(tmp_path: Path) -> None:
    brewfile = tmp_path / "Brewfile"
    brewfile.write_text(
        """
        brew "name"
        brew "other", version: "1.2.3"
        """
    )
    dependencies = read_brewfile(brewfile)
    assert dependencies == {"name": "latest", "other": "1.2.3"}


def test_read_gemfile_lock(tmp_path: Path) -> None:
    gemfile_lock = tmp_path / "Gemfile.lock"
    gemfile_lock.write_text(
        """
        GEM
          remote: https://rubygems.org/
          specs:
            name (1.2.3)
            other (4.5.6)
        """
    )
    dependencies = read_gemfile_lock(gemfile_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_cargo_lock(tmp_path: Path) -> None:
    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_text(
        """
        [[package]]
        name = "name"
        version = "1.2.3"
        [[package]]
        name = "other"
        version = "4.5.6"
        """
    )
    dependencies = read_cargo_lock(cargo_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_composer_lock(tmp_path: Path) -> None:
    composer_lock = tmp_path / "composer.lock"
    composer_lock.write_text(
        """
        {
            "packages": [
                {
                    "name": "name",
                    "version": "1.2.3"
                },
                {
                    "name": "other",
                    "version": "4.5.6"
                }
            ]
        }
        """
    )
    dependencies = read_composer_lock(composer_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_maven_pom(tmp_path: Path) -> None:
    pom_xml = tmp_path / "pom.xml"
    pom_xml.write_text(
        """
        <project>
            <dependencies>
                <dependency>
                    <groupId>group</groupId>
                    <artifactId>name</artifactId>
                    <version>1.2.3</version>
                </dependency>
                <dependency>
                    <groupId>group</groupId>
                    <artifactId>other</artifactId>
                    <version>4.5.6</version>
                </dependency>
            </dependencies>
        </project>
        """
    )
    dependencies = read_maven_pom(pom_xml)
    assert dependencies == {"group:name": "1.2.3", "group:other": "4.5.6"}


def test_read_environment_yml(tmp_path: Path) -> None:
    environment_yml = tmp_path / "environment.yml"
    environment_yml.write_text(
        """
        dependencies:
          - conda-forge::name=1.2.3
          - other==4.5.6
          - pip:
            - pip-name==7.8.9
        """
    )
    dependencies = read_environment_yml(environment_yml)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6", "pip-name": "7.8.9"}


def test_read_packages_lock(tmp_path: Path) -> None:
    packages_lock = tmp_path / "packages.lock.json"
    packages_lock.write_text(
        """
        {
            "dependencies": {
                "name": {
                    "version": "1.2.3"
                },
                "other": {
                    "resolved": "4.5.6"
                }
            }
        }
        """
    )
    dependencies = read_packages_lock(packages_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_poetry_lock(tmp_path: Path) -> None:
    poetry_lock = tmp_path / "poetry.lock"
    poetry_lock.write_text(
        """
        [[package]]
        name = "name"
        version = "1.2.3"
        [[package]]
        name = "other"
        version = "4.5.6"
        """
    )
    dependencies = read_poetry_lock(poetry_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_uv_lock(tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
        version = 1

        [[package]]
        name = "name"
        version = "1.2.3"

        [[package]]
        name = "other"
        version = "4.5.6"
        """
    )
    dependencies = read_uv_lock(uv_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


def test_read_pnpm_lock(tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        """
        packages:
          /name/1.2.3:
            resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
            dev: false
          /other/4.5.6:
            resolution: {integrity: sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=}
            dev: true
        """
    )
    dependencies = read_pnpm_lock(pnpm_lock)
    assert dependencies == {"name": "1.2.3", "other": "4.5.6"}


@pytest.mark.parametrize(
    ("key", "expected_name", "expected_version"),
    [
        ("", None, None),
        ("/name/1.2.3", "name", "1.2.3"),
        ("/@scope/name/1.2.3", "@scope/name", "1.2.3"),
        ("name@1.2.3", "name", "1.2.3"),
        ("@scope/name@1.2.3", "@scope/name", "1.2.3"),
        ("node_modules/name", "name", None),
        ("node_modules/@scope/name", "@scope/name", None),
        ("name", "name", None),
        ("@scope/name", "@scope/name", None),
        ("/name", "name", None),
        ("/@scope/name", "@scope/name", None),
        ("name/1.2.3", "name", "1.2.3"),
        ("@scope/name/1.2.3", "@scope/name", "1.2.3"),
        # Additional cases for robustness
        ("name@^1.0.0", "name", "^1.0.0"),
        ("@scope/name@~1.0.0", "@scope/name", "~1.0.0"),
        ("name@latest", "name", "latest"),
        ("/name", "name", None),
        ("/@scope/name", "@scope/name", None),
        ("node_modules/name/1.2.3", "name", "1.2.3"),
        ("node_modules/@scope/name/1.2.3", "@scope/name", "1.2.3"),
    ],
)
def test_parse_pnpm_package_key(key: str, expected_name: str | None, expected_version: str | None) -> None:
    name, version = _parse_pnpm_package_key(key)
    assert name == expected_name
    assert version == expected_version


@pytest.mark.parametrize(
    ("raw_version", "expected_version"),
    [
        (None, None),
        ("", None),
        ("1.2.3", "1.2.3"),
        ("1.2.3 (some-hash)", "1.2.3"),
        ("link:../foo", None),
        ("workspace:^1.0.0", None),
        ("file:../foo.tgz", None),
        ("github:user/repo", None),
        ("git+ssh://git@github.com/user/repo.git", None),
        ("npm:name@1.2.3", "1.2.3"),
        ("npm:@scope/name@1.2.3", "1.2.3"),
    ],
)
def test_clean_pnpm_version(raw_version: str | None, expected_version: str | None) -> None:
    assert _clean_pnpm_version(raw_version) == expected_version

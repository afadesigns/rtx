from __future__ import annotations

import textwrap
from pathlib import Path

from rtx.scanners import common


def test_parse_pnpm_package_key_handles_scoped() -> None:
    name, version = common._parse_pnpm_package_key("/@scope/pkg@1.2.3")
    assert name == "@scope/pkg"
    assert version == "1.2.3"


def test_clean_pnpm_version_strips_disallowed_prefixes() -> None:
    assert common._clean_pnpm_version("link:../demo") is None
    assert common._clean_pnpm_version("npm:@scope/pkg@2.0.0") == "2.0.0"
    assert common._clean_pnpm_version("1.0.0") == "1.0.0"


def test_read_uv_lock_prefers_virtual_dependencies(tmp_path: Path) -> None:
    lock_path = tmp_path / "uv.lock"
    lock_path.write_text(
        textwrap.dedent(
            """
            [[package]]
            name = "demo"
            version = "1.0.0"
            [package.source]
            virtual = "."
            [[package.dependencies]]
            name = "requests"
            specifier = "==2.31.0"

            [[package]]
            name = "requests"
            version = "2.31.0"
            """
        ),
        encoding="utf-8",
    )
    resolved = common.read_uv_lock(lock_path)
    assert resolved == {"requests": "2.31.0"}


def test_read_pnpm_lock_prefers_importer_sections(tmp_path: Path) -> None:
    lock_path = tmp_path / "pnpm-lock.yaml"
    lock_path.write_text(
        textwrap.dedent(
            """
            importers:
              .:
                dependencies:
                  lodash:
                    version: 4.17.21
            packages:
              /lodash@5.0.0:
                version: 5.0.0
            """
        ),
        encoding="utf-8",
    )
    resolved = common.read_pnpm_lock(lock_path)
    assert resolved == {"lodash": "4.17.21"}


def test_read_requirements_parses_advanced_specs(tmp_path: Path) -> None:
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(
        textwrap.dedent(
            """
            requests>=2.31 # comment
            uvicorn[standard]==0.23.0
            example @ git+https://example.com/example.git
            --find-links https://example.com/simple
            -e .
            """
        ),
        encoding="utf-8",
    )
    resolved = common.read_requirements(reqs)
    assert resolved == {
        "requests": ">=2.31",
        "uvicorn": "0.23.0",
        "example": "@ git+https://example.com/example.git",
    }


def test_read_environment_yml_parses_conda_and_pip_sections(tmp_path: Path) -> None:
    env_file = tmp_path / "environment.yml"
    env_file.write_text(
        textwrap.dedent(
            """
            name: demo
            dependencies:
              - python=3.11.5=h1234
              - numpy=1.24.3=py310
              - pandas >=1.5
              - pip:
                  - rich>=13.7
                  - uvicorn[standard]==0.23.0
                  - example @ git+https://example.com/example.git
            """
        ),
        encoding="utf-8",
    )
    resolved = common.read_environment_yml(env_file)
    assert resolved == {
        "python": "3.11.5",
        "numpy": "1.24.3",
        "pandas": ">=1.5",
        "rich": ">=13.7",
        "uvicorn": "0.23.0",
        "example": "@ git+https://example.com/example.git",
    }


def test_read_dockerfile_handles_multiline_and_scoped_packages(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        textwrap.dedent(
            """
            FROM python:3.11-slim

            RUN pip install --no-cache-dir \
                requests==2.31.0 \
                "uvicorn[standard]==0.23.0" && \
                npm install --global @angular/cli@17.3.0 --prefix /usr/local

            RUN python -m pip install -r requirements.txt && npm install lodash@4.17.21
            RUN npm install ./local-package
            """
        ),
        encoding="utf-8",
    )
    resolved = common.read_dockerfile(dockerfile)
    assert resolved == {
        "pypi:requests": "2.31.0",
        "pypi:uvicorn": "0.23.0",
        "npm:@angular/cli": "17.3.0",
        "npm:lodash": "4.17.21",
    }

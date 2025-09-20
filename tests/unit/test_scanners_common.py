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

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency, ScannerResult
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class CargoScanner(BaseScanner):
    manager: ClassVar[str] = "cargo"
    manifests: ClassVar[list[str]] = ["Cargo.toml", "Cargo.lock"]
    ecosystem: ClassVar[str] = "crates"

    def scan(self, root: Path) -> ScannerResult:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}
        relationships: list[tuple[str, str]] = []

        cargo_lock = root / "Cargo.lock"
        if cargo_lock.exists():
            deps, rels = common.read_cargo_lock(cargo_lock)
            for name, version in deps.items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, cargo_lock)
            relationships.extend(rels)

        cargo_toml = root / "Cargo.toml"
        if cargo_toml.exists():
            data = common.read_toml(cargo_toml)
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                section_data = data.get(section, {})
                if isinstance(section_data, dict):
                    for name, info in section_data.items():
                        if isinstance(info, dict) and "version" in info:
                            version = info["version"]
                        else:
                            version = info if isinstance(info, str) else "*"
                        dependencies.setdefault(name, str(version))
                        origins.setdefault(name, cargo_toml)

        results: list[Dependency] = [
            self._dependency(
                name=name,
                version=common.normalize_version(version),
                manifest=origins.get(name, root),
                direct=True,
                metadata={"source": origins.get(name, root).name},
            )
            for name, version in sorted(dependencies.items())
        ]
        return ScannerResult(dependencies=results, relationships=relationships)

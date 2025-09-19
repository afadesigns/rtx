from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class CargoScanner(BaseScanner):
    manager = "cargo"
    manifests = ["Cargo.toml", "Cargo.lock"]
    ecosystem = "crates"

    def scan(self, root: Path) -> List[Dependency]:
        dependencies: Dict[str, str] = {}
        origins: Dict[str, Path] = {}

        cargo_lock = root / "Cargo.lock"
        if cargo_lock.exists():
            for name, version in common.read_cargo_lock(cargo_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, cargo_lock)

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

        return [
            self._dependency(
                name=name,
                version=common.normalize_version(version),
                manifest=origins.get(name, root),
                direct=True,
                metadata={"source": origins.get(name, root).name},
            )
            for name, version in sorted(dependencies.items())
        ]

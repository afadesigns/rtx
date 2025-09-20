from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner
from rtx.utils import read_json


class NpmScanner(BaseScanner):
    manager: ClassVar[str] = "npm"
    manifests: ClassVar[list[str]] = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ]
    ecosystem: ClassVar[str] = "npm"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}

        def record(name: str, version: str, source: Path) -> None:
            dependencies.setdefault(name, version)
            origins.setdefault(name, source)

        package_lock = root / "package-lock.json"
        if package_lock.exists():
            for name, version in common.load_lock_dependencies(package_lock).items():
                record(name, version, package_lock)

        pnpm_lock = root / "pnpm-lock.yaml"
        if pnpm_lock.exists():
            for name, version in common.read_pnpm_lock(pnpm_lock).items():
                record(name, version, pnpm_lock)

        yarn_lock = root / "yarn.lock"
        if yarn_lock.exists():
            current_name: str | None = None
            for line in yarn_lock.read_text(encoding="utf-8").splitlines():
                line = line.rstrip()
                if not line:
                    current_name = None
                elif not line.startswith(" ") and ":" in line:
                    segment = line.split(":", 1)[0]
                    if segment.startswith("\"") and segment.endswith("\""):
                        segment = segment.strip("\"")
                    if "@" in segment:
                        current_name = segment.split("@", 1)[0]
                elif current_name and line.strip().startswith("version "):
                    version = line.split("\"", 2)[1]
                    record(current_name, version, yarn_lock)

        package_json = root / "package.json"
        if package_json.exists():
            data = read_json(package_json)
            for section in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ):
                section_data = data.get(section, {})
                if isinstance(section_data, dict):
                    for name, spec in section_data.items():
                        version = str(spec)
                        record(name, version, package_json)

        results: list[Dependency] = []
        for name, version in sorted(dependencies.items()):
            results.append(
                self._dependency(
                    name=name,
                    version=common.normalize_version(version.lstrip("^~>=")),
                    manifest=origins.get(name, root),
                    direct=True,
                    metadata={"source": origins.get(name, root).name},
                )
            )
        return results

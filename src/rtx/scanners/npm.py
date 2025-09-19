from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner
from rtx.utils import read_json, read_yaml


class NpmScanner(BaseScanner):
    manager = "npm"
    manifests = ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
    ecosystem = "npm"

    def scan(self, root: Path) -> List[Dependency]:
        dependencies: Dict[str, str] = {}
        origins: Dict[str, Path] = {}

        package_lock = root / "package-lock.json"
        if package_lock.exists():
            for name, version in common.load_lock_dependencies(package_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, package_lock)

        pnpm_lock = root / "pnpm-lock.yaml"
        if pnpm_lock.exists():
            data = read_yaml(pnpm_lock) or {}
            packages = data.get("packages", {})
            if isinstance(packages, dict):
                for name, meta in packages.items():
                    if isinstance(meta, dict) and "resolution" in meta:
                        version = meta.get("version") or meta["resolution"].get("version")
                        if isinstance(version, str):
                            normalized = name.split("/")[-1]
                            dependencies.setdefault(normalized, version)
                            origins.setdefault(normalized, pnpm_lock)

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
                    dependencies.setdefault(current_name, version)
                    origins.setdefault(current_name, yarn_lock)

        package_json = root / "package.json"
        if package_json.exists():
            data = read_json(package_json)
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                section_data = data.get(section, {})
                if isinstance(section_data, dict):
                    for name, spec in section_data.items():
                        version = str(spec)
                        dependencies.setdefault(name, version)
                        origins.setdefault(name, package_json)

        results: List[Dependency] = []
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

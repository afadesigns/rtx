from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import xml.etree.ElementTree as ET

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner
from rtx.utils import detect_files


class NuGetScanner(BaseScanner):
    manager: ClassVar[str] = "nuget"
    manifests: ClassVar[list[str]] = ["packages.lock.json", "*.csproj", "*.fsproj"]
    ecosystem: ClassVar[str] = "nuget"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}

        lock = root / "packages.lock.json"
        if lock.exists():
            for name, version in common.read_packages_lock(lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, lock)

        for pattern in ("*.csproj", "*.fsproj"):
            for path in detect_files(root, [pattern]):
                try:
                    tree = ET.parse(path)
                except ET.ParseError:
                    continue
                root_tag = tree.getroot()
                namespace = (
                    ""
                    if not root_tag.tag.startswith("{")
                    else root_tag.tag.split("}", 1)[0] + "}"
                )
                for package_ref in root_tag.findall(f".//{namespace}PackageReference"):
                    raw_name = package_ref.attrib.get("Include")
                    raw_version = package_ref.attrib.get("Version")
                    if raw_version is None:
                        raw_version = package_ref.findtext(f"{namespace}Version")
                    if not raw_name or not raw_version:
                        continue
                    name = raw_name.strip()
                    version = raw_version.strip()
                    if not name or not version:
                        continue
                    dependencies.setdefault(name, version)
                    origins.setdefault(name, path)

        return [
            self._dependency(
                name=name,
                version=version,
                manifest=origins.get(name, root),
                direct=True,
                metadata={"source": origins.get(name, root).name},
            )
            for name, version in sorted(dependencies.items())
        ]

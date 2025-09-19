from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner
from rtx.utils import detect_files


class NuGetScanner(BaseScanner):
    manager = "nuget"
    manifests = ["packages.lock.json", "*.csproj", "*.fsproj"]
    ecosystem = "nuget"

    def scan(self, root: Path) -> List[Dependency]:
        dependencies: Dict[str, str] = {}
        origins: Dict[str, Path] = {}

        lock = root / "packages.lock.json"
        if lock.exists():
            for name, version in common.read_packages_lock(lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, lock)

        for pattern in ("*.csproj", "*.fsproj"):
            for path in detect_files(root, [pattern]):
                import xml.etree.ElementTree as ET

                tree = ET.parse(path)
                root_tag = tree.getroot()
                namespace = "" if not root_tag.tag.startswith("{") else root_tag.tag.split("}", 1)[0] + "}"
                for package_ref in root_tag.findall(f".//{namespace}PackageReference"):
                    name = package_ref.attrib.get("Include")
                    version = package_ref.attrib.get("Version") or package_ref.findtext(f"{namespace}Version")
                    if name and version:
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

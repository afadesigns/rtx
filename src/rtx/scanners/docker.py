from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class DockerScanner(BaseScanner):
    manager: ClassVar[str] = "docker"
    manifests: ClassVar[list[str]] = ["Dockerfile"]
    ecosystem: ClassVar[str] = "docker"

    def scan(self, root: Path) -> list[Dependency]:
        dockerfile = root / "Dockerfile"
        dependencies: dict[str, str] = {}
        if dockerfile.exists():
            dependencies.update(common.read_dockerfile(dockerfile))

        results: list[Dependency] = []
        for coordinate, version in sorted(dependencies.items()):
            ecosystem, name = coordinate.split(":", 1)
            results.append(
                self._dependency(
                    name=name,
                    version=version,
                    manifest=dockerfile,
                    direct=False,
                    metadata={"from": "Dockerfile", "ecosystem": ecosystem},
                )
            )
        return results

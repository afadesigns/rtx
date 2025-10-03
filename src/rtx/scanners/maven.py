from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class MavenScanner(BaseScanner):
    manager: ClassVar[str] = "maven"
    manifests: ClassVar[list[str]] = ["pom.xml", "build.gradle", "build.gradle.kts"]
    ecosystem: ClassVar[str] = "maven"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}

        pom = root / "pom.xml"
        if pom.exists():
            for name, version in common.read_maven_pom(pom).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, pom)

        for gradle_name in ("build.gradle", "build.gradle.kts"):
            path = root / gradle_name
            if path.exists():
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if (
                        line.startswith(
                            ("implementation", "api", "compileOnly", "runtimeOnly")
                        )
                        and "(" in line
                    ):
                        coords = line.split("(", 1)[1].rstrip(")").strip("'\"")
                        if ":" in coords:
                            parts = coords.split(":")
                            if len(parts) >= 3:
                                group, artifact, version = parts[:3]
                                name = f"{group}:{artifact}"
                                dependencies.setdefault(name, version)
                                origins.setdefault(name, path)

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

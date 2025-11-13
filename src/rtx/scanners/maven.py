from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner

_GRADLE_DECLARATIONS = (
    "implementation",
    "api",
    "compileOnly",
    "runtimeOnly",
)

_GRADLE_KEY_VALUE_PATTERN = re.compile(
    r"(group|name|version)\s*(?::|=)\s*['\"]([^'\"]+)['\"]"
)


def _extract_gradle_dependency(line: str) -> tuple[str, str] | None:
    """Extract ``group:artifact`` + version from common Gradle declarations."""
    stripped = line.strip()
    if not stripped or stripped.startswith("//"):
        return None

    for declaration in _GRADLE_DECLARATIONS:
        if not stripped.startswith(declaration):
            continue

        remainder = stripped[len(declaration) :].strip()
        if not remainder:
            continue

        if remainder.endswith("{"):
            remainder = remainder[:-1].strip()
        if remainder.startswith("(") and remainder.endswith(")"):
            remainder = remainder[1:-1].strip()
        remainder = remainder.rstrip(",")
        if "//" in remainder:
            remainder = remainder.split("//", 1)[0].strip()
        if not remainder:
            continue

        candidate = remainder
        if candidate.startswith(("'", '"')):
            quote = candidate[0]
            closing = candidate.find(quote, 1)
            if closing > 0:
                literal = candidate[1:closing]
                parts = [segment.strip() for segment in literal.split(":") if segment]
                if len(parts) >= 3:
                    return f"{parts[0]}:{parts[1]}", parts[-1]

        matches = dict(_GRADLE_KEY_VALUE_PATTERN.findall(candidate))
        group = matches.get("group")
        artifact = matches.get("name")
        version = matches.get("version")
        if group and artifact and version:
            return f"{group}:{artifact}", version

    return None


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
                    extracted = _extract_gradle_dependency(line)
                    if extracted is None:
                        continue
                    name, version = extracted
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

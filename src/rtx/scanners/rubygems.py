from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class RubyGemsScanner(BaseScanner):
    manager: ClassVar[str] = "rubygems"
    manifests: ClassVar[list[str]] = ["Gemfile", "Gemfile.lock"]
    ecosystem: ClassVar[str] = "rubygems"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}

        gemfile_lock = root / "Gemfile.lock"
        if gemfile_lock.exists():
            for name, version in common.read_gemfile_lock(gemfile_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, gemfile_lock)

        gemfile = root / "Gemfile"
        if gemfile.exists():
            for line in gemfile.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("gem "):
                    parts = [segment.strip("'\"") for segment in line.split(",")]
                    if parts:
                        name = parts[0].split()[1]
                        version = parts[1] if len(parts) > 1 else "*"
                        dependencies.setdefault(name, version)
                        origins.setdefault(name, gemfile)

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

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class ComposerScanner(BaseScanner):
    manager: ClassVar[str] = "composer"
    manifests: ClassVar[list[str]] = ["composer.json", "composer.lock"]
    ecosystem: ClassVar[str] = "packagist"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}

        composer_lock = root / "composer.lock"
        if composer_lock.exists():
            for name, version in common.read_composer_lock(composer_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, composer_lock)

        composer_json = root / "composer.json"
        if composer_json.exists():
            raw_data = common.read_json(composer_json)
            data = raw_data if isinstance(raw_data, dict) else {}
            for section in ("require", "require-dev"):
                section_data = data.get(section, {})
                if not isinstance(section_data, dict):
                    continue
                for name, version in section_data.items():
                    if not isinstance(name, str):
                        continue
                    dependencies.setdefault(name, str(version))
                    origins.setdefault(name, composer_json)

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

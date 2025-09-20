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
        direct_flags: dict[str, bool] = {}
        metadata_map: dict[str, dict[str, object]] = {}
        direct_scopes: dict[str, str] = {}

        composer_json = root / "composer.json"
        if composer_json.exists():
            raw_data = common.read_json(composer_json)
            data = raw_data if isinstance(raw_data, dict) else {}
            for section in ("require", "require-dev"):
                section_data = data.get(section, {})
                if not isinstance(section_data, dict):
                    continue
                is_dev = section == "require-dev"
                scope = "development" if is_dev else "production"
                for name, version in section_data.items():
                    if not isinstance(name, str):
                        continue
                    dependencies.setdefault(name, str(version))
                    origins.setdefault(name, composer_json)
                    direct_flags.setdefault(name, True)
                    direct_scopes[name] = scope
                    metadata = metadata_map.setdefault(name, {})
                    metadata.setdefault("scope", scope)
                    metadata.setdefault("dev", is_dev)
                    metadata.setdefault("source", composer_json.name)

        composer_lock = root / "composer.lock"
        if composer_lock.exists():
            locked = common.read_composer_lock(composer_lock)
            for name, version in locked.items():
                if not isinstance(name, str):
                    continue
                dependencies[name] = version
                origins[name] = composer_lock
                metadata = metadata_map.setdefault(name, {})
                metadata["source"] = composer_lock.name
                scope = direct_scopes.get(name)
                if scope is None:
                    metadata.setdefault("scope", "transitive")
                    metadata.setdefault("dev", False)
                direct_flags[name] = scope is not None

        return [
            self._dependency(
                name=name,
                version=common.normalize_version(version),
                manifest=origins.get(name, root),
                direct=direct_flags.get(name, False),
                metadata=metadata_map.get(
                    name, {"source": origins.get(name, root).name}
                ),
            )
            for name, version in sorted(dependencies.items())
        ]

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
        metadata_map: dict[str, dict[str, object]] = {}
        direct_flags: dict[str, bool] = {}
        direct_scopes: dict[str, str] = {}

        def record(
            name: str,
            version: str,
            source: Path,
            *,
            direct: bool | None = None,
            scope: str | None = None,
            flags: dict[str, bool] | None = None,
            prefer_source: bool = False,
        ) -> None:
            normalized_version = version.strip() if isinstance(version, str) else str(version)
            if not normalized_version:
                normalized_version = "*"
            updated = common.merge_dependency_version(dependencies, name, normalized_version)
            if updated or name not in origins or prefer_source:
                origins[name] = source
            metadata = metadata_map.setdefault(name, {})
            if direct is True:
                direct_flags[name] = True
                if scope:
                    direct_scopes[name] = scope
            elif direct is False:
                direct_flags.setdefault(name, False)
            if scope:
                if direct_flags.get(name, False):
                    metadata["scope"] = scope
                else:
                    metadata.setdefault("scope", scope)
            if flags:
                for key, value in flags.items():
                    if value:
                        metadata[key] = True
            metadata.setdefault("scope", "transitive")
            metadata["source"] = origins[name].name

        package_json = root / "package.json"
        if package_json.exists():
            data = read_json(package_json)
            sections = {
                "dependencies": ("production", {"dev": False}),
                "devDependencies": ("development", {"dev": True}),
                "optionalDependencies": ("optional", {"optional": True}),
                "peerDependencies": ("peer", {"peer": True}),
            }
            for section, (scope, flags) in sections.items():
                section_data = data.get(section, {})
                if not isinstance(section_data, dict):
                    continue
                for name, spec in section_data.items():
                    if not isinstance(name, str):
                        continue
                    record(
                        name,
                        str(spec),
                        package_json,
                        direct=True,
                        scope=scope,
                        flags=flags,
                    )

        package_lock = root / "package-lock.json"
        if package_lock.exists():
            for name, version in common.load_lock_dependencies(package_lock).items():
                if not name:
                    continue
                record(
                    name,
                    version,
                    package_lock,
                    direct=direct_flags.get(name),
                    scope=direct_scopes.get(name, "transitive"),
                    prefer_source=True,
                )

        pnpm_lock = root / "pnpm-lock.yaml"
        if pnpm_lock.exists():
            for name, version in common.read_pnpm_lock(pnpm_lock).items():
                record(
                    name,
                    version,
                    pnpm_lock,
                    direct=direct_flags.get(name, True),
                    scope=direct_scopes.get(name, "production"),
                    prefer_source=True,
                )

        yarn_lock = root / "yarn.lock"
        if yarn_lock.exists():
            current_name: str | None = None
            for line in yarn_lock.read_text(encoding="utf-8").splitlines():
                line = line.rstrip()
                if not line:
                    current_name = None
                elif not line.startswith(" ") and ":" in line:
                    segment = line.split(":", 1)[0]
                    if segment.startswith('"') and segment.endswith('"'):
                        segment = segment.strip('"')
                    if "@" in segment:
                        current_name = segment.split("@", 1)[0]
                elif current_name and line.strip().startswith("version "):
                    version = line.split('"', 2)[1]
                    record(
                        current_name,
                        version,
                        yarn_lock,
                        direct=direct_flags.get(current_name),
                        scope=direct_scopes.get(current_name, "transitive"),
                        prefer_source=True,
                    )

        results: list[Dependency] = []
        for name, version in sorted(dependencies.items()):
            manifest = origins.get(name, root)
            direct = direct_flags.get(name, False)
            metadata = metadata_map.get(name, {})
            scope = direct_scopes.get(name)
            if scope:
                metadata["scope"] = scope
            elif direct is False:
                metadata.setdefault("scope", "transitive")
            metadata.setdefault("source", manifest.name)
            results.append(
                self._dependency(
                    name=name,
                    version=_normalize_npm_version(version),
                    manifest=manifest,
                    direct=direct,
                    metadata=metadata,
                )
            )
        return results


def _normalize_npm_version(raw: str) -> str:
    candidate = raw.strip()
    if not candidate:
        return "*"
    lowered = candidate.lower()
    if lowered.startswith(
        ("http://", "https://", "git+", "github:", "file:", "link:", "workspace:", "npm:")
    ):
        return f"@ {candidate}" if not candidate.startswith("@ ") else candidate
    if candidate[0] in {"^", "~"}:
        candidate = candidate[1:].strip() or "*"
    if candidate.startswith((">=", "<=", ">", "<")):
        return candidate
    if candidate.startswith("=") and not candidate.startswith("=="):
        candidate = candidate.lstrip("=") or "*"
    normalized = common.normalize_version(candidate)
    return normalized if normalized else candidate

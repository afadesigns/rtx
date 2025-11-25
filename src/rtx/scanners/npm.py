from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

from rtx.models import Dependency, ScannerResult
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

    def scan(self, root: Path) -> ScannerResult:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}
        metadata_map: dict[str, dict[str, Any]] = {}
        direct_flags: dict[str, bool] = {}
        direct_scopes: dict[str, str] = {}
        relationships: list[tuple[str, str]] = [] # Placeholder for future implementation

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
            metadata: dict[str, Any] = metadata_map.setdefault(name, {})
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
            deps, rels = common.load_lock_dependencies(package_lock)
            for name, version in deps.items():
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
            relationships.extend(rels)
        pnpm_lock = root / "pnpm-lock.yaml"
        if pnpm_lock.exists():
            deps, rels = common.read_pnpm_lock(pnpm_lock)
            for name, version in deps.items():
                record(
                    name,
                    version,
                    pnpm_lock,
                    direct=direct_flags.get(name, True),
                    scope=direct_scopes.get(name, "production"),
                    prefer_source=True,
                )
            relationships.extend(rels)
        yarn_lock = root / "yarn.lock"
        if yarn_lock.exists():
            try:
                import yaml
            except ImportError:
                # This should not happen if pyyaml is installed, but as a fallback
                # we might consider logging a warning or raising an error.
                pass # Handled by the final return statement
            else:
                content = yarn_lock.read_text(encoding="utf-8")
                data = yaml.safe_load(content)

                for key, value in data.items():
                    if not isinstance(value, dict):
                        continue
                    name_match = key.split("@", 1)[0].strip()
                    version = value.get("version")
                    if name_match and version and isinstance(version, str):
                        record(
                            name_match,
                            version,
                            yarn_lock,
                            direct=direct_flags.get(name_match),
                            scope=direct_scopes.get(name_match, "transitive"),
                            prefer_source=True,
                        )

                    # Extract relationships from yarn.lock
                    if "dependencies" in value and isinstance(value["dependencies"], dict):
                        for dep_name in value["dependencies"].keys():
                            if isinstance(dep_name, str) and name_match:
                                relationships.append((name_match, dep_name))
        results: list[Dependency] = []
        for name, version in sorted(dependencies.items()):
            manifest = origins.get(name, root)
            direct = direct_flags.get(name, False)
            metadata = metadata_map.setdefault(name, {})
            active_scope = direct_scopes.get(name)
            if active_scope:
                metadata["scope"] = active_scope
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
        return ScannerResult(dependencies=results, relationships=relationships)


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

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import ClassVar

from packaging.requirements import InvalidRequirement, Requirement

from rtx.models import Dependency
from rtx.scanners import common
from rtx.scanners.base import BaseScanner


class PyPIScanner(BaseScanner):
    manager: ClassVar[str] = "pypi"
    manifests: ClassVar[list[str]] = [
        "pyproject.toml",
        "poetry.lock",
        "requirements.txt",
        "requirements.in",
        "constraints.txt",
        "Pipfile",
        "Pipfile.lock",
        "uv.lock",
        "uv.toml",
    ]
    ecosystem: ClassVar[str] = "pypi"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: dict[str, str] = {}
        origins: dict[str, Path] = {}
        direct_flags: dict[str, bool] = {}
        metadata_map: dict[str, dict[str, object]] = {}

        def record(
            name: str,
            version: str,
            source: Path,
            *,
            direct: bool | None,
            scope: str,
            optional: bool = False,
            extras: tuple[str, ...] | None = None,
            marker: str | None = None,
            requires_extras: tuple[str, ...] | None = None,
            constraint: bool = False,
        ) -> None:
            normalized_version = version.strip() if isinstance(version, str) else str(version)
            if not normalized_version:
                normalized_version = "*"
            updated = common.merge_dependency_version(dependencies, name, normalized_version)
            if updated or name not in origins:
                origins[name] = source

            if direct is True:
                direct_flags[name] = True
            elif direct is False:
                direct_flags.setdefault(name, False)

            metadata = metadata_map.setdefault(name, {})
            metadata["source"] = origins[name].name
            if scope:
                if direct:
                    metadata["scope"] = scope
                else:
                    metadata.setdefault("scope", scope)
            if optional:
                metadata["optional"] = True
            if extras:
                existing = metadata.get("extras")
                previous = set(existing) if isinstance(existing, list) else set()
                metadata["extras"] = sorted({*previous, *extras})
            if requires_extras:
                existing_requires = metadata.get("requires_extras")
                if isinstance(existing_requires, list):
                    previous_requires = set(existing_requires)
                elif isinstance(existing_requires, str):
                    previous_requires = {existing_requires}
                else:
                    previous_requires = set()
                metadata["requires_extras"] = sorted({*previous_requires, *requires_extras})
            if marker:
                existing_markers = metadata.get("markers")
                if isinstance(existing_markers, list):
                    marker_set = set(existing_markers)
                elif isinstance(existing_markers, str):
                    marker_set = {existing_markers}
                else:
                    marker_set = set()
                marker_set.add(marker)
                metadata["markers"] = sorted(marker_set)
            if constraint:
                metadata["constraint"] = True
                if not direct:
                    metadata.setdefault("scope", "constraints")

        requirement_context: dict[str, set[str]] = {}

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            data = common.read_toml(pyproject)
            project = data.get("project", {}) if isinstance(data, dict) else {}
            deps = project.get("dependencies", []) if isinstance(project, dict) else []
            _record_requirements(
                deps,
                pyproject,
                record,
                scope="production",
                direct=True,
            )

            optional_section = project.get("optional-dependencies", {})
            if isinstance(optional_section, dict):
                for group, entries in optional_section.items():
                    if isinstance(group, str) and isinstance(entries, list):
                        _record_requirements(
                            entries,
                            pyproject,
                            record,
                            scope=f"optional:{group}",
                            direct=True,
                            optional=True,
                            extras=(group,),
                        )

            tool_section = data.get("tool", {}) if isinstance(data, dict) else {}
            poetry = tool_section.get("poetry", {}) if isinstance(tool_section, dict) else {}
            if isinstance(poetry, dict):
                poetry_deps = poetry.get("dependencies", {})
                if isinstance(poetry_deps, dict):
                    for name, version in poetry_deps.items():
                        if not isinstance(name, str) or name == "python":
                            continue
                        record(
                            name,
                            _coerce_version_spec(version),
                            pyproject,
                            direct=True,
                            scope="production",
                        )

                legacy_dev = poetry.get("dev-dependencies", {})
                if isinstance(legacy_dev, dict):
                    for name, version in legacy_dev.items():
                        if not isinstance(name, str):
                            continue
                        record(
                            name,
                            _coerce_version_spec(version),
                            pyproject,
                            direct=True,
                            scope="development",
                            optional=True,
                            extras=("dev",),
                        )

                poetry_groups = poetry.get("group", {})
                if isinstance(poetry_groups, dict):
                    for group_name, group_data in poetry_groups.items():
                        if not isinstance(group_name, str) or not isinstance(group_data, dict):
                            continue
                        group_scope = (
                            "development"
                            if group_name in {"dev", "test", "tests"}
                            else f"group:{group_name}"
                        )
                        group_optional = group_name != "default"
                        entries = group_data.get("dependencies")
                        if isinstance(entries, dict):
                            for dep_name, spec in entries.items():
                                if not isinstance(dep_name, str):
                                    continue
                                record(
                                    dep_name,
                                    _coerce_version_spec(spec),
                                    pyproject,
                                    direct=True,
                                    scope=group_scope,
                                    optional=group_optional,
                                    extras=(group_name,) if group_optional else None,
                                )

        poetry_lock = root / "poetry.lock"
        if poetry_lock.exists():
            for name, version in common.read_poetry_lock(poetry_lock).items():
                record(
                    name,
                    version,
                    poetry_lock,
                    direct=direct_flags.get(name),
                    scope=metadata_map.get(name, {}).get("scope", "transitive"),
                )

        uv_lock = root / "uv.lock"
        if uv_lock.exists():
            for name, version in common.read_uv_lock(uv_lock).items():
                record(
                    name,
                    version,
                    uv_lock,
                    direct=direct_flags.get(name),
                    scope=metadata_map.get(name, {}).get("scope", "transitive"),
                )

        for filename in ("requirements.txt", "requirements.in", "constraints.txt"):
            path = root / filename
            if path.exists():
                scope = "constraints" if filename == "constraints.txt" else "production"
                requirement_scope = "constraint" if filename == "constraints.txt" else "requirement"
                resolved = common.read_requirements(
                    path,
                    context=requirement_context,
                    kind=requirement_scope,
                )
                for name, version in resolved.items():
                    flags = requirement_context.get(name, set())
                    direct_flag = "requirement" in flags
                    constraint_flag = "constraint" in flags
                    effective_direct: bool | None
                    if direct_flag:
                        effective_direct = True
                    elif constraint_flag:
                        effective_direct = False
                    else:
                        effective_direct = None
                    effective_scope = (
                        "constraints" if constraint_flag and not direct_flag else scope
                    )
                    record(
                        name,
                        version,
                        path,
                        direct=effective_direct,
                        scope=effective_scope,
                        constraint=constraint_flag,
                    )

        pipfile_lock = root / "Pipfile.lock"
        if pipfile_lock.exists():
            for name, version in common.load_lock_dependencies(pipfile_lock).items():
                record(
                    name,
                    version,
                    pipfile_lock,
                    direct=direct_flags.get(name),
                    scope=metadata_map.get(name, {}).get("scope", "transitive"),
                )

        pipfile = root / "Pipfile"
        if pipfile.exists():
            data = common.read_toml(pipfile)
            for section in ("packages", "dev-packages"):
                section_data = data.get(section, {})
                if not isinstance(section_data, dict):
                    continue
                for name, version in section_data.items():
                    if isinstance(name, str):
                        record(
                            name,
                            _coerce_version_spec(version),
                            pipfile,
                            direct=True,
                            scope="development" if section == "dev-packages" else "production",
                            optional=section == "dev-packages",
                            extras=("dev",) if section == "dev-packages" else None,
                        )

        uv_toml = root / "uv.toml"
        if uv_toml.exists():
            uv_data = common.read_toml(uv_toml)

            def _record_uv_entries(
                entries: object,
                *,
                scope: str,
                optional: bool = False,
                label: str | None = None,
            ) -> None:
                if isinstance(entries, dict):
                    for dep_name, spec in entries.items():
                        if isinstance(dep_name, str):
                            record(
                                dep_name,
                                _coerce_version_spec(spec),
                                uv_toml,
                                direct=True,
                                scope=scope,
                                optional=optional,
                                extras=(label,) if label else None,
                            )
                elif isinstance(entries, list):
                    _record_requirements(
                        entries,
                        uv_toml,
                        record,
                        scope=scope,
                        direct=True,
                        optional=optional,
                        extras=(label,) if label else None,
                    )

            _record_uv_entries(uv_data.get("dependencies"), scope="production")
            _record_uv_entries(
                uv_data.get("dev-dependencies"), scope="development", optional=True, label="dev"
            )
            optional_deps = uv_data.get("optional-dependencies")
            if isinstance(optional_deps, dict):
                for extra_name, entries in optional_deps.items():
                    if isinstance(extra_name, str):
                        _record_uv_entries(
                            entries,
                            scope=f"optional:{extra_name}",
                            optional=True,
                            label=extra_name,
                        )

            tool_section = uv_data.get("tool")
            if isinstance(tool_section, dict):
                uv_tool = tool_section.get("uv")
                if isinstance(uv_tool, dict):
                    _record_uv_entries(uv_tool.get("dependencies"), scope="production")
                    _record_uv_entries(
                        uv_tool.get("dev-dependencies"),
                        scope="development",
                        optional=True,
                        label="dev",
                    )
                    optional_tool = uv_tool.get("optional-dependencies")
                    if isinstance(optional_tool, dict):
                        for extra_name, entries in optional_tool.items():
                            if isinstance(extra_name, str):
                                _record_uv_entries(
                                    entries,
                                    scope=f"optional:{extra_name}",
                                    optional=True,
                                    label=extra_name,
                                )

        results: list[Dependency] = []
        for name, version in sorted(dependencies.items()):
            manifest = origins.get(name, root)
            metadata = metadata_map.get(name, {"source": manifest.name})
            if "extras" in metadata and isinstance(metadata["extras"], list):
                metadata["extras"] = sorted(set(metadata["extras"]))
            if "requires_extras" in metadata and isinstance(metadata["requires_extras"], list):
                metadata["requires_extras"] = sorted(set(metadata["requires_extras"]))
            if "markers" in metadata:
                markers = metadata["markers"]
                if isinstance(markers, list):
                    metadata["markers"] = sorted(set(markers))
                elif isinstance(markers, str):
                    metadata["markers"] = [markers]
            results.append(
                self._dependency(
                    name=name,
                    version=common.normalize_version(version),
                    manifest=manifest,
                    direct=direct_flags.get(name, False),
                    metadata=metadata,
                )
            )
        return results


def _record_requirements(
    entries: Iterable[object],
    source: Path,
    record: Callable[..., None],
    *,
    scope: str,
    direct: bool,
    optional: bool = False,
    extras: tuple[str, ...] | None = None,
) -> None:
    for dependency in entries:
        if not isinstance(dependency, str):
            continue
        try:
            requirement = Requirement(dependency)
        except InvalidRequirement:
            name = dependency.strip()
            if name:
                record(
                    name,
                    "*",
                    source,
                    direct=direct,
                    scope=scope,
                    optional=optional,
                    extras=extras,
                    marker=None,
                    requires_extras=None,
                )
            continue
        if requirement.url:
            version = f"@ {requirement.url}"
        else:
            specifier = requirement.specifier
            if specifier:
                specs = list(specifier)
                if len(specs) == 1 and specs[0].operator == "==":
                    version = specs[0].version
                else:
                    version = str(specifier)
            else:
                version = "*"
        marker_str = str(requirement.marker) if requirement.marker else None
        requires_extras = tuple(sorted(requirement.extras)) if requirement.extras else None
        record(
            requirement.name,
            version,
            source,
            direct=direct,
            scope=scope,
            optional=optional,
            extras=extras,
            marker=marker_str,
            requires_extras=requires_extras,
        )


def _coerce_version_spec(value: object) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("==") and len(stripped) > 2:
            return stripped[2:]
        return stripped or "*"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        for key in ("version", "specifier"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                normalized = _coerce_version_spec(candidate)
                if normalized:
                    return normalized
        for key in ("ref", "tag", "rev", "branch"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for key in ("path", "file", "git", "url"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return f"@ {candidate}"
    return "*"

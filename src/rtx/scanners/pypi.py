from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import ClassVar

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

        def record(name: str, version: str, source: Path) -> None:
            if name in dependencies:
                existing = dependencies[name]
                if existing in {"*", ""} and version not in {"*", ""}:
                    dependencies[name] = version
                    origins[name] = source
                return
            dependencies[name] = version
            origins[name] = source

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            data = common.read_toml(pyproject)
            project = data.get("project", {}) if isinstance(data, dict) else {}
            deps = project.get("dependencies", []) if isinstance(project, dict) else []
            _record_requirements(deps, pyproject, record)
            tool_section = data.get("tool", {}) if isinstance(data, dict) else {}
            poetry = tool_section.get("poetry", {}) if isinstance(tool_section, dict) else {}
            if isinstance(poetry, dict):
                for name, version in poetry.get("dependencies", {}).items():
                    if isinstance(name, str):
                        record(name, str(version), pyproject)

        poetry_lock = root / "poetry.lock"
        if poetry_lock.exists():
            for name, version in common.read_poetry_lock(poetry_lock).items():
                record(name, version, poetry_lock)

        uv_lock = root / "uv.lock"
        if uv_lock.exists():
            for name, version in common.read_uv_lock(uv_lock).items():
                record(name, version, uv_lock)

        for filename in ("requirements.txt", "requirements.in", "constraints.txt"):
            path = root / filename
            if path.exists():
                for name, version in common.read_requirements(path).items():
                    record(name, version, path)

        pipfile_lock = root / "Pipfile.lock"
        if pipfile_lock.exists():
            for name, version in common.load_lock_dependencies(pipfile_lock).items():
                record(name, version, pipfile_lock)

        pipfile = root / "Pipfile"
        if pipfile.exists():
            data = common.read_toml(pipfile)
            for section in ("packages", "dev-packages"):
                for name, version in data.get(section, {}).items():
                    if isinstance(name, str):
                        record(name, str(version), pipfile)

        results: list[Dependency] = []
        for name, version in sorted(dependencies.items()):
            manifest = origins.get(name, root)
            results.append(
                self._dependency(
                    name=name,
                    version=common.normalize_version(version),
                    manifest=manifest,
                    direct=True,
                    metadata={"source": manifest.name},
                )
            )
        return results


def _record_requirements(
    entries: Iterable[object],
    source: Path,
    record: Callable[[str, str, Path], None],
) -> None:
    for dependency in entries:
        if not isinstance(dependency, str):
            continue
        parts = dependency.split("==", 1)
        name = parts[0].strip()
        version = parts[1].strip() if len(parts) == 2 else "*"
        record(name, version, source)

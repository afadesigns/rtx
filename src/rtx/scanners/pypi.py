from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from rtx.models import Dependency
from rtx.scanners.base import BaseScanner
from rtx.scanners import common


class PyPIScanner(BaseScanner):
    manager = "pypi"
    manifests = [
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
    ecosystem = "pypi"

    def scan(self, root: Path) -> List[Dependency]:
        dependencies: Dict[str, str] = {}
        origins: Dict[str, Path] = {}

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            data = common.read_toml(pyproject)
            project = data.get("project", {}) if isinstance(data, dict) else {}
            deps = project.get("dependencies", []) if isinstance(project, dict) else []
            for dependency in deps:
                if isinstance(dependency, str):
                    parts = dependency.split("==", 1)
                    name = parts[0].strip()
                    version = parts[1].strip() if len(parts) == 2 else "*"
                    dependencies.setdefault(name, version)
                    origins.setdefault(name, pyproject)
            tool_section = data.get("tool", {}) if isinstance(data, dict) else {}
            poetry = tool_section.get("poetry", {}) if isinstance(tool_section, dict) else {}
            if isinstance(poetry, dict):
                for name, version in poetry.get("dependencies", {}).items():
                    if isinstance(name, str):
                        dependencies.setdefault(name, str(version))
                        origins.setdefault(name, pyproject)

        poetry_lock = root / "poetry.lock"
        if poetry_lock.exists():
            for name, version in common.read_poetry_lock(poetry_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, poetry_lock)

        uv_lock = root / "uv.lock"
        if uv_lock.exists():
            for name, version in common.read_uv_lock(uv_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, uv_lock)

        for filename in ("requirements.txt", "requirements.in", "constraints.txt"):
            path = root / filename
            if path.exists():
                for name, version in common.read_requirements(path).items():
                    dependencies.setdefault(name, version)
                    origins.setdefault(name, path)

        pipfile_lock = root / "Pipfile.lock"
        if pipfile_lock.exists():
            for name, version in common.load_lock_dependencies(pipfile_lock).items():
                dependencies.setdefault(name, version)
                origins.setdefault(name, pipfile_lock)

        pipfile = root / "Pipfile"
        if pipfile.exists():
            data = common.read_toml(pipfile)
            for section in ("packages", "dev-packages"):
                for name, version in data.get(section, {}).items():
                    if isinstance(name, str):
                        dependencies.setdefault(name, str(version))
                        origins.setdefault(name, pipfile)

        results: List[Dependency] = []
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

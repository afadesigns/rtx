from __future__ import annotations

import subprocess
from dataclasses import dataclass
from shutil import which
from typing import Iterable


@dataclass(slots=True)
class ToolStatus:
    name: str
    available: bool
    path: str | None = None
    version: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "name": self.name,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "error": self.error,
        }


def _parse_version(result: subprocess.CompletedProcess[str]) -> str | None:
    output = (result.stdout or "").strip()
    if not output:
        output = (result.stderr or "").strip()
    return output or None


def probe_tool(name: str, *, version_args: Iterable[str] | None = None, timeout: float = 2.0) -> ToolStatus:
    path = which(name)
    if path is None:
        return ToolStatus(name=name, available=False)

    args = [path]
    args.extend(list(version_args or ["--version"]))
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception as exc:  # pragma: no cover - subprocess runtime errors
        return ToolStatus(name=name, available=True, path=path, error=str(exc))

    if result.returncode != 0:
        error = (result.stderr or result.stdout or f"exit code {result.returncode}").strip()
        return ToolStatus(name=name, available=True, path=path, error=error)

    version = _parse_version(result)
    return ToolStatus(name=name, available=True, path=path, version=version)


def collect_manager_diagnostics() -> list[ToolStatus]:
    """Probe the local environment for the primary package managers."""
    tools = [
        ("pip", ("--version",)),
        ("npm", ("--version",)),
        ("uv", ("--version",)),
    ]
    return [probe_tool(name, version_args=args) for name, args in tools]

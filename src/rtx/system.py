from __future__ import annotations

import subprocess
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from shutil import which


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


def _sanitize_version_args(flags: Iterable[str]) -> tuple[str, ...]:
    sanitized: list[str] = []
    for flag in flags:
        if not flag.startswith("-"):
            msg = f"unsafe version flag: {flag!r}"
            raise ValueError(msg)
        if any(ch in flag for ch in {" ", "\t", "\n", "\r", "|", "&", ";"}):
            msg = f"unsafe characters in version flag: {flag!r}"
            raise ValueError(msg)
        sanitized.append(flag)
    return tuple(sanitized)


def _parse_version(result: subprocess.CompletedProcess[str]) -> str | None:
    output = (result.stdout or "").strip()
    if not output:
        output = (result.stderr or "").strip()
    return output or None


def probe_tool(
    name: str, *, version_args: Iterable[str] | None = None, timeout: float = 2.0
) -> ToolStatus:
    path = which(name)
    if path is None:
        return ToolStatus(name=name, available=False)

    try:
        version_flags = _sanitize_version_args(version_args or ("--version",))
    except ValueError as exc:
        return ToolStatus(name=name, available=True, path=path, error=str(exc))

    args = [path, *version_flags]
    try:
        # Bandit S603 flags subprocess usage; arguments are sanitized and path resolved.
        result = subprocess.run(  # noqa: S603
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


DEFAULT_TOOL_PROBES: list[tuple[str, tuple[str, ...]]] = [
    ("pip", ("--version",)),
    ("npm", ("--version",)),
    ("uv", ("--version",)),
]


def collect_manager_diagnostics() -> list[ToolStatus]:
    """Probe the local environment for the primary package managers."""
    if not DEFAULT_TOOL_PROBES:
        return []
    with ThreadPoolExecutor(max_workers=min(len(DEFAULT_TOOL_PROBES), 8)) as executor:
        futures = [
            (name, executor.submit(probe_tool, name, version_args=args))
            for name, args in DEFAULT_TOOL_PROBES
        ]
        results: list[ToolStatus] = []
        for name, future in futures:
            try:
                results.append(future.result())
            except Exception as exc:  # pragma: no cover - defensive fallback
                results.append(ToolStatus(name=name, available=True, error=str(exc)))
    return results

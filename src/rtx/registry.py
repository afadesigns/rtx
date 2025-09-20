from __future__ import annotations

from rtx.scanners import (
    BaseScanner,
    BrewScanner,
    CargoScanner,
    ComposerScanner,
    CondaScanner,
    DockerScanner,
    GoScanner,
    MavenScanner,
    NpmScanner,
    NuGetScanner,
    PyPIScanner,
    RubyGemsScanner,
)
from rtx.utils import unique_preserving_order

SCANNER_CLASSES: dict[str, type[BaseScanner]] = {
    "npm": NpmScanner,
    "pypi": PyPIScanner,
    "maven": MavenScanner,
    "cargo": CargoScanner,
    "go": GoScanner,
    "composer": ComposerScanner,
    "nuget": NuGetScanner,
    "rubygems": RubyGemsScanner,
    "brew": BrewScanner,
    "conda": CondaScanner,
    "docker": DockerScanner,
}

SCANNER_ALIASES: dict[str, str] = {
    "pip": "pypi",
    "pip3": "pypi",
    "python": "pypi",
    "python3": "pypi",
    "poetry": "pypi",
    "uv": "pypi",
    "node": "npm",
    "nodejs": "npm",
    "yarn": "npm",
    "gem": "rubygems",
    "ruby": "rubygems",
    "rust": "cargo",
    "gomod": "go",
}


def get_scanners(names: list[str] | None = None) -> list[BaseScanner]:
    selected = (
        list(SCANNER_CLASSES.keys())
        if names is None
        else unique_preserving_order(names, key=str.casefold)
    )

    scanners: list[BaseScanner] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for raw_name in selected:
        normalized = raw_name.casefold()
        canonical = SCANNER_ALIASES.get(normalized, normalized)
        if canonical in seen:
            continue
        seen.add(canonical)
        cls = SCANNER_CLASSES.get(canonical)
        if cls is None:
            unknown.append(raw_name)
            continue
        scanners.append(cls())
    if unknown:
        message = ", ".join(unique_preserving_order(unknown, key=str.casefold))
        raise ValueError(f"Unknown package manager(s): {message}")
    return scanners

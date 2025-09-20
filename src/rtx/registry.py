from __future__ import annotations

from typing import Dict, List, Type

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

SCANNER_CLASSES: Dict[str, Type[BaseScanner]] = {
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


def get_scanners(names: List[str] | None = None) -> List[BaseScanner]:
    if names is None:
        selected = list(SCANNER_CLASSES.keys())
    else:
        selected = unique_preserving_order(names, key=str.casefold)

    scanners: List[BaseScanner] = []
    unknown: List[str] = []
    seen: set[str] = set()
    for raw_name in selected:
        normalized = raw_name.casefold()
        if normalized in seen:
            continue
        seen.add(normalized)
        cls = SCANNER_CLASSES.get(normalized)
        if cls is None:
            unknown.append(raw_name)
            continue
        scanners.append(cls())
    if unknown:
        message = ", ".join(unique_preserving_order(unknown, key=str.casefold))
        raise ValueError(f"Unknown package manager(s): {message}")
    return scanners

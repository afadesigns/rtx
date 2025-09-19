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
    selected = names or list(SCANNER_CLASSES.keys())
    scanners: List[BaseScanner] = []
    unknown: List[str] = []
    seen: set[str] = set()
    for name in selected:
        if name in seen:
            continue
        seen.add(name)
        cls = SCANNER_CLASSES.get(name)
        if cls is None:
            unknown.append(name)
            continue
        scanners.append(cls())
    if unknown:
        unknown_sorted = ", ".join(sorted(set(unknown)))
        raise ValueError(f"Unknown package manager(s): {unknown_sorted}")
    return scanners

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
    for name in selected:
        cls = SCANNER_CLASSES.get(name)
        if cls is not None:
            scanners.append(cls())
    return scanners

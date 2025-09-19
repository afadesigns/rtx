from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from rtx.models import Dependency
from rtx.utils import detect_files


class BaseScanner(ABC):
    manager: str
    manifests: List[str]
    ecosystem: str

    def matches(self, root: Path) -> bool:
        return bool(detect_files(root, self.manifests))

    @abstractmethod
    def scan(self, root: Path) -> List[Dependency]:
        """Return a list of resolved dependencies."""

    def _dependency(self, *, name: str, version: str, manifest: Path, direct: bool, metadata: dict | None = None) -> Dependency:
        return Dependency(
            ecosystem=self.ecosystem,
            name=name,
            version=version,
            direct=direct,
            manifest=manifest,
            metadata=metadata or {},
        )

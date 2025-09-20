from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from pathlib import Path

from rtx.models import Dependency
from rtx.utils import has_matching_file


class BaseScanner(ABC):
    manager: str
    manifests: Sequence[str]
    ecosystem: str

    def matches(self, root: Path) -> bool:
        return has_matching_file(root, self.manifests)

    @abstractmethod
    def scan(self, root: Path) -> list[Dependency]:
        """Return a list of resolved dependencies."""

    def _dependency(
        self,
        *,
        name: str,
        version: str,
        manifest: Path,
        direct: bool,
        metadata: dict | None = None,
    ) -> Dependency:
        return Dependency(
            ecosystem=self.ecosystem,
            name=name,
            version=version,
            direct=direct,
            manifest=manifest,
            metadata=metadata or {},
        )

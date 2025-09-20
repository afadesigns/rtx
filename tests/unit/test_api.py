from __future__ import annotations

from pathlib import Path

import pytest

from rtx.api import _merge_dependency, scan_project_async
from rtx.models import Dependency, PackageFinding


class _StubScanner:
    def __init__(
        self,
        manager: str,
        dependencies: list[Dependency],
        *,
        matches: bool = True,
    ) -> None:
        self.manager = manager
        self.manifests = []
        self.ecosystem = manager
        self._dependencies = list(dependencies)
        self._matches = matches

    def matches(self, _: Path) -> bool:
        return self._matches

    def scan(self, _: Path) -> list[Dependency]:
        return list(self._dependencies)


class _StubAdvisoryClient:
    async def __aenter__(self) -> _StubAdvisoryClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # - interface compliance
        return None

    async def fetch_advisories(
        self, dependencies: list[Dependency]
    ) -> dict[str, list[object]]:
        return {dependency.coordinate: [] for dependency in dependencies}


class _StubPolicyEngine:
    async def __aenter__(self) -> _StubPolicyEngine:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def close(self) -> None:
        return None

    async def analyze(
        self, dependency: Dependency, advisories: list[object]
    ) -> PackageFinding:
        return PackageFinding(
            dependency=dependency, advisories=[], signals=[], score=0.0
        )


def test_merge_dependency_preserves_manifest_order(tmp_path: Path) -> None:
    first = Dependency(
        ecosystem="npm",
        name="demo",
        version="1.0.0",
        direct=True,
        manifest=tmp_path / "package.json",
        metadata={
            "source": "a",
            "manifests": [str(tmp_path / "package.json"), "extra"],
        },
    )
    second = Dependency(
        ecosystem="npm",
        name="demo",
        version="1.0.0",
        direct=False,
        manifest=tmp_path / "nested" / "package.json",
        metadata={"origin": "nested"},
    )

    merged = _merge_dependency(first, second)

    assert merged.version == "1.0.0"
    assert merged.direct is True
    assert merged.metadata["source"] == "a"
    assert merged.metadata["origin"] == "nested"
    assert merged.metadata["manifests"] == [
        str(tmp_path / "package.json"),
        str(tmp_path / "nested" / "package.json"),
        "extra",
    ]


@pytest.mark.asyncio
async def test_scan_project_async_preserves_manager_order(
    monkeypatch, tmp_path: Path
) -> None:
    primary = Dependency(
        ecosystem="npm",
        name="demo",
        version="1.0.0",
        direct=True,
        manifest=tmp_path / "pkg.json",
        metadata={},
    )
    duplicate = Dependency(
        ecosystem="npm",
        name="demo",
        version="1.0.0",
        direct=False,
        manifest=tmp_path / "sub" / "pkg.json",
        metadata={},
    )
    secondary = Dependency(
        ecosystem="pypi",
        name="example",
        version="0.1.0",
        direct=True,
        manifest=tmp_path / "pyproject.toml",
        metadata={},
    )

    scanners = [
        _StubScanner("npm", [primary, duplicate]),
        _StubScanner("pypi", [secondary]),
    ]

    monkeypatch.setattr("rtx.api.get_scanners", lambda _: scanners)
    monkeypatch.setattr("rtx.api.AdvisoryClient", _StubAdvisoryClient)
    monkeypatch.setattr("rtx.api.TrustPolicyEngine", _StubPolicyEngine)

    report = await scan_project_async(tmp_path)

    assert report.managers == ["npm", "pypi"]
    finding = next(f for f in report.findings if f.dependency.name == "demo")
    assert finding.dependency.metadata["manifests"] == [
        str(primary.manifest),
        str(duplicate.manifest),
    ]

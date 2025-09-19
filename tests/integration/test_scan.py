from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from rtx.api import scan_project
from rtx.metadata import ReleaseMetadata
from rtx.models import Dependency, PackageFinding
from rtx.policy import TrustPolicyEngine


def test_scan_project_examples(monkeypatch) -> None:
    project_root = Path("examples/mixed").resolve()

    async def fake_fetch_advisories(self, dependencies):  # type: ignore[override]
        return {dep.coordinate: [] for dep in dependencies}

    async def fake_metadata(_dep: Dependency) -> ReleaseMetadata:
        return ReleaseMetadata(
            latest_release=datetime.utcnow(),
            releases_last_30d=1,
            total_releases=5,
            maintainers=["afahl"],
            ecosystem="pypi",
        )

    async def fake_analyze(self, dependency: Dependency, advisories):  # type: ignore[override]
        return PackageFinding(dependency=dependency, advisories=advisories, score=0.0)

    monkeypatch.setattr("rtx.advisory.AdvisoryClient.fetch_advisories", fake_fetch_advisories, raising=False)
    monkeypatch.setattr(TrustPolicyEngine, "analyze", fake_analyze, raising=False)
    monkeypatch.setattr("rtx.metadata.MetadataClient.fetch", lambda self, dep: fake_metadata(dep), raising=False)

    report = scan_project(project_root)
    assert report.summary()["total"] > 0
    assert report.exit_code() == 0

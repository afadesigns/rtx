from __future__ import annotations

import asyncio
from datetime import datetime

import pytest

from rtx.metadata import ReleaseMetadata
from rtx.models import Advisory, Dependency, Severity
from rtx.policy import TrustPolicyEngine


@pytest.mark.asyncio
async def test_typosquat_detection(monkeypatch, tmp_path) -> None:
    engine = TrustPolicyEngine()

    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return ReleaseMetadata(latest_release=datetime.utcnow(), releases_last_30d=0, total_releases=1, maintainers=["alice"], ecosystem="npm")

    monkeypatch.setattr(engine._metadata_client, "fetch", fake_fetch)
    try:
        dependency = Dependency(
            ecosystem="npm",
            name="reqct",
            version="1.0.0",
            direct=True,
            manifest=tmp_path,
        )
        finding = await engine.analyze(dependency, [])
        assert any(signal.category == "typosquat" for signal in finding.signals)
    finally:
        await engine.close()


@pytest.mark.asyncio
async def test_advisory_influences_score(monkeypatch, tmp_path) -> None:
    engine = TrustPolicyEngine()

    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return ReleaseMetadata(latest_release=datetime.utcnow(), releases_last_30d=0, total_releases=1, maintainers=["alice"], ecosystem="pypi")

    monkeypatch.setattr(engine._metadata_client, "fetch", fake_fetch)
    dependency = Dependency(
        ecosystem="pypi",
        name="requests",
        version="2.19.0",
        direct=True,
        manifest=tmp_path,
    )
    advisory = Advisory(
        identifier="CVE-2020-1234",
        source="test",
        severity=Severity.HIGH,
        summary="Test advisory",
    )
    try:
        finding = await engine.analyze(dependency, [advisory])
        assert finding.score >= 0.85
        assert finding.verdict in {Severity.HIGH, Severity.CRITICAL}
    finally:
        await engine.close()

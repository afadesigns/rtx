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


@pytest.mark.asyncio
async def test_policy_flags_missing_maintainers(monkeypatch, tmp_path) -> None:
    engine = TrustPolicyEngine()

    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return ReleaseMetadata(
            latest_release=datetime.utcnow(),
            releases_last_30d=0,
            total_releases=5,
            maintainers=[],
            ecosystem="pypi",
        )

    monkeypatch.setattr(engine._metadata_client, "fetch", fake_fetch)
    dependency = Dependency(
        ecosystem="pypi",
        name="example",
        version="1.0.0",
        direct=True,
        manifest=tmp_path,
    )
    try:
        finding = await engine.analyze(dependency, [])
        maintainer_signal = next(signal for signal in finding.signals if signal.category == "maintainer")
        assert maintainer_signal.severity == Severity.MEDIUM
    finally:
        await engine.close()


@pytest.mark.asyncio
async def test_policy_flags_high_churn(monkeypatch, tmp_path) -> None:
    engine = TrustPolicyEngine()

    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return ReleaseMetadata(
            latest_release=datetime.utcnow(),
            releases_last_30d=12,
            total_releases=20,
            maintainers=["alice", "bob", "carol"],
            ecosystem="npm",
        )

    monkeypatch.setattr(engine._metadata_client, "fetch", fake_fetch)
    dependency = Dependency(
        ecosystem="npm",
        name="example-package",
        version="1.0.0",
        direct=True,
        manifest=tmp_path,
    )
    try:
        finding = await engine.analyze(dependency, [])
        churn_signal = next(signal for signal in finding.signals if signal.category == "churn")
        assert churn_signal.severity == Severity.HIGH
    finally:
        await engine.close()


@pytest.mark.asyncio
async def test_policy_flags_low_maturity(monkeypatch, tmp_path) -> None:
    engine = TrustPolicyEngine()

    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return ReleaseMetadata(
            latest_release=datetime.utcnow(),
            releases_last_30d=0,
            total_releases=1,
            maintainers=["alice", "bob"],
            ecosystem="crates",
        )

    monkeypatch.setattr(engine._metadata_client, "fetch", fake_fetch)
    dependency = Dependency(
        ecosystem="crates",
        name="demo",
        version="1.0.0",
        direct=True,
        manifest=tmp_path,
    )
    try:
        finding = await engine.analyze(dependency, [])
        maturity_signal = next(signal for signal in finding.signals if signal.category == "maturity")
        assert maturity_signal.severity == Severity.LOW
    finally:
        await engine.close()

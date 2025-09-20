from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime

import pytest

from rtx.metadata import ReleaseMetadata
from rtx.models import Advisory, Dependency, Severity
from rtx.policy import TrustPolicyEngine, levenshtein

FetchFn = Callable[[Dependency], Awaitable[ReleaseMetadata]]


@asynccontextmanager
async def policy_engine(
    monkeypatch: pytest.MonkeyPatch,
    fetch: FetchFn,
) -> AsyncIterator[TrustPolicyEngine]:
    engine = TrustPolicyEngine()
    monkeypatch.setattr(engine._metadata_client, "fetch", fetch)
    try:
        yield engine
    finally:
        await engine.close()


def make_metadata(
    *,
    ecosystem: str,
    latest_release: datetime | None = None,
    releases_last_30d: int = 0,
    total_releases: int = 1,
    maintainers: list[str] | None = None,
) -> ReleaseMetadata:
    return ReleaseMetadata(
        latest_release=latest_release or datetime.utcnow(),
        releases_last_30d=releases_last_30d,
        total_releases=total_releases,
        maintainers=list(maintainers) if maintainers is not None else ["alice"],
        ecosystem=ecosystem,
    )


@pytest.mark.asyncio
async def test_typosquat_detection(monkeypatch, tmp_path) -> None:
    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return make_metadata(ecosystem="npm")

    async with policy_engine(monkeypatch, fake_fetch) as engine:
        dependency = Dependency(
            ecosystem="npm",
            name="reqct",
            version="1.0.0",
            direct=True,
            manifest=tmp_path,
        )
        finding = await engine.analyze(dependency, [])
        assert any(signal.category == "typosquat" for signal in finding.signals)


def test_levenshtein_returns_cutoff_when_distance_exceeds_limit() -> None:
    result = levenshtein("react", "vue", max_distance=1)
    assert result == 2


def test_levenshtein_rejects_negative_max_distance() -> None:
    with pytest.raises(ValueError):
        levenshtein("a", "b", max_distance=-1)


@pytest.mark.asyncio
async def test_typosquat_detection_ignores_identical_name_case(monkeypatch, tmp_path) -> None:
    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return make_metadata(ecosystem="npm", total_releases=5)

    async with policy_engine(monkeypatch, fake_fetch) as engine:
        dependency = Dependency(
            ecosystem="npm",
            name="React",
            version="1.0.0",
            direct=True,
            manifest=tmp_path,
        )
        finding = await engine.analyze(dependency, [])
        assert all(signal.category != "typosquat" for signal in finding.signals)


@pytest.mark.asyncio
async def test_advisory_influences_score(monkeypatch, tmp_path) -> None:
    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return make_metadata(ecosystem="pypi")

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
    async with policy_engine(monkeypatch, fake_fetch) as engine:
        finding = await engine.analyze(dependency, [advisory])
        assert finding.score >= 0.85
        assert finding.verdict in {Severity.HIGH, Severity.CRITICAL}


@pytest.mark.asyncio
async def test_policy_flags_missing_maintainers(monkeypatch, tmp_path) -> None:
    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return make_metadata(ecosystem="pypi", total_releases=5, maintainers=[])

    async with policy_engine(monkeypatch, fake_fetch) as engine:
        dependency = Dependency(
            ecosystem="pypi",
            name="example",
            version="1.0.0",
            direct=True,
            manifest=tmp_path,
        )
        finding = await engine.analyze(dependency, [])
        maintainer_signal = next(
            signal for signal in finding.signals if signal.category == "maintainer"
        )
        assert maintainer_signal.severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_policy_flags_high_churn(monkeypatch, tmp_path) -> None:
    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return make_metadata(
            ecosystem="npm",
            releases_last_30d=12,
            total_releases=20,
            maintainers=["alice", "bob", "carol"],
        )

    async with policy_engine(monkeypatch, fake_fetch) as engine:
        dependency = Dependency(
            ecosystem="npm",
            name="example-package",
            version="1.0.0",
            direct=True,
            manifest=tmp_path,
        )
        finding = await engine.analyze(dependency, [])
        churn_signal = next(
            signal for signal in finding.signals if signal.category == "churn"
        )
        assert churn_signal.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_policy_flags_low_maturity(monkeypatch, tmp_path) -> None:
    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return make_metadata(
            ecosystem="crates",
            total_releases=1,
            maintainers=["alice", "bob"],
        )

    async with policy_engine(monkeypatch, fake_fetch) as engine:
        dependency = Dependency(
            ecosystem="crates",
            name="demo",
            version="1.0.0",
            direct=True,
            manifest=tmp_path,
        )
        finding = await engine.analyze(dependency, [])
        maturity_signal = next(
            signal for signal in finding.signals if signal.category == "maturity"
        )
        assert maturity_signal.severity == Severity.LOW


@pytest.mark.asyncio
async def test_compromised_detection_is_case_insensitive(monkeypatch, tmp_path) -> None:
    async def fake_fetch(_dep: Dependency) -> ReleaseMetadata:
        return make_metadata(ecosystem="npm", total_releases=10)

    async with policy_engine(monkeypatch, fake_fetch) as engine:
        dependency = Dependency(
            ecosystem="npm",
            name="COA",
            version="1.0.0",
            direct=True,
            manifest=tmp_path,
        )
        finding = await engine.analyze(dependency, [])
        compromised = next(
            signal
            for signal in finding.signals
            if signal.category == "compromised-maintainer"
        )
        assert compromised.severity == Severity.CRITICAL

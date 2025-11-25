from __future__ import annotations

import os
import textwrap
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest
import pytest_asyncio

from rtx.metadata import ReleaseMetadata
from rtx.models import Advisory, Dependency, Severity
from rtx.policy import TrustPolicyEngine, levenshtein
from rtx.utils import utc_now


@pytest_asyncio.fixture
async def policy_engine() -> AsyncIterator[TrustPolicyEngine]:
    engine = TrustPolicyEngine()
    yield engine
    await engine.close()


@pytest_asyncio.fixture
async def policy_engine_with_config(tmp_path: Path) -> AsyncIterator[TrustPolicyEngine]:
    # Create a dummy rtx.toml for testing config loading
    config_content = textwrap.dedent("""
    [rtx]
    policy_abandonment_threshold_days = 365
    policy_churn_high_threshold = 15
    policy_churn_medium_threshold = 7
    policy_bus_factor_zero_threshold = 1
    policy_bus_factor_one_threshold = 2
    policy_low_maturity_threshold = 5
    policy_typosquat_max_distance = 1
    """)
    (tmp_path / "rtx.toml").write_text(config_content)
    # Temporarily change the current working directory to load the config
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # Reload config to pick up the new rtx.toml
        import rtx.config

        rtx.config._FILE_CONFIG = rtx.config._load_config_from_file().get("rtx", {})
        engine = TrustPolicyEngine()
        yield engine
    finally:
        os.chdir(original_cwd)
        await engine.close()


@pytest.mark.parametrize(
    ("a", "b", "max_distance", "expected"),
    [
        ("test", "test", None, 0),
        ("test", "tset", None, 1),
        ("test", "tesst", None, 1),
        ("test", "tent", None, 2),
        ("apple", "aple", None, 1),
        ("apple", "apply", None, 1),
        ("kitten", "sitting", None, 3),
        ("flaw", "lawn", None, 2),
        ("test", "tent", 1, 2),  # max_distance exceeded
        ("test", "tesst", 1, 1),  # max_distance not exceeded
        ("a", "b", 0, 1), # max_distance 0
        ("a", "a", 0, 0), # max_distance 0
    ],
)
def test_levenshtein(a: str, b: str, max_distance: int | None, expected: int) -> None:
    assert levenshtein(a, b, max_distance=max_distance) == expected


def test_levenshtein_max_distance_validation() -> None:
    with pytest.raises(ValueError, match="max_distance must be >= 0"):
        levenshtein("a", "b", max_distance=-1)


@pytest.mark.asyncio
async def test_configurable_policy_thresholds(policy_engine_with_config: TrustPolicyEngine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    engine = policy_engine_with_config
    mock_metadata_client = MagicMock(spec=engine._metadata_client)
    engine._metadata_client = mock_metadata_client

    # Test abandonment threshold
    dep_abandoned = Dependency("pypi", "abandoned_pkg", "1.0.0", Path("pkg.txt"))
    old_date = utc_now() - timedelta(days=366)  # Older than 365 days
    mock_metadata_client.fetch.return_value = ReleaseMetadata(
        latest_release=old_date,
        releases_last_30d=1,
        total_releases=10,
        maintainers=["alice"],
        ecosystem="pypi",
    )
    finding = await engine.analyze(dep_abandoned, [])
    assert any(s.category == "abandonment" for s in finding.signals)
    assert any(
        s.message == "No release in the last 365 days" for s in finding.signals
    )

    # Test churn high threshold
    dep_churn_high = Dependency("pypi", "churn_high_pkg", "1.0.0", Path("pkg.txt"))
    mock_metadata_client.fetch.return_value = ReleaseMetadata(
        latest_release=utc_now(),
        releases_last_30d=16,  # Higher than 15
        total_releases=100,
        maintainers=["alice", "bob"],
        ecosystem="pypi",
    )
    finding = await engine.analyze(dep_churn_high, [])
    assert any(s.category == "churn" for s in finding.signals)
    assert any(
        s.message == "Extreme release velocity in the last 30 days (>15 releases)" for s in finding.signals
    )

    # Test churn medium threshold
    dep_churn_medium = Dependency("pypi", "churn_medium_pkg", "1.0.0", Path("pkg.txt"))
    mock_metadata_client.fetch.return_value = ReleaseMetadata(
        latest_release=utc_now(),
        releases_last_30d=8,  # Higher than 7, lower than 15
        total_releases=50,
        maintainers=["alice", "bob"],
        ecosystem="pypi",
    )
    finding = await engine.analyze(dep_churn_medium, [])
    assert any(s.category == "churn" for s in finding.signals)
    assert any(
        s.message == "High release velocity in the last 30 days (>7 releases)" for s in finding.signals
    )

    # Test bus factor zero
    dep_bus_zero = Dependency("pypi", "bus_zero_pkg", "1.0.0", Path("pkg.txt"))
    mock_metadata_client.fetch.return_value = ReleaseMetadata(
        latest_release=utc_now(),
        releases_last_30d=1,
        total_releases=10,
        maintainers=[], # Zero maintainers
        ecosystem="pypi",
    )
    finding = await engine.analyze(dep_bus_zero, [])
    assert any(s.category == "maintainer" for s in finding.signals)
    assert any(s.message == "No maintainers listed in upstream metadata" for s in finding.signals)

    # Test bus factor one
    dep_bus_one = Dependency("pypi", "bus_one_pkg", "1.0.0", Path("pkg.txt"))
    mock_metadata_client.fetch.return_value = ReleaseMetadata(
        latest_release=utc_now(),
        releases_last_30d=1,
        total_releases=10,
        maintainers=["single"], # One maintainer
        ecosystem="pypi",
    )
    finding = await engine.analyze(dep_bus_one, [])
    assert any(s.category == "maintainer" for s in finding.signals)
    assert any(s.message == "Single maintainer detected" for s in finding.signals)

    # Test low maturity threshold
    dep_low_maturity = Dependency("pypi", "low_maturity_pkg", "1.0.0", Path("pkg.txt"))
    mock_metadata_client.fetch.return_value = ReleaseMetadata(
        latest_release=utc_now(),
        releases_last_30d=1,
        total_releases=4,  # Lower than 5
        maintainers=["alice"],
        ecosystem="pypi",
    )
    finding = await engine.analyze(dep_low_maturity, [])
    assert any(s.category == "maturity" for s in finding.signals)
    assert any(s.message == "Limited release history detected" for s in finding.signals)

    # Test typosquat max distance
    # To test typosquatting, we need to mock _top_package_pairs
    monkeypatch.setattr(
        engine, "_top_package_pairs", {"pypi": [("requests", "requests")]}
    )
    dep_typo = Dependency("pypi", "requestz", "1.0.0", Path("pkg.txt")) # 1 edit distance
    mock_metadata_client.fetch.return_value = ReleaseMetadata(
        latest_release=utc_now(),
        releases_last_30d=1,
        total_releases=10,
        maintainers=["alice"],
        ecosystem="pypi",
    )
    finding = await engine.analyze(dep_typo, [])
    assert any(s.category == "typosquat" for s in finding.signals)
    assert any(s.message == "Name is 1 edit away from popular package 'requests'" for s in finding.signals)

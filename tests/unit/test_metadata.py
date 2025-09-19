from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

import pytest

from rtx.metadata import MetadataClient, ReleaseMetadata, _parse_date
from rtx.models import Dependency


def test_parse_date_normalizes_timezone() -> None:
    parsed = _parse_date("2024-09-19T12:34:56+02:00")
    assert parsed is not None
    assert parsed.tzinfo is None
    assert parsed.year == 2024
    assert parsed.month == 9
    assert parsed.day == 19


@pytest.mark.asyncio
async def test_fetch_caches_concurrent_requests(monkeypatch, tmp_path: Path) -> None:
    client = MetadataClient()
    calls = 0

    async def fake_fetch(_dependency: Dependency) -> ReleaseMetadata:
        nonlocal calls
        calls += 1
        return ReleaseMetadata(
            latest_release=datetime.utcnow(),
            releases_last_30d=0,
            total_releases=1,
            maintainers=["alice"],
            ecosystem="pypi",
        )

    monkeypatch.setattr(client, "_fetch_uncached", fake_fetch)

    dependency = Dependency("pypi", "requests", "2.31.0", True, tmp_path)

    try:
        results = await asyncio.gather(client.fetch(dependency), client.fetch(dependency))
    finally:
        await client.close()

    assert calls == 1
    assert results[0] is results[1]

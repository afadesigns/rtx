from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from rtx.metadata import MetadataClient, ReleaseMetadata, _parse_date
from rtx.models import Dependency

try:
    import httpx
except ImportError:  # pragma: no cover - httpx is a runtime dependency
    httpx = None


def test_parse_date_normalizes_timezone() -> None:
    parsed = _parse_date("2024-09-19T12:34:56+02:00")
    assert parsed is not None
    assert parsed.tzinfo is None
    assert parsed.year == 2024
    assert parsed.month == 9
    assert parsed.day == 19


class _PassthroughRetry:
    async def __call__(self, task):  # type: ignore[override]
        return await task()


def _client_with_transport(handler):
    assert httpx is not None  # pragma: no cover - safety guard
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


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


@pytest.mark.asyncio
async def test_fetch_pypi_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("pypi", "demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow()

    async def handler(request: "httpx.Request") -> "httpx.Response":
        if request.url.path.endswith("/json"):
            return httpx.Response(
                200,
                json={
                    "info": {
                        "maintainers": [{"username": "alice"}],
                        "author": "bob",
                    },
                    "releases": {
                        "1.0.0": [{"upload_time_iso_8601": now.isoformat()}],
                        "0.9.0": [{"upload_time_iso_8601": (now - timedelta(days=31)).isoformat()}],
                    },
                },
            )
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_pypi(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.latest_release.date() == now.date()
    assert metadata.releases_last_30d == 1
    assert metadata.total_releases == 2
    assert metadata.maintainers == ["alice"]


@pytest.mark.asyncio
async def test_fetch_npm_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("npm", "demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow().isoformat()

    async def handler(request: "httpx.Request") -> "httpx.Response":
        if request.url.path.endswith("/demo"):
            return httpx.Response(
                200,
                json={
                    "time": {
                        "created": "2020-01-01T00:00:00.000Z",
                        "modified": now,
                        "1.0.0": now,
                        "0.9.0": "2020-01-01T00:00:00.000Z",
                    },
                    "maintainers": [{"name": "alice"}],
                },
            )
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_npm(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.releases_last_30d >= 1
    assert "alice" in metadata.maintainers


@pytest.mark.asyncio
async def test_fetch_crates_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("crates", "demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow().isoformat()

    async def handler(request: "httpx.Request") -> "httpx.Response":
        if request.url.path.endswith("/demo"):
            return httpx.Response(
                200,
                json={
                    "crate": {"updated_at": now},
                    "versions": [
                        {"created_at": now},
                        {"created_at": (datetime.utcnow() - timedelta(days=60)).isoformat()},
                    ],
                    "teams": [{"login": "team"}],
                },
            )
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_crates(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.releases_last_30d == 1
    assert metadata.total_releases == 2
    assert metadata.maintainers == ["team"]


@pytest.mark.asyncio
async def test_fetch_gomod_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("go", "example.com/demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow().isoformat()
    requested = []

    async def handler(request: "httpx.Request") -> "httpx.Response":
        requested.append(request.url.path)
        if request.url.path.endswith("/list"):
            return httpx.Response(200, text="v1.0.0\nv1.1.0\n")
        if request.url.path.endswith("v1.1.0.info"):
            return httpx.Response(200, json={"Time": now})
        if request.url.path.endswith("v1.0.0.info"):
            return httpx.Response(200, json={"Time": (datetime.utcnow() - timedelta(days=40)).isoformat()})
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_gomod(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.releases_last_30d == 1
    assert metadata.total_releases == 2
    assert metadata.maintainers == []
    assert any(path.endswith("@v/list") for path in requested)

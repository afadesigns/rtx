from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from rtx.metadata import MetadataClient, ReleaseMetadata, _dedupe_names, _parse_date
from rtx.models import Dependency

httpx = pytest.importorskip("httpx")


def json_response(payload: dict[str, Any], *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=payload)


def text_response(content: str, *, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, text=content)


def test_parse_date_normalizes_timezone() -> None:
    parsed = _parse_date("2024-09-19T12:34:56+02:00")
    assert parsed is not None
    assert parsed.tzinfo is None
    assert parsed.year == 2024
    assert parsed.month == 9
    assert parsed.day == 19


def test_parse_date_supports_fractional_and_z_suffix() -> None:
    parsed = _parse_date("2024-09-19T12:34:56.123456Z")
    assert parsed is not None
    assert parsed.microsecond == 123456
    assert parsed.tzinfo is None


def test_dedupe_names_normalizes_and_trims() -> None:
    candidates = ["Alice", " alice ", "ALICE", None, "Bob", "bob", ""]
    assert _dedupe_names(candidates) == ["Alice", "Bob"]


def test_dedupe_names_preserves_order() -> None:
    assert _dedupe_names(["One", "Two", "one", "TWO", "Three"]) == [
        "One",
        "Two",
        "Three",
    ]


def test_release_metadata_uses_slots() -> None:
    metadata = ReleaseMetadata(datetime.utcnow(), 1, 2, ["alice"], "pypi")
    with pytest.raises(AttributeError):
        metadata.extra = "value"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_clear_cache_resets_state(tmp_path: Path) -> None:
    client = MetadataClient()
    dependency = Dependency("pypi", "pkg", "1.0.0", True, tmp_path)
    metadata = ReleaseMetadata(None, 0, 0, [], "pypi")
    client._cache[client._cache_key(dependency)] = metadata

    async def pending() -> None:
        await asyncio.sleep(10)

    task = asyncio.create_task(pending())
    client._inflight[client._cache_key(dependency)] = task

    try:
        await client.clear_cache(cancel_inflight=True)
        await asyncio.sleep(0)
        assert not client._cache
        assert not client._inflight
        assert task.cancelled()
    finally:
        await client.close()


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
        results = await asyncio.gather(
            client.fetch(dependency), client.fetch(dependency)
        )
    finally:
        await client.close()

    assert calls == 1
    assert results[0] is results[1]


@pytest.mark.asyncio
async def test_fetch_reuses_cache_for_same_package(monkeypatch, tmp_path: Path) -> None:
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

    dep_v1 = Dependency("pypi", "Requests", "2.31.0", True, tmp_path)
    dep_v2 = Dependency("pypi", "requests", "2.32.0", True, tmp_path)

    try:
        first = await client.fetch(dep_v1)
        second = await client.fetch(dep_v2)
    finally:
        await client.close()

    assert calls == 1
    assert first is second


@pytest.mark.asyncio
async def test_fetch_pypi_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("pypi", "demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow()
    older = now - timedelta(days=1)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/json"):
            return json_response(
                {
                    "info": {
                        "maintainers": [{"username": "alice"}, {"username": "ALICE"}],
                        "author": "bob",
                    },
                    "releases": {
                        "1.0.0": [
                            {"upload_time_iso_8601": older.isoformat(), "yanked": True},
                            {
                                "upload_time": now.replace(microsecond=0).isoformat()
                                + "Z",
                            },
                        ],
                        "0.9.0": [
                            {
                                "upload_time_iso_8601": (
                                    now - timedelta(days=31)
                                ).isoformat()
                            }
                        ],
                    },
                }
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

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/demo"):
            return json_response(
                {
                    "time": {
                        "created": "2020-01-01T00:00:00.000Z",
                        "modified": now,
                        "1.0.0": now,
                        "0.9.0": "2020-01-01T00:00:00.000Z",
                    },
                    "maintainers": [],
                    "author": {"name": "Acme Corp"},
                }
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
    assert metadata.maintainers == ["Acme Corp"]


@pytest.mark.asyncio
async def test_fetch_crates_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("crates", "demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow().isoformat()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/demo"):
            return json_response(
                {
                    "crate": {"updated_at": now},
                    "versions": [
                        {"created_at": now},
                        {
                            "created_at": (
                                datetime.utcnow() - timedelta(days=60)
                            ).isoformat()
                        },
                    ],
                    "teams": [{"login": "team"}],
                }
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

    async def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        path = request.url.path
        if path.endswith("/list"):
            return text_response("v1.0.0\nv1.1.0\n")
        if path.endswith("v1.1.0.info"):
            return json_response({"Time": now})
        if path.endswith("v1.0.0.info"):
            return json_response(
                {"Time": (datetime.utcnow() - timedelta(days=40)).isoformat()}
            )
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


@pytest.mark.asyncio
async def test_fetch_gomod_respects_concurrency(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("go", "example.com/concurrent", "1.0.0", True, tmp_path)
    requested: list[str] = []
    active = 0
    max_active = 0
    lock = asyncio.Lock()

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal active, max_active
        requested.append(request.url.path)
        path = request.url.path
        if path.endswith("/list"):
            return text_response("v1.0.0\nv1.1.0\nv1.2.0\n")
        async with lock:
            active += 1
            max_active = max(max_active, active)
        try:
            await asyncio.sleep(0.01)
            return json_response({"Time": datetime.utcnow().isoformat()})
        finally:
            async with lock:
                active -= 1

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    monkeypatch.setattr("rtx.config.GOMOD_METADATA_CONCURRENCY", 2, raising=False)
    try:
        await client._fetch_gomod(dependency)
    finally:
        await client.close()

    assert any(path.endswith("@v/list") for path in requested)
    assert max_active <= 2


@pytest.mark.asyncio
async def test_fetch_rubygems_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("rubygems", "demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow()

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/versions/demo.json"):
            return json_response(
                [
                    {"created_at": now.isoformat()},
                    {"created_at": (now - timedelta(days=45)).isoformat()},
                ]
            )
        if path.endswith("/gems/demo.json"):
            return json_response({"authors": "Alice, Bob"})
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_rubygems(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.releases_last_30d == 1
    assert metadata.total_releases == 2
    assert metadata.maintainers == ["Alice", "Bob"]


@pytest.mark.asyncio
async def test_fetch_maven_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("maven", "org.demo:demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow()
    recent = int(now.timestamp() * 1000)
    older = int((now - timedelta(days=60)).timestamp() * 1000)

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "search.maven.org":
            return json_response(
                {
                    "response": {
                        "numFound": 2,
                        "docs": [
                            {"timestamp": recent, "v": "1.1.0"},
                            {"timestamp": older, "v": "1.0.0"},
                        ],
                    }
                }
            )
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_maven(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.releases_last_30d == 1
    assert metadata.total_releases == 2
    assert metadata.maintainers == []


@pytest.mark.asyncio
async def test_fetch_nuget_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("nuget", "Demo.Package", "1.0.0", True, tmp_path)
    now = datetime.utcnow().isoformat()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.nuget.org":
            return json_response(
                {
                    "items": [
                        {
                            "items": [
                                {
                                    "catalogEntry": {
                                        "published": now,
                                        "authors": "Alice, Bob",
                                    }
                                },
                                {
                                    "catalogEntry": {
                                        "published": (
                                            datetime.utcnow() - timedelta(days=45)
                                        ).isoformat(),
                                        "authors": "alice",
                                    }
                                },
                            ]
                        }
                    ]
                }
            )
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_nuget(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.releases_last_30d == 1
    assert metadata.total_releases == 2
    assert metadata.maintainers == ["Alice", "Bob"]


@pytest.mark.asyncio
async def test_fetch_packagist_parses_metadata(monkeypatch, tmp_path: Path) -> None:
    dependency = Dependency("packagist", "vendor/demo", "1.0.0", True, tmp_path)
    now = datetime.utcnow().isoformat()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "repo.packagist.org":
            return json_response(
                {
                    "package": {
                        "versions": {
                            "1.0.0": {
                                "time": now,
                                "authors": [{"name": "Alice"}, {"name": "Bob"}],
                            },
                            "0.9.0": {
                                "time": (
                                    datetime.utcnow() - timedelta(days=90)
                                ).isoformat(),
                                "authors": [{"name": "alice"}, {"name": "Bob"}],
                            },
                        }
                    }
                }
            )
        return httpx.Response(404)

    client = MetadataClient()
    await client._client.aclose()
    client._client = _client_with_transport(handler)
    client._retry = _PassthroughRetry()
    try:
        metadata = await client._fetch_packagist(dependency)
    finally:
        await client.close()

    assert metadata.latest_release is not None
    assert metadata.releases_last_30d == 1
    assert metadata.total_releases == 2
    assert metadata.maintainers == ["Alice", "Bob"]


def test_release_metadata_helper_methods() -> None:
    latest = datetime(2025, 1, 1, 12, 0, 0)
    metadata = ReleaseMetadata(
        latest_release=latest,
        releases_last_30d=7,
        total_releases=2,
        maintainers=["Alice", "bob", "Alice"],
        ecosystem="pypi",
    )
    assert metadata.churn_band() == "medium"
    assert metadata.maintainer_count() == 2
    assert metadata.is_low_maturity()
    assert metadata.days_since_latest(now=datetime(2025, 1, 11, 12, 0, 0)) == 10

    high_churn = ReleaseMetadata(
        latest_release=latest,
        releases_last_30d=11,
        total_releases=5,
        maintainers=["Alice"],
        ecosystem="pypi",
    )
    assert high_churn.churn_band() == "high"
    assert not high_churn.is_low_maturity()

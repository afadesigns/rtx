from __future__ import annotations

from pathlib import Path

import pytest

from rtx import config
from rtx.advisory import AdvisoryClient
from rtx.models import Dependency, Severity


class _FakeResponse:
    def __init__(self, payload: dict | None = None, *, status_code: int = 200) -> None:
        self._payload = payload or {"data": {"securityVulnerabilities": {"nodes": []}}}
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._payload


@pytest.mark.asyncio
async def test_osv_queries_use_expected_ecosystem_names(monkeypatch, tmp_path: Path) -> None:
    client = AdvisoryClient()
    captured: list[dict] = []

    async def fake_post(url: str, *, json: dict | None = None, **_: object) -> _FakeResponse:
        assert json is not None
        captured.append(json)
        results = {"results": [{} for _ in json["queries"]]}
        return _FakeResponse(results)

    monkeypatch.setattr(client._client, "post", fake_post)
    dependencies = [
        Dependency("pypi", "requests", "2.31.0", True, tmp_path),
        Dependency("crates", "serde", "1.0.0", True, tmp_path),
    ]

    try:
        await client._query_osv(dependencies)
    finally:
        await client.close()

    ecosystems = [query["package"]["ecosystem"] for query in captured[0]["queries"]]
    assert ecosystems == ["PyPI", "crates.io"]


@pytest.mark.asyncio
async def test_osv_query_deduplicates_dependencies(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "OSV_CACHE_SIZE", 512)
    client = AdvisoryClient()
    calls = 0

    async def fake_post(url: str, *, json: dict | None = None, **_: object) -> _FakeResponse:
        nonlocal calls
        calls += 1
        results = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "OSV-1",
                            "summary": "",
                            "severity": [{"score": "9.8"}],
                        }
                    ]
                }
            ]
        }
        return _FakeResponse(results)

    monkeypatch.setattr(client._client, "post", fake_post)

    dependencies = [
        Dependency("pypi", "requests", "2.31.0", True, tmp_path),
        Dependency("pypi", "requests", "2.31.0", False, tmp_path),
    ]

    try:
        results = await client._query_osv(dependencies)
    finally:
        await client.close()

    assert calls == 1
    assert len(results["pypi:requests@2.31.0"]) == 1


@pytest.mark.asyncio
async def test_github_query_deduplicates_packages(monkeypatch, tmp_path: Path) -> None:
    client = AdvisoryClient()
    client._gh_token = "test-token"  # enable GitHub path
    calls = 0

    async def fake_post(url: str, *, headers: dict | None = None, json: dict | None = None) -> _FakeResponse:
        nonlocal calls
        calls += 1
        assert headers and "Authorization" in headers
        payload = {
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "advisory": {
                                "ghsaId": "GHSA-1234-5678",
                                "summary": "Example",
                                "references": [{"url": "https://example.com"}],
                            },
                            "severity": "HIGH",
                            "vulnerableVersionRange": ">=0",
                        },
                        {
                            "advisory": {
                                "ghsaId": "GHSA-8765-4321",
                                "summary": "Moderate",
                                "references": [],
                            },
                            "severity": "MODERATE",
                            "vulnerableVersionRange": ">=0",
                        },
                    ]
                }
            }
        }
        return _FakeResponse(payload)

    monkeypatch.setattr(client._client, "post", fake_post)

    dependencies = [
        Dependency("pypi", "requests", "2.31.0", True, tmp_path),
        Dependency("pypi", "requests", "2.30.0", False, tmp_path),
    ]

    try:
        results = await client._query_github(dependencies)
    finally:
        await client.close()

    assert calls == 1
    first = results["pypi:requests@2.31.0"]
    second = results["pypi:requests@2.30.0"]
    assert first and second
    assert first[0].severity is Severity.HIGH
    assert first[1].severity is Severity.MEDIUM


@pytest.mark.asyncio
async def test_osv_query_uses_cache(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "OSV_CACHE_SIZE", 512)
    client = AdvisoryClient()
    calls = 0

    async def fake_post(url: str, *, json: dict | None = None, **_: object) -> _FakeResponse:
        nonlocal calls
        calls += 1
        results = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "OSV-1",
                            "summary": "",
                            "severity": [{"score": "5.0"}],
                        }
                    ]
                }
            ]
        }
        return _FakeResponse(results)

    monkeypatch.setattr(client._client, "post", fake_post)
    dependencies = [Dependency("pypi", "requests", "2.31.0", True, tmp_path)]

    try:
        await client._query_osv(dependencies)
        await client._query_osv(dependencies)
    finally:
        await client.close()

    assert calls == 1


@pytest.mark.asyncio
async def test_fetch_advisories_respects_disable_flag(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("RTX_DISABLE_GITHUB_ADVISORIES", "1")
    monkeypatch.setattr(config, "OSV_CACHE_SIZE", 0)
    client = AdvisoryClient()
    client._gh_token = "token"
    invoked = False

    async def fail_query(_: list[Dependency]) -> dict:
        nonlocal invoked
        invoked = True
        return {}

    async def fake_osv(_: list[Dependency]) -> dict:
        return {}

    monkeypatch.setattr(client, "_query_github", fail_query)
    monkeypatch.setattr(client, "_query_osv", fake_osv)

    dependencies = [Dependency("pypi", "requests", "2.31.0", True, tmp_path)]

    try:
        results = await client.fetch_advisories(dependencies)
    finally:
        await client.close()
        monkeypatch.delenv("RTX_DISABLE_GITHUB_ADVISORIES", raising=False)

    assert invoked is False
    assert results["pypi:requests@2.31.0"] == []


@pytest.mark.asyncio
async def test_osv_cache_lru_eviction(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "OSV_CACHE_SIZE", 1)
    client = AdvisoryClient()
    calls = 0

    async def fake_post(url: str, *, json: dict | None = None, **_: object) -> _FakeResponse:
        nonlocal calls
        calls += 1
        return _FakeResponse(
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "OSV-1",
                                "summary": "",
                                "severity": [{"score": "4.1"}],
                            }
                        ]
                    }
                ]
            }
        )

    monkeypatch.setattr(client._client, "post", fake_post)

    dep_a = Dependency("pypi", "pkg-a", "1.0.0", True, tmp_path)
    dep_b = Dependency("pypi", "pkg-b", "1.0.0", True, tmp_path)

    try:
        await client._query_osv([dep_a])
        await client._query_osv([dep_b])
        await client._query_osv([dep_a])
    finally:
        await client.close()

    assert calls == 3


@pytest.mark.asyncio
async def test_osv_batch_size_respects_config(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "OSV_BATCH_SIZE", 1)
    monkeypatch.setattr(config, "OSV_CACHE_SIZE", 0)
    client = AdvisoryClient()
    calls = 0
    batch_lengths: list[int] = []

    async def fake_post(url: str, *, json: dict | None = None, **_: object) -> _FakeResponse:
        nonlocal calls
        calls += 1
        assert json is not None
        batch_lengths.append(len(json.get("queries", [])))
        return _FakeResponse({"results": [{}]})

    monkeypatch.setattr(client._client, "post", fake_post)

    deps = [
        Dependency("pypi", f"pkg-{idx}", "1.0.0", True, tmp_path)
        for idx in range(3)
    ]

    try:
        await client._query_osv(deps)
    finally:
        await client.close()

    assert calls == 3
    assert batch_lengths == [1, 1, 1]


@pytest.mark.asyncio
async def test_clear_cache_empties_entries(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(config, "OSV_CACHE_SIZE", 8)
    client = AdvisoryClient()
    calls = 0

    async def fake_post(url: str, *, json: dict | None = None, **_: object) -> _FakeResponse:
        nonlocal calls
        calls += 1
        return _FakeResponse({"results": [{}]})

    monkeypatch.setattr(client._client, "post", fake_post)
    dep = Dependency("pypi", "cached", "1.0.0", True, tmp_path)

    try:
        await client._query_osv([dep])
        client.clear_cache()
        await client._query_osv([dep])
    finally:
        await client.close()

    assert calls == 2

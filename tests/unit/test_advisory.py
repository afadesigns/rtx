from __future__ import annotations

from pathlib import Path

import pytest

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
                        }
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

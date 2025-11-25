from __future__ import annotations

import os
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
import respx
from diskcache import Cache

from rtx.advisory import (
    AdvisoryClient,
    _extract_numeric_score,
    _severity_from_github,
    _severity_from_label,
    _severity_from_osv,
)
from rtx.models import Advisory, Dependency, Severity


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"severity": [{"score": "9.0"}]}, Severity.CRITICAL),
        ({"severity": [{"score": "7.0"}]}, Severity.HIGH),
        ({"severity": [{"score": "4.0"}]}, Severity.MEDIUM),
        ({"severity": [{"score": "0.1"}]}, Severity.LOW),
        ({"database_specific": {"severity": "CRITICAL"}}, Severity.CRITICAL),
        ({}, Severity.NONE),
        ({"severity": []}, Severity.NONE),
        ({"severity": [None]}, Severity.NONE),
        ({"database_specific": None}, Severity.NONE),
        ({"database_specific": {"severity": None}}, Severity.NONE),
        ({"database_specific": "foo"}, Severity.NONE),
    ],
)
def test_severity_from_osv(entry: dict, expected: Severity) -> None:
    assert _severity_from_osv(entry) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (1.0, 1.0),
        ("2.0", 2.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.0),
        ("Score: 9.8", 9.8),
        (None, 0.0),
        ("foo", 0.0),
        ("", 0.0),
        ("1.2.3", 1.2),
        ("CVSS:foo", 0.0),
        (False, 0.0),
    ],
)
def test_extract_numeric_score(raw: object, expected: float) -> None:
    assert _extract_numeric_score(raw) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        (None, Severity.NONE),
        ("unknown", Severity.NONE),
    ],
)
def test_severity_from_label(label: str | None, expected: Severity) -> None:
    assert _severity_from_label(label) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        (None, Severity.LOW),
        ("unknown", Severity.LOW),
    ],
)
def test_severity_from_github(label: str | None, expected: Severity) -> None:
    assert _severity_from_github(label) == expected


@pytest_asyncio.fixture
async def advisory_client_with_cache(tmp_path: Path) -> AdvisoryClient:
    client = AdvisoryClient(cache_dir=str(tmp_path))
    yield client
    await client.close()


@pytest_asyncio.fixture
async def advisory_client_no_cache() -> AdvisoryClient:
    client = AdvisoryClient(cache_dir="/dev/null")  # Use a null directory for no effective cache
    yield client
    await client.close()


@respx.mock
@pytest.mark.asyncio
async def test_advisory_client_osv_caching(advisory_client_with_cache: AdvisoryClient) -> None:
    client = advisory_client_with_cache
    dep = Dependency("pypi", "requests", "2.28.1", Path("requirements.txt"))
    osv_response_payload = {
        "results": [
            {
                "vulns": [
                    {
                        "id": "OSV-2022-0001",
                        "summary": "Test advisory",
                        "severity": [{"score": "9.8", "type": "CVSS_V3"}],
                        "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
                    }
                ]
            }
        ]
    }

    # First call: should hit the network and populate cache
    respx.post("https://api.osv.dev/v1/querybatch").respond(200, json=osv_response_payload)
    results = await client.fetch_advisories([dep])
    assert len(results[dep.coordinate]) == 1
    assert results[dep.coordinate][0].identifier == "OSV-2022-0001"

    # Second call: should hit the cache, network should not be called
    respx.post("https://api.osv.dev/v1/querybatch").respond(500) # This should not be hit
    results_cached = await client.fetch_advisories([dep])
    assert len(results_cached[dep.coordinate]) == 1
    assert results_cached[dep.coordinate][0].identifier == "OSV-2022-0001"

    # Clear cache and try again: should hit network again
    client.clear_cache()
    respx.post("https://api.osv.dev/v1/querybatch").respond(200, json=osv_response_payload)
    results_after_clear = await client.fetch_advisories([dep])
    assert len(results_after_clear[dep.coordinate]) == 1
    assert results_after_clear[dep.coordinate][0].identifier == "OSV-2022-0001"


@respx.mock
@pytest.mark.asyncio
async def test_advisory_client_github_caching(advisory_client_with_cache: AdvisoryClient) -> None:
    client = advisory_client_with_cache
    dep = Dependency("npm", "express", "4.17.1", Path("package.json"))
    github_response_payload = {
        "data": {
            "securityVulnerabilities": {
                "nodes": [
                    {
                        "advisory": {
                            "ghsaId": "GHSA-abcd-1234-efgh",
                            "summary": "GitHub Test Advisory",
                            "references": [{"url": "https://github.com/advisory/1"}],
                            "severity": "HIGH",
                        }
                    }
                ]
            }
        }
    }

    # First call: should hit the network and populate cache
    os.environ["GITHUB_TOKEN"] = "test_token"
    respx.post("https://api.github.com/graphql").respond(200, json=github_response_payload)
    results = await client.fetch_advisories([dep])
    assert len(results[dep.coordinate]) == 1
    assert results[dep.coordinate][0].identifier == "GHSA-abcd-1234-efgh"
    del os.environ["GITHUB_TOKEN"]

    # Second call: should hit the cache, network should not be called
    respx.post("https://api.github.com/graphql").respond(500) # This should not be hit
    results_cached = await client.fetch_advisories([dep])
    assert len(results_cached[dep.coordinate]) == 1
    assert results_cached[dep.coordinate][0].identifier == "GHSA-abcd-1234-efgh"

    # Clear cache and try again: should hit network again
    client.clear_cache()
    os.environ["GITHUB_TOKEN"] = "test_token"
    respx.post("https://api.github.com/graphql").respond(200, json=github_response_payload)
    results_after_clear = await client.fetch_advisories([dep])
    assert len(results_after_clear[dep.coordinate]) == 1
    assert results_after_clear[dep.coordinate][0].identifier == "GHSA-abcd-1234-efgh"
    del os.environ["GITHUB_TOKEN"]




@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"severity": [{"score": "9.0"}]}, Severity.CRITICAL),
        ({"severity": [{"score": "7.0"}]}, Severity.HIGH),
        ({"severity": [{"score": "4.0"}]}, Severity.MEDIUM),
        ({"severity": [{"score": "0.1"}]}, Severity.LOW),
        ({"database_specific": {"severity": "CRITICAL"}}, Severity.CRITICAL),
        ({}, Severity.NONE),
        ({"severity": []}, Severity.NONE),
        ({"severity": [None]}, Severity.NONE),
        ({"database_specific": None}, Severity.NONE),
        ({"database_specific": {"severity": None}}, Severity.NONE),
        ({"database_specific": "foo"}, Severity.NONE),
    ],
)
def test_severity_from_osv(entry: dict, expected: Severity) -> None:
    assert _severity_from_osv(entry) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (1.0, 1.0),
        ("2.0", 2.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 0.0),
        ("Score: 9.8", 9.8),
        (None, 0.0),
        ("foo", 0.0),
        ("", 0.0),
        ("1.2.3", 1.2),
        ("CVSS:foo", 0.0),
        (False, 0.0),
    ],
)
def test_extract_numeric_score(raw: object, expected: float) -> None:
    assert _extract_numeric_score(raw) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        (None, Severity.NONE),
        ("unknown", Severity.NONE),
    ],
)
def test_severity_from_label(label: str | None, expected: Severity) -> None:
    assert _severity_from_label(label) == expected


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("critical", Severity.CRITICAL),
        ("CRITICAL", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("moderate", Severity.MEDIUM),
        ("medium", Severity.MEDIUM),
        ("low", Severity.LOW),
        (None, Severity.LOW),
        ("unknown", Severity.LOW),
    ],
)
def test_severity_from_github(label: str | None, expected: Severity) -> None:
    assert _severity_from_github(label) == expected
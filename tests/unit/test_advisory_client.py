from pathlib import Path

import httpx
import pytest

from rtx import config
from rtx.advisory import AdvisoryClient
from rtx.exceptions import AdvisoryServiceError
from rtx.models import Dependency


@pytest.mark.asyncio
async def test_query_osv_success(httpx_mock):
    """Test a successful query to OSV with a single dependency."""
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-1234",
                            "summary": "A vulnerability",
                            "references": [{"url": "http://example.com"}],
                        }
                    ]
                }
            ]
        },
    )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client._query_osv(dependencies)

    assert "pypi:test@1.0.0" in results
    advisories = results["pypi:test@1.0.0"]
    assert len(advisories) == 1
    assert advisories[0].identifier == "GHSA-1234"
    assert advisories[0].summary == "A vulnerability"


@pytest.mark.asyncio
async def test_query_osv_multiple_dependencies(httpx_mock):
    """Test a successful query to OSV with multiple dependencies."""
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={
            "results": [
                {
                    "vulns": [
                        {
                            "id": "GHSA-1234",
                            "summary": "A vulnerability",
                            "references": [{"url": "http://example.com"}],
                        }
                    ]
                },
                {"vulns": []},
            ]
        },
    )

    dependencies = [
        Dependency(
            name="test1",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        ),
        Dependency(
            name="test2",
            version="2.0.0",
            ecosystem="npm",
            direct=True,
            manifest=Path("package.json"),
        ),
    ]
    async with AdvisoryClient() as client:
        results = await client._query_osv(dependencies)

    assert "pypi:test1@1.0.0" in results
    assert "npm:test2@2.0.0" in results
    assert len(results["pypi:test1@1.0.0"]) == 1
    assert len(results["npm:test2@2.0.0"]) == 0


@pytest.mark.asyncio
async def test_query_osv_unsupported_ecosystem():
    """Test a query for an unsupported ecosystem."""
    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="unsupported",
            direct=True,
            manifest=Path("file"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client._query_osv(dependencies)

    assert "unsupported:test@1.0.0" in results
    assert len(results["unsupported:test@1.0.0"]) == 0


@pytest.mark.asyncio
async def test_query_osv_api_error(httpx_mock):
    """Test a query that returns an error from the OSV API."""
    for _ in range(config.HTTP_RETRIES + 1):
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            method="POST",
            status_code=500,
        )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        with pytest.raises(ExceptionGroup) as excinfo:
            await client._query_osv(dependencies)
        assert any(isinstance(exc, AdvisoryServiceError) for exc in excinfo.value.exceptions)


@pytest.mark.asyncio
async def test_query_osv_caching(httpx_mock):
    """Test the caching behavior of _query_osv."""
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": []}]},
    )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        # First call, should query the API
        await client._query_osv(dependencies)
        # Second call, should use the cache
        await client._query_osv(dependencies)

    assert len(httpx_mock.get_requests()) == 1


@pytest.mark.asyncio
async def test_query_github_success(httpx_mock, monkeypatch):
    """Test a successful query to GitHub."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "test_token")
    httpx_mock.add_response(
        url="https://api.github.com/graphql",
        method="POST",
        json={
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "advisory": {
                                "ghsaId": "GHSA-1234",
                                "summary": "A vulnerability",
                                "references": [{"url": "http://example.com"}],
                                "severity": "HIGH",
                            }
                        }
                    ]
                }
            }
        },
    )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client._query_github(dependencies)

    assert "pypi:test@1.0.0" in results
    advisories = results["pypi:test@1.0.0"]
    assert len(advisories) == 1
    assert advisories[0].identifier == "GHSA-1234"
    assert advisories[0].summary == "A vulnerability"


@pytest.mark.asyncio
async def test_query_github_api_error(httpx_mock, monkeypatch):
    """Test a query that returns an error from the GitHub API."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "test_token")
    for _ in range(config.HTTP_RETRIES + 1):
        httpx_mock.add_response(
            url="https://api.github.com/graphql",
            method="POST",
            status_code=500,
        )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client._query_github(dependencies)
        assert not results["pypi:test@1.0.0"]


@pytest.mark.asyncio
async def test_query_github_invalid_token(httpx_mock, monkeypatch):
    """Test a query with an invalid GitHub token."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "invalid_token")
    httpx_mock.add_response(
        url="https://api.github.com/graphql",
        method="POST",
        status_code=401,
    )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client._query_github(dependencies)
        assert not results["pypi:test@1.0.0"]


@pytest.mark.asyncio
async def test_fetch_advisories_success(httpx_mock, monkeypatch):
    """Test a successful query with both OSV and GitHub results."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "test_token")
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": [{"id": "OSV-1234"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.github.com/graphql",
        method="POST",
        json={
            "data": {
                "securityVulnerabilities": {
                    "nodes": [{"advisory": {"ghsaId": "GHSA-1234"}}]
                }
            }
        },
    )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client.fetch_advisories(dependencies)

    advisories = results["pypi:test@1.0.0"]
    assert len(advisories) == 2
    assert {"OSV-1234", "GHSA-1234"} == {adv.identifier for adv in advisories}


@pytest.mark.asyncio
async def test_fetch_advisories_osv_fails(httpx_mock, monkeypatch):
    """Test a query where OSV fails but GitHub succeeds."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "test_token")
    for _ in range(config.HTTP_RETRIES + 1):
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            method="POST",
            status_code=500,
        )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        with pytest.raises(ExceptionGroup) as excinfo:
            await client.fetch_advisories(dependencies)
        assert any(isinstance(exc, AdvisoryServiceError) for exc in excinfo.value.exceptions)


@pytest.mark.asyncio
async def test_fetch_advisories_github_fails(httpx_mock, monkeypatch):
    """Test a query where GitHub fails but OSV succeeds."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "test_token")
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": [{"id": "OSV-1234"}]}]},
    )
    for _ in range(config.HTTP_RETRIES + 1):
        httpx_mock.add_response(
            url="https://api.github.com/graphql",
            method="POST",
            status_code=500,
        )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client.fetch_advisories(dependencies)

    advisories = results["pypi:test@1.0.0"]
    assert len(advisories) == 1
    assert advisories[0].identifier == "OSV-1234"


@pytest.mark.asyncio
async def test_fetch_advisories_both_fail(httpx_mock, monkeypatch):
    """Test a query where both OSV and GitHub fail."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "test_token")
    for _ in range(config.HTTP_RETRIES + 1):
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/querybatch",
            method="POST",
            status_code=500,
        )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        with pytest.raises(ExceptionGroup) as excinfo:
            await client.fetch_advisories(dependencies)
        assert any(isinstance(exc, AdvisoryServiceError) for exc in excinfo.value.exceptions)


@pytest.mark.asyncio
async def test_fetch_advisories_no_dependencies():
    """Test a query with no dependencies."""
    async with AdvisoryClient() as client:
        results = await client.fetch_advisories([])
    assert not results


@pytest.mark.asyncio
async def test_fetch_advisories_merging(httpx_mock, monkeypatch):
    """Test the merging of advisories from different sources."""
    monkeypatch.setenv("RTX_GITHUB_TOKEN", "test_token")
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        method="POST",
        json={"results": [{"vulns": [{"id": "GHSA-1234", "summary": "OSV summary"}]}]},
    )
    httpx_mock.add_response(
        url="https://api.github.com/graphql",
        method="POST",
        json={
            "data": {
                "securityVulnerabilities": {
                    "nodes": [
                        {
                            "advisory": {
                                "ghsaId": "GHSA-1234",
                                "summary": "GitHub summary",
                                "severity": "HIGH",
                            }
                        }
                    ]
                }
            }
        },
    )

    dependencies = [
        Dependency(
            name="test",
            version="1.0.0",
            ecosystem="pypi",
            direct=True,
            manifest=Path("requirements.txt"),
        )
    ]
    async with AdvisoryClient() as client:
        results = await client.fetch_advisories(dependencies)

    advisories = results["pypi:test@1.0.0"]
    assert len(advisories) == 1
    assert advisories[0].identifier == "GHSA-1234"
    assert advisories[0].summary == "GitHub summary"

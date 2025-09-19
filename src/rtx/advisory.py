from __future__ import annotations

import asyncio
import os
from typing import Dict, Iterable, List, Tuple

import httpx

from rtx import config
from rtx.exceptions import AdvisoryServiceError
from rtx.models import Advisory, Dependency, Severity
from rtx.utils import AsyncRetry, chunked

OSV_ECOSYSTEM_MAP: Dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "crates": "crates.io",
    "packagist": "Packagist",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "homebrew": "Homebrew",
    "conda": "conda",
    "docker": "Docker",
}

GITHUB_MAX_CONCURRENCY = 6


def _severity_from_osv(entry: dict) -> Severity:
    severity = entry.get("severity") or []
    for item in severity:
        score = item.get("score")
        if isinstance(score, str) and score.startswith("CVSS:"):
            try:
                value = float(score.split("/" if "/" in score else ":")[-1])
            except ValueError:
                value = 0.0
        else:
            try:
                value = float(item.get("score", 0))
            except (TypeError, ValueError):
                value = 0.0
        if value >= 9.0:
            return Severity.CRITICAL
        if value >= 7.0:
            return Severity.HIGH
        if value >= 4.0:
            return Severity.MEDIUM
        if value > 0:
            return Severity.LOW
    return Severity.NONE


class AdvisoryClient:
    def __init__(self, *, timeout: float = config.HTTP_TIMEOUT, retries: int = config.HTTP_RETRIES) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, headers={"User-Agent": config.USER_AGENT})
        self._retry = AsyncRetry(retries=retries, delay=0.5)
        self._gh_token = os.getenv("RTX_GITHUB_TOKEN") or os.getenv(config.GITHUB_DEFAULT_TOKEN_ENV)

    async def __aenter__(self) -> "AdvisoryClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def fetch_advisories(self, dependencies: Iterable[Dependency]) -> Dict[str, List[Advisory]]:
        deps = list(dependencies)
        osv_results = await self._query_osv(deps)
        gh_results: Dict[str, List[Advisory]] = {}
        if self._gh_token:
            try:
                gh_results = await self._query_github(deps)
            except AdvisoryServiceError:
                gh_results = {}
        combined: Dict[str, List[Advisory]] = {}
        for dep in deps:
            key = dep.coordinate
            combined[key] = osv_results.get(key, []) + gh_results.get(key, [])
        return combined

    async def _query_osv(self, dependencies: List[Dependency]) -> Dict[str, List[Advisory]]:
        results: Dict[str, List[Advisory]] = {}
        queries = []
        for dep in dependencies:
            ecosystem = OSV_ECOSYSTEM_MAP.get(dep.ecosystem, dep.ecosystem)
            queries.append(
                {
                    "package": {"name": dep.name, "ecosystem": ecosystem},
                    "version": dep.version,
                }
            )
        async def task(chunk: List[dict]) -> Dict[str, List[Advisory]]:
            response = await self._client.post(config.OSV_API_URL, json={"queries": chunk})
            response.raise_for_status()
            payload = response.json()
            out: Dict[str, List[Advisory]] = {}
            for entry, dep in zip(payload.get("results", []), chunk, strict=False):
                key = f"{dep['package']['ecosystem'].lower()}:{dep['package']['name']}@{dep['version']}"
                advisories: List[Advisory] = []
                for vuln in entry.get("vulns", []) or []:
                    severity = _severity_from_osv(vuln)
                    advisory = Advisory(
                        identifier=vuln.get("id", "UNKNOWN"),
                        source="osv.dev",
                        severity=severity,
                        summary=vuln.get("summary", ""),
                        references=[ref.get("url") for ref in vuln.get("references", []) or [] if isinstance(ref, dict) and ref.get("url")],
                    )
                    advisories.append(advisory)
                out[key] = advisories
            return out

        for chunk in chunked(queries, 18):  # OSV limits 1000 queries; keep small for reliability
            chunk_result = await self._retry(lambda c=chunk: task(list(c)))
            results.update(chunk_result)
        return results

    async def _query_github(self, dependencies: List[Dependency]) -> Dict[str, List[Advisory]]:
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
          securityVulnerabilities(first: 20, ecosystem: $ecosystem, package: $package) {
            nodes {
              advisory {
                ghsaId
                summary
                references { url }
                severity
              }
              vulnerableVersionRange
            }
          }
        }
        """

        async def fetch(dep: Dependency) -> List[Advisory]:
            variables = {
                "ecosystem": dep.ecosystem.upper(),
                "package": dep.name,
            }
            response = await self._client.post(
                config.GITHUB_ADVISORY_URL,
                headers={"Authorization": f"Bearer {self._gh_token}"},
                json={"query": query, "variables": variables},
            )
            if response.status_code == 401:
                raise AdvisoryServiceError("Invalid GitHub token")
            response.raise_for_status()
            data = response.json()
            advisories: List[Advisory] = []
            nodes = (
                data.get("data", {})
                .get("securityVulnerabilities", {})
                .get("nodes", [])
            )
            for node in nodes:
                advisory_node = node.get("advisory", {})
                severity = Severity[node.get("severity", "LOW").upper()] if node.get("severity") else Severity.LOW
                advisories.append(
                    Advisory(
                        identifier=advisory_node.get("ghsaId", "GHSA-unknown"),
                        source="github",
                        severity=severity,
                        summary=advisory_node.get("summary", ""),
                        references=[ref.get("url") for ref in advisory_node.get("references", []) if isinstance(ref, dict) and ref.get("url")],
                    )
                )
            return advisories

        results: Dict[str, List[Advisory]] = {}
        semaphore = asyncio.Semaphore(GITHUB_MAX_CONCURRENCY)

        async def run(dep: Dependency) -> Tuple[Dependency, List[Advisory] | Exception]:
            async with semaphore:
                try:
                    advisories = await self._retry(lambda dep=dep: fetch(dep))
                except Exception as exc:  # noqa: BLE001 - propagate to caller
                    return dep, exc
                return dep, advisories

        unique: Dict[Tuple[str, str], Dependency] = {}
        for dep in dependencies:
            key = (dep.ecosystem, dep.name)
            unique.setdefault(key, dep)

        tasks = [run(dep) for dep in unique.values()]
        completed = await asyncio.gather(*tasks)
        per_package: Dict[Tuple[str, str], List[Advisory]] = {}
        for dep, outcome in completed:
            if isinstance(outcome, Exception):
                continue
            per_package[(dep.ecosystem, dep.name)] = outcome

        for dep in dependencies:
            key = dep.coordinate
            package_key = (dep.ecosystem, dep.name)
            advisories = per_package.get(package_key, [])
            results[key] = list(advisories)
        return results

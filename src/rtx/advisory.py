from __future__ import annotations

import asyncio
import os
import re
from collections import OrderedDict
from itertools import zip_longest
from typing import Dict, Iterable, List, Tuple

import httpx

from rtx import config
from rtx.exceptions import AdvisoryServiceError
from rtx.models import Advisory, Dependency, Severity
from rtx.utils import AsyncRetry, chunked, env_flag

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

def _extract_numeric_score(raw: object) -> float:
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        stripped = raw.strip()
        try:
            return float(stripped)
        except ValueError:
            if stripped.startswith("CVSS:"):
                return 0.0
            match = re.search(r"\d+(?:\.\d+)?", stripped)
            if match:
                try:
                    return float(match.group(0))
                except ValueError:
                    return 0.0
    return 0.0


def _severity_from_label(label: str | None) -> Severity:
    if not label:
        return Severity.NONE
    normalized = label.strip().lower()
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(normalized, Severity.NONE)


def _severity_from_github(label: str | None) -> Severity:
    if not label:
        return Severity.LOW
    normalized = label.strip().lower()
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(normalized, Severity.LOW)


def _severity_from_osv(entry: dict) -> Severity:
    severity_entries = entry.get("severity") or []
    max_score = 0.0
    for item in severity_entries:
        score = _extract_numeric_score(item.get("score")) if isinstance(item, dict) else 0.0
        max_score = max(max_score, score)
    if max_score >= 9.0:
        return Severity.CRITICAL
    if max_score >= 7.0:
        return Severity.HIGH
    if max_score >= 4.0:
        return Severity.MEDIUM
    if max_score > 0:
        return Severity.LOW
    label = (entry.get("database_specific") or {}).get("severity")
    return _severity_from_label(label)


class AdvisoryClient:
    def __init__(self, *, timeout: float = config.HTTP_TIMEOUT, retries: int = config.HTTP_RETRIES) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, headers={"User-Agent": config.USER_AGENT})
        self._retry = AsyncRetry(retries=retries, delay=0.5, exceptions=(httpx.HTTPError,))
        self._gh_token = os.getenv("RTX_GITHUB_TOKEN") or os.getenv(config.GITHUB_DEFAULT_TOKEN_ENV)
        self._gh_disabled = env_flag("RTX_DISABLE_GITHUB_ADVISORIES", False)
        self._osv_cache: OrderedDict[str, List[Advisory]] = OrderedDict()
        self._osv_cache_size = config.OSV_CACHE_SIZE

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
        if self._gh_token and not self._gh_disabled:
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
        if not dependencies:
            return {}

        cached: Dict[str, List[Advisory]] = {}
        unique_uncached: Dict[str, Dependency] = {}
        for dep in dependencies:
            coordinate = dep.coordinate
            if self._osv_cache_size > 0:
                cached_value = self._osv_cache.get(coordinate)
                if cached_value is not None:
                    cached[coordinate] = list(cached_value)
                    self._osv_cache.move_to_end(coordinate)
                    continue
            unique_uncached.setdefault(coordinate, dep)

        async def task(chunk_deps: List[Dependency]) -> Dict[str, List[Advisory]]:
            queries = [
                {
                    "package": {
                        "name": dep.name,
                        "ecosystem": OSV_ECOSYSTEM_MAP.get(dep.ecosystem, dep.ecosystem),
                    },
                    "version": dep.version,
                }
                for dep in chunk_deps
            ]
            response = await self._client.post(config.OSV_API_URL, json={"queries": queries})
            response.raise_for_status()
            payload = response.json()
            out: Dict[str, List[Advisory]] = {}
            results_iterable = payload.get("results") or []
            for dep, entry in zip_longest(chunk_deps, results_iterable, fillvalue=None):
                assert dep is not None
                vulns = (entry or {}).get("vulns", []) if isinstance(entry, dict) else []
                advisories: List[Advisory] = []
                for vuln in vulns or []:
                    severity = _severity_from_osv(vuln)
                    advisory = Advisory(
                        identifier=vuln.get("id", "UNKNOWN"),
                        source="osv.dev",
                        severity=severity,
                        summary=vuln.get("summary", ""),
                        references=[
                            ref.get("url")
                            for ref in (vuln.get("references", []) or [])
                            if isinstance(ref, dict) and ref.get("url")
                        ],
                    )
                    advisories.append(advisory)
                out[dep.coordinate] = advisories
            return out

        aggregated: Dict[str, List[Advisory]] = dict(cached)
        if unique_uncached:
            for chunk_deps in chunked(list(unique_uncached.values()), config.OSV_BATCH_SIZE):
                chunk_result = await self._retry(lambda deps=chunk_deps: task(list(deps)))
                for key, advisories in chunk_result.items():
                    aggregated[key] = advisories
                    if self._osv_cache_size > 0:
                        if key in self._osv_cache:
                            self._osv_cache.move_to_end(key)
                        else:
                            while len(self._osv_cache) >= self._osv_cache_size:
                                self._osv_cache.popitem(last=False)
                        self._osv_cache[key] = list(advisories)

        return {dep.coordinate: list(aggregated.get(dep.coordinate, [])) for dep in dependencies}

    def clear_cache(self) -> None:
        self._osv_cache.clear()

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
                severity = _severity_from_github(node.get("severity"))
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
        semaphore = asyncio.Semaphore(config.GITHUB_MAX_CONCURRENCY)

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

from __future__ import annotations

import asyncio
import os
import re
from collections import OrderedDict
from collections.abc import Iterable
from itertools import chain

import httpx

from rtx import config
from rtx.exceptions import AdvisoryServiceError
from rtx.models import SEVERITY_RANK, Advisory, Dependency, Severity
from rtx.utils import AsyncRetry, chunked, env_flag, unique_preserving_order

OSV_ECOSYSTEM_MAP: dict[str, str] = {
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
    if isinstance(raw, int | float):
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
    def __init__(
        self,
        *,
        timeout: float = config.HTTP_TIMEOUT,
        retries: int = config.HTTP_RETRIES,
    ) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, headers={"User-Agent": config.USER_AGENT})
        self._retry = AsyncRetry(retries=retries, delay=0.5, exceptions=(httpx.HTTPError,))
        self._gh_token = os.getenv("RTX_GITHUB_TOKEN") or os.getenv(config.GITHUB_DEFAULT_TOKEN_ENV)
        self._gh_disabled = env_flag("RTX_DISABLE_GITHUB_ADVISORIES", False)
        self._osv_cache: OrderedDict[str, list[Advisory]] = OrderedDict()
        self._osv_cache_size = config.OSV_CACHE_SIZE

    async def __aenter__(self) -> AdvisoryClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def fetch_advisories(
        self,
        dependencies: Iterable[Dependency],
    ) -> dict[str, list[Advisory]]:
        deps = list(dependencies)
        osv_results = await self._query_osv(deps)
        gh_results: dict[str, list[Advisory]] = {}
        if self._gh_token and not self._gh_disabled:
            try:
                gh_results = await self._query_github(deps)
            except AdvisoryServiceError:
                gh_results = {}
        combined: dict[str, list[Advisory]] = {}
        for dep in deps:
            key = dep.coordinate
            merged: dict[tuple[str, str], Advisory] = {}
            for advisory in chain(osv_results.get(key, []), gh_results.get(key, [])):
                dedup_key = (advisory.source, advisory.identifier)
                existing = merged.get(dedup_key)
                if existing is None:
                    merged[dedup_key] = Advisory(
                        identifier=advisory.identifier,
                        source=advisory.source,
                        severity=advisory.severity,
                        summary=advisory.summary,
                        references=unique_preserving_order(advisory.references),
                    )
                    continue
                references = unique_preserving_order(existing.references + advisory.references)
                summary = existing.summary or advisory.summary
                if SEVERITY_RANK[advisory.severity.value] > SEVERITY_RANK[existing.severity.value]:
                    summary = advisory.summary or summary
                    severity = advisory.severity
                else:
                    severity = existing.severity
                merged[dedup_key] = Advisory(
                    identifier=existing.identifier,
                    source=existing.source,
                    severity=severity,
                    summary=summary,
                    references=references,
                )
            combined[key] = sorted(
                merged.values(),
                key=lambda adv: (
                    -SEVERITY_RANK[adv.severity.value],
                    adv.source,
                    adv.identifier,
                ),
            )
        return combined

    async def _query_osv(self, dependencies: list[Dependency]) -> dict[str, list[Advisory]]:
        if not dependencies:
            return {}

        cached: dict[str, list[Advisory]] = {}
        unique_uncached: dict[str, Dependency] = {}
        for dep in dependencies:
            coordinate = dep.coordinate
            if self._osv_cache_size > 0:
                cached_value = self._osv_cache.get(coordinate)
                if cached_value is not None:
                    cached[coordinate] = list(cached_value)
                    self._osv_cache.move_to_end(coordinate)
                    continue
            unique_uncached.setdefault(coordinate, dep)

        async def task(chunk_deps: list[Dependency]) -> dict[str, list[Advisory]]:
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
            out: dict[str, list[Advisory]] = {}
            results = list(payload.get("results") or [])
            for index, dep in enumerate(chunk_deps):
                entry = results[index] if index < len(results) else None
                vulns = (entry or {}).get("vulns", []) if isinstance(entry, dict) else []
                advisories: list[Advisory] = []
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

        aggregated: dict[str, list[Advisory]] = dict(cached)
        if unique_uncached:
            uncached = list(unique_uncached.values())
            chunks = [list(chunk) for chunk in chunked(uncached, config.OSV_BATCH_SIZE)]
            max_concurrency = max(1, getattr(config, "OSV_MAX_CONCURRENCY", 1))
            semaphore = asyncio.Semaphore(max_concurrency)

            async def run_chunk(chunk_deps: list[Dependency]) -> dict[str, list[Advisory]]:
                async with semaphore:
                    deps_copy = list(chunk_deps)
                    return await self._retry(lambda deps=deps_copy: task(deps))

            chunk_results: list[dict[str, list[Advisory]]] = []

            async def worker(chunk_deps: list[Dependency]) -> None:
                chunk_results.append(await run_chunk(chunk_deps))

            if hasattr(asyncio, "TaskGroup"):
                async with asyncio.TaskGroup() as task_group:
                    for chunk in chunks:
                        deps_copy = list(chunk)
                        task_group.create_task(worker(deps_copy))
            else:  # pragma: no cover - Python <3.11 fallback
                await asyncio.gather(*(worker(list(chunk)) for chunk in chunks))

            for chunk_result in chunk_results:
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

    async def _query_github(self, dependencies: list[Dependency]) -> dict[str, list[Advisory]]:
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

        async def fetch(dep: Dependency) -> list[Advisory]:
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
            advisories: list[Advisory] = []
            nodes = (
                data.get("data", {})
                .get("securityVulnerabilities", {})
                .get("nodes", [])
            )
            for node in nodes:
                advisory_node = node.get("advisory", {})
                severity_label = node.get("severity") or advisory_node.get("severity")
                severity = _severity_from_github(severity_label)
                references = unique_preserving_order(
                    (
                        ref.get("url")
                        for ref in (advisory_node.get("references", []) or [])
                        if isinstance(ref, dict) and isinstance(ref.get("url"), str)
                    ),
                )
                advisories.append(
                    Advisory(
                        identifier=advisory_node.get("ghsaId", "GHSA-unknown"),
                        source="github",
                        severity=severity,
                        summary=advisory_node.get("summary", ""),
                        references=references,
                    )
                )
            return advisories

        results: dict[str, list[Advisory]] = {}
        semaphore = asyncio.Semaphore(config.GITHUB_MAX_CONCURRENCY)

        async def run(dep: Dependency) -> tuple[Dependency, list[Advisory] | Exception]:
            async with semaphore:
                try:
                    advisories = await self._retry(lambda dep=dep: fetch(dep))
                except Exception as exc:
                    return dep, exc
                return dep, advisories

        unique: dict[tuple[str, str], Dependency] = {}
        for dep in dependencies:
            key = (dep.ecosystem, dep.name)
            unique.setdefault(key, dep)

        tasks = [run(dep) for dep in unique.values()]
        completed = await asyncio.gather(*tasks)
        per_package: dict[tuple[str, str], list[Advisory]] = {}
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

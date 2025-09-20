from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Dict, Optional

import httpx

from rtx import config
from rtx.models import Dependency
from rtx.utils import AsyncRetry

ISO_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
]


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _parse_date(value: str | None) -> Optional[datetime]:
    if not value:
        return None
    trimmed = value.strip()
    if trimmed.endswith("Z"):
        trimmed = f"{trimmed[:-1]}+00:00"
    for fmt in ISO_FORMATS:
        try:
            return _normalize_datetime(datetime.strptime(trimmed, fmt))
        except ValueError:
            continue
    try:
        return _normalize_datetime(datetime.fromisoformat(trimmed))
    except ValueError:
        return None


@dataclass
class ReleaseMetadata:
    latest_release: Optional[datetime]
    releases_last_30d: int
    total_releases: int
    maintainers: list[str]
    ecosystem: str

    def is_abandoned(self, threshold_days: int = 540) -> bool:
        if not self.latest_release:
            return False
        return (datetime.utcnow() - self.latest_release).days > threshold_days

    def has_suspicious_churn(self) -> bool:
        return self.releases_last_30d >= 5

    def churn_band(self) -> str:
        if self.releases_last_30d >= 10:
            return "high"
        if self.releases_last_30d >= 5:
            return "medium"
        return "normal"

    def maintainer_count(self) -> int:
        unique = set()
        for maintainer in self.maintainers:
            if not isinstance(maintainer, str):
                continue
            cleaned = maintainer.strip()
            if cleaned:
                unique.add(cleaned.lower())
        return len(unique)

    def has_maintainers(self) -> bool:
        return self.maintainer_count() > 0

    def is_low_maturity(self, minimum_releases: int = 3) -> bool:
        if minimum_releases <= 0:
            return False
        return self.total_releases < minimum_releases

    def days_since_latest(self, *, now: Optional[datetime] = None) -> Optional[int]:
        if not self.latest_release:
            return None
        reference = now or datetime.utcnow()
        delta = reference - self.latest_release
        return max(delta.days, 0)


class MetadataClient:
    def __init__(self, *, timeout: float = config.HTTP_TIMEOUT, retries: int = config.HTTP_RETRIES) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, headers={"User-Agent": config.USER_AGENT})
        self._retry = AsyncRetry(retries=retries, delay=0.5, exceptions=(httpx.HTTPError,))
        self._cache: Dict[str, ReleaseMetadata] = {}
        self._inflight: Dict[str, asyncio.Task[ReleaseMetadata]] = {}
        self._lock = asyncio.Lock()
        self._fetchers: Dict[str, Callable[[Dependency], Awaitable[ReleaseMetadata]]] = {
            "pypi": self._fetch_pypi,
            "npm": self._fetch_npm,
            "crates": self._fetch_crates,
            "go": self._fetch_gomod,
            "rubygems": self._fetch_rubygems,
            "maven": self._fetch_maven,
            "nuget": self._fetch_nuget,
            "packagist": self._fetch_packagist,
        }

    async def __aenter__(self) -> "MetadataClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

    async def clear_cache(self, *, cancel_inflight: bool = False) -> None:
        async with self._lock:
            if cancel_inflight:
                for task in self._inflight.values():
                    task.cancel()
            self._cache.clear()
            self._inflight.clear()

    async def fetch(self, dependency: Dependency) -> ReleaseMetadata:
        key = dependency.coordinate
        async with self._lock:
            cached = self._cache.get(key)
            if cached is not None:
                return cached
            inflight = self._inflight.get(key)
            if inflight is None:
                inflight = asyncio.create_task(self._fetch_uncached(dependency))
                self._inflight[key] = inflight
        try:
            result = await inflight
        except Exception:
            async with self._lock:
                self._inflight.pop(key, None)
            raise
        async with self._lock:
            self._cache[key] = result
            self._inflight.pop(key, None)
        return result

    async def _fetch_uncached(self, dependency: Dependency) -> ReleaseMetadata:
        fetcher = self._fetchers.get(dependency.ecosystem)
        if fetcher is not None:
            return await self._retry(lambda fetch=fetcher: fetch(dependency))
        return ReleaseMetadata(latest_release=None, releases_last_30d=0, total_releases=0, maintainers=[], ecosystem=dependency.ecosystem)

    async def _fetch_pypi(self, dependency: Dependency) -> ReleaseMetadata:
        url = f"https://pypi.org/pypi/{dependency.name}/json"
        response = await self._client.get(url)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        data = response.json()
        releases = data.get("releases", {})
        last_release = None
        releases_last_30d = 0
        now = datetime.utcnow()
        total = 0
        for version, files in releases.items():
            if not files:
                continue
            total += 1
            upload_time = None
            if isinstance(files, list):
                for file_meta in files:
                    if not isinstance(file_meta, dict):
                        continue
                    timestamp = file_meta.get("upload_time_iso_8601") or file_meta.get("upload_time")
                    parsed = _parse_date(timestamp if isinstance(timestamp, str) else None)
                    if parsed is not None and (upload_time is None or parsed > upload_time):
                        upload_time = parsed
            if upload_time and (not last_release or upload_time > last_release):
                last_release = upload_time
            if upload_time and (now - upload_time).days <= 30:
                releases_last_30d += 1
        maintainers = [user.get("username") for user in data.get("info", {}).get("maintainers", []) if isinstance(user, dict) and user.get("username")]
        if not maintainers:
            maintainers = [data.get("info", {}).get("author"), data.get("info", {}).get("maintainer")]  # type: ignore[list-item]
        maintainers = [m for m in maintainers if isinstance(m, str) and m]
        return ReleaseMetadata(last_release, releases_last_30d, total, maintainers, dependency.ecosystem)

    async def _fetch_npm(self, dependency: Dependency) -> ReleaseMetadata:
        url = f"https://registry.npmjs.org/{dependency.name}"
        response = await self._client.get(url)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        data = response.json()
        time_entries = data.get("time", {})
        maintainers = [m.get("name") for m in data.get("maintainers", []) if isinstance(m, dict) and m.get("name")]
        last_release = _parse_date(time_entries.get(dependency.version)) if isinstance(time_entries, dict) else None
        now = datetime.utcnow()
        releases_last_30d = 0
        total = 0
        if isinstance(time_entries, dict):
            for key, value in time_entries.items():
                if key in {"created", "modified"}:
                    continue
                release_time = _parse_date(value)
                if release_time:
                    total += 1
                    if now - release_time <= timedelta(days=30):
                        releases_last_30d += 1
                    if not last_release or release_time > last_release:
                        last_release = release_time
        return ReleaseMetadata(last_release, releases_last_30d, total, maintainers, dependency.ecosystem)

    async def _fetch_crates(self, dependency: Dependency) -> ReleaseMetadata:
        url = f"https://crates.io/api/v1/crates/{dependency.name}"
        response = await self._client.get(url)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        data = response.json()
        crate = data.get("crate", {})
        versions = data.get("versions", []) or []
        last_release = _parse_date(crate.get("updated_at"))
        now = datetime.utcnow()
        releases_last_30d = 0
        total = len(versions)
        for version in versions:
            created = _parse_date(version.get("created_at"))
            if created and now - created <= timedelta(days=30):
                releases_last_30d += 1
            if created and (not last_release or created > last_release):
                last_release = created
        maintainers = [team.get("login") for team in data.get("teams", []) if isinstance(team, dict) and team.get("login")]
        return ReleaseMetadata(last_release, releases_last_30d, total, maintainers, dependency.ecosystem)

    async def _fetch_gomod(self, dependency: Dependency) -> ReleaseMetadata:
        module = dependency.name
        url = f"https://proxy.golang.org/{module}/@v/list"
        response = await self._client.get(url)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        versions = [line.strip() for line in response.text.splitlines() if line.strip()]
        total = len(versions)
        last_release = None
        releases_last_30d = 0
        now = datetime.utcnow()
        for version in versions[-10:]:
            info_resp = await self._client.get(f"https://proxy.golang.org/{module}/@v/{version}.info")
            if info_resp.status_code != 200:
                continue
            info = info_resp.json()
            released = _parse_date(info.get("Time"))
            if released:
                if not last_release or released > last_release:
                    last_release = released
                if now - released <= timedelta(days=30):
                    releases_last_30d += 1
        return ReleaseMetadata(last_release, releases_last_30d, total, [], dependency.ecosystem)

    async def _fetch_rubygems(self, dependency: Dependency) -> ReleaseMetadata:
        name = dependency.name
        versions_url = f"https://rubygems.org/api/v1/versions/{name}.json"
        response = await self._client.get(versions_url)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        entries = response.json()
        if not isinstance(entries, list):
            entries = []
        now = datetime.utcnow()
        latest = None
        releases_last_30d = 0
        total = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            created = _parse_date(entry.get("created_at") or entry.get("built_at"))
            if not created:
                continue
            total += 1
            if not latest or created > latest:
                latest = created
            if now - created <= timedelta(days=30):
                releases_last_30d += 1

        maintainers: list[str] = []
        gem_url = f"https://rubygems.org/api/v1/gems/{name}.json"
        detail_response = await self._client.get(gem_url)
        if detail_response.status_code == 200:
            details = detail_response.json()
            authors = details.get("authors")
            if isinstance(authors, str):
                maintainers = [author.strip() for author in authors.split(",") if author.strip()]

        return ReleaseMetadata(latest, releases_last_30d, total, maintainers, dependency.ecosystem)

    async def _fetch_maven(self, dependency: Dependency) -> ReleaseMetadata:
        if ":" not in dependency.name:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        group, artifact = dependency.name.split(":", 1)
        params = {
            "q": f'g:"{group}" AND a:"{artifact}"',
            "core": "gav",
            "rows": 50,
            "wt": "json",
            "sort": "timestamp desc",
        }
        response = await self._client.get("https://search.maven.org/solrsearch/select", params=params)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        payload = response.json()
        docs = payload.get("response", {}).get("docs", [])
        if not isinstance(docs, list):
            docs = []
        now = datetime.utcnow()
        latest = None
        releases_last_30d = 0
        total = 0
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            timestamp = doc.get("timestamp")
            created: datetime | None
            if isinstance(timestamp, (int, float)):
                created = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc).replace(tzinfo=None)
            elif isinstance(timestamp, str):
                created = _parse_date(timestamp)
            else:
                created = None
            if not created:
                continue
            total += 1
            if not latest or created > latest:
                latest = created
            if now - created <= timedelta(days=30):
                releases_last_30d += 1

        if total == 0:
            total = int(payload.get("response", {}).get("numFound", 0))

        return ReleaseMetadata(latest, releases_last_30d, total, [], dependency.ecosystem)

    async def _fetch_nuget(self, dependency: Dependency) -> ReleaseMetadata:
        package_id = dependency.name.lower()
        url = f"https://api.nuget.org/v3/registration5-semver1/{package_id}/index.json"
        response = await self._client.get(url)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        data = response.json()
        items = data.get("items", []) if isinstance(data, dict) else []
        now = datetime.utcnow()
        latest = None
        releases_last_30d = 0
        total = 0
        maintainers: list[str] = []
        for page in items:
            entries = page.get("items") if isinstance(page, dict) else None
            if not isinstance(entries, list):
                continue
            for entry in entries:
                catalog = entry.get("catalogEntry") if isinstance(entry, dict) else None
                if not isinstance(catalog, dict):
                    continue
                published = _parse_date(catalog.get("published"))
                if not published:
                    continue
                total += 1
                if not latest or published > latest:
                    latest = published
                if now - published <= timedelta(days=30):
                    releases_last_30d += 1
                authors = catalog.get("authors")
                if isinstance(authors, str):
                    maintainers.extend(author.strip() for author in authors.split(",") if author.strip())
        maintainers = sorted({name for name in maintainers if name})
        return ReleaseMetadata(latest, releases_last_30d, total, maintainers, dependency.ecosystem)

    async def _fetch_packagist(self, dependency: Dependency) -> ReleaseMetadata:
        if "/" not in dependency.name:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        vendor, package = dependency.name.split("/", 1)
        url = f"https://repo.packagist.org/packages/{vendor}/{package}.json"
        response = await self._client.get(url)
        if response.status_code == 404:
            return ReleaseMetadata(None, 0, 0, [], dependency.ecosystem)
        response.raise_for_status()
        payload = response.json()
        packages = payload.get("package", {}).get("versions", {})
        if not isinstance(packages, dict):
            packages = {}
        now = datetime.utcnow()
        latest = None
        releases_last_30d = 0
        total = 0
        maintainers: list[str] = []
        for version_data in packages.values():
            if not isinstance(version_data, dict):
                continue
            time_value = version_data.get("time")
            published = _parse_date(time_value) if isinstance(time_value, str) else None
            if published:
                total += 1
                if not latest or published > latest:
                    latest = published
                if now - published <= timedelta(days=30):
                    releases_last_30d += 1
            authors = version_data.get("authors")
            if isinstance(authors, list):
                for author in authors:
                    if isinstance(author, dict):
                        name = author.get("name") or author.get("homepage")
                        if isinstance(name, str) and name:
                            maintainers.append(name)
        maintainers = sorted({name for name in maintainers if name})
        return ReleaseMetadata(latest, releases_last_30d, total, maintainers, dependency.ecosystem)

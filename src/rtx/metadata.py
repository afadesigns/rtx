from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

import httpx

from rtx import config
from rtx.models import Dependency
from rtx.utils import AsyncRetry

ISO_FORMATS = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"]


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _parse_date(value: str | None) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ISO_FORMATS:
        try:
            return _normalize_datetime(datetime.strptime(value, fmt))
        except ValueError:
            continue
    try:
        return _normalize_datetime(datetime.fromisoformat(value))
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


class MetadataClient:
    def __init__(self, *, timeout: float = config.HTTP_TIMEOUT, retries: int = config.HTTP_RETRIES) -> None:
        self._client = httpx.AsyncClient(timeout=timeout, headers={"User-Agent": config.USER_AGENT})
        self._retry = AsyncRetry(retries=retries, delay=0.5)
        self._cache: Dict[str, ReleaseMetadata] = {}
        self._inflight: Dict[str, asyncio.Task[ReleaseMetadata]] = {}
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> "MetadataClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.aclose()

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
        if dependency.ecosystem == "pypi":
            return await self._retry(lambda: self._fetch_pypi(dependency))
        if dependency.ecosystem == "npm":
            return await self._retry(lambda: self._fetch_npm(dependency))
        if dependency.ecosystem == "crates":
            return await self._retry(lambda: self._fetch_crates(dependency))
        if dependency.ecosystem == "go":
            return await self._retry(lambda: self._fetch_gomod(dependency))
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
            upload_time = _parse_date(files[-1].get("upload_time_iso_8601")) if isinstance(files, list) else None
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

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from rtx.models import Dependency

from rtx.metadata import _parse_date, _dedupe_names, ReleaseMetadata, MetadataClient

from rtx.utils import utc_now





class TestMetadataClient:

    async def test_context_management(self) -> None:

        async with MetadataClient() as client:

            assert not client._client.is_closed

        assert client._client.is_closed



    async def test_clear_cache(self) -> None:

        client = MetadataClient()

        client._cache["key"] = ReleaseMetadata(None, 0, 0, [], "")

        await client.clear_cache()

        assert not client._cache



    async def test_fetch_caching(self) -> None:



            client = MetadataClient()



            dependency = Dependency("pypi", "name", "1.0", True, "manifest")



            key = client._cache_key(dependency)



            metadata = ReleaseMetadata(None, 0, 0, [], "pypi")



            client._cache[key] = metadata



            assert await client.fetch(dependency) is metadata









class TestReleaseMetadata:

    def test_is_abandoned(self) -> None:

        now = utc_now()

        assert not ReleaseMetadata(None, 0, 0, [], "").is_abandoned()

        assert ReleaseMetadata(now - timedelta(days=539), 0, 0, [], "").is_abandoned(540) is False

        assert ReleaseMetadata(now - timedelta(days=541), 0, 0, [], "").is_abandoned(540) is True





    def test_has_suspicious_churn(self) -> None:

        assert ReleaseMetadata(None, 4, 0, [], "").has_suspicious_churn() is False

        assert ReleaseMetadata(None, 5, 0, [], "").has_suspicious_churn() is True



    def test_churn_band(self) -> None:

        assert ReleaseMetadata(None, 0, 0, [], "").churn_band() == "normal"

        assert ReleaseMetadata(None, 5, 0, [], "").churn_band() == "medium"

        assert ReleaseMetadata(None, 10, 0, [], "").churn_band() == "high"



    def test_maintainer_count(self) -> None:

        assert ReleaseMetadata(None, 0, 0, ["a", "b", " a "], "").maintainer_count() == 2

        assert ReleaseMetadata(None, 0, 0, [1, None], "").maintainer_count() == 0



    def test_has_maintainers(self) -> None:

        assert ReleaseMetadata(None, 0, 0, [], "").has_maintainers() is False

        assert ReleaseMetadata(None, 0, 0, ["a"], "").has_maintainers() is True



    def test_is_low_maturity(self) -> None:

        assert ReleaseMetadata(None, 0, 2, [], "").is_low_maturity(3) is True

        assert ReleaseMetadata(None, 0, 3, [], "").is_low_maturity(3) is False

        assert ReleaseMetadata(None, 0, 0, [], "").is_low_maturity(0) is False



    def test_days_since_latest(self) -> None:

        now = utc_now()

        assert ReleaseMetadata(None, 0, 0, [], "").days_since_latest() is None

        assert ReleaseMetadata(now - timedelta(days=10), 0, 0, [], "").days_since_latest(now=now) == 10

        assert ReleaseMetadata(now + timedelta(days=10), 0, 0, [], "").days_since_latest(now=now) == 0





@pytest.mark.parametrize(

    ("candidates", "expected"),

    [

        ([], []),

        ([None, " a ", "b", " A "], ["a", "b"]),

        (["c", "b", "a"], ["c", "b", "a"]),

    ],

)

def test_dedupe_names(candidates: list[str | None], expected: list[str]) -> None:

    assert _dedupe_names(candidates) == expected







@pytest.mark.parametrize(

    ("value", "expected"),

    [

        (None, None),

        ("", None),

        ("   ", None),

        ("2023-01-01T12:34:56.123456+00:00", datetime(2023, 1, 1, 12, 34, 56, 123456)),

        ("2023-01-01T12:34:56Z", datetime(2023, 1, 1, 12, 34, 56)),

        ("2023-01-01", datetime(2023, 1, 1)),

        ("invalid-date", None),

    ],

)

def test_parse_date(value: str | None, expected: datetime | None) -> None:

    assert _parse_date(value) == expected

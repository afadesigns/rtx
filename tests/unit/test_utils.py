from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest

from rtx.scanners import common
from rtx.utils import AsyncRetry, Graph, chunked, env_flag, has_matching_file, slugify


def test_normalize_version_handles_semver() -> None:
    assert common.normalize_version("1.0.0") == "1.0.0"
    assert common.normalize_version("01.02.000") == "1.2.0"
    assert common.normalize_version("invalid") == "invalid"


def test_slugify() -> None:
    assert slugify("Real Tracker X") == "real-tracker-x"


def test_graph_adds_nodes_and_edges(tmp_path: Path) -> None:
    graph = Graph()
    graph.add_node("pypi:demo@1.0.0", {"direct": True})
    graph.add_node("npm:demo@2.0.0", {"direct": False})
    graph.add_edge("pypi:demo@1.0.0", "npm:demo@2.0.0")
    assert len(graph) == 2
    assert graph.edge_count() == 1


def test_graph_add_node_merges_metadata() -> None:
    graph = Graph()
    graph.add_node("pkg", {"direct": True})
    graph.add_node("pkg", {"ecosystem": "pypi"})
    assert graph.to_dict()["nodes"]["pkg"] == {"direct": True, "ecosystem": "pypi"}


def test_graph_dependencies_of_returns_copy() -> None:
    graph = Graph()
    graph.add_edge("root", "child")
    deps = graph.dependencies_of("root")
    deps.append("other")
    assert graph.dependencies_of("root") == ["child"]


def test_chunked_rejects_non_positive_size() -> None:
    with pytest.raises(ValueError):
        list(chunked([1, 2, 3], 0))
    with pytest.raises(ValueError):
        list(chunked([1, 2, 3], -2))


def test_chunked_supports_iterables() -> None:
    def generator() -> Iterator[int]:
        for value in range(5):
            yield value

    chunks = list(chunked(generator(), 2))
    assert chunks == [[0, 1], [2, 3], [4]]


@pytest.mark.asyncio
async def test_async_retry_respects_cancelled_error() -> None:
    retry = AsyncRetry(retries=2, delay=0.01)

    async def task() -> int:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await retry(task)


@pytest.mark.asyncio
async def test_async_retry_honors_custom_exceptions() -> None:
    attempts = 0
    retry = AsyncRetry(retries=2, delay=0.0, exceptions=(RuntimeError,))

    async def task() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise RuntimeError("boom")
        return "done"

    assert await retry(task) == "done"
    assert attempts == 2


@pytest.mark.asyncio
async def test_async_retry_propagates_unhandled_exception() -> None:
    retry = AsyncRetry(retries=2, delay=0.0, exceptions=(RuntimeError,))

    async def task() -> None:
        raise ValueError("no retry")

    with pytest.raises(ValueError):
        await retry(task)


def test_env_flag_strips_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RTX_TEST_FLAG", "  TrUe  ")
    assert env_flag("RTX_TEST_FLAG") is True
    monkeypatch.setenv("RTX_TEST_FLAG", " 0 ")
    assert env_flag("RTX_TEST_FLAG", default=True) is False


def test_graph_to_dict_returns_copies() -> None:
    graph = Graph()
    graph.add_node("pkg", {"direct": True})
    graph.add_edge("pkg", "child")
    exported = graph.to_dict()
    exported["nodes"]["pkg"]["direct"] = False
    exported["edges"]["pkg"].append("other")
    fresh = graph.to_dict()
    assert fresh["nodes"]["pkg"]["direct"] is True
    assert fresh["edges"]["pkg"] == ["child"]


def test_has_matching_file_handles_literal_path(tmp_path: Path) -> None:
    target = tmp_path / "package.json"
    target.write_text("{}", encoding="utf-8")
    assert has_matching_file(tmp_path, ["package.json"]) is True
    assert has_matching_file(tmp_path, ["missing.json"]) is False


def test_has_matching_file_handles_glob_patterns(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "requirements.txt").write_text("requests==2.31.0", encoding="utf-8")
    assert has_matching_file(tmp_path, ["nested/*.txt"]) is True
    assert has_matching_file(tmp_path, ["*.lock"]) is False

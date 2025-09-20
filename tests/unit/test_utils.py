from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest

from rtx.scanners import common
from rtx.utils import (
    AsyncRetry,
    Graph,
    chunked,
    env_flag,
    has_matching_file,
    slugify,
    unique_preserving_order,
)


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
        yield from range(5)

    chunks = list(chunked(generator(), 2))
    assert chunks == [[0, 1], [2, 3], [4]]


def test_unique_preserving_order_respects_key() -> None:
    values = ["Alpha", "beta", "ALPHA", "Beta", "gamma"]
    assert unique_preserving_order(values) == [
        "Alpha",
        "beta",
        "ALPHA",
        "Beta",
        "gamma",
    ]
    assert unique_preserving_order(values, key=str.lower) == ["Alpha", "beta", "gamma"]


def test_parse_requirement_lines_prefers_specific_specifiers() -> None:
    lines = [
        "requests",
        "requests>=2.0",
        "requests==2.31.0",
        "requests @ git+https://example.com/pkg.git",
    ]
    result = common._parse_requirement_lines(lines)
    assert result["requests"].startswith("@")


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


def test_read_uv_lock_extracts_direct_dependencies(tmp_path: Path) -> None:
    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
version = 1
requires-python = ">=3.13"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "httpx" },
    { name = "rich" },
]

[[package]]
name = "httpx"
version = "0.27.2"

[[package]]
name = "rich"
version = "13.7.1"
""",
        encoding="utf-8",
    )

    result = common.read_uv_lock(uv_lock)
    assert result == {"httpx": "0.27.2", "rich": "13.7.1"}


def test_read_pnpm_lock_prefers_importers(tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        """
lockfileVersion: '9.0'

importers:
  app:
    dependencies:
      react:
        specifier: ^19.0.0
        version: 19.1.1(@types/react@19.1.13)
      '@scope/pkg':
        specifier: ^1.0.0
        version: 1.2.3(peer@1.0.0)
    devDependencies:
      typescript:
        specifier: ^5.2.0
        version: 5.3.2

packages:
  '/react@19.1.1':
    resolution: {integrity: sha512-example}
  '/@scope/pkg@1.2.3':
    resolution: {integrity: sha512-example}
  'typescript@5.3.2':
    resolution: {integrity: sha512-example}
""",
        encoding="utf-8",
    )

    result = common.read_pnpm_lock(pnpm_lock)
    assert result == {"react": "19.1.1", "@scope/pkg": "1.2.3", "typescript": "5.3.2"}


def test_read_pnpm_lock_falls_back_to_packages(tmp_path: Path) -> None:
    pnpm_lock = tmp_path / "pnpm-lock.yaml"
    pnpm_lock.write_text(
        """
lockfileVersion: '9.0'

packages:
  '@scope/other@2.0.0':
    resolution: {integrity: sha512-example}
  'react@18.2.0':
    resolution: {integrity: sha512-example}
""",
        encoding="utf-8",
    )

    result = common.read_pnpm_lock(pnpm_lock)
    assert result == {"@scope/other": "2.0.0", "react": "18.2.0"}


def test_merge_dependency_version_prefers_specific_specifiers() -> None:
    store: dict[str, str] = {}
    assert common.merge_dependency_version(store, "pkg", "*") is True
    assert store["pkg"] == "*"
    assert common.merge_dependency_version(store, "pkg", "==1.0.0") is True
    assert store["pkg"] == "==1.0.0"
    assert common.merge_dependency_version(store, "pkg", ">=0.9.0") is False
    assert store["pkg"] == "==1.0.0"


def test_read_requirements_follows_include_directives(tmp_path: Path) -> None:
    root = tmp_path / "reqs"
    root.mkdir()
    (root / "requirements.txt").write_text(
        """
        requests==2.31.0
        -r extras.txt
        """,
        encoding="utf-8",
    )
    (root / "extras.txt").write_text("rich>=13.0.0", encoding="utf-8")

    result = common.read_requirements(root / "requirements.txt")

    assert result["requests"] == "2.31.0"
    assert result["rich"] == ">=13.0.0"

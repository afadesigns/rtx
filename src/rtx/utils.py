from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import textwrap
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable, Sequence
from functools import cache
from hashlib import sha256
from pathlib import Path
from typing import Any, TypeGuard, TypeVar

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python <3.11
    import tomli as tomllib

import yaml

T = TypeVar("T")

if sys.version_info >= (3, 12):  # Python 3.12+
    from itertools import batched
else:  # pragma: no cover - fallback for Python <3.12
    from itertools import islice as _islice

    def batched(iterable: Iterable[T], size: int) -> Iterable[tuple[T, ...]]:
        if size <= 0:
            raise ValueError("batch size must be positive")
        iterator = iter(iterable)
        while True:
            chunk = tuple(_islice(iterator, size))
            if not chunk:
                break
            yield chunk


class AsyncRetry:
    def __init__(
        self,
        retries: int,
        delay: float,
        *,
        exceptions: tuple[type[Exception], ...] = (Exception,),
    ) -> None:
        self.retries = retries
        self.delay = delay
        self._exceptions = exceptions

    async def __call__(self, task: Callable[[], Awaitable[T]]) -> T:
        attempt = 0
        while True:
            try:
                return await task()
            except asyncio.CancelledError:
                raise
            except self._exceptions:
                attempt += 1
                if attempt > self.retries:
                    raise
                await asyncio.sleep(self.delay * attempt)


def sha256_digest(content: bytes) -> str:
    return sha256(content).hexdigest()


def safe_json_loads(content: str) -> Any:
    return json.loads(content)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - logged by caller
        raise ValueError(f"Invalid JSON in {path}") from exc


def read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover
        raise ValueError(f"Invalid YAML in {path}") from exc


def read_toml(path: Path) -> Any:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, ValueError) as exc:  # pragma: no cover
        raise ValueError(f"Invalid TOML in {path}") from exc


def detect_files(root: Path, patterns: Sequence[str]) -> list[Path]:
    matches: list[Path] = []
    for pattern in patterns:
        if any(char in pattern for char in "*?["):
            matches.extend(root.glob(pattern))
        else:
            candidate = root / pattern
            if candidate.exists():
                matches.append(candidate)
    return sorted(set(matches))


def has_matching_file(root: Path, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        if any(char in pattern for char in "*?["):
            iterator = root.glob(pattern)
            try:
                next(iterator)
                return True
            except StopIteration:
                continue
        else:
            if (root / pattern).exists():
                return True
    return False


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def chunked(iterable: Iterable[T], size: int) -> Iterable[list[T]]:
    if size <= 0:
        raise ValueError("chunk size must be positive")
    for chunk in batched(iterable, size):
        yield list(chunk)


def multiline(text: str) -> str:
    return textwrap.dedent(text).strip()


def unique_preserving_order(
    values: Iterable[T],
    *,
    key: Callable[[T], Any] | None = None,
) -> list[T]:
    seen: dict[Any, None] = {}
    output: list[T] = []
    for value in values:
        marker = key(value) if key else value
        if marker in seen:
            continue
        seen[marker] = None
        output.append(value)
    return output


def is_non_string_sequence(value: object) -> TypeGuard[Sequence[object]]:
    """Return True when ``value`` is a non-string/bytes sequence."""

    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


@cache
def load_json_resource(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@cache
def load_yaml_resource(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Graph:
    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[str, set[str]] = defaultdict(set)
        self._edge_count = 0

    def add_node(self, key: str, metadata: dict[str, Any]) -> None:
        node = self._nodes.setdefault(key, {})
        node.update(metadata)

    def add_edge(self, src: str, dest: str) -> None:
        edges = self._edges[src]
        if dest not in edges:
            edges.add(dest)
            self._edge_count += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {key: dict(value) for key, value in self._nodes.items()},
            "edges": {
                key: sorted(values)
                for key, values in self._edges.items()
                if values
            },
        }

    def dependencies_of(self, key: str) -> list[str]:
        return sorted(self._edges.get(key, set()))

    def __len__(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return self._edge_count

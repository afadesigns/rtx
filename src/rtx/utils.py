from __future__ import annotations

import asyncio
import json
import os
import re
import textwrap
from collections import defaultdict
from functools import lru_cache
from hashlib import sha256
from itertools import islice
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Sequence, Tuple, TypeVar

import yaml

T = TypeVar("T")


class AsyncRetry:
    def __init__(self, retries: int, delay: float, *, exceptions: tuple[type[Exception], ...] = (Exception,)) -> None:
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
        import tomllib  # type: ignore[attr-defined]
    except ModuleNotFoundError:  # pragma: no cover - Python <3.11
        import tomli as tomllib  # type: ignore[no-redef]

    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, ValueError) as exc:  # pragma: no cover
        raise ValueError(f"Invalid TOML in {path}") from exc


def detect_files(root: Path, patterns: Sequence[str]) -> List[Path]:
    matches: List[Path] = []
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


def chunked(iterable: Iterable[T], size: int) -> Iterable[List[T]]:
    if size <= 0:
        raise ValueError("chunk size must be positive")
    if isinstance(iterable, Sequence):
        for i in range(0, len(iterable), size):
            chunk = iterable[i : i + size]
            if chunk:
                yield list(chunk)
        return
    iterator = iter(iterable)
    while True:
        chunk = list(islice(iterator, size))
        if not chunk:
            break
        yield chunk


def multiline(text: str) -> str:
    return textwrap.dedent(text).strip()


@lru_cache(maxsize=None)
def load_json_resource(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def load_yaml_resource(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class Graph:
    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[str, List[str]] = defaultdict(list)

    def add_node(self, key: str, metadata: Dict[str, Any]) -> None:
        node = self._nodes.setdefault(key, {})
        node.update(metadata)

    def add_edge(self, src: str, dest: str) -> None:
        if dest not in self._edges[src]:
            self._edges[src].append(dest)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {key: dict(value) for key, value in self._nodes.items()},
            "edges": {key: list(values) for key, values in self._edges.items()},
        }

    def dependencies_of(self, key: str) -> List[str]:
        return list(self._edges.get(key, []))

    def __len__(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._edges.values())

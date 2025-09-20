from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


def test_requires_python_range() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    requires = data["project"]["requires-python"]
    assert requires == ">=3.10"


def test_classifiers_cover_supported_versions() -> None:
    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    classifiers: list[str] = data["project"]["classifiers"]
    for version in ("3.10", "3.11", "3.12", "3.13", "3.14"):
        assert f"Programming Language :: Python :: {version}" in classifiers

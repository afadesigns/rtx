from __future__ import annotations

import os
from pathlib import Path

from rtx import __version__

DATA_DIR = Path(__file__).parent / "data"
CACHE_DIR = Path.home() / ".cache" / "rtx"
USER_AGENT = f"rtx/{__version__} (+https://github.com/afadesigns/rtx)"


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(1, value)


def _non_negative_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 0 else default


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


POLICY_ANALYSIS_CONCURRENCY = _int_env("RTX_POLICY_CONCURRENCY", 16)
HTTP_TIMEOUT = _float_env("RTX_HTTP_TIMEOUT", 5.0)
HTTP_RETRIES = _non_negative_int_env("RTX_HTTP_RETRIES", 2)
OSV_BATCH_SIZE = _int_env("RTX_OSV_BATCH_SIZE", 18)
OSV_MAX_CONCURRENCY = _int_env("RTX_OSV_MAX_CONCURRENCY", 4)
OSV_CACHE_SIZE = _non_negative_int_env("RTX_OSV_CACHE_SIZE", 512)
GITHUB_MAX_CONCURRENCY = _int_env("RTX_GITHUB_MAX_CONCURRENCY", 6)

OSV_API_URL = "https://api.osv.dev/v1/querybatch"
GITHUB_ADVISORY_URL = "https://api.github.com/graphql"
GITHUB_DEFAULT_TOKEN_ENV = os.getenv("RTX_GITHUB_DEFAULT_TOKEN_ENV", "GITHUB_TOKEN")

SUPPORTED_MANAGERS: dict[str, dict[str, list[str]]] = {
    "npm": {
        "manifests": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "ecosystem": ["npm"],
    },
    "pypi": {
        "manifests": [
            "pyproject.toml",
            "poetry.lock",
            "requirements.txt",
            "requirements.in",
            "constraints.txt",
            "Pipfile",
            "Pipfile.lock",
            "uv.lock",
            "uv.toml",
        ],
        "ecosystem": ["pypi"],
    },
    "maven": {
        "manifests": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "ecosystem": ["maven"],
    },
    "cargo": {
        "manifests": ["Cargo.toml", "Cargo.lock"],
        "ecosystem": ["crates"],
    },
    "go": {
        "manifests": ["go.mod", "go.sum"],
        "ecosystem": ["go"],
    },
    "composer": {
        "manifests": ["composer.json", "composer.lock"],
        "ecosystem": ["packagist"],
    },
    "nuget": {
        "manifests": ["packages.lock.json", "*.csproj", "*.fsproj"],
        "ecosystem": ["nuget"],
    },
    "rubygems": {
        "manifests": ["Gemfile", "Gemfile.lock"],
        "ecosystem": ["rubygems"],
    },
    "brew": {
        "manifests": ["Brewfile"],
        "ecosystem": ["homebrew"],
    },
    "conda": {
        "manifests": ["environment.yml", "environment.yaml"],
        "ecosystem": ["conda"],
    },
    "docker": {
        "manifests": ["Dockerfile"],
        "ecosystem": ["docker"],
    },
}

HTML_TEMPLATE = (DATA_DIR / "report.html.j2").read_text(encoding="utf-8")

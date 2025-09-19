from __future__ import annotations

from pathlib import Path
from typing import Dict, List

DATA_DIR = Path(__file__).parent / "data"
CACHE_DIR = Path.home() / ".cache" / "rtx"
HTTP_TIMEOUT = 5.0
HTTP_RETRIES = 2
USER_AGENT = "rtx/0.1.0 (+https://github.com/afadesigns/rtx)"

OSV_API_URL = "https://api.osv.dev/v1/querybatch"
GITHUB_ADVISORY_URL = "https://api.github.com/graphql"
GITHUB_DEFAULT_TOKEN_ENV = "GITHUB_TOKEN"

SUPPORTED_MANAGERS: Dict[str, Dict[str, List[str]]] = {
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

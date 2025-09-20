from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from rtx import __version__
from rtx.models import PackageFinding, Report

PURL_ECOSYSTEMS = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "crates": "cargo",
    "go": "golang",
    "packagist": "composer",
    "nuget": "nuget",
    "rubygems": "gem",
    "homebrew": "generic",
    "conda": "conda",
    "docker": "docker",
}


def _purl(finding: PackageFinding) -> str:
    ecosystem = PURL_ECOSYSTEMS.get(finding.dependency.ecosystem, "generic")
    if ecosystem == "maven" and ":" in finding.dependency.name:
        group, artifact = finding.dependency.name.split(":", 1)
        return f"pkg:maven/{group}/{artifact}@{finding.dependency.version}"
    return f"pkg:{ecosystem}/{finding.dependency.name}@{finding.dependency.version}"


def generate_sbom(report: Report) -> Dict[str, object]:
    components: List[Dict[str, object]] = []
    vulnerabilities: List[Dict[str, object]] = []
    for finding in report.findings:
        components.append(
            {
                "type": "library",
                "name": finding.dependency.name,
                "version": finding.dependency.version,
                "purl": _purl(finding),
                "scope": "required" if finding.dependency.direct else "optional",
                "licenses": _normalize_licenses(finding.dependency.metadata),
            }
        )
        for advisory in finding.advisories:
            vulnerabilities.append(
                {
                    "id": advisory.identifier,
                    "source": {
                        "name": advisory.source,
                    },
                    "ratings": [
                        {
                            "severity": advisory.severity.value,
                        }
                    ],
                    "affects": [
                        {
                            "ref": _purl(finding),
                        }
                    ],
                    "description": advisory.summary,
                    "references": [
                        {
                            "url": reference,
                        }
                        for reference in advisory.references
                    ],
                }
            )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "afadesigns",
                    "name": "Real Tracker X",
                    "version": __version__,
                }
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def write_sbom(report: Report, *, path: str | Path) -> None:
    payload = generate_sbom(report)
    sbom_path = Path(path)
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _normalize_licenses(metadata: dict[str, Any]) -> List[Dict[str, object]]:
    raw = metadata.get("license")
    entries: List[Dict[str, object]] = []
    if isinstance(raw, str):
        cleaned = raw.strip()
        if cleaned:
            entries.append({"license": {"id": cleaned}})
    elif isinstance(raw, dict):
        identifier = raw.get("id") or raw.get("name")
        if isinstance(identifier, str) and identifier.strip():
            entries.append({"license": {"id": identifier.strip()}})
        else:
            entries.append({"license": raw})
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            if isinstance(item, str) and item.strip():
                entries.append({"license": {"id": item.strip()}})
            elif isinstance(item, dict):
                identifier = item.get("id") or item.get("name")
                if isinstance(identifier, str) and identifier.strip():
                    entries.append({"license": {"id": identifier.strip()}})
                else:
                    entries.append({"license": item})

    if not entries:
        entries.append({"license": {"id": "UNKNOWN"}})
    return entries

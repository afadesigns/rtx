from __future__ import annotations

import json
from datetime import datetime
from typing import Dict, List

from rtx.models import PackageFinding, Report, Severity

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
                "licenses": [{"license": {"id": finding.dependency.metadata.get("license", "UNKNOWN")}}],
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
                    "version": "0.1.0",
                }
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def write_sbom(report: Report, *, path: str) -> None:
    payload = generate_sbom(report)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

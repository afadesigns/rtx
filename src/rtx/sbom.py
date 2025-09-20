from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from rtx import __version__
from rtx.models import PackageFinding, Report, SEVERITY_RANK
from rtx.utils import unique_preserving_order

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
    component_index: Dict[str, Dict[str, object]] = {}
    vulnerability_index: Dict[Tuple[str, str], Dict[str, object]] = {}

    for finding in report.findings:
        coordinate = finding.dependency.coordinate
        purl = _purl(finding)
        licenses = _normalize_licenses(finding.dependency.metadata)
        scope = "required" if finding.dependency.direct else "optional"

        component = component_index.get(coordinate)
        if component is None:
            component_index[coordinate] = {
                "type": "library",
                "name": finding.dependency.name,
                "version": finding.dependency.version,
                "purl": purl,
                "scope": scope,
                "licenses": licenses,
            }
        else:
            if component["scope"] != "required" and scope == "required":
                component["scope"] = "required"
            component["licenses"] = unique_preserving_order(
                component["licenses"] + licenses,
                key=_license_key,
            )

        for advisory in finding.advisories:
            key = (advisory.source, advisory.identifier)
            references = [
                {"url": ref.strip()}
                for ref in advisory.references
                if isinstance(ref, str) and ref.strip()
            ]
            affects_entry = {"ref": purl}
            entry = vulnerability_index.get(key)
            if entry is None:
                entry = {
                    "id": advisory.identifier,
                    "source": {"name": advisory.source},
                    "ratings": [{"severity": advisory.severity.value}],
                    "affects": [affects_entry],
                    "description": advisory.summary,
                    "references": references,
                }
                vulnerability_index[key] = entry
            else:
                rating = entry["ratings"][0]
                if SEVERITY_RANK[advisory.severity.value] > SEVERITY_RANK[rating["severity"]]:
                    rating["severity"] = advisory.severity.value
                if not entry.get("description") and advisory.summary:
                    entry["description"] = advisory.summary
                entry["affects"] = unique_preserving_order(
                    entry["affects"] + [affects_entry], key=lambda item: item["ref"]
                )
                entry["references"] = unique_preserving_order(
                    entry["references"] + references, key=lambda item: item["url"]
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
        "components": list(component_index.values()),
        "vulnerabilities": list(vulnerability_index.values()),
    }


def write_sbom(report: Report, *, path: str | Path) -> None:
    payload = generate_sbom(report)
    sbom_path = Path(path)
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def _normalize_licenses(metadata: dict[str, Any]) -> List[Dict[str, object]]:
    raw = metadata.get("license")
    entries: List[Dict[str, object]] = []

    def append_entry(value: Any) -> None:
        entry = _license_entry(value)
        if entry is not None:
            entries.append(entry)

    if isinstance(raw, str) or isinstance(raw, dict):
        append_entry(raw)
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            append_entry(item)
    elif raw is not None:
        append_entry(raw)

    if not entries:
        entries.append({"license": {"id": "UNKNOWN"}})
    return unique_preserving_order(entries, key=_license_key)


def _license_entry(value: Any) -> Dict[str, object] | None:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            return {"license": {"id": cleaned}}
        return None
    if isinstance(value, dict):
        identifier = value.get("id") or value.get("name")
        if isinstance(identifier, str) and identifier.strip():
            return {"license": {"id": identifier.strip()}}
        nested = value.get("license")
        if isinstance(nested, dict):
            return {"license": nested}
        return {"license": value}
    return None


def _license_key(entry: Dict[str, object]) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
    license_info = entry.get("license")
    if isinstance(license_info, dict):
        identifier = license_info.get("id") or license_info.get("name")
        if isinstance(identifier, str) and identifier.strip():
            return (identifier.strip(), tuple())
        normalized_items = tuple(sorted((str(k), str(v)) for k, v in license_info.items()))
        return ("dict", normalized_items)
    return ("raw", tuple(sorted((str(k), str(v)) for k, v in entry.items())))

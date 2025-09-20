from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TypedDict

from rtx import __version__
from rtx.models import SEVERITY_RANK, PackageFinding, Report
from rtx.utils import unique_preserving_order


class ComponentEntry(TypedDict):
    type: Literal["library"]
    name: str
    version: str
    purl: str
    scope: Literal["required", "optional"]
    licenses: list[dict[str, object]]


class VulnerabilityRating(TypedDict):
    severity: str


class VulnerabilityAffect(TypedDict):
    ref: str


class VulnerabilityReference(TypedDict):
    url: str


class VulnerabilityEntry(TypedDict, total=False):
    id: str
    source: dict[str, str]
    ratings: list[VulnerabilityRating]
    affects: list[VulnerabilityAffect]
    description: str
    references: list[VulnerabilityReference]


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


def generate_sbom(report: Report) -> dict[str, object]:
    component_index: dict[str, ComponentEntry] = {}
    vulnerability_index: dict[tuple[str, str], VulnerabilityEntry] = {}

    for finding in report.findings:
        coordinate = finding.dependency.coordinate
        purl = _purl(finding)
        licenses = _normalize_licenses(finding.dependency.metadata)
        scope: Literal["required", "optional"] = (
            "required" if finding.dependency.direct else "optional"
        )

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
            existing_licenses = component["licenses"]
            component["licenses"] = unique_preserving_order(
                existing_licenses + licenses,
                key=_license_key,
            )

        for advisory in finding.advisories:
            key = (advisory.source, advisory.identifier)
            references = _serialize_references(advisory.references)
            affects_entry: VulnerabilityAffect = {"ref": purl}
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
                if (
                    SEVERITY_RANK[advisory.severity.value]
                    > SEVERITY_RANK[rating["severity"]]
                ):
                    rating["severity"] = advisory.severity.value
                if not entry.get("description") and advisory.summary:
                    entry["description"] = advisory.summary
                affects = entry.get("affects", [])
                references_list = entry.get("references", [])
                entry["affects"] = unique_preserving_order(
                    affects + [affects_entry], key=lambda item: item["ref"]
                )
                entry["references"] = unique_preserving_order(
                    references_list + references, key=lambda item: item["url"]
                )

    components = [component_index[key] for key in sorted(component_index)]
    vulnerabilities = [vulnerability_index[key] for key in sorted(vulnerability_index)]
    for entry in vulnerabilities:
        affects = entry.get("affects", [])
        references_list = entry.get("references", [])
        entry["affects"] = sorted(affects, key=lambda item: item["ref"])
        entry["references"] = sorted(references_list, key=lambda item: item["url"])

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
    sbom_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def _normalize_licenses(metadata: dict[str, Any]) -> list[dict[str, object]]:
    raw = metadata.get("license")
    entries: list[dict[str, object]] = []

    def append_entry(value: Any) -> None:
        entry = _license_entry(value)
        if entry is not None:
            entries.append(entry)

    if isinstance(raw, str) or isinstance(raw, dict):
        append_entry(raw)
    elif isinstance(raw, Iterable):
        for item in raw:
            append_entry(item)
    elif raw is not None:
        append_entry(raw)

    if not entries:
        entries.append({"license": {"id": "UNKNOWN"}})
    return unique_preserving_order(entries, key=_license_key)


def _license_entry(value: Any) -> dict[str, object] | None:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            return {"license": {"id": cleaned}}
        return None
    if isinstance(value, Mapping):
        identifier = value.get("id") or value.get("name")
        if isinstance(identifier, str) and identifier.strip():
            return {"license": {"id": identifier.strip()}}
        nested = value.get("license")
        if isinstance(nested, Mapping):
            return {"license": nested}
        return {"license": value}
    return None


def _license_key(entry: dict[str, object]) -> tuple[str, tuple[tuple[str, str], ...]]:
    license_info = entry.get("license")
    if isinstance(license_info, Mapping):
        identifier = license_info.get("id") or license_info.get("name")
        if isinstance(identifier, str) and identifier.strip():
            return (identifier.strip(), tuple())
        normalized_items = tuple(
            sorted((str(k), str(v)) for k, v in license_info.items())
        )
        return ("dict", normalized_items)
    return ("raw", tuple(sorted((str(k), str(v)) for k, v in entry.items())))


def _serialize_references(
    raw_references: Iterable[str],
) -> list[VulnerabilityReference]:
    entries: list[VulnerabilityReference] = []
    for ref in raw_references:
        if not isinstance(ref, str):
            continue
        cleaned = ref.strip()
        if cleaned:
            entries.append({"url": cleaned})
    return entries

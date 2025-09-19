from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rtx import config
from rtx.advisory import AdvisoryClient
from rtx.exceptions import ManifestNotFound
from rtx.models import Dependency, PackageFinding, Report
from rtx.policy import TrustPolicyEngine
from rtx.registry import get_scanners
from rtx.utils import Graph


async def scan_project_async(path: Path, *, managers: Optional[List[str]] = None) -> Report:
    root = path.resolve()
    scanners = get_scanners(managers)
    discovered = []
    used_managers: List[str] = []
    for scanner in scanners:
        if managers is None and not scanner.matches(root):
            continue
        packages = scanner.scan(root)
        if packages:
            discovered.extend(packages)
            used_managers.append(scanner.manager)
    if not discovered:
        raise ManifestNotFound("No supported manifests found")

    unique_deps: Dict[str, Dependency] = {}
    for dep in discovered:
        existing = unique_deps.get(dep.coordinate)
        if existing is None:
            unique_deps[dep.coordinate] = dep
            continue
        combined_metadata = {**existing.metadata, **dep.metadata}
        manifest_values = {str(existing.manifest), str(dep.manifest)}
        previous_manifests = combined_metadata.get("manifests")
        if isinstance(previous_manifests, (list, tuple, set)):
            manifest_values.update(str(path) for path in previous_manifests)
        elif isinstance(previous_manifests, str):
            manifest_values.add(previous_manifests)
        combined_metadata["manifests"] = sorted(manifest_values)
        unique_deps[dep.coordinate] = Dependency(
            ecosystem=existing.ecosystem,
            name=existing.name,
            version=existing.version,
            direct=existing.direct or dep.direct,
            manifest=existing.manifest,
            metadata=combined_metadata,
        )
    dependencies = list(unique_deps.values())

    async with AdvisoryClient() as advisory_client:
        advisory_map = await advisory_client.fetch_advisories(dependencies)

    engine = TrustPolicyEngine()
    limit = max(1, getattr(config, "POLICY_ANALYSIS_CONCURRENCY", 1))
    semaphore = asyncio.Semaphore(limit)

    async def analyze_with_limit(dep: Dependency) -> PackageFinding:
        async with semaphore:
            return await engine.analyze(dep, advisory_map.get(dep.coordinate, []))

    try:
        findings: List[PackageFinding] = list(
            await asyncio.gather(*(analyze_with_limit(dep) for dep in dependencies))
        )
    finally:
        await engine.close()

    graph = Graph()
    for finding in findings:
        graph.add_node(
            finding.dependency.coordinate,
            {
                "ecosystem": finding.dependency.ecosystem,
                "direct": finding.dependency.direct,
                "manifest": str(finding.dependency.manifest),
            },
        )

    report = Report(
        path=root,
        managers=sorted(set(used_managers or managers or [])),
        findings=sorted(findings, key=lambda f: f.dependency.coordinate),
        generated_at=datetime.utcnow(),
        stats={
            "dependency_count": len(findings),
            "graph_nodes": len(graph),
            "graph_edges": graph.edge_count(),
        },
    )
    return report


def scan_project(path: Path, managers: Optional[List[str]] = None) -> Report:
    return asyncio.run(scan_project_async(path, managers=managers))

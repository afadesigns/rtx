from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from rtx import config
from rtx.advisory import AdvisoryClient
from rtx.exceptions import ManifestNotFound
from rtx.models import PackageFinding, Report
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

    async with AdvisoryClient() as advisory_client:
        advisory_map = await advisory_client.fetch_advisories(discovered)

    engine = TrustPolicyEngine()
    try:
        findings: List[PackageFinding] = list(
            await asyncio.gather(
                *[
                    engine.analyze(dep, advisory_map.get(dep.coordinate, []))
                    for dep in discovered
                ]
            )
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

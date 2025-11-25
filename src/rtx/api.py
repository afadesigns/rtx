from __future__ import annotations

import asyncio
from collections import Counter
from collections.abc import Awaitable
from pathlib import Path
from typing import Any, cast

from rtx import config
from rtx.advisory import AdvisoryClient
from rtx.exceptions import ManifestNotFound
from rtx.models import Dependency, PackageFinding, Report, ScannerResult
from rtx.policy import TrustPolicyEngine
from rtx.registry import get_scanners
from rtx.utils import Graph, is_non_string_sequence, unique_preserving_order, utc_now


def _merge_dependency(existing: Dependency, new: Dependency) -> Dependency:
    combined_metadata = {**existing.metadata, **new.metadata}
    manifests: list[str] = [str(existing.manifest), str(new.manifest)]
    previous = combined_metadata.get("manifests")
    if is_non_string_sequence(previous):
        manifests.extend(str(value) for value in previous)
    elif isinstance(previous, str):
        manifests.append(previous)
    combined_metadata["manifests"] = unique_preserving_order(manifests)
    return Dependency(
        ecosystem=existing.ecosystem,
        name=existing.name,
        version=existing.version,
        direct=existing.direct or new.direct,
        manifest=existing.manifest,
        metadata=combined_metadata,
    )


async def scan_project_async(path: Path, *, managers: list[str] | None = None) -> Report:
    root = path.resolve()
    scanners = get_scanners(managers)
    discovered: list[Dependency] = []
    all_relationships: list[tuple[str, str]] = []
    used_managers: list[str] = []
    scan_jobs: list[tuple[str, Awaitable[ScannerResult]]] = []
    for scanner in scanners:
        if managers is None and not scanner.matches(root):
            continue
        scan_jobs.append((scanner.manager, asyncio.to_thread(scanner.scan, root)))

    if scan_jobs:
        results = await asyncio.gather(*(job for _, job in scan_jobs))
        for (manager, _), scanner_result in zip(scan_jobs, results):
            if scanner_result.dependencies:
                discovered.extend(scanner_result.dependencies)
                all_relationships.extend(scanner_result.relationships)
                used_managers.append(manager)
    if not discovered:
        raise ManifestNotFound("No supported manifests found")

    unique_deps: dict[str, Dependency] = {}
    for dep in discovered:
        existing = unique_deps.get(dep.coordinate)
        if existing is None:
            unique_deps[dep.coordinate] = dep
        else:
            unique_deps[dep.coordinate] = _merge_dependency(existing, dep)
    dependencies = list(unique_deps.values())

    async with AdvisoryClient() as advisory_client:
        advisory_map = await advisory_client.fetch_advisories(dependencies)

    limit = max(1, getattr(config, "POLICY_ANALYSIS_CONCURRENCY", 1))
    semaphore = asyncio.Semaphore(limit)
    findings_buffer: list[PackageFinding | None] = [None] * len(dependencies)

    async with TrustPolicyEngine() as engine:

        async def analyze_with_limit(index: int, dep: Dependency) -> None:
            async with semaphore:
                findings_buffer[index] = await engine.analyze(
                    dep, advisory_map.get(dep.coordinate, [])
                )

        task_group_cls = getattr(asyncio, "TaskGroup", None)
        if task_group_cls is not None:
            tg = cast(Any, task_group_cls())
            async with tg:
                for index, dep in enumerate(dependencies):
                    tg.create_task(analyze_with_limit(index, dep))
        else:
            await asyncio.gather(
                *(analyze_with_limit(index, dep) for index, dep in enumerate(dependencies))
            )

    findings: list[PackageFinding] = [finding for finding in findings_buffer if finding is not None]

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
    for src, dest in all_relationships:
        # Only add edges if both source and destination nodes exist in the graph
        if src in graph._nodes and dest in graph._nodes:
            graph.add_edge(src, dest)

    direct_count = sum(1 for finding in findings if finding.dependency.direct)
    manager_usage = Counter(finding.dependency.ecosystem for finding in findings)

    manager_list: list[str]
    if used_managers:
        manager_list = unique_preserving_order(used_managers, key=str.casefold)
    elif managers:
        manager_list = unique_preserving_order(list(managers), key=str.casefold)
    else:
        manager_list = []

    report = Report(
        path=root,
        managers=manager_list,
        findings=sorted(findings, key=lambda f: f.dependency.coordinate),
        generated_at=utc_now(),
        stats={
            "dependency_count": len(findings),
            "direct_dependencies": direct_count,
            "indirect_dependencies": len(findings) - direct_count,
            "graph_nodes": len(graph),
            "graph_edges": graph.edge_count(),
            "manager_usage": dict(sorted(manager_usage.items())),
        },
    )
    return report


def scan_project(path: Path, managers: list[str] | None = None) -> Report:
    return asyncio.run(scan_project_async(path, managers=managers))

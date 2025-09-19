from __future__ import annotations

from pathlib import Path

from rtx.scanners import common
from rtx.utils import Graph, slugify


def test_normalize_version_handles_semver() -> None:
    assert common.normalize_version("1.0.0") == "1.0.0"
    assert common.normalize_version("01.02.000") == "1.2.0"
    assert common.normalize_version("invalid") == "invalid"


def test_slugify() -> None:
    assert slugify("Real Tracker X") == "real-tracker-x"


def test_graph_adds_nodes_and_edges(tmp_path: Path) -> None:
    graph = Graph()
    graph.add_node("pypi:demo@1.0.0", {"direct": True})
    graph.add_node("npm:demo@2.0.0", {"direct": False})
    graph.add_edge("pypi:demo@1.0.0", "npm:demo@2.0.0")
    assert len(graph) == 2
    assert graph.edge_count() == 1

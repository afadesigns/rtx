from __future__ import annotations

from pathlib import Path

from rtx.api import _merge_dependency, scan_project
from rtx.models import Dependency, Report


def test_scan_project(mocker) -> None:
    mocker.patch(
        "rtx.api.get_scanners",
        return_value=[
            mocker.Mock(
                manager="pip",
                matches=mocker.Mock(return_value=True),
                scan=mocker.Mock(
                    return_value=[
                        Dependency("pypi", "name", "1.0", True, Path("manifest"))
                    ]
                ),
            )
        ],
    )
    mocker.patch(
        "rtx.api.AdvisoryClient.fetch_advisories", return_value={}
    )
    report = scan_project(Path("."))
    assert isinstance(report, Report)
    assert len(report.findings) == 1


def test_merge_dependency() -> None:
    dep1 = Dependency("pypi", "name", "1.0", True, Path("manifest1"))
    dep2 = Dependency("pypi", "name", "1.0", False, Path("manifest2"))
    merged = _merge_dependency(dep1, dep2)
    assert merged.direct
    assert merged.metadata["manifests"] == ["manifest1", "manifest2"]
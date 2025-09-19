from __future__ import annotations

from pathlib import Path

from rtx.models import Dependency, PackageFinding, Severity, SignalSummary, TrustSignal


def _finding_with_signals(category: str, severity: Severity) -> PackageFinding:
    dependency = Dependency(
        ecosystem="pypi",
        name="demo",
        version="1.0.0",
        direct=True,
        manifest=Path("pyproject.toml"),
        metadata={},
    )
    signal = TrustSignal(category=category, severity=severity, message="msg", evidence={})
    return PackageFinding(dependency=dependency, signals=[signal], score=0.0)


def test_signal_summary_from_findings() -> None:
    findings = [
        _finding_with_signals("maintainer", Severity.MEDIUM),
        _finding_with_signals("maintainer", Severity.MEDIUM),
        _finding_with_signals("churn", Severity.HIGH),
    ]

    summary = SignalSummary.from_findings(findings)

    assert summary.has_data()
    assert summary.counts == {"churn": 1, "maintainer": 2}
    assert list(summary.severity_counts["maintainer"].keys()) == ["medium"]
    assert summary.severity_counts["maintainer"]["medium"] == 2
    assert summary.severity_totals == {"medium": 2, "high": 1}


def test_signal_summary_empty() -> None:
    summary = SignalSummary.from_findings([])
    assert not summary.has_data()
    assert summary.counts == {}

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

SEVERITY_RANK = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> Severity:
        if score >= 0.85:
            return cls.CRITICAL
        if score >= 0.7:
            return cls.HIGH
        if score >= 0.4:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.NONE


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    direct: bool
    manifest: Path
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def coordinate(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"

    @property
    def normalized_name(self) -> str:
        """Case-insensitive identifier for cross-ecosystem lookups."""
        return self.name.casefold()

    @property
    def normalized_ecosystem(self) -> str:
        """Case-insensitive ecosystem key used for lookups."""
        return self.ecosystem.casefold()


@dataclass
class Advisory:
    identifier: str
    source: str
    severity: Severity
    summary: str
    references: list[str] = field(default_factory=list)


@dataclass
class TrustSignal:
    category: str
    severity: Severity
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SignalSummary:
    counts: dict[str, int]
    severity_counts: dict[str, dict[str, int]]
    severity_totals: dict[str, int]

    @classmethod
    def from_findings(cls, findings: Iterable[PackageFinding]) -> SignalSummary:
        category_counts: Counter[str] = Counter()
        per_category_severity: dict[str, Counter[str]] = defaultdict(Counter)
        severity_totals: Counter[str] = Counter()
        for finding in findings:
            for signal in finding.signals:
                category_counts[signal.category] += 1
                per_category_severity[signal.category][signal.severity.value] += 1
                severity_totals[signal.severity.value] += 1
        def _sort_severity(data: dict[str, int]) -> dict[str, int]:
            return dict(
                sorted(
                    data.items(),
                    key=lambda item: SEVERITY_RANK.get(item[0], float("inf")),
                )
            )

        return cls(
            counts=dict(sorted(category_counts.items())),
            severity_counts={
                category: _sort_severity(dict(counter))
                for category, counter in sorted(per_category_severity.items())
            },
            severity_totals=_sort_severity(dict(severity_totals)),
        )

    def has_data(self) -> bool:
        return bool(self.counts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts,
            "severity_counts": self.severity_counts,
            "severity_totals": self.severity_totals,
        }


@dataclass
class PackageFinding:
    dependency: Dependency
    advisories: list[Advisory] = field(default_factory=list)
    signals: list[TrustSignal] = field(default_factory=list)
    score: float = 0.0

    @property
    def verdict(self) -> Severity:
        severities = [Severity.from_score(self.score)]
        if self.advisories:
            severities.append(
                max(self.advisories, key=lambda adv: SEVERITY_RANK[adv.severity.value]).severity
            )
        if self.signals:
            severities.append(
                max(self.signals, key=lambda sig: SEVERITY_RANK[sig.severity.value]).severity
            )
        return max(severities, key=lambda level: SEVERITY_RANK[level.value])


@dataclass
class Report:
    path: Path
    managers: list[str]
    findings: list[PackageFinding]
    generated_at: datetime
    stats: dict[str, Any] = field(default_factory=dict)
    _signal_summary: SignalSummary | None = field(default=None, init=False, repr=False)

    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.NONE
        return max(
            (finding.verdict for finding in self.findings),
            key=lambda severity: SEVERITY_RANK[severity.value],
        )

    def exit_code(self) -> int:
        verdict = self.highest_severity()
        if verdict in (Severity.CRITICAL, Severity.HIGH):
            return 2
        if verdict == Severity.MEDIUM:
            return 1
        return 0

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {severity.value: 0 for severity in Severity}
        direct = 0
        manager_usage: Counter[str] = Counter()
        for finding in self.findings:
            counts[finding.verdict.value] += 1
            if finding.dependency.direct:
                direct += 1
            manager_usage[finding.dependency.ecosystem] += 1
        signal_summary = self.signal_summary()
        indirect = len(self.findings) - direct
        return {
            "generated_at": self.generated_at.isoformat(),
            "managers": self.managers,
            "counts": counts,
            "total": len(self.findings),
            "direct_dependencies": direct,
            "indirect_dependencies": indirect,
            "manager_usage": dict(sorted(manager_usage.items())),
            "exit_code": self.exit_code(),
            "path": str(self.path),
            "signal_counts": signal_summary.counts,
            "signal_severity_counts": signal_summary.severity_counts,
            "signal_severity_totals": signal_summary.severity_totals,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "findings": [
                {
                    "dependency": finding.dependency.coordinate,
                    "ecosystem": finding.dependency.ecosystem,
                    "name": finding.dependency.name,
                    "version": finding.dependency.version,
                    "direct": finding.dependency.direct,
                    "manifest": str(finding.dependency.manifest),
                    "metadata": finding.dependency.metadata,
                    "score": finding.score,
                    "verdict": finding.verdict.value,
                    "advisories": [
                        {
                            "id": advisory.identifier,
                            "source": advisory.source,
                            "severity": advisory.severity.value,
                            "summary": advisory.summary,
                            "references": advisory.references,
                        }
                        for advisory in finding.advisories
                    ],
                    "signals": [
                        {
                            "category": signal.category,
                            "severity": signal.severity.value,
                            "message": signal.message,
                            "evidence": signal.evidence,
                        }
                        for signal in finding.signals
                    ],
                }
                for finding in self.findings
            ],
            "stats": self.stats,
            "signal_summary": self.signal_summary().to_dict(),
        }

    def __iter__(self) -> Iterable[PackageFinding]:
        return iter(self.findings)

    def signal_summary(self) -> SignalSummary:
        if self._signal_summary is None:
            self._signal_summary = SignalSummary.from_findings(self.findings)
        return self._signal_summary

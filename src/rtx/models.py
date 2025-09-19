from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List

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
    def from_score(cls, score: float) -> "Severity":
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
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def coordinate(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


@dataclass
class Advisory:
    identifier: str
    source: str
    severity: Severity
    summary: str
    references: List[str] = field(default_factory=list)


@dataclass
class TrustSignal:
    category: str
    severity: Severity
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PackageFinding:
    dependency: Dependency
    advisories: List[Advisory] = field(default_factory=list)
    signals: List[TrustSignal] = field(default_factory=list)
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
    managers: List[str]
    findings: List[PackageFinding]
    generated_at: datetime
    stats: Dict[str, Any] = field(default_factory=dict)

    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.NONE
        return max((finding.verdict for finding in self.findings), key=lambda s: SEVERITY_RANK[s.value])

    def exit_code(self) -> int:
        verdict = self.highest_severity()
        if verdict in (Severity.CRITICAL, Severity.HIGH):
            return 2
        if verdict == Severity.MEDIUM:
            return 1
        return 0

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.verdict.value] += 1
        return {
            "generated_at": self.generated_at.isoformat(),
            "managers": self.managers,
            "counts": counts,
            "total": len(self.findings),
            "exit_code": self.exit_code(),
            "path": str(self.path),
        }

    def to_dict(self) -> Dict[str, Any]:
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
        }

    def __iter__(self) -> Iterable[PackageFinding]:
        return iter(self.findings)

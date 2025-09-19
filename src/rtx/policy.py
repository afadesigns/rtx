from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from rtx import config
from rtx.metadata import MetadataClient, ReleaseMetadata
from rtx.models import Advisory, Dependency, PackageFinding, Severity, TrustSignal
from rtx.utils import load_json_resource

SEVERITY_SCORE = {
    Severity.NONE: 0.0,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 1.0,
}


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        row = [i]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            row.append(min(row[-1] + 1, prev_row[j] + 1, prev_row[j - 1] + cost))
        prev_row = row
    return prev_row[-1]


@dataclass
class ThreatSignals:
    metadata: ReleaseMetadata
    signals: List[TrustSignal]


class TrustPolicyEngine:
    def __init__(self) -> None:
        top_packages_path = config.DATA_DIR / "top_packages.json"
        compromised_path = config.DATA_DIR / "compromised_maintainers.json"
        self._top_packages: Dict[str, List[str]] = load_json_resource(top_packages_path)
        self._compromised = load_json_resource(compromised_path)
        self._metadata_client = MetadataClient()

    async def analyze(self, dependency: Dependency, advisories: List[Advisory]) -> PackageFinding:
        metadata = await self._metadata_client.fetch(dependency)
        signals = self._derive_signals(dependency, metadata)
        score = max((SEVERITY_SCORE[advisory.severity] for advisory in advisories), default=0.0)
        for signal in signals:
            score = max(score, SEVERITY_SCORE.get(signal.severity, 0.0))
        finding = PackageFinding(
            dependency=dependency,
            advisories=advisories,
            signals=signals,
            score=min(score, 1.0),
        )
        return finding

    def _derive_signals(self, dependency: Dependency, metadata: ReleaseMetadata) -> List[TrustSignal]:
        signals: List[TrustSignal] = []
        # Abandonment
        if metadata.is_abandoned():
            signals.append(
                TrustSignal(
                    category="abandonment",
                    severity=Severity.HIGH,
                    message="No release in the last 18 months",
                    evidence={"latest_release": metadata.latest_release.isoformat() if metadata.latest_release else None},
                )
            )
        # Suspicious churn
        if metadata.has_suspicious_churn():
            signals.append(
                TrustSignal(
                    category="churn",
                    severity=Severity.MEDIUM,
                    message="High release velocity in the last 30 days",
                    evidence={"releases_last_30d": metadata.releases_last_30d},
                )
            )
        # Bus factor
        if len(metadata.maintainers) <= 1:
            signals.append(
                TrustSignal(
                    category="maintainer",
                    severity=Severity.LOW,
                    message="Single maintainer detected",
                    evidence={"maintainers": metadata.maintainers},
                )
            )
        # Compromised maintainers dataset
        for entry in self._compromised:
            if (
                entry.get("ecosystem") == dependency.ecosystem
                and entry.get("package") == dependency.name
            ):
                signals.append(
                    TrustSignal(
                        category="compromised-maintainer",
                        severity=Severity.CRITICAL,
                        message="Package previously compromised",
                        evidence={"reference": entry.get("reference")},
                    )
                )
                break
        # Typosquatting detection
        baseline = self._top_packages.get(dependency.ecosystem, [])
        for top_name in baseline:
            distance = levenshtein(dependency.name.lower(), top_name.lower())
            if distance == 1 and dependency.name.lower() != top_name.lower():
                signals.append(
                    TrustSignal(
                        category="typosquat",
                        severity=Severity.HIGH,
                        message=f"Name is 1 edit away from popular package '{top_name}'",
                        evidence={"target": top_name},
                    )
                )
                break
            if distance == 2:
                signals.append(
                    TrustSignal(
                        category="typosquat",
                        severity=Severity.MEDIUM,
                        message=f"Name is 2 edits away from popular package '{top_name}'",
                        evidence={"target": top_name},
                    )
                )
                break
        return signals

    async def close(self) -> None:
        await self._metadata_client.close()

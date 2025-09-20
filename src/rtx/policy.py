from __future__ import annotations

from dataclasses import dataclass

from rtx import config
from rtx.metadata import MetadataClient, ReleaseMetadata
from rtx.models import Advisory, Dependency, PackageFinding, Severity, TrustSignal
from rtx.utils import load_json_resource, unique_preserving_order

SEVERITY_SCORE = {
    Severity.NONE: 0.0,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.85,
    Severity.CRITICAL: 1.0,
}


def levenshtein(a: str, b: str, *, max_distance: int | None = None) -> int:
    if max_distance is not None and max_distance < 0:
        raise ValueError("max_distance must be >= 0")
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if max_distance is not None and abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if len(a) > len(b):
        a, b = b, a
    prev_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        row = [i]
        min_in_row = row[0]
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            value = min(row[-1] + 1, prev_row[j] + 1, prev_row[j - 1] + cost)
            row.append(value)
            if value < min_in_row:
                min_in_row = value
        if max_distance is not None and min_in_row > max_distance:
            return max_distance + 1
        prev_row = row
    distance = prev_row[-1]
    if max_distance is not None and distance > max_distance:
        return max_distance + 1
    return distance


@dataclass(slots=True)
class ThreatSignals:
    metadata: ReleaseMetadata
    signals: list[TrustSignal]


class TrustPolicyEngine:
    def __init__(self) -> None:
        top_packages_path = config.DATA_DIR / "top_packages.json"
        compromised_path = config.DATA_DIR / "compromised_maintainers.json"
        raw_top_packages: dict[str, list[str]] = load_json_resource(top_packages_path)
        self._top_package_pairs: dict[str, list[tuple[str, str]]] = {}
        for ecosystem, names in raw_top_packages.items():
            if not isinstance(names, list):
                continue
            cleaned = unique_preserving_order(
                [
                    candidate.strip()
                    for candidate in names
                    if isinstance(candidate, str) and candidate.strip()
                ],
                key=str.casefold,
            )
            if not cleaned:
                continue
            normalized_ecosystem = str(ecosystem).casefold()
            self._top_package_pairs[normalized_ecosystem] = [
                (name, name.casefold()) for name in cleaned
            ]
        compromised_entries = load_json_resource(compromised_path)
        self._compromised_index: dict[tuple[str, str], dict[str, str]] = {}
        for entry in compromised_entries:
            if not isinstance(entry, dict):
                continue
            ecosystem = entry.get("ecosystem")
            package = entry.get("package")
            if not ecosystem or not package:
                continue
            self._compromised_index[(str(ecosystem).casefold(), str(package).casefold())] = entry
        self._metadata_client = MetadataClient()

    async def __aenter__(self) -> TrustPolicyEngine:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    async def analyze(self, dependency: Dependency, advisories: list[Advisory]) -> PackageFinding:
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

    def _derive_signals(
        self,
        dependency: Dependency,
        metadata: ReleaseMetadata,
    ) -> list[TrustSignal]:
        signals: list[TrustSignal] = []
        if metadata.latest_release is None:
            signals.append(
                TrustSignal(
                    category="release-metadata",
                    severity=Severity.MEDIUM,
                    message="Upstream registry does not publish release timestamps",
                    evidence={"ecosystem": metadata.ecosystem},
                )
            )
        # Abandonment
        if metadata.is_abandoned():
            evidence = {
                "latest_release": (
                    metadata.latest_release.isoformat()
                    if metadata.latest_release
                    else None
                ),
                "days_since_release": metadata.days_since_latest(),
            }
            signals.append(
                TrustSignal(
                    category="abandonment",
                    severity=Severity.HIGH,
                    message="No release in the last 18 months",
                    evidence=evidence,
                )
            )
        # Suspicious churn
        churn_band = metadata.churn_band()
        if churn_band == "high":
            signals.append(
                TrustSignal(
                    category="churn",
                    severity=Severity.HIGH,
                    message="Extreme release velocity in the last 30 days",
                    evidence={"releases_last_30d": metadata.releases_last_30d},
                )
            )
        elif churn_band == "medium":
            signals.append(
                TrustSignal(
                    category="churn",
                    severity=Severity.MEDIUM,
                    message="High release velocity in the last 30 days",
                    evidence={"releases_last_30d": metadata.releases_last_30d},
                )
            )
        # Bus factor
        maintainer_count = metadata.maintainer_count()
        if maintainer_count == 0:
            signals.append(
                TrustSignal(
                    category="maintainer",
                    severity=Severity.MEDIUM,
                    message="No maintainers listed in upstream metadata",
                    evidence={"maintainers": metadata.maintainers},
                )
            )
        elif maintainer_count == 1:
            signals.append(
                TrustSignal(
                    category="maintainer",
                    severity=Severity.LOW,
                    message="Single maintainer detected",
                    evidence={"maintainers": metadata.maintainers},
                )
            )
        # Release maturity
        if metadata.is_low_maturity():
            signals.append(
                TrustSignal(
                    category="maturity",
                    severity=Severity.LOW,
                    message="Limited release history detected",
                    evidence={"total_releases": metadata.total_releases},
                )
            )
        # Compromised maintainers dataset
        ecosystem_key = dependency.normalized_ecosystem
        compromised = self._compromised_index.get((ecosystem_key, dependency.normalized_name))
        if compromised:
            signals.append(
                TrustSignal(
                    category="compromised-maintainer",
                    severity=Severity.CRITICAL,
                    message="Package previously compromised",
                    evidence={"reference": compromised.get("reference")},
                )
            )
        # Typosquatting detection
        candidate = dependency.normalized_name
        for top_name, normalized in self._top_package_pairs.get(ecosystem_key, []):
            if candidate == normalized:
                continue
            distance = levenshtein(candidate, normalized, max_distance=2)
            if distance == 1:
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

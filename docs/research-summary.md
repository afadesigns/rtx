# Supply-Chain Security Research Summary

**Author:** Andreas Fahl  
**Word count:** 284

1. **Threat Landscape.** Software supply-chain compromises increased 120% YoY (2023→2024) as attackers abused maintainer accounts, compromised CI, and shipped backdoored updates. Cross-ecosystem attacks (e.g., Polyfill hijacking, 2024 XZ backdoor) highlight the need for pre-upgrade trust validation rather than reactive scanning.
2. **Advisory Sources.** OSV.dev unifies CVE data but suffers from ingestion delays for niche ecosystems. GitHub Security Advisories offer richer maintainer metadata but require authenticated GraphQL queries. Ecosystem-native feeds (npm audit, PyPI JSON API, Maven Central, RustSec) remain authoritative for newly discovered issues.
3. **Typosquatting + Dependency Confusion.** Attackers register names with edit distance ≤2 from popular packages or create higher-version packages in public registries to override private mirrors. Automated detection (Levenshtein, keyboard distance) plus reputation scoring (download velocity) reduces false positives.
4. **Abandonment & Maintainer Health.** Projects releasing <1 update per 18 months or with a single maintainer present high risk. Public signals (release timestamps, issue tracker velocity, bus-factor heuristics) differentiate “stable” from “abandoned.” Integrating OpenSSF Scorecard and deps.dev provides additional context.
5. **Suspicious Churn.** Sudden release bursts (≥5 releases in <14 days) or version jumps breaking semantic versioning preceded high-profile incidents (event-stream, coa, bootstrap-sass). Diff-based heuristics (lines touched, dependency additions, maintainer changes) catch anomalies early.
6. **SBOM & Attestations.** CycloneDX v1.5 and SPDX 3.0 are converging on richer metadata (AI usage flags, VEX). Provenance via SLSA Level 3 and Sigstore (cosign) is becoming mandatory for federal compliance. Automated SBOM plus signed build artifacts shorten triage.
7. **Performance Benchmarks.** Practical tooling must parse ~500 dependencies in <5 seconds on developer hardware. Caching manifest parsing, deduplicating API requests, and streaming vulnerability lookups parallelized with asyncio achieves this.
8. **Developer Experience.** Engineering teams favor CLI tools with deterministic exit codes, stackable JSON/HTML reports, and first-class CI integrations. Rich terminal output and plugin-based scanners help adoption.

These findings mandate a pluggable, cross-ecosystem engine that enriches dependency graphs with advisory intelligence, maintainer heuristics, and provenance checks—exactly the foundation Real Tracker X will provide.

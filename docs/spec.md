# Real Tracker X — One-Page Product Specification

**Author:** Andreas Fahl  
**Revision:** 2025-09-19  
**Audience:** Security engineering, DevOps, platform teams

## 1. Mission & Goals
Provide a pre-upgrade dependency trust scanner that prevents supply-chain compromises by evaluating risk before merging dependency changes. Success is defined by: deterministic CI outcomes, actionable trust scores covering ≥12 ecosystems, and <5s scans for projects with ≤500 dependencies.

## 2. Personas & Workflows
- **Release Engineer:** runs `rtx pre-upgrade` in CI to compare current vs. proposed dependency trees, blocking risky PRs.
- **Security Analyst:** exports HTML/JSON reports for audits, monitors SBOM drift, and enforces policy via exit codes.
- **Developer:** locally runs `rtx scan` for quick feedback, inspects Rich table output, and remediates flagged packages.

## 3. Functional Requirements
1. Detect manifests for npm, Yarn, pnpm, PyPI/Pip/Poetry/uv, Maven/Gradle, Cargo, Go modules, Composer, NuGet, RubyGems, Conda, Homebrew, Dockerfiles.
2. Build a unified dependency graph with direct + transitive nodes, normalized coordinates (`ecosystem`, `name`, `version`).
3. Enrich graph with vulnerability intelligence (OSV, GitHub Security Advisories, ecosystem feeds) and heuristics (typosquat distance, abandonment, suspicious churn, compromised maintainers).
4. Emit trust scores per package and aggregate severity buckets; map to exit codes {0,1,2}.
5. Output formats: Rich table (terminal), JSON, HTML bundle, CycloneDX SBOM.
6. Library API: `scan_project(path: Path, managers: list[str] | None) -> Report` with sync + async variants.
7. CLI commands: `scan`, `pre-upgrade`, `report`, `list-managers` with consistent logging, caching, and configuration.

## 4. Non-Functional Requirements
- Python ≥ 3.11, cross-platform (Linux, macOS, Windows).
- Strict typing (mypy), linted (ruff), static analysis (bandit, semgrep), fuzz tests (atheris).
- Deterministic network behavior: timeouts, retries, offline cache with SHA256 integrity.
- Performance budget: manifest parsing ≤ 2s, advisory enrichment ≤ 3s with asyncio concurrency.
- Security: never execute arbitrary scripts; operate on metadata only; signed artifacts + SLSA provenance at release.

## 5. Architecture Overview
- **Scanner Registry:** maps manifest signatures to scanner plugins; supports auto-detection and manual selection.
- **Graph Builder:** merges scanner outputs into a deduplicated dependency DAG; tracks relationships and metadata.
- **Threat Intel Service:** async provider orchestrating OSV, GitHub, ecosystem feeds with caching and rate-limit guards.
- **Trust Policy Engine:** calculates risk signals (CVE severity, maintainer reputation, abandonment, churn) and aggregates final scores.
- **Reporters:** render table/JSON/HTML plus generate CycloneDX SBOMs; HTML uses the same JSON payload + template.
- **Persistence:** optional cache directory storing API responses, SBOMs, and signed attestations.

## 6. Release & Ops Plan
- CI (Linux/macOS/Windows) runs lint, type-check, unit/integration tests, fuzz harness (atheris), SBOM generation.
- Release workflow on tag: build wheels/sdist, run cosign signing, emit provenance (SLSA level 3), upload to PyPI, attach SBOM & HTML report.
- Dependabot security updates enabled; branch protection enforcing required checks; secret scanning + code scanning enabled.

## 7. Open Questions
1. Should we bundle an embedded heuristics database (deps.dev, OpenSSF Scorecard snapshots) or fetch on-demand?
2. How aggressively should we parallelize advisory lookups to balance rate limits vs. performance?
3. What governance model best sustains community contributions (steering committee vs. BDFL)?

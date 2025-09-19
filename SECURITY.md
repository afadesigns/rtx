# Security Policy

## Contact
Report vulnerabilities confidentially to `security@afadesigns.com` (PGP fingerprint: 4F1B 0D4C 3B7E C893 1F2B  9F47 8BE3 1AF1 4D78 6B0C). Please include proof-of-concept, impact assessment, and suggested mitigation if available. Do **not** open public issues for undisclosed vulnerabilities.

## Supported Versions
| Version | Supported |
|---------|-----------|
| 0.y.z   | ✅ (security + bug fixes)

We follow a rolling release model until 1.0. After 1.0, the latest two minor releases remain supported.

## Disclosure Timeline
1. Acknowledge receipt within 24 hours.
2. Provide remediation plan within 72 hours.
3. Release fix, SBOM updates, and security advisory as soon as a patch is ready, typically within 7 days.
4. Credit reporters in the advisory (unless anonymity requested).

## Threat Model
- **Attack Surface:** Manifest parsers, network clients fetching advisory metadata, report renderers.
- **Assets Protected:** Integrity of scan results, authenticity of trust scores, signing keys for release artefacts.
- **Adversaries:** Malicious package maintainers, supply-chain attackers targeting CI/CD pipelines, opportunistic typosquatters.
- **Assumptions:** Scans run in read-only mode against project metadata; no direct execution of third-party code; operators manage their own credentials.
- **Controls:**
  - Strict dependency pinning with hashes; CI fails on drift.
  - Network calls enforce HTTPS with certificate validation, 5s timeouts, and retries with backoff.
  - Sandboxed analysis — no execution of package scripts or build hooks.
  - SBOM + SLSA provenance emitted for reproducibility and auditing.
  - Static analysis (ruff, mypy, bandit, semgrep) and atheris fuzzing on parsers.
  - Cosign-signed release artifacts with OIDC (GitHub → PyPI) attestation.

## Coordinated Disclosure
We collaborate with upstream maintainers and registries (OSV.dev, PyPI, npm, Maven Central, etc.). Coordinated disclosure may extend the public release timeline if upstream patches are pending.

## Public Security Advisories
We publish advisories under `GHSA-` identifiers via GitHub Security Advisories and link them in CHANGELOG.md.

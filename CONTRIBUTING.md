# Contributing to Real Tracker X

Thank you for your interest in contributing! Real Tracker X (rtx) is authored by **Andreas Fahl** and welcomes community collaboration focused on keeping software supply chains safe.

## Getting Started
1. **Fork & Clone.** Fork `afadesigns/rtx` and clone your fork.
2. **Install Tooling.** Ensure Python ≥3.11 is available. Install dependencies via `uv pip install -r requirements.lock` or `pip install .[dev]`.
3. **Pre-commit Hooks.** Run `pre-commit install` to enable automatic formatting and security checks.

## Development Workflow
- Create a feature branch (`git checkout -b feature/your-change`).
- Write tests alongside code; favor unit tests for parsers and integration tests for CLI flows.
- Keep commits small, focused, and signed (`git commit -S`).
- Run the full validation suite before opening a PR:
  ```bash
  make lint
  make typecheck
  make test
  make fuzz
  make sbom
  ```
- Submit a pull request referencing relevant issues. Follow the PR template.

## Coding Standards
- Python: Ruff and Black-compatible styling, typed with mypy strict mode.
- Async-first design: network operations must use asyncio with timeouts.
- No TODOs or placeholders; resolve issues within the same change.
- Keep security in mind—never execute arbitrary package scripts during scans.

## Security Disclosures
Sensitive discoveries belong in [SECURITY.md](SECURITY.md) or the `/security.txt` contact channel. Do not open public issues for undisclosed vulnerabilities.

## Docs & Knowledge Base
Documentation lives under `docs/` (MkDocs). Use `uv run mkdocs serve` during authoring. Code snippets must be tested.

## Community Expectations
Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Project governance and decision-making details reside in [GOVERNANCE.md](GOVERNANCE.md).

## Recognition
Contributors are acknowledged in the CHANGELOG and release notes. Exceptional contributions may receive repository roles per GOVERNANCE.md.

With gratitude,

**Andreas Fahl**  
Lead Maintainer, Real Tracker X

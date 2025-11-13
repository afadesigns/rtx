# Repository Guidelines

## Project Structure & Module Organization
Production code lives under `src/rtx/`, with policy evaluation in `policy.py`, ecosystem adapters in `scanners/`, and CLI surfaces in `cli.py`, `api.py`, and `__main__.py`. SBOM helpers reside in `sbom.py` and `sbom_cli.py`. Tests are split into `tests/unit/`, `tests/integration/`, and `tests/fuzz/` to mirror scope. Documentation sources live in `docs/`, sample manifests in `examples/`, and generated artifacts in `dist/`. Release metadata and tooling defaults are centralized in `pyproject.toml`, `Makefile`, and `RELEASE.md`.

## Build, Test, and Development Commands
- `make install` — upgrade pip and install the `.[dev]` extras.  
- `make lint` — run `ruff check` and `semgrep --config p/ci`.  
- `make format` / `make format-check` — apply or verify Ruff formatter plus Black.  
- `make typecheck` — execute mypy across `src/`.  
- `make unit`, `make integration`, `make fuzz`, `make test` — drive the pytest suites.  
- `make sbom` — emit `reports/sbom.json` via `rtx.sbom_cli`.  
- `make clean` — remove build, cache, and report directories.

## Coding Style & Naming Conventions
Target Python 3.11+ and keep functions fully type-annotated. Modules and packages use `snake_case`, classes use `PascalCase`, and module-level constants stay `UPPER_SNAKE`. Export public APIs through `src/rtx/__init__.py` and keep CLI command flags kebab-case to match existing subcommands. Always run `ruff format` before committing; rely on Ruff to manage import ordering and Black for stable formatting.

## Testing Guidelines
Add fast checks under `tests/unit/test_<module>.py` and reserve multi-component scenarios for `tests/integration/` with descriptive filenames. Long-running heuristics or randomized checks belong in `tests/fuzz/` and should guard flakiness with timeouts. Use `pytest --cov=rtx --cov-report=term-missing` locally and sustain coverage at or above the 95% CI baseline. Prefer async tests with `pytest.mark.asyncio` when exercising asynchronous engines.

## Commit & Pull Request Guidelines
Follow Conventional Commits (`feat:`, `fix:`, `docs:`) mirrored in history; automation loops continue using `loop-<n>-consolidation: applied 5 optimizations` when applicable. Keep each commit buildable with passing tests. Pull requests must summarize intent, link issues, and attach CLI output or screenshots for user-facing changes. Highlight configuration or dependency impacts, update adjacent docs, and flag security reviewers when trust policies shift.

## Security & Configuration Tips
Never check in secrets; rely on environment configuration and sample manifests under `examples/`. Run `semgrep --config p/ci` locally to catch policy regressions before CI. Report suspected vulnerabilities through `SECURITY.md`, and include SBOM diffs from `make sbom` whenever dependency risk or advisory coverage changes.


## Vault Secrets Automation

- Codex agents MUST resolve every secret, credential, or API token from Vault at `/srv/vault` using the shared manifest/loader (`05-vault-loader.zsh` and `10-secrets.zsh`).
- Plaintext secrets MUST NOT be stored in repositories or local config files; add or update a `secret/...` path in Vault instead.
- Automation MUST reference these Vault paths (and document the manifest linkage) rather than hardcoding values in configs, scripts, or AGENTS files.

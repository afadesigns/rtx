# Codex deploy hooks

Drop executable `*.sh` scripts in this directory to participate in the global deployment harness.
Scripts run in lexical order after the base `.codex/ci/auto-deploy.sh` preflight checks pass.

Each script should:

1. Exit non-zero on failure (the harness will stop immediately).
2. Log useful progress to stdout/stderr.
3. Consume credentials from Vault-backed environment variables instead of hardcoding secrets.

Deployment hooks also receive useful context:

- `CD_CHANGED_FILES_JSON` — JSON array of changed files.
- `CODEX_SKIP_REASON` — CI skip reason when the test matrix was bypassed.
- `CODEX_PRUNED_LANGUAGES_JSON` — JSON array mirroring languages skipped during CI detection.
- `CODEX_TOTAL_DURATION_SECONDS` — aggregate CI runtime across matrix runs.

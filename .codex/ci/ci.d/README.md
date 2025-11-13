# Codex CI hooks

Put executable shell scripts (`*.sh`) in this directory to extend the global CI harness.
Each script runs in lexical order after the built-in language checks finish.

Guidelines:

1. Exit non-zero to fail the pipeline; the harness stops at the first failure.
2. Log meaningful progress to stdout/stderr so summaries stay useful.
3. Source secrets from Vault-managed environment variables instead of embedding credentials.

CI exposes helpful context to each hook:

- `CI_CHANGED_FILES_JSON` — JSON array of changed paths.
- `CI_PYTHON_TOUCHED`, `CI_NODE_TOUCHED`, `CI_GO_TOUCHED`, `CI_RUST_TOUCHED`, `CI_TERRAFORM_TOUCHED`, `CI_DOCKER_TOUCHED` — `true`/`false` flags indicating whether each stack matched change filters.
- `CI_FORCE_CI` — `true` when CI was forced (label, commit tag, or config override).
- `CI_PRUNED_LANGUAGES` — JSON array of languages skipped because their targets didn’t change.
- `CI_SKIP_REASON` — reason code when the matrix was skipped (`no_changes`, `docs_only`, `no_matching_targets`, `config`, or empty).
- `CI_STEP_DURATION_JSON` — JSON object mapping step labels to duration in milliseconds.
- `CI_TELEMETRY_PATH` — path to a JSON file (`telemetry.json`) summarising executed steps.

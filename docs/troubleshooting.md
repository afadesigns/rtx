# Troubleshooting

## Installation Issues
- **Missing Python 3.11+:** Verify with `python3 --version`. Install via pyenv or your OS package manager.
- **Dependency Conflicts:** Use an isolated virtual environment and install from `requirements.lock` to ensure hashes match.

## Runtime Errors
- **Network Timeouts:** Set `RTX_HTTP_TIMEOUT` (seconds) or run with `--offline` to rely on cached advisories.
- **Permission Denied:** Ensure the cache directory (`~/.cache/rtx`) is writable.
- **Unsupported Manifest:** Run `rtx list-managers` to confirm support and open a feature request with a sample manifest.

## CI Failures
- **Exit Code 1:** Medium risk issues detected. Review the generated JSON/HTML for remediation steps.
- **Exit Code 2:** High or critical risk (e.g., active CVE). Block deployment until mitigated.
- **Hash Mismatch:** Regenerate `requirements.lock` using `make lock` and commit the update.

## Logging & Diagnostics
Run with `--log-level debug` or set `RTX_LOG_LEVEL=DEBUG`. Attach logs to GitHub issues after redacting sensitive data.

from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest
import tomli

import rtx.config as config
from rtx import __version__


@pytest.fixture(autouse=True)
def setup_config_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("rtx.config.Path", lambda p: tmp_path / p if isinstance(p, str) and p == "rtx.toml" else Path(p))
    monkeypatch.setattr("rtx.config.CACHE_DIR", tmp_path / ".cache" / "rtx")
    monkeypatch.setattr("rtx.config._FILE_CONFIG", {})
    # Ensure we don't interfere with other tests that might rely on original config state
    importlib.reload(config)


def test_config_from_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_content = """
[rtx]
cache_dir = "/tmp/test_cache"
http_timeout = 10.0
http_retries = 3
osv_batch_size = 5
disable_osv = true
"""
    (tmp_path / "rtx.toml").write_text(config_content)

    reloaded = importlib.reload(config)

    assert reloaded.RTX_CACHE_DIR == "/tmp/test_cache"
    assert reloaded.HTTP_TIMEOUT == pytest.approx(10.0)
    assert reloaded.HTTP_RETRIES == 3
    assert reloaded.OSV_BATCH_SIZE == 5
    assert reloaded.DISABLE_OSV is True


def test_env_precedence_over_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_content = """
[rtx]
cache_dir = "/tmp/test_cache"
http_timeout = 10.0
http_retries = 3
osv_batch_size = 5
disable_osv = true
"""
    (tmp_path / "rtx.toml").write_text(config_content)

    monkeypatch.setenv("RTX_HTTP_TIMEOUT", "20.0")
    monkeypatch.setenv("RTX_HTTP_RETRIES", "10")
    monkeypatch.setenv("RTX_DISABLE_OSV", "false")

    reloaded = importlib.reload(config)

    assert reloaded.RTX_CACHE_DIR == "/tmp/test_cache" # Should still come from file as no ENV override
    assert reloaded.HTTP_TIMEOUT == pytest.approx(20.0)
    assert reloaded.HTTP_RETRIES == 10
    assert reloaded.OSV_BATCH_SIZE == 5 # Should still come from file
    assert reloaded.DISABLE_OSV is False


def test_http_settings_respect_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RTX_HTTP_TIMEOUT", "12.5")
    monkeypatch.setenv("RTX_HTTP_RETRIES", "5")
    monkeypatch.setenv("RTX_GITHUB_MAX_CONCURRENCY", "12")
    monkeypatch.setenv("RTX_OSV_BATCH_SIZE", "3")
    monkeypatch.setenv("RTX_OSV_CACHE_SIZE", "42")
    monkeypatch.setenv("RTX_OSV_MAX_CONCURRENCY", "9")
    reloaded = importlib.reload(config)
    assert reloaded.HTTP_TIMEOUT == pytest.approx(12.5)
    assert reloaded.HTTP_RETRIES == 5
    assert reloaded.GITHUB_MAX_CONCURRENCY == 12
    assert reloaded.OSV_BATCH_SIZE == 3
    assert reloaded.OSV_CACHE_SIZE == 42
    assert reloaded.OSV_MAX_CONCURRENCY == 9

    monkeypatch.delenv("RTX_HTTP_TIMEOUT", raising=False)
    monkeypatch.delenv("RTX_HTTP_RETRIES", raising=False)
    monkeypatch.delenv("RTX_GITHUB_MAX_CONCURRENCY", raising=False)
    monkeypatch.delenv("RTX_OSV_BATCH_SIZE", raising=False)
    monkeypatch.delenv("RTX_OSV_CACHE_SIZE", raising=False)
    monkeypatch.delenv("RTX_OSV_MAX_CONCURRENCY", raising=False)
    reloaded = importlib.reload(config)
    assert reloaded.HTTP_TIMEOUT == pytest.approx(5.0)
    assert reloaded.HTTP_RETRIES == 2
    assert reloaded.GITHUB_MAX_CONCURRENCY == 6
    assert reloaded.OSV_BATCH_SIZE == 18
    assert reloaded.OSV_CACHE_SIZE == 512
    assert reloaded.OSV_MAX_CONCURRENCY == 4
    assert reloaded.USER_AGENT.startswith(f"rtx/{__version__}")


def test_policy_concurrency_defaults_to_cpu(monkeypatch: pytest.MonkeyPatch) -> None:
    original_cpu = os.cpu_count
    monkeypatch.delenv("RTX_POLICY_CONCURRENCY", raising=False)
    monkeypatch.setattr("os.cpu_count", lambda: 12)
    reloaded = importlib.reload(config)
    assert reloaded.DEFAULT_POLICY_CONCURRENCY == 12
    assert reloaded.POLICY_ANALYSIS_CONCURRENCY == 12

    monkeypatch.setattr("os.cpu_count", lambda: None)
    reloaded = importlib.reload(config)
    assert reloaded.DEFAULT_POLICY_CONCURRENCY == 4
    assert reloaded.POLICY_ANALYSIS_CONCURRENCY == 4

    monkeypatch.setattr("os.cpu_count", original_cpu)
    reloaded = importlib.reload(config)
    expected = original_cpu()
    if expected is None or expected <= 0:
        expected = 4
    expected = max(1, min(32, expected))
    assert reloaded.DEFAULT_POLICY_CONCURRENCY == expected
    assert reloaded.POLICY_ANALYSIS_CONCURRENCY == expected

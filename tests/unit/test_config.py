from __future__ import annotations

import importlib

import pytest

from rtx import __version__
import rtx.config as config


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

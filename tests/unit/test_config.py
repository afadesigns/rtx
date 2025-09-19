from __future__ import annotations

import importlib

import pytest

from rtx import __version__
import rtx.config as config


def test_http_settings_respect_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RTX_HTTP_TIMEOUT", "12.5")
    monkeypatch.setenv("RTX_HTTP_RETRIES", "5")
    monkeypatch.setenv("RTX_GITHUB_MAX_CONCURRENCY", "12")
    reloaded = importlib.reload(config)
    assert reloaded.HTTP_TIMEOUT == pytest.approx(12.5)
    assert reloaded.HTTP_RETRIES == 5
    assert reloaded.GITHUB_MAX_CONCURRENCY == 12

    monkeypatch.delenv("RTX_HTTP_TIMEOUT", raising=False)
    monkeypatch.delenv("RTX_HTTP_RETRIES", raising=False)
    monkeypatch.delenv("RTX_GITHUB_MAX_CONCURRENCY", raising=False)
    reloaded = importlib.reload(config)
    assert reloaded.HTTP_TIMEOUT == pytest.approx(5.0)
    assert reloaded.HTTP_RETRIES == 2
    assert reloaded.GITHUB_MAX_CONCURRENCY == 6
    assert reloaded.USER_AGENT.startswith(f"rtx/{__version__}")

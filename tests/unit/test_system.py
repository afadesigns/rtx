from __future__ import annotations

import pytest

from rtx.system import _sanitize_version_args, _parse_version, probe_tool, collect_manager_diagnostics


def test_collect_manager_diagnostics() -> None:
    results = collect_manager_diagnostics()
    assert isinstance(results, list)
    assert results


def test_probe_tool() -> None:
    status = probe_tool("nonexistent-tool")
    assert not status.available

    status = probe_tool("echo", version_args=["--version"])
    assert status.available
    assert status.version is not None

    status = probe_tool("sh", version_args=["-c", "exit 1"])
    assert status.available
    assert status.error is not None


def test_parse_version() -> None:
    class MockProcess:
        def __init__(self, stdout: str | None = None, stderr: str | None = None):
            self.stdout = stdout
            self.stderr = stderr

    assert _parse_version(MockProcess(stdout="1.0")) == "1.0"
    assert _parse_version(MockProcess(stderr="1.0")) == "1.0"
    assert _parse_version(MockProcess()) is None


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        (["--version"], ("--version",)),
        (["-v"], ("-v",)),
    ],
)
def test_sanitize_version_args(flags: list[str], expected: tuple[str, ...]) -> None:
    assert _sanitize_version_args(flags) == expected


@pytest.mark.parametrize(
    "flags",
    [
        ["version"],
        ["--version|"],
    ],
)
def test_sanitize_version_args_raises(flags: list[str]) -> None:
    with pytest.raises(ValueError):
        _sanitize_version_args(flags)
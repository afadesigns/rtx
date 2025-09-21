from __future__ import annotations

import subprocess

from rtx.system import (
    DEFAULT_TOOL_PROBES,
    ToolStatus,
    collect_manager_diagnostics,
    probe_tool,
)


def test_probe_tool_missing(monkeypatch):
    monkeypatch.setattr("rtx.system.which", lambda _: None)
    status = probe_tool("pip")
    assert status.name == "pip"
    assert status.available is False


def test_probe_tool_success(monkeypatch):
    monkeypatch.setattr("rtx.system.which", lambda _: "/usr/bin/pip")
    monkeypatch.setattr(
        "rtx.system.subprocess.run",
        lambda *_, **__: subprocess.CompletedProcess(
            args=["pip"], returncode=0, stdout="pip 25.2", stderr=""
        ),
    )
    status = probe_tool("pip")
    assert status.available is True
    assert status.version == "pip 25.2"
    assert status.error is None


def test_collect_manager_diagnostics_invokes_probe(monkeypatch):
    calls: list[str] = []

    def fake_probe(name: str, **_: object) -> ToolStatus:
        calls.append(name)
        return ToolStatus(name=name, available=True)

    monkeypatch.setattr("rtx.system.probe_tool", fake_probe)
    statuses = collect_manager_diagnostics()
    assert sorted(calls) == sorted(entry[0] for entry in DEFAULT_TOOL_PROBES)
    assert [status.name for status in statuses] == [entry[0] for entry in DEFAULT_TOOL_PROBES]
    assert len(statuses) == len(DEFAULT_TOOL_PROBES)

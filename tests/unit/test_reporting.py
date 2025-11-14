from __future__ import annotations

from datetime import datetime
from pathlib import Path
import json

from rtx.models import Report, Severity, TrustSignal
from rtx.reporting import _format_signal, render_json


def test_render_json() -> None:
    report = Report(
        path=Path("."), findings=[], generated_at=datetime.utcnow(), managers=[]
    )
    json_string = render_json(report)
    assert isinstance(json_string, str)
    assert json.loads(json_string) is not None


def test_format_signal() -> None:
    signal = TrustSignal(
        category="test",
        severity=Severity.HIGH,
        message="message",
        evidence={"key": "value"},
    )
    assert (
        _format_signal(signal)
        == "test (high) — message [key=value]"
    )
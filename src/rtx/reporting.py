from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from rtx import config
from rtx.exceptions import ReportRenderingError
from rtx.models import Report, TrustSignal

_HTML_REPORT_TEMPLATE = Template(config.HTML_TEMPLATE)


def render_table(report: Report, *, console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title="Real Tracker X Findings", show_lines=True)
    table.add_column("Dependency", style="cyan", no_wrap=False)
    table.add_column("Verdict", style="magenta")
    table.add_column("Score", style="yellow")
    table.add_column("Advisories", style="red")
    table.add_column("Signals", style="green")
    for finding in report.findings:
        advisories = "\n".join(
            f"{adv.source}:{adv.identifier} ({adv.severity.value}) — {adv.summary}".strip()
            for adv in finding.advisories
        ) or "-"
        signals = "\n".join(_format_signal(signal) for signal in finding.signals) or "-"
        table.add_row(
            finding.dependency.coordinate,
            finding.verdict.value,
            f"{finding.score:.2f}",
            advisories,
            signals,
        )
    summary = report.summary()
    console.print(table)
    console.print(
        "Total: {total} | High: {high} | Medium: {medium} | Exit: {exit_code}".format(
            total=summary["total"],
            high=summary["counts"]["high"],
            medium=summary["counts"]["medium"],
            exit_code=summary["exit_code"],
        ),
        style="bold",
    )
    signal_counts = summary.get("signal_counts", {})
    if signal_counts:
        formatted = ", ".join(f"{category}={count}" for category, count in signal_counts.items())
        console.print(f"Signals: {formatted}", style="bold cyan")
    severity_totals = summary.get("signal_severity_totals", {})
    if severity_totals:
        formatted = ", ".join(f"{severity}={count}" for severity, count in severity_totals.items())
        console.print(f"Signal severities: {formatted}", style="cyan")


def render_json(report: Report, *, path: Path | None = None) -> str:
    payload = report.to_dict()
    payload["signal_summary"] = report.signal_summary().to_dict()
    serialized = json.dumps(payload, indent=2)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(serialized, encoding="utf-8")
    return serialized


def _format_signal(signal: TrustSignal) -> str:
    evidence = signal.evidence or {}
    evidence_parts: list[str] = []
    for key, value in evidence.items():
        if isinstance(value, dict):
            subparts = ", ".join(f"{subkey}={subvalue}" for subkey, subvalue in value.items())
            evidence_parts.append(f"{key}={{ {subparts} }}")
        elif isinstance(value, list):
            rendered = ", ".join(str(item) for item in value)
            evidence_parts.append(f"{key}=[{rendered}]")
        else:
            evidence_parts.append(f"{key}={value}")
    details = f" — {signal.message}" if signal.message else ""
    evidence_suffix = f" [{'; '.join(evidence_parts)}]" if evidence_parts else ""
    return f"{signal.category} ({signal.severity.value}){details}{evidence_suffix}"


def render_html(report: Report, *, path: Path) -> None:
    try:
        payload = report.to_dict()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            _HTML_REPORT_TEMPLATE.render(summary=payload["summary"], findings=payload["findings"]),
            encoding="utf-8",
        )
    except Exception as exc:
        raise ReportRenderingError("Failed to render HTML report") from exc


def render(report: Report, *, fmt: str, output: Path | None = None) -> None:
    if fmt == "table":
        render_table(report)
    elif fmt == "json":
        if not output:
            raise ReportRenderingError("JSON output requires --output path")
        render_json(report, path=output)
    elif fmt == "html":
        if not output:
            raise ReportRenderingError("HTML output requires --output path")
        render_html(report, path=output)
    else:
        raise ReportRenderingError(f"Unknown format: {fmt}")

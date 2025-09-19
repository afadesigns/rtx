from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from jinja2 import Template
from rich.console import Console
from rich.table import Table

from rtx import config
from rtx.exceptions import ReportRenderingError
from rtx.models import PackageFinding, Report


def render_table(report: Report, *, console: Optional[Console] = None) -> None:
    console = console or Console()
    table = Table(title="Real Tracker X Findings", show_lines=True)
    table.add_column("Dependency", style="cyan", no_wrap=False)
    table.add_column("Verdict", style="magenta")
    table.add_column("Score", style="yellow")
    table.add_column("Advisories", style="red")
    table.add_column("Signals", style="green")
    for finding in report.findings:
        advisories = "\n".join(f"{adv.source}:{adv.identifier} ({adv.severity.value})" for adv in finding.advisories) or "-"
        signals = "\n".join(f"{signal.category} ({signal.severity.value})" for signal in finding.signals) or "-"
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
        f"Total: {summary['total']} | High: {summary['counts']['high']} | Medium: {summary['counts']['medium']} | Exit: {summary['exit_code']}",
        style="bold",
    )


def render_json(report: Report, *, path: Optional[Path] = None) -> str:
    payload = report.to_dict()
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return json.dumps(payload, indent=2)


def render_html(report: Report, *, path: Path) -> None:
    try:
        template = Template(config.HTML_TEMPLATE)
        payload = report.to_dict()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            template.render(summary=payload["summary"], findings=payload["findings"]),
            encoding="utf-8",
        )
    except Exception as exc:  # noqa: BLE001
        raise ReportRenderingError("Failed to render HTML report") from exc


def render(report: Report, *, fmt: str, output: Optional[Path] = None) -> None:
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

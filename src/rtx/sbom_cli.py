from __future__ import annotations

import argparse
from pathlib import Path

from rtx.api import scan_project
from rtx.sbom import write_sbom


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a CycloneDX SBOM with Real Tracker X")
    parser.add_argument("--path", type=Path, default=Path("."), help="Project root to scan")
    parser.add_argument("--output", type=Path, required=True, help="Output SBOM path")
    parser.add_argument("--managers", nargs="*", help="Restrict to specific managers (e.g., npm pypi)")
    args = parser.parse_args()

    report = scan_project(args.path, managers=args.managers)
    write_sbom(report, path=str(args.output))


if __name__ == "__main__":
    main()

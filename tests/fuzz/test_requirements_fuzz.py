from __future__ import annotations

import os
import random

import pytest

from rtx.scanners import common

atheris = pytest.importorskip("atheris", reason="atheris required for fuzz tests")


def _fuzz_once(data: bytes, tmp_dir) -> None:
    text = data.decode("utf-8", errors="ignore")
    path = tmp_dir / "requirements.txt"
    path.write_text(text, encoding="utf-8")
    try:
        common.read_requirements(path)
    except ValueError:
        pass


def test_requirements_parser_fuzz(tmp_path) -> None:
    instrumented = atheris.instrument_func(_fuzz_once)
    for _ in range(64):
        payload = os.urandom(random.randint(0, 128))
        instrumented(payload, tmp_path)

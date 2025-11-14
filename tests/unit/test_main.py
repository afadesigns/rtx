from __future__ import annotations

from unittest.mock import patch
import runpy
import sys


def test_main() -> None:
    with patch("rtx.cli.entrypoint") as mock_entrypoint:
        # The module is likely already loaded by pytest, so we need to unload it to re-trigger the __main__ block.
        if "rtx.__main__" in sys.modules:
            del sys.modules["rtx.__main__"]
        runpy.run_module("rtx.__main__", run_name="__main__")
        mock_entrypoint.assert_called_once()

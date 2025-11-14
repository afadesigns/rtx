from __future__ import annotations

import os

import pytest

from rtx import config


@pytest.mark.parametrize(
    ("name", "value", "default", "expected"),
    [
        ("RTX_TEST_INT", "10", 5, 10),
        ("RTX_TEST_INT", "abc", 5, 5),
        ("RTX_TEST_INT", None, 5, 5),
    ],
)
def test_int_env(name: str, value: str | None, default: int, expected: int) -> None:
    if value is not None:
        os.environ[name] = value
    elif name in os.environ:
        del os.environ[name]
    assert config._int_env(name, default) == expected


@pytest.mark.parametrize(
    ("name", "value", "default", "expected"),
    [
        ("RTX_TEST_NON_NEGATIVE_INT", "10", 5, 10),
        ("RTX_TEST_NON_NEGATIVE_INT", "-10", 5, 5),
        ("RTX_TEST_NON_NEGATIVE_INT", "abc", 5, 5),
        ("RTX_TEST_NON_NEGATIVE_INT", None, 5, 5),
    ],
)
def test_non_negative_int_env(
    name: str, value: str | None, default: int, expected: int
) -> None:
    if value is not None:
        os.environ[name] = value
    elif name in os.environ:
        del os.environ[name]
    assert config._non_negative_int_env(name, default) == expected


@pytest.mark.parametrize(
    ("name", "value", "default", "expected"),
    [
        ("RTX_TEST_FLOAT", "10.5", 5.5, 10.5),
        ("RTX_TEST_FLOAT", "-10.5", 5.5, 5.5),
        ("RTX_TEST_FLOAT", "abc", 5.5, 5.5),
        ("RTX_TEST_FLOAT", None, 5.5, 5.5),
    ],
)
def test_float_env(
    name: str, value: str | None, default: float, expected: float
) -> None:
    if value is not None:
        os.environ[name] = value
    elif name in os.environ:
        del os.environ[name]
    assert config._float_env(name, default) == expected


@pytest.mark.parametrize(
    ("name", "value", "default", "expected"),
    [
        ("RTX_TEST_BOOL", "true", False, True),
        ("RTX_TEST_BOOL", "false", True, False),
        ("RTX_TEST_BOOL", "abc", False, False),
        ("RTX_TEST_BOOL", None, True, True),
    ],
)
def test_bool_env(name: str, value: str | None, default: bool, expected: bool) -> None:
    if value is not None:
        os.environ[name] = value
    elif name in os.environ:
        del os.environ[name]
    assert config._bool_env(name, default) == expected
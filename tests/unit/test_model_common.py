# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for shared model helpers."""

import pytest
from pydantic import TypeAdapter, ValidationError

from dg_configurator.model.common import SupportingFileName, raise_coded_issues

_ADAPTER = TypeAdapter(SupportingFileName)


@pytest.mark.parametrize("value", ["", "/abs", "a/../b", "a/./b", "a\\b", "a\x00b", "a//b", "../a"])
def test_supporting_file_name_rejects_unsafe_values(value: str):
    with pytest.raises(ValidationError):
        _ADAPTER.validate_python(value)


@pytest.mark.parametrize("value", ["ca.pem", "certs/ca.pem"])
def test_supporting_file_name_accepts_safe_values(value: str):
    assert _ADAPTER.validate_python(value) == value


def test_raise_coded_issues_is_a_no_op_without_issues():
    raise_coded_issues("Sample", [])


def test_raise_coded_issues_carries_code_in_message():
    with pytest.raises(ValidationError) as exc_info:
        raise_coded_issues("Sample", [("my_code", ("a", 0), "something is wrong")])

    error = exc_info.value.errors()[0]
    assert error["loc"] == ("a", 0)
    assert error["msg"] == "Value error, [my_code] something is wrong"

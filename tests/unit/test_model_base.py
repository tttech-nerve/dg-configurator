# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the shared model base and primitive types."""

import pytest
from pydantic import TypeAdapter, ValidationError

from dg_configurator.model.base import StrictModel, Uint32


class _Sample(StrictModel):
    tls_enabled: bool = False


def test_alias_is_camel_case_and_python_name_is_accepted():
    assert _Sample.model_validate({"tlsEnabled": True}).tls_enabled is True
    assert _Sample.model_validate({"tls_enabled": True}).tls_enabled is True


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        _Sample.model_validate({"unknownField": 1})


@pytest.mark.parametrize("value", [0, 4294967295])
def test_uint32_accepts_bounds(value: int):
    assert TypeAdapter(Uint32).validate_python(value) == value


@pytest.mark.parametrize("value", [-1, 4294967296])
def test_uint32_rejects_out_of_range(value: int):
    with pytest.raises(ValidationError):
        TypeAdapter(Uint32).validate_python(value)

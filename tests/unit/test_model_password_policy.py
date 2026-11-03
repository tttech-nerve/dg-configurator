# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for PasswordPolicy."""

import pytest
from pydantic import ValidationError

from dg_configurator.model.password_policy import PasswordPolicy


def test_defaults_validate():
    policy = PasswordPolicy.model_validate({})

    assert (policy.min_length, policy.max_length) == (15, 15)
    assert policy.symbols == "!#$%*+-.:=?@^_~"


def test_min_length_above_max_length_is_rejected():
    with pytest.raises(ValidationError):
        PasswordPolicy.model_validate({"minLength": 20, "maxLength": 10})


def test_all_character_classes_disabled_is_rejected():
    with pytest.raises(ValidationError):
        PasswordPolicy.model_validate(
            {"useLowercase": False, "useUppercase": False, "useDigits": False, "useSymbols": False}
        )


def test_symbols_outside_the_alphabet_are_rejected():
    with pytest.raises(ValidationError):
        PasswordPolicy.model_validate({"symbols": "ab"})


def test_single_symbol_is_accepted_when_symbols_are_disabled():
    assert PasswordPolicy.model_validate({"useSymbols": False, "symbols": "!"}).symbols == "!"

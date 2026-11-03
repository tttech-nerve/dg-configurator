# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Unit tests for the domain exception hierarchy."""

import pytest

from dg_configurator import errors


@pytest.mark.parametrize(
    "exception_class",
    [
        errors.InvalidPackageError,
        errors.SignatureError,
        errors.KeyLoadError,
        errors.UnsafeArchiveError,
        errors.OutputExistsError,
        errors.PkiError,
        errors.ConversionError,
    ],
)
def test_domain_errors_derive_from_configurator_error(exception_class: type[Exception]):
    assert issubclass(exception_class, errors.ConfiguratorError)
    assert issubclass(exception_class, Exception)

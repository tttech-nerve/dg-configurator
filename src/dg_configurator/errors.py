# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Domain exceptions for dg_configurator. Caught only at the CLI and HTTP edges."""


class ConfiguratorError(Exception):
    """Base class for all dg_configurator domain errors."""


class InvalidPackageError(ConfiguratorError):
    """Raised when an imported package is not a recognised config/zip/tar/project format."""


class SignatureError(ConfiguratorError):
    """Raised when a detached signature cannot be verified against the given public key."""


class KeyLoadError(ConfiguratorError):
    """Raised when a private or public key cannot be parsed, or is the wrong type/size."""


class UnsafeArchiveError(ConfiguratorError):
    """Raised when a zip/tar archive violates the safety limits in safe_archive.py."""


class OutputExistsError(ConfiguratorError):
    """Raised when a CLI command would overwrite an existing file without --force."""


class PkiError(ConfiguratorError):
    """Raised when a PKI request is invalid or an existing CA/key cannot be used."""


class ConversionError(ConfiguratorError):
    """Raised when a certificate or key file cannot be converted to PEM."""

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""configurator - a Nerve Data Gateway tool."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("dg-configurator")
except PackageNotFoundError:  # pragma: no cover - only reached when running from an uninstalled source tree
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]

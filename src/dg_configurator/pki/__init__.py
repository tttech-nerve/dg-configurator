# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""PKI generation (CA, server and client certificates) for the Data Gateway."""

from .builder import SanSpec, SubjectSpec
from .convert import ConversionResult, convert_to_pem
from .generator import CaRequest, ExistingCa, GeneratedFile, LeafRequest, PkiRequest, PkiResult, generate_pki
from .keys import ALLOWED_KEYS, KeySpec
from .profiles import PROFILES, Usage

__all__ = [
    "ALLOWED_KEYS",
    "PROFILES",
    "CaRequest",
    "ConversionResult",
    "ExistingCa",
    "GeneratedFile",
    "KeySpec",
    "LeafRequest",
    "PkiRequest",
    "PkiResult",
    "SanSpec",
    "SubjectSpec",
    "Usage",
    "convert_to_pem",
    "generate_pki",
]

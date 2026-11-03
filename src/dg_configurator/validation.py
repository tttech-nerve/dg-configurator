# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Validation entry point: turns raw config bytes/dict into a ValidationReport."""

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import ValidationError

from .model import SCHEMA_URLS, UserConfig

Path = tuple[str | int, ...]

_PEM_SUFFIX = ".pem"

_CODE_PATTERN = re.compile(r"^Value error, \[(?P<code>[a-z_]+)\] (?P<rest>.*)$", re.DOTALL)
_LINE_COL_PATTERN = re.compile(r"line (?P<line>\d+) column (?P<column>\d+)")
# discriminator values pydantic inserts into error locations of tagged unions
_UNION_TAGS = frozenset({"mqtt-client", "opcua-client", "sql-client", "sql-columnar-writer", "sql-binary-writer"})


@dataclass
class Diagnostic:
    """One validation finding."""

    severity: Literal["error", "warning"]
    code: str
    path: Path
    message: str
    line: int | None = None
    column: int | None = None


@dataclass
class ValidationReport:
    """Result of validating a config document."""

    valid: bool
    version: str | None
    diagnostics: list[Diagnostic] = field(default_factory=list)


def _clean_path(loc: Iterable[str | int]) -> Path:
    """Drop the union discriminator tags pydantic adds after list indices."""
    cleaned: list[str | int] = []
    for segment in loc:
        if isinstance(segment, str) and segment in _UNION_TAGS and cleaned and isinstance(cleaned[-1], int):
            continue
        cleaned.append(segment)
    return tuple(cleaned)


def _extract_diagnostic(error: dict[str, Any]) -> Diagnostic:
    """Map one pydantic ``ErrorDetails`` dict to a Diagnostic.

    ``json_invalid`` keeps its line/column. A ``value_error`` whose message starts with a ``[code]`` tag (raised by the
    cross-object validators) keeps that code. Any other ``value_error`` is a cross-field rule of the model, and every
    remaining pydantic error type is a plain schema violation.
    """
    err_type = error["type"]
    msg = error["msg"]
    path = _clean_path(error["loc"])

    if err_type == "json_invalid":
        match = _LINE_COL_PATTERN.search(msg)
        line = int(match.group("line")) if match else None
        column = int(match.group("column")) if match else None
        return Diagnostic("error", "json_invalid", path, msg, line, column)

    if err_type == "value_error":
        match = _CODE_PATTERN.match(msg)
        if match:
            return Diagnostic("error", match.group("code"), path, match.group("rest"))
        return Diagnostic("error", "cross_field_invalid", path, msg.removeprefix("Value error, "))

    return Diagnostic("error", "schema_invalid", path, msg)


def _declared_version(data: bytes) -> str | None:
    try:
        document = json.loads(data)
    except ValueError:
        return None
    version = document.get("version") if isinstance(document, dict) else None
    return version if isinstance(version, str) else None


def validate(raw: bytes | str, available_files: set[str] | None = None) -> ValidationReport:
    """Validate a config document (JSON text or bytes).

    Args:
        raw: The config.json content, as bytes or str.
        available_files: Names of supporting files available alongside the config. When ``None``, the
            ``file_missing`` / ``file_unreferenced`` checks are skipped.

    Returns:
        A ValidationReport. ``valid`` is False iff there is at least one error-severity diagnostic; warnings never
        flip it.
    """
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    try:
        config = UserConfig.model_validate_json(data)
    except ValidationError as exc:
        return ValidationReport(
            valid=False,
            version=_declared_version(data),
            diagnostics=[_extract_diagnostic(error) for error in exc.errors()],
        )
    return validate_model(config, available_files)


def validate_model(config: UserConfig, available_files: set[str] | None = None) -> ValidationReport:
    """Run the checks that need an already parsed config (files and warnings)."""
    diagnostics: list[Diagnostic] = []

    if available_files is not None:
        referenced = {linked.name for linked in config.linked_files()}
        diagnostics.extend(
            Diagnostic("error", "file_missing", (), f"referenced file not found: {name}")
            for name in sorted(referenced - available_files)
        )
        diagnostics.extend(
            Diagnostic("warning", "file_unreferenced", (), f"file not referenced by config: {name}")
            for name in sorted(available_files - referenced)
        )

    diagnostics.extend(_warnings(config))
    valid = not any(d.severity == "error" for d in diagnostics)
    return ValidationReport(valid=valid, version=config.version.value, diagnostics=diagnostics)


def _warnings(config: UserConfig) -> list[Diagnostic]:
    warnings: list[Diagnostic] = []
    if config.json_schema_url is not None and config.json_schema_url != SCHEMA_URLS.get(config.version):
        warnings.append(
            Diagnostic("warning", "schema_url_mismatch", ("$schema",), "$schema does not match the declared version")
        )
    for e_idx, endpoint in enumerate(config.endpoints):
        security = getattr(endpoint, "security", None)
        if security is not None and getattr(security, "tls_insecure", False):
            warnings.append(
                Diagnostic(
                    "warning",
                    "tls_insecure",
                    ("endpoints", e_idx, "security", "tlsInsecure"),
                    "the peer certificate is not verified",
                )
            )
        warnings.extend(
            Diagnostic(
                "warning",
                "file_not_pem",
                ("endpoints", e_idx, "security", linked.role),
                f"{linked.role} file must be PEM encoded and named *.pem: {linked.name}",
            )
            for linked in endpoint.linked_files()
            if not linked.name.lower().endswith(_PEM_SUFFIX)
        )
        bootstrap = getattr(endpoint, "bootstrap", None)
        if bootstrap is not None and bootstrap.allow_plaintext_export:
            warnings.append(
                Diagnostic(
                    "warning",
                    "plaintext_export",
                    ("endpoints", e_idx, "bootstrap", "allowPlaintextExport"),
                    "exported credential files are not encrypted",
                )
            )
    return warnings

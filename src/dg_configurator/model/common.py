# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Shared enums, the supporting-file-name type, and endpoint/input/output ABCs."""

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Annotated, ClassVar

from pydantic import AfterValidator, ValidationError
from pydantic_core import InitErrorDetails

from .base import StrictModel, Uint32
from .version import ConfigVersion


class MessageEncoding(StrEnum):
    """Message payload format used by an input or output."""

    JSON = "json"
    PROTOBUF = "protobuf"
    BINARY = "binary"


_FORBIDDEN_PATH_CHARS = ("\\", "\x00")


def _validate_supporting_file_name(value: str) -> str:
    if not value:
        raise ValueError("supporting file name must not be empty")
    if value.startswith("/"):
        raise ValueError("supporting file name must not be an absolute path")
    for ch in _FORBIDDEN_PATH_CHARS:
        if ch in value:
            raise ValueError(f"supporting file name must not contain {ch!r}")
    parts = value.split("/")
    if any(part in ("", "..", ".") for part in parts):
        raise ValueError("supporting file name must not contain '..', '.' or empty segments")
    return value


SupportingFileName = Annotated[str, AfterValidator(_validate_supporting_file_name)]


def raise_coded_issues(title: str, issues: list[tuple[str, tuple[str | int, ...], str]]) -> None:
    """Raise one ``ValidationError`` carrying every ``(code, loc, message)`` issue (no-op when empty).

    The diagnostic code travels as a ``[code]`` prefix inside the error message, which is the only channel that
    survives ``ValidationError.errors()`` unchanged.
    """
    if not issues:
        return
    raise ValidationError.from_exception_data(
        title=title,
        line_errors=[
            InitErrorDetails(type="value_error", loc=loc, input=None, ctx={"error": ValueError(f"[{code}] {message}")})
            for code, loc, message in issues
        ],
    )


class LinkedFile(StrictModel):
    """One supporting file referenced by an endpoint's security settings."""

    endpoint_id: int
    role: str  # "ca" | "certificate" | "key"
    name: str


class EndpointBase(StrictModel, ABC):
    """Common fields shared by every endpoint type."""

    MIN_CONFIG_VERSION: ClassVar[ConfigVersion] = ConfigVersion.V1_0

    id: Uint32
    name: str
    description: str = ""

    @abstractmethod
    def linked_files(self) -> list[LinkedFile]:
        """Return every supporting file this endpoint references."""


class InputBase(StrictModel, ABC):
    """Common fields shared by every input type."""

    id: Uint32
    name: str
    description: str = ""

    @property
    @abstractmethod
    def encoding(self) -> MessageEncoding:
        """The message format this input produces."""


class OutputBase(StrictModel, ABC):
    """Common fields shared by every output type."""

    id: Uint32
    name: str
    description: str = ""

    @abstractmethod
    def accepts(self, encoding: MessageEncoding) -> bool:
        """Whether this output can consume the given encoding."""

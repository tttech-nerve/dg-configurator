# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""PasswordPolicy — generated-password characteristics (config.json, v1.1+)."""

from typing import ClassVar, Self

from pydantic import Field, model_validator

from .base import StrictModel
from .version import ConfigVersion

_SYMBOL_ALPHABET = "!#$%*+-.:=?@^_~"


class PasswordPolicy(StrictModel):
    """Characteristics of every password the Data Gateway generates."""

    MIN_CONFIG_VERSION: ClassVar[ConfigVersion] = ConfigVersion.V1_1

    min_length: int = Field(15, ge=8, le=256)
    max_length: int = Field(15, ge=8, le=256)
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    symbols: str = Field(_SYMBOL_ALPHABET, min_length=1, pattern=r"^[!#$%*+.:=?@^_~-]+$")

    @model_validator(mode="after")
    def _check_cross_fields(self) -> Self:
        if self.min_length > self.max_length:
            raise ValueError("minLength must be <= maxLength")
        if not any((self.use_lowercase, self.use_uppercase, self.use_digits, self.use_symbols)):
            raise ValueError("at least one of useLowercase/useUppercase/useDigits/useSymbols must be true")
        return self

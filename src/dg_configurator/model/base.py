# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""Shared Pydantic base model and primitive types for the config.json domain model."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

Uint32 = Annotated[int, Field(ge=0, le=4294967295)]


class StrictModel(BaseModel):
    """Base model for every config.json object.

    - ``extra="forbid"``: unknown JSON fields are rejected (config.json has ``additionalProperties: false``).
    - Fields can be populated by Python name or by JSON alias.
    - ``alias_generator=to_camel``: every field's JSON alias is the camelCase form of its snake_case
      Python name (e.g. ``tls_enabled`` -> ``tlsEnabled``).
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_by_name=True,
        validate_by_alias=True,
        alias_generator=to_camel,
    )
